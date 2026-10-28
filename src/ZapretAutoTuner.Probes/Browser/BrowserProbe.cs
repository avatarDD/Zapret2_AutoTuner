using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Playwright;
using ZapretAutoTuner.Core.Diagnostics;

namespace ZapretAutoTuner.Probes.Browser;

public enum BrowserKind
{
    Chromium,
    Firefox,
}

public sealed record BrowserProbeOptions
{
    public required string Url { get; init; }

    public BrowserKind Browser { get; init; } = BrowserKind.Chromium;

    /// <summary>The browser binary; null finds a bundled one (<see cref="BrowserLocator"/>) or Playwright's own.</summary>
    public string? ExecutablePath { get; init; }

    public bool Headless { get; init; } = true;

    /// <summary>
    /// DoH template such as <c>https://cloudflare-dns.com/dns-query</c>: the browser resolves through it only, so a
    /// poisoned system DNS does not spoil the check. Null uses the system resolver.
    /// </summary>
    public string? DohTemplate { get; init; }

    /// <summary>Host to address overrides (Chromium only), to check a pinned IP before writing hosts.</summary>
    public IReadOnlyDictionary<string, string> Resolve { get; init; } = new Dictionary<string, string>();

    /// <summary>How long to wait for the <c>load</c> event.</summary>
    public TimeSpan LoadTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>After <c>load</c>, how long to let late requests finish; whatever is still pending is stalled.</summary>
    public TimeSpan Settle { get; init; } = TimeSpan.FromSeconds(5);

    public string? HarPath { get; init; }

    public string? ScreenshotPath { get; init; }

    /// <summary>Tests only: accept any certificate (the local test servers use a private CA).</summary>
    public bool IgnoreCertificateErrors { get; init; }

    public string? UserAgent { get; init; }
}

/// <summary>
/// Opens a page in a real browser (PLAN 2.4, dpi-diagnostics §3 L3 and §4): a fresh isolated profile with no cache
/// and no extensions, the network log of every request, the hosts the page hints at, HAR and a screenshot.
/// </summary>
public static class BrowserProbe
{
    private const string HintsScript =
        "() => Array.from(document.querySelectorAll('link[rel~=preconnect],link[rel~=dns-prefetch]')).map(l => l.href)";

    public static async Task<PageLoad> RunAsync(BrowserProbeOptions o, CancellationToken ct = default)
    {
        using var pw = await Playwright.CreateAsync().ConfigureAwait(false);
        var type = o.Browser == BrowserKind.Firefox ? pw.Firefox : pw.Chromium;
        IBrowser browser;
        try
        {
            browser = await type.LaunchAsync(LaunchOptions(o)).ConfigureAwait(false);
        }
        catch (PlaywrightException e) when (e.Message.Contains("executable doesn't exist", StringComparison.OrdinalIgnoreCase))
        {
            throw new BrowserNotFoundException(o.Browser, e);
        }
        await using var owned = browser;
        return await OpenAsync(owned, o, ct).ConfigureAwait(false);
    }

    /// <summary>Opens the page in an already running browser, in a new isolated context.</summary>
    public static async Task<PageLoad> OpenAsync(IBrowser browser, BrowserProbeOptions o, CancellationToken ct = default)
    {
        var ctxOptions = new BrowserNewContextOptions
        {
            IgnoreHTTPSErrors = o.IgnoreCertificateErrors,
            ServiceWorkers = ServiceWorkerPolicy.Block, // a worker would hide its requests from the page log
            RecordHarPath = o.HarPath,
            RecordHarContent = o.HarPath is null ? null : HarContentPolicy.Omit,
            UserAgent = o.UserAgent,
        };
        await using var context = await browser.NewContextAsync(ctxOptions).ConfigureAwait(false);
        var page = await context.NewPageAsync().ConfigureAwait(false);

        var sw = Stopwatch.StartNew();
        var log = new ConcurrentDictionary<IRequest, Entry>();
        var webSockets = new ConcurrentBag<string>();
        var altSvc = new ConcurrentBag<string>();
        var pending = new ConcurrentBag<Task>();

        page.Request += (_, r) => log.TryAdd(r, new Entry(sw.Elapsed));
        page.RequestFailed += (_, r) =>
        {
            if (log.TryGetValue(r, out var e))
                e.Finish(sw.Elapsed, r.Failure ?? "failed");
        };
        page.RequestFinished += (_, r) =>
        {
            if (!log.TryGetValue(r, out var e))
                return;
            e.Finish(sw.Elapsed, null);
            pending.Add(FillAsync(r, e, altSvc));
        };
        page.Response += (_, resp) =>
        {
            if (log.TryGetValue(resp.Request, out var e))
                e.Answered(sw.Elapsed, resp.Status);
        };
        page.WebSocket += (_, ws) => webSockets.Add(ws.Url);

        bool loadFired = false;
        TimeSpan? loadTime = null;
        string? navError = null;
        using var reg = ct.Register(() => _ = page.CloseAsync());
        try
        {
            var resp = await page.GotoAsync(o.Url, new PageGotoOptions
            {
                WaitUntil = WaitUntilState.Load,
                Timeout = (float)o.LoadTimeout.TotalMilliseconds,
            }).ConfigureAwait(false);
            loadFired = true;
            loadTime = sw.Elapsed;
            if (resp is null)
                navError = "no response";
        }
        catch (TimeoutException)
        {
            // the page may have rendered: what failed is in the log
        }
        catch (PlaywrightException ex)
        {
            navError = FirstLine(ex.Message);
        }
        ct.ThrowIfCancellationRequested();

        // let late requests settle, but stop as soon as nothing is in flight
        var settleUntil = sw.Elapsed + o.Settle;
        while (sw.Elapsed < settleUntil && log.Values.Any(e => !e.Done && e.Headers is null))
            await Task.Delay(200, ct).ConfigureAwait(false);

        List<string> hints = [];
        string? screenshot = null;
        if (!page.IsClosed)
        {
            try
            {
                hints = [.. await page.EvaluateAsync<string[]>(HintsScript).ConfigureAwait(false) ?? []];
            }
            catch (PlaywrightException)
            {
            }
            if (o.ScreenshotPath is not null)
            {
                try
                {
                    await page.ScreenshotAsync(new PageScreenshotOptions { Path = o.ScreenshotPath, Timeout = 10_000 }).ConfigureAwait(false);
                    screenshot = o.ScreenshotPath;
                }
                catch (Exception ex) when (ex is PlaywrightException or TimeoutException)
                {
                }
            }
        }
        await Task.WhenAll(pending).ConfigureAwait(false);
        var duration = sw.Elapsed;
        var requests = log.OrderBy(kv => kv.Value.Started).Select(kv => kv.Value.ToRequest(kv.Key)).ToList();
        await context.CloseAsync().ConfigureAwait(false); // writes the HAR

        return new PageLoad
        {
            Url = o.Url,
            Browser = o.Browser == BrowserKind.Firefox ? "firefox" : "chromium",
            LoadFired = loadFired,
            LoadTime = loadTime,
            Duration = duration,
            Requests = requests,
            Hints = hints,
            WebSockets = [.. webSockets.Distinct()],
            AltSvc = [.. altSvc.Distinct()],
            Error = navError,
            HarPath = o.HarPath is not null && File.Exists(o.HarPath) ? o.HarPath : null,
            ScreenshotPath = screenshot,
        };
    }

    public static BrowserTypeLaunchOptions LaunchOptions(BrowserProbeOptions o)
    {
        var launch = new BrowserTypeLaunchOptions
        {
            Headless = o.Headless,
            ExecutablePath = o.ExecutablePath ?? (o.Browser == BrowserKind.Firefox ? BrowserLocator.Firefox() : BrowserLocator.Chromium()),
        };
        if (o.Browser == BrowserKind.Chromium)
        {
            launch.Args = ChromiumArgs(o);
        }
        else
        {
            var prefs = new Dictionary<string, object>
            {
                ["browser.cache.disk.enable"] = false,
                ["network.http.speculative-parallel-limit"] = 0,
            };
            if (o.DohTemplate is not null)
            {
                prefs["network.trr.mode"] = 3; // DoH only
                prefs["network.trr.uri"] = o.DohTemplate;
            }
            launch.FirefoxUserPrefs = prefs;
        }
        return launch;
    }

    internal static List<string> ChromiumArgs(BrowserProbeOptions o)
    {
        var args = new List<string> { "--disable-extensions", "--no-first-run", "--disk-cache-size=1", "--disable-background-networking" };
        if (o.Resolve.Count > 0)
            args.Add("--host-resolver-rules=" + string.Join(", ", o.Resolve.Select(kv => $"MAP {kv.Key} {kv.Value}")));
        if (o.DohTemplate is not null)
        {
            // Chromium has no plain switch for secure DNS; the field trial is how its own tests turn it on
            args.Add("--enable-features=DnsOverHttps<DoHTrial");
            args.Add("--force-fieldtrials=DoHTrial/Group1");
            args.Add("--force-fieldtrial-params=DoHTrial.Group1:Fallback/false/Templates/" + Uri.EscapeDataString(o.DohTemplate));
        }
        return args;
    }

    private static async Task FillAsync(IRequest r, Entry e, ConcurrentBag<string> altSvc)
    {
        try
        {
            var sizes = await r.SizesAsync().ConfigureAwait(false);
            e.Bytes = Math.Max(0, sizes.ResponseBodySize);
            var resp = await r.ResponseAsync().ConfigureAwait(false);
            if (resp is not null)
            {
                e.Status = resp.Status;
                if (await resp.HeaderValueAsync("alt-svc").ConfigureAwait(false) is { } alt)
                {
                    foreach (var h in Har.AltSvcHosts(alt))
                        altSvc.Add(h);
                }
            }
        }
        catch (PlaywrightException)
        {
            // the page or context closed under us: keep what we have
        }
    }

    private static string FirstLine(string s)
    {
        int i = s.IndexOf('\n', StringComparison.Ordinal);
        return (i < 0 ? s : s[..i]).Trim();
    }

    private sealed class Entry(TimeSpan started)
    {
        private readonly Lock _gate = new();

        public TimeSpan Started { get; } = started;

        public TimeSpan? Ended { get; private set; }

        public string? Error { get; private set; }

        public bool Done => Ended is not null;

        public long Bytes { get; set; }

        public int? Status { get; set; }

        /// <summary>When the response headers came; a stream (SSE, long poll) may never finish but is not stalled.</summary>
        public TimeSpan? Headers { get; private set; }

        public void Answered(TimeSpan at, int status)
        {
            lock (_gate)
            {
                Headers ??= at;
                Status ??= status;
            }
        }

        public void Finish(TimeSpan at, string? error)
        {
            lock (_gate)
            {
                Ended ??= at;
                Error ??= error;
            }
        }

        public PageRequest ToRequest(IRequest r) => new()
        {
            Url = r.Url,
            Method = r.Method,
            ResourceType = r.ResourceType,
            Status = Status,
            Error = Error,
            Bytes = Bytes,
            Started = Started,
            Duration = Error is not null ? null : Ended is { } end ? end - Started : Headers is { } h ? h - Started : null,
        };
    }
}

/// <summary>No browser to open the page with: none bundled and none installed by Playwright.</summary>
public sealed class BrowserNotFoundException(BrowserKind kind, Exception? inner = null) : Exception(
    kind == BrowserKind.Firefox
        ? "не найден браузер Firefox для Playwright / no Playwright Firefox found"
        : "не найден браузер программы для проверки страницы (папка browsers рядом с ZapretAutoTuner): переустановите программу из релиза или укажите путь к Chromium в ZT_CHROMIUM"
          + " / the program's browser for the page check is missing (the browsers folder next to ZapretAutoTuner): reinstall from a release or set ZT_CHROMIUM to a Chromium",
    inner)
{
    public BrowserKind Kind { get; } = kind;
}
