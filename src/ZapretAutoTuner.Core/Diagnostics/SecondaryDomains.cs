using System.Text.Json;
using System.Text.Json.Serialization;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Core.Diagnostics;

/// <summary>How a domain fared while the page loaded (dpi-diagnostics §4.3).</summary>
public enum DomainState
{
    Ok,

    /// <summary>Some requests went through and some failed: typical of a cutoff at 16 KB.</summary>
    Partial,

    Failed,

    /// <summary>Requests never finished before the page timeout.</summary>
    Stalled,

    /// <summary>Blocked by the browser itself (an extension or the browser's own list), not by the network.</summary>
    BlockedByClient,

    /// <summary>Seen only as a hint (preconnect, Alt-Svc) with no traffic: nothing to judge yet.</summary>
    NotUsed,
}

[Flags]
public enum DomainSource
{
    None = 0,
    Request = 1,
    Hint = 2,
    WebSocket = 4,
    AltSvc = 8,
    Pcap = 16,
}

public sealed record SecondaryDomain
{
    public required string Host { get; init; }

    public DomainState State { get; init; }

    /// <summary>The first error seen for the domain.</summary>
    public string? Error { get; init; }

    /// <summary>The page needs it: a failure here breaks the page. Ads and trackers are not important.</summary>
    public bool Important { get; init; }

    public string ReasonRu { get; init; } = "";

    public string ReasonEn { get; init; } = "";

    /// <summary>Something worth showing even when the domain works, such as QUIC being blocked.</summary>
    public string? Note { get; init; }

    public DomainSource Sources { get; init; }

    public int Requests { get; init; }

    public int FailedRequests { get; init; }

    public long Bytes { get; init; }

    public bool IsMain { get; init; }

    public bool Broken => State is DomainState.Partial or DomainState.Failed or DomainState.Stalled;

    public override string ToString() => $"{Host} {State}{(Important ? "" : " (не важно)")}{(Error is null ? "" : $" {Error}")}";
}

/// <summary>Ad and tracker hosts (data, <c>Diagnostics/Data/noise-domains.json</c>).</summary>
public sealed class NoiseList
{
    public List<string> Suffixes { get; set; } = [];

    private static readonly Lazy<NoiseList> DefaultLazy = new(() =>
    {
        using var s = typeof(NoiseList).Assembly.GetManifestResourceStream("ZapretAutoTuner.Core.Diagnostics.noise-domains.json")
            ?? throw new InvalidOperationException("noise-domains.json is missing");
        return JsonSerializer.Deserialize(s, PageJsonContext.Default.NoiseList) ?? new NoiseList();
    });

    public static NoiseList Default => DefaultLazy.Value;

    public bool Matches(string host)
    {
        host = host.TrimEnd('.').ToLowerInvariant();
        foreach (var s in Suffixes)
        {
            if (host == s || host.EndsWith("." + s, StringComparison.Ordinal))
                return true;
        }
        return false;
    }
}

/// <summary>
/// Secondary domains of a page (PLAN 2.6, dpi-diagnostics §4): every host the page touched, from the browser's
/// requests, hints, WebSockets, Alt-Svc and the SNI seen in the capture, each with a state and an importance. Pure:
/// the browser and the capture run elsewhere.
/// </summary>
public static class SecondaryDomains
{
    /// <summary>Errors that do not mean the network failed: the page itself cancelled the request.</summary>
    private static readonly string[] Benign = ["net::ERR_ABORTED", "NS_BINDING_ABORTED", "NS_BINDING_REDIRECTED", "net::ERR_CACHE_MISS"];

    /// <summary>Errors the browser raises when it blocks a request on its own.</summary>
    private static readonly string[] ByClient = ["net::ERR_BLOCKED_BY_CLIENT", "net::ERR_BLOCKED_BY_RESPONSE", "NS_ERROR_TRACKING_URI", "NS_ERROR_BLOCKED_URI"];

    /// <summary>Resource types a page cannot do without.</summary>
    private static readonly HashSet<string> NeededTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "document", "script", "stylesheet", "xhr", "fetch", "font", "media", "image", "websocket", "eventsource", "texttrack",
    };

    public static List<SecondaryDomain> Analyze(PageLoad load, string mainHost, IEnumerable<Flow>? flows = null, NoiseList? noise = null)
    {
        noise ??= NoiseList.Default;
        mainHost = mainHost.TrimEnd('.').ToLowerInvariant();
        var acc = new Dictionary<string, Acc>(StringComparer.OrdinalIgnoreCase);
        Acc Get(string host) => acc.TryGetValue(host, out var a) ? a : acc[host] = new Acc(host);

        foreach (var r in load.Requests)
        {
            var host = r.Host;
            if (host.Length == 0)
                continue; // data:, blob:, about:
            var a = Get(host);
            a.Sources |= r.ResourceType.Equals("websocket", StringComparison.OrdinalIgnoreCase) ? DomainSource.Request | DomainSource.WebSocket : DomainSource.Request;
            a.Requests++;
            a.Bytes += r.Bytes;
            if (NeededTypes.Contains(r.ResourceType))
                a.Needed = true;
            if (r.Error is { } e)
            {
                if (Benign.Any(b => e.StartsWith(b, StringComparison.Ordinal)))
                    continue;
                if (ByClient.Any(b => e.StartsWith(b, StringComparison.Ordinal)))
                {
                    a.ByClient++;
                    continue;
                }
                a.Failed++;
                a.Error ??= e;
            }
            else if (r.Duration is null)
            {
                a.Stalled++;
            }
            else
            {
                a.Ok++;
            }
        }

        foreach (var (list, src) in new[] { (load.Hints, DomainSource.Hint), (load.WebSockets, DomainSource.WebSocket), (load.AltSvc, DomainSource.AltSvc) })
        {
            foreach (var item in list)
            {
                var host = HostOf(item);
                if (host.Length > 0)
                    Get(host).Sources |= src;
            }
        }

        foreach (var f in flows ?? [])
        {
            if (f.ClientHello?.Sni is not { Length: > 0 } sni)
                continue;
            var a = Get(sni.ToLowerInvariant());
            a.Sources |= DomainSource.Pcap;
            bool quic = f.Protocol == "udp";
            // the server sent nothing back, or the connection was reset from the middle: blocked on the wire
            bool dead = f.PacketsIn == 0 || (!quic && f.BytesIn < 512 && f.Rsts.Count > 0);
            if (dead)
            {
                if (quic)
                    a.QuicDead++;
                else
                    a.WireDead++;
                a.WireError ??= quic ? "QUIC без ответа" : f.Rsts.Count > 0 ? "RST после ClientHello" : "ClientHello без ответа";
            }
            else
            {
                a.WireOk++;
            }
        }

        var mainReg = Classifier.Registrable(mainHost);
        return acc.Values
            .Select(a => Finish(a, mainHost, mainReg, noise))
            .OrderByDescending(d => d.IsMain)
            .ThenByDescending(d => d.Important && d.Broken)
            .ThenByDescending(d => d.Important)
            .ThenBy(d => d.Host, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// L3 (dpi-diagnostics §3): the <c>load</c> event fired, the main document loaded and no important domain is
    /// broken.
    /// </summary>
    public static bool PagePasses(PageLoad load, IReadOnlyList<SecondaryDomain> domains) =>
        load.LoadFired && load.Error is null && !domains.Any(d => d.Important && d.Broken);

    /// <summary>
    /// The largest successful GET of a host: the L2 probe uses it as the "large resource" (dpi-diagnostics §3), so a
    /// cutoff at 16 KB shows even when the main page is small. Null when the page loaded nothing large from it.
    /// </summary>
    public static PageRequest? LargestResponse(PageLoad load, string host, long minBytes = 32 * 1024) =>
        load.Requests
            .Where(r => r.Host.Equals(host, StringComparison.OrdinalIgnoreCase) && r.Error is null && r.Duration is not null
                && r.Status is >= 200 and < 300 && r.Method == "GET" && r.Bytes >= minBytes)
            .MaxBy(r => r.Bytes);

    private static SecondaryDomain Finish(Acc a, string mainHost, string mainReg, NoiseList noise)
    {
        bool isMain = a.Host.Equals(mainHost, StringComparison.OrdinalIgnoreCase);
        bool firstParty = isMain || Classifier.Registrable(a.Host).Equals(mainReg, StringComparison.OrdinalIgnoreCase);

        DomainState state;
        string? error = a.Error;
        int failed = a.Failed;
        if (a.Requests > 0)
        {
            int good = a.Ok;
            int bad = a.Failed + a.Stalled;
            if (bad == 0 && good == 0 && a.ByClient > 0)
                state = DomainState.BlockedByClient;
            else if (bad == 0)
                state = DomainState.Ok;
            else if (good > 0)
                state = DomainState.Partial;
            else
                state = a.Failed >= a.Stalled ? DomainState.Failed : DomainState.Stalled;
            if (state == DomainState.Stalled)
                error ??= "запрос не завершился";
        }
        else if (a.WireDead > 0 && a.WireOk == 0)
        {
            // the browser never reported it (service worker, a request that never started), but the wire saw it fail
            state = DomainState.Failed;
            error = a.WireError;
            failed = a.WireDead;
        }
        else
        {
            state = a.WireOk > 0 ? DomainState.Ok : DomainState.NotUsed;
        }

        // QUIC failures alone do not break a page that loaded over TCP: the browser falls back. They still say the
        // DPI blocks QUIC here, so they are kept as a note.
        string? note = a.QuicDead > 0 && a.WireDead == 0 && state is DomainState.Ok or DomainState.Partial
            ? "QUIC без ответа, браузер перешёл на TCP" : null;

        (bool important, string ru, string en) = isMain ? (true, "основной сайт", "main site")
            : noise.Matches(a.Host) ? (false, "реклама или счётчик", "ads or analytics")
            : state == DomainState.BlockedByClient ? (false, "заблокирован самим браузером", "blocked by the browser itself")
            : firstParty ? (true, "часть сайта", "part of the site")
            : a.Needed ? (true, "нужен странице: скрипты, стили, картинки или данные", "the page needs it: scripts, styles, images or data")
            : a.Requests == 0 && state == DomainState.Failed ? (true, "виден только в трафике, браузер о нём не сообщил", "seen only on the wire, the browser did not report it")
            : a.Requests == 0 ? (false, "только упомянут страницей", "only mentioned by the page")
            : (false, "служебные запросы", "auxiliary requests");

        return new SecondaryDomain
        {
            Host = a.Host,
            State = state,
            Error = state == DomainState.Ok ? null : error,
            Note = note,
            Important = important,
            ReasonRu = ru,
            ReasonEn = en,
            Sources = a.Sources,
            Requests = a.Requests,
            FailedRequests = failed + a.Stalled,
            Bytes = a.Bytes,
            IsMain = isMain,
        };
    }

    private static string HostOf(string item)
    {
        if (Uri.TryCreate(item, UriKind.Absolute, out var u) && u.Host.Length > 0)
            return u.IdnHost.ToLowerInvariant();
        if (item.StartsWith("//", StringComparison.Ordinal) && Uri.TryCreate("https:" + item, UriKind.Absolute, out u))
            return u.IdnHost.ToLowerInvariant();
        var h = item.Trim().TrimEnd('.').ToLowerInvariant();
        return Model.Target.IsValidHostName(h) ? h : "";
    }

    private sealed class Acc(string host)
    {
        public string Host { get; } = host.ToLowerInvariant();
        public DomainSource Sources { get; set; }
        public int Requests { get; set; }
        public int Ok { get; set; }
        public int Failed { get; set; }
        public int Stalled { get; set; }
        public int ByClient { get; set; }
        public long Bytes { get; set; }
        public bool Needed { get; set; }
        public string? Error { get; set; }
        public int WireOk { get; set; }
        public int WireDead { get; set; }
        public int QuicDead { get; set; }
        public string? WireError { get; set; }
    }
}

/// <summary>
/// The fix-and-reload loop of dpi-diagnostics §4.5: open the page, fix the broken important domains, open it again,
/// up to three rounds, because new domains appear only once their scripts load.
/// </summary>
public static class SecondaryDomainLoop
{
    public const int MaxIterations = 3;

    public sealed record Round(int Number, PageLoad Load, IReadOnlyList<SecondaryDomain> Domains, IReadOnlyList<SecondaryDomain> Fixed);

    public sealed record Result(IReadOnlyList<Round> Rounds, bool Passed)
    {
        public IReadOnlyList<SecondaryDomain> Remaining => Rounds.Count == 0 ? [] : [.. Rounds[^1].Domains.Where(d => d.Important && d.Broken)];
    }

    /// <param name="open">Opens the page once and returns what the browser saw (and the capture flows, if any).</param>
    /// <param name="fix">Tries to fix the given domains (classifier and search); returns the ones it fixed.</param>
    public static async Task<Result> RunAsync(
        string mainHost,
        Func<CancellationToken, Task<(PageLoad Load, IReadOnlyList<Flow>? Flows)>> open,
        Func<IReadOnlyList<SecondaryDomain>, CancellationToken, Task<IReadOnlyList<SecondaryDomain>>> fix,
        int maxIterations = MaxIterations,
        NoiseList? noise = null,
        CancellationToken ct = default)
    {
        var rounds = new List<Round>();
        var tried = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i <= Math.Max(1, maxIterations); i++)
        {
            var (load, flows) = await open(ct).ConfigureAwait(false);
            var domains = SecondaryDomains.Analyze(load, mainHost, flows, noise);
            if (SecondaryDomains.PagePasses(load, domains))
            {
                rounds.Add(new Round(i, load, domains, []));
                return new Result(rounds, true);
            }
            // a domain that a fix did not help the first time is not retried: the loop is for new domains
            var broken = domains.Where(d => d.Important && d.Broken && tried.Add(d.Host)).ToList();
            if (broken.Count == 0 || i == maxIterations)
            {
                rounds.Add(new Round(i, load, domains, []));
                break;
            }
            var fixedNow = await fix(broken, ct).ConfigureAwait(false);
            rounds.Add(new Round(i, load, domains, fixedNow));
            if (fixedNow.Count == 0)
                break;
        }
        return new Result(rounds, false);
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true)]
[JsonSerializable(typeof(NoiseList))]
internal sealed partial class PageJsonContext : JsonSerializerContext;
