using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit.Abstractions;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Probes.Browser;

namespace ZapretAutoTuner.Probes.Tests;

/// <summary>
/// PLAN 2.4 and 2.6 against a local page in a real Chromium: hosts are mapped to local ports with
/// <c>--host-resolver-rules</c>, so one test sees a working CDN, a refused domain, a stalled request, an ad domain and
/// a preconnect hint. Needs a Chromium (bundled, <c>ZT_CHROMIUM</c>, Playwright's or the system Chrome); returns early
/// without one.
/// </summary>
[Trait("Category", "Browser")]
public sealed class BrowserProbeTests(ITestOutputHelper output)
{
    private const string Page = """
        <!doctype html><html><head>
        <link rel="preconnect" href="https://hint.test">
        <script src="http://cdn.test/app.js"></script>
        </head><body><h1>main</h1>
        <img src="http://dead.test/logo.png">
        <img src="http://ad.doubleclick.net/pixel.gif">
        <script>window.addEventListener('load', () => fetch('http://slow.test/feed').catch(() => {}));</script>
        </body></html>
        """;

    internal static string? Chromium()
    {
        if (BrowserLocator.Chromium() is { } bundled)
            return bundled;
        string[] system = OperatingSystem.IsWindows()
            ? [@"C:\Program Files\Google\Chrome\Application\chrome.exe", @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"]
            : ["/opt/pw-browsers/chromium-1194/chrome-linux/chrome", "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"];
        return system.FirstOrDefault(File.Exists);
    }

    [Fact]
    public async Task Page_load_reports_every_domain()
    {
        if (Chromium() is not { } chrome)
            return;
        await using var server = new PageServer();
        int closed = ClosedPort();
        var dir = Directory.CreateTempSubdirectory("ztbrowser").FullName;
        try
        {
            var load = await BrowserProbe.RunAsync(new BrowserProbeOptions
            {
                Url = "http://main.test/",
                ExecutablePath = chrome,
                Resolve = new Dictionary<string, string>
                {
                    ["main.test"] = $"127.0.0.1:{server.Port}",
                    ["cdn.test"] = $"127.0.0.1:{server.Port}",
                    ["slow.test"] = $"127.0.0.1:{server.Port}",
                    ["dead.test"] = $"127.0.0.1:{closed}",
                    ["ad.doubleclick.net"] = $"127.0.0.1:{closed}",
                    ["hint.test"] = $"127.0.0.1:{closed}",
                },
                LoadTimeout = TimeSpan.FromSeconds(20),
                Settle = TimeSpan.FromSeconds(2),
                HarPath = Path.Combine(dir, "page.har"),
                ScreenshotPath = Path.Combine(dir, "page.png"),
            });

            Assert.True(load.LoadFired, load.Error);
            Assert.Null(load.Error);
            Assert.Contains(load.Hints, h => h.StartsWith("https://hint.test", StringComparison.Ordinal));
            Assert.NotNull(load.HarPath);
            Assert.NotNull(load.ScreenshotPath);
            Assert.True(new FileInfo(load.ScreenshotPath!).Length > 0);

            var domains = SecondaryDomains.Analyze(load, "main.test");
            output.WriteLine($"{chrome}: load={load.LoadTime} requests={load.Requests.Count}\n" + string.Join("\n", domains));
            var by = domains.ToDictionary(d => d.Host);
            Assert.Equal(DomainState.Ok, by["main.test"].State);
            Assert.True(by["main.test"].IsMain);
            Assert.Equal(DomainState.Ok, by["cdn.test"].State);
            Assert.True(by["cdn.test"].Bytes >= 20_000);
            Assert.Equal(DomainState.Failed, by["dead.test"].State);
            Assert.True(by["dead.test"].Important);
            Assert.StartsWith("net::ERR_", by["dead.test"].Error, StringComparison.Ordinal);
            Assert.Equal(DomainState.Stalled, by["slow.test"].State);
            Assert.Equal(DomainState.Failed, by["ad.doubleclick.net"].State);
            Assert.False(by["ad.doubleclick.net"].Important);
            Assert.Equal(DomainState.NotUsed, by["hint.test"].State);
            Assert.False(SecondaryDomains.PagePasses(load, domains));

            // the HAR Playwright wrote reads back into the same picture
            var har = Har.Parse(await File.ReadAllTextAsync(load.HarPath!));
            Assert.Contains(har.Requests, r => r.Host == "cdn.test" && r.Status == 200);
            Assert.Contains(har.Requests, r => r.Host == "dead.test" && r.Error is not null);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static int ClosedPort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }

    /// <summary>Minimal HTTP/1.1 server: the page, a 20 KB script, and a request that never gets an answer.</summary>
    private sealed class PageServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _loop;

        public PageServer()
        {
            _listener.Start();
            _loop = Task.Run(LoopAsync);
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        private async Task LoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient c;
                try
                {
                    c = await _listener.AcceptTcpClientAsync(_cts.Token);
                }
                catch (Exception) when (_cts.IsCancellationRequested)
                {
                    return;
                }
                _ = Task.Run(() => ServeAsync(c));
            }
        }

        private async Task ServeAsync(TcpClient c)
        {
            using var _ = c;
            var s = c.GetStream();
            var buf = new byte[8192];
            try
            {
                while (true)
                {
                    var sb = new StringBuilder();
                    while (!sb.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
                    {
                        int n = await s.ReadAsync(buf, _cts.Token);
                        if (n == 0)
                            return;
                        sb.Append(Encoding.ASCII.GetString(buf, 0, n));
                    }
                    var head = sb.ToString();
                    var path = head.Split(' ')[1];
                    var host = head.Split("\r\n").FirstOrDefault(l => l.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))?[5..].Trim() ?? "";
                    if (host.StartsWith("slow.test", StringComparison.Ordinal))
                    {
                        await Task.Delay(Timeout.Infinite, _cts.Token);
                        return;
                    }
                    var (type, body) = path switch
                    {
                        "/app.js" => ("application/javascript", "/*" + new string('x', 20_000) + "*/ console.log('app');"),
                        "/" => ("text/html; charset=utf-8", Page),
                        _ => ("text/plain", "not found"),
                    };
                    var bytes = Encoding.UTF8.GetBytes(body);
                    int status = path is "/" or "/app.js" ? 200 : 404;
                    var hdr = $"HTTP/1.1 {status} X\r\nContent-Type: {type}\r\nContent-Length: {bytes.Length}\r\nCache-Control: no-store\r\n\r\n";
                    await s.WriteAsync(Encoding.ASCII.GetBytes(hdr), _cts.Token);
                    await s.WriteAsync(bytes, _cts.Token);
                }
            }
            catch (Exception) when (_cts.IsCancellationRequested)
            {
            }
            catch (IOException)
            {
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _cts.CancelAsync();
            _listener.Stop();
            try
            {
                await _loop;
            }
            catch (OperationCanceledException)
            {
            }
            _cts.Dispose();
        }
    }
}
