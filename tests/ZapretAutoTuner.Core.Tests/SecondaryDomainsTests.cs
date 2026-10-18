using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Core.Tests;

public sealed class SecondaryDomainsTests
{
    private static PageRequest Ok(string url, string type = "script", long bytes = 1000) =>
        new() { Url = url, ResourceType = type, Status = 200, Bytes = bytes, Duration = TimeSpan.FromMilliseconds(50) };

    private static PageRequest Fail(string url, string error, string type = "script") =>
        new() { Url = url, ResourceType = type, Error = error };

    private static PageRequest Pending(string url, string type = "fetch") => new() { Url = url, ResourceType = type };

    private static PageLoad Load(params PageRequest[] requests) =>
        new() { Url = "https://www.example.com/", LoadFired = true, Requests = requests };

    private static Dictionary<string, SecondaryDomain> Analyze(PageLoad load, IEnumerable<Flow>? flows = null) =>
        SecondaryDomains.Analyze(load, "www.example.com", flows).ToDictionary(d => d.Host);

    [Fact]
    public void States_cover_ok_partial_failed_stalled_and_client_blocks()
    {
        var d = Analyze(Load(
            Ok("https://www.example.com/", "document"),
            Ok("https://cdn.example.net/a.js"),
            Ok("https://img.cdn.test/1.jpg", "image"),
            Fail("https://img.cdn.test/big.jpg", "net::ERR_CONNECTION_RESET", "image"),
            Fail("https://api.blocked.test/v1", "net::ERR_CONNECTION_TIMED_OUT", "xhr"),
            Pending("https://feed.slow.test/live"),
            Fail("https://tracker.test/t.js", "net::ERR_BLOCKED_BY_CLIENT"),
            Fail("https://cancelled.test/x", "net::ERR_ABORTED")));

        Assert.Equal(DomainState.Ok, d["www.example.com"].State);
        Assert.True(d["www.example.com"].IsMain);
        Assert.Equal(DomainState.Ok, d["cdn.example.net"].State);
        Assert.Equal(DomainState.Partial, d["img.cdn.test"].State);
        Assert.Equal(1, d["img.cdn.test"].FailedRequests);
        Assert.Equal(DomainState.Failed, d["api.blocked.test"].State);
        Assert.Equal("net::ERR_CONNECTION_TIMED_OUT", d["api.blocked.test"].Error);
        Assert.Equal(DomainState.Stalled, d["feed.slow.test"].State);
        Assert.Equal(DomainState.BlockedByClient, d["tracker.test"].State);
        Assert.False(d["tracker.test"].Important);
        // a request the page cancelled itself is not a network failure
        Assert.Equal(DomainState.Ok, d["cancelled.test"].State);
    }

    [Fact]
    public void Importance_follows_the_rules()
    {
        var d = Analyze(Load(
            Ok("https://www.example.com/", "document"),
            Fail("https://static.example.com/x.png", "net::ERR_CONNECTION_RESET", "image"),
            Fail("https://www.google-analytics.com/collect", "net::ERR_CONNECTION_RESET", "ping"),
            Fail("https://mc.yandex.ru/watch/1", "net::ERR_CONNECTION_RESET", "script"),
            Fail("https://beacon.other.test/b", "net::ERR_CONNECTION_RESET", "ping"),
            Fail("https://fonts.other.test/f.woff2", "net::ERR_CONNECTION_RESET", "font")));

        Assert.True(d["static.example.com"].Important); // same site
        Assert.Equal("часть сайта", d["static.example.com"].ReasonRu);
        Assert.False(d["www.google-analytics.com"].Important); // noise list
        Assert.False(d["mc.yandex.ru"].Important); // noise list wins over the resource type
        Assert.False(d["beacon.other.test"].Important); // only pings
        Assert.True(d["fonts.other.test"].Important); // fonts are needed
        Assert.Equal("the page needs it: scripts, styles, images or data", d["fonts.other.test"].ReasonEn);
    }

    [Fact]
    public void Broken_important_domains_come_first_and_fail_l3()
    {
        var load = Load(
            Ok("https://www.example.com/", "document"),
            Ok("https://a.test/a.js"),
            Fail("https://z.test/z.js", "net::ERR_CONNECTION_RESET"),
            Fail("https://ads.doubleclick.net/x", "net::ERR_CONNECTION_RESET"));
        var list = SecondaryDomains.Analyze(load, "www.example.com");
        Assert.Equal(["www.example.com", "z.test", "a.test", "ads.doubleclick.net"], list.Select(d => d.Host));
        Assert.False(SecondaryDomains.PagePasses(load, list));

        // only noise broken: the page passes
        var clean = Load(Ok("https://www.example.com/", "document"), Fail("https://ads.doubleclick.net/x", "net::ERR_CONNECTION_RESET"));
        Assert.True(SecondaryDomains.PagePasses(clean, SecondaryDomains.Analyze(clean, "www.example.com")));
        // no load event: fails even with no broken domain
        var noLoad = clean with { LoadFired = false };
        Assert.False(SecondaryDomains.PagePasses(noLoad, SecondaryDomains.Analyze(noLoad, "www.example.com")));
    }

    [Fact]
    public void Hints_websockets_and_alt_svc_add_hosts()
    {
        var load = Load(Ok("https://www.example.com/", "document")) with
        {
            Hints = ["https://fonts.gstatic.com/", "//cdn.hint.test", "not a host!"],
            WebSockets = ["wss://ws.example.com/socket"],
            AltSvc = ["alt.example.net"],
        };
        var d = Analyze(load);
        Assert.Equal(DomainSource.Hint, d["fonts.gstatic.com"].Sources);
        Assert.Equal(DomainState.NotUsed, d["fonts.gstatic.com"].State);
        Assert.False(d["fonts.gstatic.com"].Important);
        Assert.True(d.ContainsKey("cdn.hint.test"));
        Assert.Equal(DomainSource.WebSocket, d["ws.example.com"].Sources);
        Assert.True(d["ws.example.com"].Important); // first party
        Assert.Equal(DomainSource.AltSvc, d["alt.example.net"].Sources);
        Assert.Equal(5, d.Count);
    }

    [Fact]
    public void Pcap_sni_finds_what_the_browser_did_not_report()
    {
        var flows = new[]
        {
            Flow("tcp", "sw.hidden.test", packetsIn: 0, bytesIn: 0, rst: false), // service worker request, no answer
            Flow("udp", "www.example.com", packetsIn: 0, bytesIn: 0, rst: false), // QUIC blocked, TCP worked
            Flow("tcp", "www.example.com", packetsIn: 20, bytesIn: 50_000, rst: false),
            Flow("tcp", "reset.test", packetsIn: 1, bytesIn: 0, rst: true),
            Flow("tcp", "fine.test", packetsIn: 9, bytesIn: 9000, rst: false),
        };
        var d = Analyze(Load(Ok("https://www.example.com/", "document")), flows);

        Assert.Equal(DomainState.Failed, d["sw.hidden.test"].State);
        Assert.True(d["sw.hidden.test"].Important);
        Assert.Equal("ClientHello без ответа", d["sw.hidden.test"].Error);
        Assert.Equal(DomainSource.Pcap, d["sw.hidden.test"].Sources);
        Assert.Equal(DomainState.Failed, d["reset.test"].State);
        Assert.Equal("RST после ClientHello", d["reset.test"].Error);
        Assert.Equal(DomainState.Ok, d["fine.test"].State);
        Assert.Equal(DomainState.Ok, d["www.example.com"].State);
        Assert.Equal(DomainSource.Request | DomainSource.Pcap, d["www.example.com"].Sources);
        Assert.Equal("QUIC без ответа, браузер перешёл на TCP", d["www.example.com"].Note);
        Assert.Null(d["www.example.com"].Error);
    }

    [Fact]
    public void Har_reads_requests_failures_and_alt_svc()
    {
        const string har = """
            {"log":{"version":"1.2","browser":{"name":"Chromium"},
             "pages":[{"startedDateTime":"2026-01-01T10:00:00.000Z","id":"p","pageTimings":{"onLoad":812.5}}],
             "entries":[
              {"startedDateTime":"2026-01-01T10:00:00.010Z","time":120,"_resourceType":"document",
               "request":{"method":"GET","url":"https://www.example.com/"},
               "response":{"status":200,"headers":[{"name":"alt-svc","value":"h3=\":443\"; ma=86400, h3=\"quic.example.net:443\""}],
                           "content":{"size":30000,"mimeType":"text/html"}}},
              {"startedDateTime":"2026-01-01T10:00:00.200Z","time":0,
               "request":{"method":"GET","url":"https://cdn.blocked.test/app.js"},
               "response":{"status":0,"headers":[],"content":{"size":0,"mimeType":"x-unknown"},"_failureText":"net::ERR_CONNECTION_RESET"}},
              {"startedDateTime":"2026-01-01T10:00:00.300Z","time":-1,
               "request":{"method":"GET","url":"https://slow.test/feed"},
               "response":{"status":0,"headers":[],"content":{"size":0}}},
              {"startedDateTime":"2026-01-01T10:00:00.400Z","time":40,
               "request":{"method":"GET","url":"https://img.test/a.png"},
               "response":{"status":200,"headers":[],"content":{"size":512,"mimeType":"image/png"}}}
             ]}}
            """;
        var load = Har.Parse(har);
        Assert.Equal("chromium", load.Browser);
        Assert.True(load.LoadFired);
        Assert.Equal(TimeSpan.FromMilliseconds(812.5), load.LoadTime);
        Assert.Equal("https://www.example.com/", load.Url);
        Assert.Equal(["quic.example.net"], load.AltSvc);
        Assert.Equal(4, load.Requests.Count);
        Assert.Equal(30000, load.Requests[0].Bytes);
        Assert.Equal(TimeSpan.FromMilliseconds(10), load.Requests[0].Started);
        Assert.Equal("net::ERR_CONNECTION_RESET", load.Requests[1].Error);
        Assert.Null(load.Requests[2].Duration);
        Assert.Null(load.Requests[2].Error);
        Assert.Equal("image", load.Requests[3].ResourceType); // guessed from the MIME type
        Assert.Equal("https://www.example.com/", SecondaryDomains.LargestResponse(load, "www.example.com", 16_000)?.Url);
        Assert.Null(SecondaryDomains.LargestResponse(load, "img.test"));

        var d = SecondaryDomains.Analyze(load, "www.example.com").ToDictionary(x => x.Host);
        Assert.Equal(DomainState.Failed, d["cdn.blocked.test"].State);
        Assert.Equal(DomainState.Stalled, d["slow.test"].State);
        Assert.Equal(DomainState.Ok, d["img.test"].State);
        Assert.Equal(DomainState.NotUsed, d["quic.example.net"].State);
    }

    [Fact]
    public void Alt_svc_hosts_parse()
    {
        Assert.Equal(["alt.test", "2001:db8::1"], Har.AltSvcHosts("h3=\"alt.test:443\"; ma=1, h3=\":443\", h2=\"[2001:db8::1]:8443\"").ToList());
        Assert.Empty(Har.AltSvcHosts("clear"));
    }

    [Fact]
    public async Task Loop_reloads_until_no_broken_important_domain_is_left()
    {
        // round 1: cdn broken; fixing it reveals api (loaded by the cdn script); round 3: all good
        var pages = new Queue<PageLoad>([
            Load(Ok("https://www.example.com/", "document"), Fail("https://cdn.test/app.js", "net::ERR_CONNECTION_RESET")),
            Load(Ok("https://www.example.com/", "document"), Ok("https://cdn.test/app.js"), Fail("https://api.test/v1", "net::ERR_CONNECTION_RESET", "xhr")),
            Load(Ok("https://www.example.com/", "document"), Ok("https://cdn.test/app.js"), Ok("https://api.test/v1", "xhr")),
        ]);
        var fixedHosts = new List<string>();
        var r = await SecondaryDomainLoop.RunAsync("www.example.com",
            _ => Task.FromResult<(PageLoad, IReadOnlyList<Flow>?)>((pages.Dequeue(), null)),
            (broken, _) =>
            {
                fixedHosts.AddRange(broken.Select(b => b.Host));
                return Task.FromResult<IReadOnlyList<SecondaryDomain>>(broken);
            });
        Assert.True(r.Passed);
        Assert.Equal(3, r.Rounds.Count);
        Assert.Equal(["cdn.test", "api.test"], fixedHosts);
        Assert.Empty(r.Remaining);
    }

    [Fact]
    public async Task Loop_stops_when_a_fix_does_not_help()
    {
        int opened = 0, fixes = 0;
        var r = await SecondaryDomainLoop.RunAsync("www.example.com",
            _ =>
            {
                opened++;
                return Task.FromResult<(PageLoad, IReadOnlyList<Flow>?)>((Load(Ok("https://www.example.com/", "document"), Fail("https://cdn.test/a.js", "net::ERR_CONNECTION_RESET")), null));
            },
            (broken, _) =>
            {
                fixes++;
                return Task.FromResult(broken);
            });
        // the same domain is not retried: round 2 sees nothing new to fix and stops
        Assert.False(r.Passed);
        Assert.Equal(2, opened);
        Assert.Equal(1, fixes);
        Assert.Equal(["cdn.test"], r.Remaining.Select(d => d.Host));
    }

    [Fact]
    public void Noise_list_matches_by_suffix()
    {
        var n = NoiseList.Default;
        Assert.True(n.Suffixes.Count > 20);
        Assert.True(n.Matches("ad.doubleclick.net"));
        Assert.True(n.Matches("doubleclick.net."));
        Assert.False(n.Matches("notdoubleclick.net"));
        Assert.False(n.Matches("yandex.ru"));
        Assert.All(n.Suffixes, s => Assert.True(Model.Target.IsValidHostName(s), s));
    }

    private static Flow Flow(string proto, string sni, int packetsIn, long bytesIn, bool rst)
    {
        var f = new Flow
        {
            Protocol = proto,
            Client = new IPEndPoint(IPAddress.Parse("192.168.1.2"), 50000),
            Server = new IPEndPoint(IPAddress.Parse("203.0.113.5"), 443),
            PacketsIn = packetsIn,
            BytesIn = bytesIn,
        };
        TlsClientHello.TryParseHandshake(ClientHelloBuilder.BuildHandshake(ClientHelloSpec.Get("chrome141"), new ClientHelloOptions { Sni = sni }), out var hello);
        f.ClientHellos.Add(hello!);
        if (rst)
            f.Rsts.Add(new RstInfo(DateTime.UtcNow, 60, null, true, Packets.RstOrigin.Injected, []));
        return f;
    }
}
