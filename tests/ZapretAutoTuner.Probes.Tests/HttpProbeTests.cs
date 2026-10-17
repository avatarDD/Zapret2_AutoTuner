using System.Net;
using System.Net.Sockets;
using System.Text;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Probes.Http;

namespace ZapretAutoTuner.Probes.Tests;

public class HttpProbeTests
{
    private const string Host = "blocked.test";

    private static HttpProbeOptions Opts(TestServer s, Func<HttpProbeOptions, HttpProbeOptions>? f = null)
    {
        var o = new HttpProbeOptions
        {
            Host = Host,
            Address = IPAddress.Loopback,
            Port = s.Port,
            Tls = s.Cert is not null,
            TrustedRoots = TestCerts.Roots,
            StallTimeout = TimeSpan.FromMilliseconds(800),
            HandshakeTimeout = TimeSpan.FromSeconds(2),
            MaxTime = TimeSpan.FromSeconds(10),
        };
        return f is null ? o : f(o);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Full_download_passes_L2(bool chunked, bool closeDelimited)
    {
        await using var s = new TestServer(ServerMode.Ok, TestCerts.Leaf(Host), bodyBytes: 300_000, chunked: chunked) { CloseDelimited = closeDelimited };
        var r = await HttpProbe.RunAsync(Opts(s, o => o with { MinBytes = 1_000_000 }));
        Assert.Equal(ProbeError.None, r.Error);
        Assert.True(r.ConnectOk && r.TlsOk && r.CertValid);
        Assert.Equal(200, r.HttpStatus);
        Assert.Equal(300_000, r.BodyBytes);
        Assert.True(r.Complete);
        Assert.Equal("http/1.1", r.Alpn);
        Assert.NotNull(r.TlsVersion);
        Assert.Equal(Host, s.LastSni);
        Assert.True(r.Passes(ProbeLevel.L2Body, 1_000_000));
        Assert.Contains(Host, r.CertNames);
    }

    [Fact]
    public async Task L2_stops_after_min_bytes()
    {
        await using var s = new TestServer(ServerMode.Ok, TestCerts.Leaf(Host), bodyBytes: 2_000_000);
        var r = await HttpProbe.RunAsync(Opts(s, o => o with { MinBytes = 64 * 1024 }));
        Assert.Equal(ProbeError.None, r.Error);
        Assert.InRange(r.BodyBytes, 64 * 1024, 2_000_000 - 1);
        Assert.False(r.Complete);
        Assert.True(r.Passes(ProbeLevel.L2Body));
    }

    [Fact]
    public async Task L1_uses_head_and_passes_without_body()
    {
        await using var s = new TestServer(ServerMode.Ok, TestCerts.Leaf(Host), bodyBytes: 5000);
        var r = await HttpProbe.RunAsync(Opts(s, o => o with { Level = ProbeLevel.L1Handshake }));
        Assert.StartsWith("HEAD / HTTP/1.1", s.LastRequest);
        Assert.Equal(200, r.HttpStatus);
        Assert.True(r.Passes(ProbeLevel.L1Handshake));
    }

    [Fact]
    public async Task Cutoff_at_16k_is_a_stall()
    {
        await using var s = new TestServer(ServerMode.StallAfter, TestCerts.Leaf(Host), bodyBytes: 500_000) { CutAt = 16 * 1024 };
        var r = await HttpProbe.RunAsync(Opts(s));
        Assert.Equal(ProbeError.Stalled, r.Error);
        Assert.True(r.TlsOk);
        Assert.Equal(200, r.HttpStatus);
        Assert.NotNull(r.StalledAt);
        Assert.InRange(r.StalledAt!.Value, 8 * 1024, 20 * 1024);
        Assert.True(r.Passes(ProbeLevel.L1Handshake));
        Assert.False(r.Passes(ProbeLevel.L2Body));
    }

    [Fact]
    public async Task Reset_in_the_middle_of_the_body()
    {
        await using var s = new TestServer(ServerMode.ResetAfter, TestCerts.Leaf(Host), bodyBytes: 500_000) { CutAt = 20_000 };
        var r = await HttpProbe.RunAsync(Opts(s));
        Assert.Equal(ProbeError.HttpReset, r.Error);
        Assert.True(r.RstSeen);
        Assert.False(r.Passes(ProbeLevel.L2Body));
    }

    [Theory]
    [InlineData(ServerMode.ResetOnHello, ProbeError.TlsReset)]
    [InlineData(ServerMode.SilentOnHello, ProbeError.TlsTimeout)]
    [InlineData(ServerMode.CloseOnHello, ProbeError.TlsClosed)]
    public async Task Handshake_failures(ServerMode mode, ProbeError expected)
    {
        await using var s = new TestServer(mode);
        var r = await HttpProbe.RunAsync(Opts(s, o => o with { Tls = true }));
        Assert.True(r.ConnectOk);
        Assert.False(r.TlsOk);
        Assert.Equal(expected, r.Error);
        Assert.Equal(expected == ProbeError.TlsReset, r.RstSeen);
        Assert.False(r.Passes(ProbeLevel.L1Handshake));
    }

    [Fact]
    public async Task Wrong_certificate_fails_L1_but_is_recorded()
    {
        await using var s = new TestServer(ServerMode.Ok, TestCerts.Leaf("other.test"), bodyBytes: 100);
        var r = await HttpProbe.RunAsync(Opts(s));
        Assert.True(r.TlsOk);
        Assert.False(r.CertValid);
        Assert.Contains(Host, r.CertError);
        Assert.Equal(["other.test"], r.CertNames);
        Assert.False(r.Passes(ProbeLevel.L1Handshake));
    }

    [Fact]
    public async Task Untrusted_chain_is_not_valid()
    {
        await using var s = new TestServer(ServerMode.Ok, TestCerts.Leaf(Host), bodyBytes: 100);
        var r = await HttpProbe.RunAsync(Opts(s, o => o with { TrustedRoots = null }));
        Assert.True(r.TlsOk);
        Assert.False(r.CertValid);
    }

    [Fact]
    public async Task No_sni_and_neutral_sni()
    {
        await using var s = new TestServer(ServerMode.Ok, TestCerts.Leaf(Host), bodyBytes: 100);
        var r = await HttpProbe.RunAsync(Opts(s, o => o with { Sni = "" }));
        Assert.Null(r.Sni);
        Assert.True(string.IsNullOrEmpty(s.LastSni));
        Assert.Equal(200, r.HttpStatus);
        r = await HttpProbe.RunAsync(Opts(s, o => o with { Sni = "neutral.test" }));
        Assert.Equal("neutral.test", s.LastSni);
        Assert.True(r.CertValid); // judged against Host, not the SNI
    }

    [Fact]
    public async Task Tls12_and_tls13_can_be_forced()
    {
        await using var s = new TestServer(ServerMode.Ok, TestCerts.Leaf(Host), bodyBytes: 100);
        var r12 = await HttpProbe.RunAsync(Opts(s, o => o with { TlsVersion = TlsVersionLimit.Tls12 }));
        Assert.Equal("1.2", r12.TlsVersion);
        var r13 = await HttpProbe.RunAsync(Opts(s, o => o with { TlsVersion = TlsVersionLimit.Tls13 }));
        Assert.Equal("1.3", r13.TlsVersion);
    }

    [Fact]
    public async Task Plain_http_redirect_keeps_location()
    {
        await using var s = new TestServer(ServerMode.Ok, cert: null, bodyBytes: 0, status: 302, location: "http://warning.rt.ru/?id=1");
        var r = await HttpProbe.RunAsync(Opts(s, o => o with { Tls = false }));
        Assert.Equal(302, r.HttpStatus);
        Assert.Equal("http://warning.rt.ru/?id=1", r.Location);
        Assert.True(r.Complete);
        Assert.False(r.Tls);
        Assert.True(r.Passes(ProbeLevel.L2Body));
    }

    [Fact]
    public async Task Refused_connect_is_an_rst()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        var r = await HttpProbe.RunAsync(new HttpProbeOptions { Host = Host, Address = IPAddress.Loopback, Port = port });
        Assert.False(r.ConnectOk);
        Assert.Equal(ProbeError.ConnectRefused, r.Error);
        Assert.True(r.RstSeen);
    }

    [Fact]
    public void Padding_reaches_the_requested_size()
    {
        var o = new HttpProbeOptions { Host = Host, Address = IPAddress.Loopback, PadBytes = 24_000 };
        var plain = HttpProbe.BuildRequest(o with { PadBytes = 0 });
        var padded = HttpProbe.BuildRequest(o);
        Assert.InRange(padded.Length - plain.Length, 24_000, 24_100);
        var text = Encoding.ASCII.GetString(padded);
        Assert.EndsWith("\r\n\r\n", text);
        Assert.All(text.Split("\r\n").Where(l => l.StartsWith("X-Pad", StringComparison.Ordinal)), l => Assert.True(l.Length <= 4200));
    }

    [Fact]
    public void Request_host_header_carries_nonstandard_port()
    {
        var text = Encoding.ASCII.GetString(HttpProbe.BuildRequest(new HttpProbeOptions { Host = Host, Address = IPAddress.Loopback, Port = 8443, Path = "/big.bin" }));
        Assert.StartsWith("GET /big.bin HTTP/1.1\r\nHost: blocked.test:8443\r\n", text);
    }

    [Theory]
    [InlineData("5\r\nhello\r\n0\r\n\r\n", 5, true)]
    [InlineData("5;ext=1\r\nhello\r\n3\r\nabc\r\n0\r\nTrailer: x\r\n\r\n", 8, true)]
    [InlineData("a\r\n0123456789\r\n", 10, false)]
    public void Chunked_body_is_counted(string wire, long expected, bool done)
    {
        var b = new HttpProbe.ResponseBody(true, null, false);
        long total = 0;
        bool d = false;
        // feed byte by byte to exercise state across reads
        foreach (var c in Encoding.ASCII.GetBytes(wire))
        {
            total += b.Feed([c], out var dd);
            d |= dd;
            if (dd)
                break;
        }
        Assert.False(b.Malformed);
        Assert.Equal(expected, total);
        Assert.Equal(done, d);
    }

    [Fact]
    public void Garbage_chunk_size_is_malformed()
    {
        var b = new HttpProbe.ResponseBody(true, null, false);
        b.Feed("zz\r\n"u8, out _);
        Assert.True(b.Malformed);
    }

    [Fact]
    public void Level_rules()
    {
        var ok = new ProbeResult { Host = Host, Address = "1.2.3.4", ConnectOk = true, TlsOk = true, CertValid = true, HttpStatus = 404, BodyBytes = 300, Complete = true };
        Assert.True(ok.Passes(ProbeLevel.L1Handshake));
        Assert.True(ok.Passes(ProbeLevel.L2Body)); // a complete small 404 is a server answer
        Assert.False((ok with { Complete = false }).Passes(ProbeLevel.L2Body));
        Assert.False((ok with { CertValid = false }).Passes(ProbeLevel.L1Handshake));
        Assert.True((ok with { Tls = false, TlsOk = false, CertValid = false }).Passes(ProbeLevel.L1Handshake));
        Assert.False((ok with { BodyBytes = 70_000, Complete = false, StalledAt = 16_000 }).Passes(ProbeLevel.L2Body));
        Assert.True((ok with { BodyBytes = 70_000, Complete = false }).Passes(ProbeLevel.L2Body));
        Assert.False((ok with { BodyBytes = 70_000, Complete = false }).Passes(ProbeLevel.L2Body, 128 * 1024));
    }
}
