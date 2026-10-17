using System.Net;
using System.Net.Sockets;
using System.Text;
using ZapretAutoTuner.Core.Dns;
using ZapretAutoTuner.Probes.Dns;

namespace ZapretAutoTuner.Probes.Tests;

public class DnsCodecTests
{
    private const string ExampleQuestion = "076578616d706c6503636f6d00 0001 0001";

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static string H(string s) => s.Replace(" ", "", StringComparison.Ordinal);

    [Fact]
    public void Query_without_edns_matches_hand_checked_bytes()
    {
        var q = DnsMessage.BuildQuery(0x1234, "example.com", DnsRecordType.A, new DnsQueryOptions { UseEdns = false });
        Assert.Equal(H("1234 0100 0001 0000 0000 0000 " + ExampleQuestion), Hex(q));
    }

    [Fact]
    public void Query_with_edns_has_opt_with_1232()
    {
        var q = DnsMessage.BuildQuery(0x1234, "example.com.", DnsRecordType.A);
        Assert.Equal(H("1234 0100 0001 0000 0000 0001 " + ExampleQuestion + " 00 0029 04d0 0000 0000 0000"), Hex(q));
    }

    [Fact]
    public void Query_types_and_flags()
    {
        var q = DnsMessage.BuildQuery(1, "a.b", DnsRecordType.HTTPS, new DnsQueryOptions { UseEdns = false, RecursionDesired = false });
        Assert.Equal(H("0001 0000 0001 0000 0000 0000 0161 0162 00 0041 0001"), Hex(q));
        var m = DnsMessage.Parse(DnsMessage.BuildQuery(2, "x.y", DnsRecordType.SVCB));
        Assert.Equal(DnsRecordType.SVCB, m.Questions[0].Type);
        Assert.Equal("x.y", m.Questions[0].Name);
        Assert.Equal((ushort)1232, m.Edns!.UdpPayloadSize);
        Assert.True(m.RecursionDesired);
    }

    [Fact]
    public void Ecs_option_is_encoded_with_truncated_address()
    {
        var ecs = DnsClientSubnet.Parse("203.0.113.77/24");
        Assert.Equal("000118" + "00" + "cb0071", Hex(ecs.Encode()));
        var q = DnsMessage.BuildQuery(0x1234, "example.com", DnsRecordType.A, new DnsQueryOptions { ClientSubnet = ecs });
        Assert.EndsWith(H("00 0029 04d0 0000 0000 000b 0008 0007 0001 18 00 cb0071"), Hex(q));

        Assert.Equal("000114" + "00" + "c63360", Hex(new DnsClientSubnet(IPAddress.Parse("198.51.100.1"), 20).Encode()));
        Assert.Equal("000230" + "00" + "20010db8abcd", Hex(DnsClientSubnet.Parse("2001:db8:abcd:1::/48").Encode()));
        Assert.Equal("00010000", Hex(new DnsClientSubnet(IPAddress.Parse("1.2.3.4"), 0).Encode()));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DnsClientSubnet(IPAddress.Parse("1.2.3.4"), 33));

        var back = DnsClientSubnet.TryDecode(ecs.Encode());
        Assert.NotNull(back);
        Assert.Equal(IPAddress.Parse("203.0.113.0"), back.Address);
        Assert.Equal(24, back.SourcePrefix);
        Assert.Null(DnsClientSubnet.TryDecode(Convert.FromHexString("00011800cb00"))); // 2 bytes for /24
    }

    [Theory]
    [InlineData("a..b")]
    [InlineData("пример.рф")]
    [InlineData("has space.com")]
    public void Bad_names_are_rejected(string name) =>
        Assert.Throws<ArgumentException>(() => DnsMessage.BuildQuery(1, name, DnsRecordType.A));

    [Fact]
    public void Long_labels_and_names_are_rejected()
    {
        Assert.Throws<ArgumentException>(() => DnsMessage.EncodeName(new string('a', 64) + ".com"));
        Assert.Throws<ArgumentException>(() => DnsMessage.EncodeName(string.Join('.', Enumerable.Repeat(new string('a', 63), 4))));
        Assert.Equal([0], DnsMessage.EncodeName("."));
    }

    /// <summary>www.example.com CNAME cdn.example.com (compressed twice), A and AAAA for cdn.example.com.</summary>
    internal static byte[] CnameResponse()
    {
        var w = new Wire();
        w.U16(0x1234).U16(0x8180).U16(1).U16(3).U16(0).U16(0);
        int qname = w.Pos;
        w.Name("www.example.com").U16(1).U16(1);
        int example = qname + 4;
        int cdn = 0;
        w.Ptr(qname).U16(5).U16(1).U32(300).Rdata(r =>
        {
            cdn = r.Pos;
            r.Label("cdn").Ptr(example);
        });
        w.Ptr(cdn).U16(1).U16(1).U32(60).Rdata(r => r.Ip("93.184.216.34"));
        w.Ptr(cdn).U16(28).U16(1).U32(60).Rdata(r => r.Ip("2606:2800:220:1:248:1893:25c8:1946"));
        return w.ToArray();
    }

    [Fact]
    public void Parses_compressed_cname_chain()
    {
        var m = DnsMessage.Parse(CnameResponse());
        Assert.Equal(0x1234, m.Id);
        Assert.True(m.IsResponse);
        Assert.True(m.RecursionAvailable);
        Assert.False(m.IsTruncated);
        Assert.Equal(DnsResponseCode.NoError, m.ResponseCode);
        Assert.Equal("www.example.com", m.Questions[0].Name);
        Assert.Equal(3, m.Answers.Count);
        Assert.Equal("www.example.com", m.Answers[0].Name);
        Assert.Equal("cdn.example.com", m.Answers[0].Target);
        Assert.Equal("cdn.example.com", m.Answers[1].Name);
        Assert.Equal(300u, m.Answers[0].Ttl);

        var r = m.ResolveChain("WWW.Example.com.");
        Assert.Equal("cdn.example.com", r.CanonicalName);
        Assert.Equal(["WWW.Example.com", "cdn.example.com"], r.Chain); // the queried spelling, then names from the message
        Assert.Equal([IPAddress.Parse("93.184.216.34"), IPAddress.Parse("2606:2800:220:1:248:1893:25c8:1946")], r.Addresses);
        Assert.Empty(m.ResolveChain("other.example.com").Addresses);
    }

    [Fact]
    public void Cname_loop_stops()
    {
        var w = new Wire();
        w.U16(1).U16(0x8180).U16(0).U16(2).U16(0).U16(0);
        int a = w.Pos;
        w.Name("a.test").U16(5).U16(1).U32(1).Rdata(r => r.Name("b.test"));
        w.Name("b.test").U16(5).U16(1).U32(1).Rdata(r => r.Ptr(a));
        var res = DnsMessage.Parse(w.ToArray()).ResolveChain("a.test");
        Assert.Equal(["a.test", "b.test"], res.Chain);
        Assert.Empty(res.Addresses);
    }

    internal static byte[] HttpsResponse(string name = "cloudflare.com", int id = 0)
    {
        var w = new Wire();
        w.U16(id).U16(0x8180).U16(1).U16(1).U16(0).U16(1);
        w.Name(name).U16(65).U16(1);
        w.Ptr(12).U16(65).U16(1).U32(300).Rdata(r =>
        {
            r.U16(1).U8(0); // priority 1, target "."
            r.U16(SvcbData.KeyAlpn).Rdata(v => v.Label("h3").Label("h2"));
            r.U16(SvcbData.KeyPort).Rdata(v => v.U16(8443));
            r.U16(SvcbData.KeyIpv4Hint).Rdata(v => v.Ip("104.16.132.229").Ip("104.16.133.229"));
            r.U16(SvcbData.KeyEch).Rdata(v => v.Hex("0045fe0d0041"));
            r.U16(SvcbData.KeyIpv6Hint).Rdata(v => v.Ip("2606:4700::6810:84e5"));
            r.U16(0x1234).Rdata(v => v.Hex("abcd"));
        });
        // OPT echoing an ECS option with scope 24
        w.U8(0).U16(41).U16(1232).U32(0).Rdata(r => r.U16(8).Rdata(v => v.Hex("0001 18 18 cb0071".Replace(" ", "", StringComparison.Ordinal))));
        return w.ToArray();
    }

    [Fact]
    public void Parses_https_rr()
    {
        var m = DnsMessage.Parse(HttpsResponse());
        var s = Assert.Single(m.AnswersFor("cloudflare.com", DnsRecordType.HTTPS)).Svcb;
        Assert.NotNull(s);
        Assert.Equal(1, s.Priority);
        Assert.False(s.IsAliasMode);
        Assert.Equal(".", s.TargetName);
        Assert.Equal(["h3", "h2"], s.Alpn);
        Assert.Equal(8443, s.Port);
        Assert.Equal([IPAddress.Parse("104.16.132.229"), IPAddress.Parse("104.16.133.229")], s.Ipv4Hints);
        Assert.Equal([IPAddress.Parse("2606:4700::6810:84e5")], s.Ipv6Hints);
        Assert.Equal(Convert.FromHexString("0045fe0d0041"), s.Ech);
        Assert.Equal(6, s.Parameters.Count);
        Assert.Equal(Convert.FromHexString("abcd"), s.Parameters[^1].Value);
        Assert.Equal((ushort)0x1234, s.Parameters[^1].Key);

        Assert.Empty(m.Additionals);
        Assert.NotNull(m.Edns);
        Assert.Equal(24, m.Edns.ClientSubnet!.ScopePrefix);

        var sum = HttpsRecordSummary.From("doh", m.AnswersFor("cloudflare.com", DnsRecordType.HTTPS));
        Assert.NotNull(sum);
        Assert.True(sum.SupportsHttp3);
        Assert.True(sum.HasEch);
        Assert.Equal(8443, sum.Port);
        Assert.Equal(2, sum.Ipv4Hints.Count);
    }

    [Fact]
    public void Https_alias_mode()
    {
        var w = new Wire();
        w.U16(0).U16(0x8180).U16(0).U16(1).U16(0).U16(0);
        w.Name("a.test").U16(65).U16(1).U32(1).Rdata(r => r.U16(0).Name("svc.test"));
        var m = DnsMessage.Parse(w.ToArray());
        var s = m.Answers[0].Svcb!;
        Assert.True(s.IsAliasMode);
        Assert.Equal("svc.test", s.TargetName);
        var sum = HttpsRecordSummary.From("x", m.Answers);
        Assert.Equal("svc.test", sum!.AliasTarget);
        Assert.False(sum.HasEch);
    }

    [Fact]
    public void Extended_rcode_from_opt()
    {
        var w = new Wire();
        w.U16(5).U16(0x8183).U16(0).U16(0).U16(0).U16(1);
        w.U8(0).U16(41).U16(512).U32(0x01000000).U16(0); // ext rcode 1 → 16 | 3
        var m = DnsMessage.Parse(w.ToArray());
        Assert.Equal((DnsResponseCode)0x13, m.ResponseCode);
        Assert.Equal(DnsResponseCode.NxDomain, DnsMessage.Parse(DnsKit.Respond(DnsMessage.BuildQuery(1, "x.y", DnsRecordType.A), [], rcode: 3)).ResponseCode);
    }

    [Fact]
    public void Pointer_loop_is_rejected()
    {
        var self = new Wire().U16(1).U16(0x8180).U16(1).U16(0).U16(0).U16(0).Ptr(12).U16(1).U16(1).ToArray();
        Assert.Contains("цикл", Assert.Throws<FormatException>(() => DnsMessage.Parse(self)).Message, StringComparison.Ordinal);

        // two names pointing at each other: 12 → 14 → 12
        var pair = new Wire().U16(1).U16(0x8180).U16(1).U16(0).U16(0).U16(0).Ptr(14).Ptr(12).U16(1).U16(1).ToArray();
        Assert.Throws<FormatException>(() => DnsMessage.Parse(pair));

        // label + pointer back to the label: grows the name until the 255-byte limit
        var grow = new Wire().U16(1).U16(0x8180).U16(1).U16(0).U16(0).U16(0).Label("abc").Ptr(12).U16(1).U16(1).ToArray();
        Assert.Throws<FormatException>(() => DnsMessage.Parse(grow));
    }

    [Fact]
    public void Out_of_range_pointer_and_bad_label_type_are_rejected()
    {
        var far = new Wire().U16(1).U16(0x8180).U16(1).U16(0).U16(0).U16(0).Ptr(0x3FF).U16(1).U16(1).ToArray();
        Assert.Throws<FormatException>(() => DnsMessage.Parse(far));
        var ext = new Wire().U16(1).U16(0x8180).U16(1).U16(0).U16(0).U16(0).U8(0x41).U8(0).U16(1).U16(1).ToArray();
        Assert.Throws<FormatException>(() => DnsMessage.Parse(ext));
    }

    [Fact]
    public void Wrong_rdata_lengths_are_rejected()
    {
        var a5 = new Wire().U16(1).U16(0x8180).U16(0).U16(1).U16(0).U16(0).Name("a.b").U16(1).U16(1).U32(1).Rdata(r => r.Hex("0102030405")).ToArray();
        Assert.Throws<FormatException>(() => DnsMessage.Parse(a5));
        var hint = new Wire().U16(1).U16(0x8180).U16(0).U16(1).U16(0).U16(0).Name("a.b").U16(65).U16(1).U32(1)
            .Rdata(r => r.U16(1).U8(0).U16(SvcbData.KeyIpv4Hint).Rdata(v => v.Hex("010203"))).ToArray();
        Assert.Throws<FormatException>(() => DnsMessage.Parse(hint));
        var cnameExtra = new Wire().U16(1).U16(0x8180).U16(0).U16(1).U16(0).U16(0).Name("a.b").U16(5).U16(1).U32(1)
            .Rdata(r => r.Name("c.d").U8(0)).ToArray();
        Assert.Throws<FormatException>(() => DnsMessage.Parse(cnameExtra));
    }

    [Fact]
    public void Every_truncation_is_rejected_cleanly()
    {
        foreach (var full in new[] { CnameResponse(), HttpsResponse() })
        {
            Assert.True(DnsMessage.TryParse(full, out _));
            for (int n = 0; n < full.Length; n++)
            {
                Assert.False(DnsMessage.TryParse(full.AsSpan(0, n), out var m));
                Assert.Null(m);
            }
        }
    }

    [Fact]
    public void Random_corruption_only_raises_format_exception()
    {
        var rnd = new Random(12345);
        var samples = new[] { CnameResponse(), HttpsResponse() };
        for (int i = 0; i < 20000; i++)
        {
            var b = (byte[])samples[i % 2].Clone();
            int flips = 1 + rnd.Next(4);
            for (int f = 0; f < flips; f++)
                b[rnd.Next(b.Length)] = (byte)rnd.Next(256);
            try
            {
                DnsMessage.Parse(b);
            }
            catch (FormatException)
            {
            }
        }
    }

    [Fact]
    public void Header_peek_works_on_cut_messages()
    {
        var b = DnsKit.Respond(DnsMessage.BuildQuery(0x4242, "x.y", DnsRecordType.A), ["1.2.3.4"], truncated: true);
        Assert.True(DnsMessage.TryReadHeader(b.AsSpan(0, 12), out var id, out var flags));
        Assert.Equal(0x4242, id);
        Assert.NotEqual(0, flags & 0x0200);
        Assert.False(DnsMessage.TryReadHeader(b.AsSpan(0, 11), out _, out _));
    }
}

public class DnsTransportTests
{
    private static readonly TimeSpan Short = TimeSpan.FromMilliseconds(300);

    [Fact]
    public async Task Udp_query_returns_answer()
    {
        await using var srv = new LocalDnsServer((q, _) => [DnsKit.Respond(q, ["93.184.216.34"])]);
        using var t = new UdpDnsTransport(srv.Endpoint, "local");
        var m = await t.QueryAsync("example.com", DnsRecordType.A, null, CancellationToken.None);
        Assert.Equal([IPAddress.Parse("93.184.216.34")], m.ResolveChain("example.com").Addresses);
        Assert.Equal(DnsResolverKind.Udp, t.Kind);
        Assert.Equal(srv.Endpoint.ToString(), t.Server);
    }

    [Fact]
    public async Task Truncated_udp_answer_falls_back_to_tcp()
    {
        await using var srv = new LocalDnsServer(
            (q, _) => [DnsKit.Respond(q, [], truncated: true)],
            q => DnsKit.Respond(q, ["10.0.0.1", "10.0.0.2"]));
        using var t = new UdpDnsTransport(srv.Endpoint, "local", TimeSpan.FromSeconds(2));
        var m = await t.QueryAsync("big.test", DnsRecordType.A, null, CancellationToken.None);
        Assert.False(m.IsTruncated);
        Assert.Equal(2, m.ResolveChain("big.test").Addresses.Count);
        Assert.Equal(1, srv.TcpCount);
    }

    [Fact]
    public async Task Udp_retries_once_after_timeout()
    {
        await using var srv = new LocalDnsServer((q, n) => n == 1 ? [] : [DnsKit.Respond(q, ["1.2.3.4"])]);
        using var t = new UdpDnsTransport(srv.Endpoint, "local", Short, retries: 1);
        var m = await t.QueryAsync("retry.test", DnsRecordType.A, null, CancellationToken.None);
        Assert.Single(m.Answers);
        Assert.Equal(2, srv.UdpCount);
    }

    [Fact]
    public async Task Udp_ignores_foreign_id_and_times_out_when_silent()
    {
        await using var srv = new LocalDnsServer((q, _) =>
        {
            var id = DnsMessage.Parse(q).Id;
            return [DnsKit.Respond(q, ["6.6.6.6"], id: id ^ 0xFFFF), DnsKit.Respond(q, ["1.2.3.4"])];
        });
        using var t = new UdpDnsTransport(srv.Endpoint, "local", Short);
        var m = await t.QueryAsync("id.test", DnsRecordType.A, null, CancellationToken.None);
        Assert.Equal([IPAddress.Parse("1.2.3.4")], m.ResolveChain("id.test").Addresses);

        await using var silent = new LocalDnsServer((_, _) => []);
        using var t2 = new UdpDnsTransport(silent.Endpoint, "silent", TimeSpan.FromMilliseconds(150), retries: 1);
        await Assert.ThrowsAsync<TimeoutException>(() => t2.QueryAsync("x.test", DnsRecordType.A, null, CancellationToken.None));
        Assert.Equal(2, silent.UdpCount);
    }

    [Fact]
    public async Task Udp_rejects_answer_for_another_question()
    {
        await using var srv = new LocalDnsServer((q, _) =>
        {
            var other = DnsMessage.BuildQuery(DnsMessage.Parse(q).Id, "evil.test", DnsRecordType.A);
            return [DnsKit.Respond(other, ["6.6.6.6"])];
        });
        using var t = new UdpDnsTransport(srv.Endpoint, "local", Short);
        await Assert.ThrowsAsync<DnsTransportException>(() => t.QueryAsync("good.test", DnsRecordType.A, null, CancellationToken.None));
    }

    [Fact]
    public async Task Udp_honours_caller_cancellation()
    {
        await using var srv = new LocalDnsServer((_, _) => []);
        using var t = new UdpDnsTransport(srv.Endpoint, "local", TimeSpan.FromSeconds(5));
        using var cts = new CancellationTokenSource(100);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => t.QueryAsync("x.test", DnsRecordType.A, null, cts.Token));
    }

    [Fact]
    public async Task Doh_posts_dns_message()
    {
        var handler = new StubHandler((req, body, _) =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(DnsKit.Respond(body, ["1.1.1.1"])) };
            resp.Content.Headers.ContentType = new("application/dns-message");
            return Task.FromResult(resp);
        });
        using var t = new DohTransport(new Uri("https://doh.test/dns-query"), handler, "stub");
        var m = await t.QueryAsync("example.com", DnsRecordType.AAAA, new DnsQueryOptions { ClientSubnet = DnsClientSubnet.Parse("203.0.113.0/24") }, CancellationToken.None);
        Assert.Equal([IPAddress.Parse("1.1.1.1")], m.ResolveChain("example.com").Addresses);

        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal(new Uri("https://doh.test/dns-query"), handler.Request.RequestUri);
        Assert.Equal("application/dns-message", handler.Request.Content!.Headers.ContentType!.MediaType);
        Assert.Contains(handler.Request.Headers.Accept, a => a.MediaType == "application/dns-message");
        var sent = DnsMessage.Parse(handler.Body);
        Assert.Equal(0, sent.Id); // RFC 8484 §4.1
        Assert.Equal(DnsRecordType.AAAA, sent.Questions[0].Type);
        Assert.Equal("example.com", sent.Questions[0].Name);
        Assert.Equal(24, sent.Edns!.ClientSubnet!.SourcePrefix);
    }

    [Fact]
    public async Task Doh_http_errors_and_wrong_content_type_fail()
    {
        using var err = new DohTransport(new Uri("https://doh.test/q"),
            new StubHandler((_, _, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadGateway))), "e");
        var e = await Assert.ThrowsAsync<DnsTransportException>(() => err.QueryAsync("a.test", DnsRecordType.A, null, CancellationToken.None));
        Assert.Contains("502", e.Message, StringComparison.Ordinal);

        using var html = new DohTransport(new Uri("https://doh.test/q"), new StubHandler((_, _, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>blocked</html>", Encoding.UTF8, "text/html") })), "h");
        await Assert.ThrowsAsync<DnsTransportException>(() => html.QueryAsync("a.test", DnsRecordType.A, null, CancellationToken.None));
    }

    [Fact]
    public async Task Doh_timeout_is_reported_as_timeout()
    {
        using var slow = new DohTransport(new Uri("https://doh.test/q"), new StubHandler(async (_, _, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }), "slow", TimeSpan.FromMilliseconds(150));
        await Assert.ThrowsAsync<TimeoutException>(() => slow.QueryAsync("a.test", DnsRecordType.A, null, CancellationToken.None));
    }

    [Fact]
    public void Doh_requires_https() =>
        Assert.Throws<ArgumentException>(() => new DohTransport(new Uri("http://doh.test/q"), new StubHandler((_, _, _) => throw new InvalidOperationException()), "x"));

    [Fact]
    public void Bootstrap_maps_doh_host_to_ip_and_refuses_others()
    {
        var ip = IPAddress.Parse("9.9.9.9");
        var ep = DohBootstrap.MapEndpoint(new DnsEndPoint("DNS.Quad9.net", 443), "dns.quad9.net", ip);
        Assert.Equal(new IPEndPoint(ip, 443), ep);
        Assert.Equal(8443, DohBootstrap.MapEndpoint(new DnsEndPoint("dns.quad9.net", 8443), "dns.quad9.net", ip).Port);
        Assert.Throws<DnsTransportException>(() => DohBootstrap.MapEndpoint(new DnsEndPoint("evil.test", 443), "dns.quad9.net", ip));
    }

    [Fact]
    public async Task Doh_connects_to_bootstrap_ip_without_resolving_the_host()
    {
        // ".invalid" never resolves (RFC 6761): reaching the listener proves the bootstrap IP was used
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accept = Task.Run(async () =>
        {
            using var c = await listener.AcceptTcpClientAsync();
            return true; // closing the connection fails the TLS handshake on the client side
        });
        using var t = new DohTransport(new Uri($"https://doh.invalid:{port}/dns-query"), IPAddress.Loopback, "boot", TimeSpan.FromSeconds(3));
        await Assert.ThrowsAnyAsync<Exception>(() => t.QueryAsync("a.test", DnsRecordType.A, null, CancellationToken.None));
        Assert.True(await accept.WaitAsync(TimeSpan.FromSeconds(3)));
        Assert.Contains("127.0.0.1", t.Server, StringComparison.Ordinal);
    }
}

public class DnsVerdictTests
{
    private const DnsResolverKind Sys = DnsResolverKind.System;
    private const DnsResolverKind Udp = DnsResolverKind.Udp;
    private const DnsResolverKind Doh = DnsResolverKind.Doh;
    private const DnsAnswerStatus Ok = DnsAnswerStatus.Ok;

    public static TheoryData<string, DnsResolverAnswer[], DnsVerdictKind, string> Cases => new()
    {
        {
            "stub 127.0.0.1",
            [DnsKit.Ans(Sys, "sys", Ok, "127.0.0.1"), DnsKit.Ans(Doh, "Cloudflare", Ok, "93.184.216.34")],
            DnsVerdictKind.Poisoned, "SYSTEM_SINKHOLE"
        },
        {
            "stub 0.0.0.0 without doh",
            [DnsKit.Ans(Sys, "sys", Ok, "0.0.0.0"), DnsKit.Ans(Doh, "Cloudflare", DnsAnswerStatus.Timeout)],
            DnsVerdictKind.Poisoned, "SYSTEM_SINKHOLE"
        },
        {
            "private ipv6 stub",
            [DnsKit.Ans(Sys, "sys", Ok, "fd00::1"), DnsKit.Ans(Doh, "Google", Ok, "2a00:1450::1")],
            DnsVerdictKind.Poisoned, "SYSTEM_SINKHOLE"
        },
        {
            "nxdomain on system, doh has addresses",
            [DnsKit.Ans(Sys, "sys", DnsAnswerStatus.NxDomain), DnsKit.Ans(Doh, "Google", Ok, "142.250.74.14")],
            DnsVerdictKind.Poisoned, "SYSTEM_NO_ANSWER"
        },
        {
            "no data on system, doh has addresses",
            [DnsKit.Ans(Sys, "sys", DnsAnswerStatus.NoData), DnsKit.Ans(Doh, "Google", Ok, "142.250.74.14")],
            DnsVerdictKind.Poisoned, "SYSTEM_NO_ANSWER"
        },
        {
            "disjoint cdn-ish",
            [DnsKit.Ans(Sys, "sys", Ok, "2.16.1.1"), DnsKit.Ans(Doh, "Cloudflare", Ok, "23.32.5.5"), DnsKit.Ans(Doh, "Quad9", Ok, "23.32.5.6")],
            DnsVerdictKind.Suspicious, "SYSTEM_DISJOINT"
        },
        {
            "regional udp agrees with system, no doh pair",
            [DnsKit.Ans(Sys, "sys", Ok, "5.45.1.1"), DnsKit.Ans(Udp, "Yandex", Ok, "5.45.1.1"), DnsKit.Ans(Doh, "Cloudflare", Ok, "151.101.1.1")],
            DnsVerdictKind.Suspicious, "SYSTEM_DISJOINT"
        },
        {
            "same /24",
            [DnsKit.Ans(Sys, "sys", Ok, "104.16.132.229"), DnsKit.Ans(Doh, "Cloudflare", Ok, "104.16.132.230")],
            DnsVerdictKind.Clean, "SYSTEM_RELATED"
        },
        {
            "same /48",
            [DnsKit.Ans(Sys, "sys", Ok, "2606:4700:10::1"), DnsKit.Ans(Doh, "Cloudflare", Ok, "2606:4700:10::2")],
            DnsVerdictKind.Clean, "SYSTEM_RELATED"
        },
        {
            "agreeing",
            [DnsKit.Ans(Sys, "sys", Ok, "93.184.216.34", "1.2.3.4"), DnsKit.Ans(Udp, "Google", Ok, "93.184.216.34"), DnsKit.Ans(Doh, "Google", Ok, "93.184.216.34")],
            DnsVerdictKind.Clean, "SYSTEM_MATCH"
        },
        {
            "ipv4-mapped compares as ipv4",
            [DnsKit.Ans(Sys, "sys", Ok, "::ffff:127.0.0.1"), DnsKit.Ans(Doh, "Google", Ok, "8.8.4.4")],
            DnsVerdictKind.Poisoned, "SYSTEM_SINKHOLE"
        },
        {
            "on-path spoof: google udp = system, google doh differs",
            [DnsKit.Ans(Sys, "sys", Ok, "195.1.2.3"), DnsKit.Ans(Udp, "Google", Ok, "195.1.2.3"), DnsKit.Ans(Doh, "Google", Ok, "142.250.74.14")],
            DnsVerdictKind.Poisoned, "ON_PATH_SPOOF"
        },
        {
            "udp spoofed but system uses something else",
            [DnsKit.Ans(Sys, "sys", Ok, "142.250.74.14"), DnsKit.Ans(Udp, "Google", Ok, "195.1.2.3"), DnsKit.Ans(Doh, "Google", Ok, "142.250.74.14")],
            DnsVerdictKind.Suspicious, "UDP_SPOOFED"
        },
        {
            "udp sinkhole",
            [DnsKit.Ans(Sys, "sys", Ok, "142.250.74.14"), DnsKit.Ans(Udp, "Quad9", Ok, "127.0.0.1"), DnsKit.Ans(Doh, "Google", Ok, "142.250.74.14")],
            DnsVerdictKind.Suspicious, "UDP_SINKHOLE"
        },
        {
            "all failing",
            [DnsKit.Ans(Sys, "sys", DnsAnswerStatus.Error), DnsKit.Ans(Udp, "Google", DnsAnswerStatus.Timeout), DnsKit.Ans(Doh, "Google", DnsAnswerStatus.Timeout)],
            DnsVerdictKind.Unknown, "DOH_UNAVAILABLE"
        },
        {
            "system ok, doh unavailable",
            [DnsKit.Ans(Sys, "sys", Ok, "93.184.216.34"), DnsKit.Ans(Doh, "Google", DnsAnswerStatus.Error)],
            DnsVerdictKind.Unknown, "DOH_UNAVAILABLE"
        },
        {
            "system times out, doh works",
            [DnsKit.Ans(Sys, "sys", DnsAnswerStatus.Timeout), DnsKit.Ans(Doh, "Google", Ok, "93.184.216.34")],
            DnsVerdictKind.Suspicious, "SYSTEM_FAILED"
        },
        {
            "domain does not exist",
            [DnsKit.Ans(Sys, "sys", DnsAnswerStatus.NxDomain), DnsKit.Ans(Doh, "Google", DnsAnswerStatus.NxDomain)],
            DnsVerdictKind.Clean, "NOT_EXIST"
        },
        {
            "nxdomain rewriting",
            [DnsKit.Ans(Sys, "sys", Ok, "93.158.1.1"), DnsKit.Ans(Doh, "Google", DnsAnswerStatus.NxDomain)],
            DnsVerdictKind.Suspicious, "SYSTEM_INVENTED"
        },
        {
            "filtering doh is ignored",
            [DnsKit.Ans(Sys, "sys", Ok, "93.184.216.34"), DnsKit.Ans(Doh, "AdGuard", Ok, "0.0.0.0")],
            DnsVerdictKind.Unknown, "DOH_FILTERED"
        },
        {
            "name genuinely points to loopback",
            [DnsKit.Ans(Sys, "sys", Ok, "127.0.0.1"), DnsKit.Ans(Doh, "Google", Ok, "127.0.0.1"), DnsKit.Ans(Doh, "Quad9", Ok, "127.0.0.1")],
            DnsVerdictKind.Unknown, "DOH_UNAVAILABLE"
        },
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public void Verdict(string title, DnsResolverAnswer[] answers, DnsVerdictKind expected, string code)
    {
        var v = DnsVerdictRules.Evaluate(answers, DnsResolverCatalog.Default);
        Assert.True(expected == v.Kind, $"{title}: expected {expected}, got {v.Kind} ({string.Join("; ", v.Reasons)})");
        var f = Assert.Single(v.Reasons, r => r.Code == code);
        Assert.False(string.IsNullOrWhiteSpace(f.MessageRu));
        Assert.False(string.IsNullOrWhiteSpace(f.MessageEn));
        Assert.Equal(expected == DnsVerdictKind.Poisoned, v.Poisoned);
    }

    [Fact]
    public void Block_page_ip_from_catalog_poisons()
    {
        var catalog = new DnsResolverCatalog(new DnsResolverCatalogData
        {
            BlockPages = [new BlockPageSpec { Address = "198.51.100.7", Isp = "test-isp" }],
        });
        var v = DnsVerdictRules.Evaluate([DnsKit.Ans(Sys, "sys", Ok, "198.51.100.7"), DnsKit.Ans(Doh, "Google", Ok, "93.184.216.34")], catalog);
        Assert.True(v.Poisoned);
        Assert.Contains(v.Reasons, r => r.Code == "SYSTEM_BLOCK_PAGE" && r.Evidence[0].Contains("test-isp", StringComparison.Ordinal));
    }

    [Fact]
    public void Prefix_helpers()
    {
        Assert.True(DnsVerdictRules.SamePrefix(IPAddress.Parse("1.2.3.4"), IPAddress.Parse("1.2.3.200")));
        Assert.False(DnsVerdictRules.SamePrefix(IPAddress.Parse("1.2.3.4"), IPAddress.Parse("1.2.4.4")));
        Assert.True(DnsVerdictRules.SamePrefix(IPAddress.Parse("2001:db8:1::1"), IPAddress.Parse("2001:db8:1:ffff::1")));
        Assert.False(DnsVerdictRules.SamePrefix(IPAddress.Parse("2001:db8:1::1"), IPAddress.Parse("2001:db8:2::1")));
        Assert.False(DnsVerdictRules.SamePrefix(IPAddress.Parse("1.2.3.4"), IPAddress.Parse("::1")));
    }
}

public class DnsProbeTests
{
    [Fact]
    public void Catalog_loads_defaults_and_classifies_stubs()
    {
        var c = DnsResolverCatalog.Default;
        Assert.Equal(["1.1.1.1", "8.8.8.8", "9.9.9.9", "77.88.8.8"], c.Data.Udp.Select(u => u.Address));
        Assert.Equal(4, c.Data.Doh.Count);
        Assert.All(c.Data.Doh, d => Assert.StartsWith("https://", d.Url, StringComparison.Ordinal));
        Assert.True(c.Data.Doh.Single(d => d.Name == "Google").Ecs);
        Assert.Equal("94.140.14.14", c.Data.Doh.Single(d => d.Name == "AdGuard").Bootstrap);
        foreach (var a in new[] { "127.0.0.5", "0.0.0.0", "10.1.2.3", "172.31.0.1", "192.168.1.1", "100.64.0.1", "::1", "::", "fd12::1", "fe80::1", "::ffff:10.0.0.1" })
            Assert.True(c.IsSinkhole(IPAddress.Parse(a), out _), a);
        foreach (var a in new[] { "8.8.8.8", "172.32.0.1", "100.128.0.1", "2a00:1450::1" })
            Assert.False(c.IsSinkhole(IPAddress.Parse(a), out _), a);

        var created = c.CreateTransports(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        try
        {
            Assert.Equal(4, created.Count(t => t.Kind == DnsResolverKind.Udp));
            Assert.Equal(4, created.Count(t => t.Kind == DnsResolverKind.Doh));
        }
        finally
        {
            created.ForEach(t => t.Dispose());
        }
    }

    [Theory]
    [InlineData(" Example.COM. ", "example.com")]
    [InlineData("пример.рф", "xn--e1afmkfd.xn--p1ai")]
    public void Host_is_normalized(string input, string expected) => Assert.Equal(expected, DnsProbe.NormalizeHost(input));

    [Theory]
    [InlineData("1.2.3.4")]
    [InlineData("::1")]
    [InlineData("")]
    public void Host_must_be_a_name(string input) => Assert.Throws<ArgumentException>(() => DnsProbe.NormalizeHost(input));

    [Fact]
    public async Task Probe_collects_answers_https_and_verdict_despite_failures()
    {
        var https = new FakeTransport("Cloudflare", DnsResolverKind.Doh, (n, t, _, _) => Task.FromResult(t == DnsRecordType.HTTPS
            ? DnsMessage.Parse(DnsCodecTests.HttpsResponse(n))
            : DnsKit.Message(n, t, 0, "104.16.132.229", "2606:4700::6810:84e5")));
        var broken = new FakeTransport("Quad9", DnsResolverKind.Doh, (_, _, _, _) => throw new DnsTransportException("boom"));
        var hanging = new FakeTransport("Google", DnsResolverKind.Udp, async (n, t, _, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return DnsKit.Message(n, t, 0);
        });
        var system = new FakeSystemResolver((_, _) => Task.FromResult(new[] { IPAddress.Parse("127.0.0.1") }));

        var report = await DnsProbe.RunAsync("cloudflare.com", new DnsProbeOptions
        {
            SystemResolver = system,
            Transports = [hanging, https, broken],
            ResolverTimeout = TimeSpan.FromMilliseconds(300),
        }, CancellationToken.None);

        Assert.Equal("cloudflare.com", report.Host);
        Assert.Equal(4, report.Answers.Count);
        Assert.Equal(DnsResolverKind.System, report.Answers[0].Kind);
        Assert.Equal(DnsAnswerStatus.Timeout, report.Answers[1].Status);
        Assert.Equal(DnsAnswerStatus.Ok, report.Answers[2].Status);
        Assert.Equal(2, report.Answers[2].Addresses.Count);
        Assert.Equal(DnsAnswerStatus.Error, report.Answers[3].Status);
        Assert.Contains("boom", report.Answers[3].Error, StringComparison.Ordinal);
        Assert.Equal([IPAddress.Parse("104.16.132.229"), IPAddress.Parse("2606:4700::6810:84e5")], report.TrustedAddresses);

        Assert.NotNull(report.Https);
        Assert.Equal("Cloudflare", report.Https.Source);
        Assert.True(report.Https.SupportsHttp3);
        Assert.True(report.Https.HasEch);

        Assert.True(report.Verdict.Poisoned);
        Assert.Contains(report.Verdict.Reasons, r => r.Code == "SYSTEM_SINKHOLE");
        Assert.False(https.Disposed); // caller-owned transports are not disposed
    }

    [Fact]
    public async Task Probe_maps_system_nxdomain()
    {
        var system = new FakeSystemResolver((_, _) => Task.FromException<IPAddress[]>(new SocketException((int)SocketError.HostNotFound)));
        var report = await DnsProbe.RunAsync("blocked.test", new DnsProbeOptions
        {
            SystemResolver = system,
            Transports = [FakeTransport.Addresses("Google", DnsResolverKind.Doh, "203.0.113.10")],
            QueryHttps = false,
        }, CancellationToken.None);
        Assert.Equal(DnsAnswerStatus.NxDomain, report.SystemAnswer!.Status);
        Assert.Null(report.Https);
        Assert.Equal(DnsVerdictKind.Poisoned, report.Verdict.Kind);
    }

    [Fact]
    public async Task Probe_reports_nxdomain_from_wire_resolver()
    {
        var nx = new FakeTransport("Google", DnsResolverKind.Doh, (n, t, _, _) => Task.FromResult(DnsKit.Message(n, t, 3)));
        var report = await DnsProbe.RunAsync("nope.test", new DnsProbeOptions { IncludeSystem = false, Transports = [nx], QueryIpv6 = false }, CancellationToken.None);
        var a = Assert.Single(report.Answers);
        Assert.Equal(DnsAnswerStatus.NxDomain, a.Status);
        Assert.Equal(DnsResponseCode.NxDomain, a.ResponseCode);
        Assert.Equal(2, nx.Calls); // A + HTTPS
    }

    [Fact]
    public async Task Probe_propagates_caller_cancellation()
    {
        var hanging = new FakeTransport("x", DnsResolverKind.Doh, async (n, t, _, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return DnsKit.Message(n, t, 0);
        });
        using var cts = new CancellationTokenSource(100);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DnsProbe.RunAsync("a.test", new DnsProbeOptions
        {
            IncludeSystem = false,
            Transports = [hanging],
            ResolverTimeout = TimeSpan.FromSeconds(30),
        }, cts.Token));
    }

    [Fact]
    public async Task Probe_over_real_udp_transport()
    {
        await using var srv = new LocalDnsServer((q, _) => [DnsKit.Respond(q, DnsMessage.Parse(q).Questions[0].Type == DnsRecordType.A ? ["93.184.216.34"] : [])]);
        using var udp = new UdpDnsTransport(srv.Endpoint, "Local");
        var report = await DnsProbe.RunAsync("example.com", new DnsProbeOptions { IncludeSystem = false, Transports = [udp] }, CancellationToken.None);
        var a = Assert.Single(report.Answers);
        Assert.Equal(DnsAnswerStatus.Ok, a.Status);
        Assert.Equal([IPAddress.Parse("93.184.216.34")], a.Addresses);
        Assert.Equal(DnsVerdictKind.Unknown, report.Verdict.Kind); // no DoH to compare with
    }

    [Fact]
    public async Task Subnet_search_sends_ecs_per_subnet()
    {
        var seen = new System.Collections.Concurrent.ConcurrentBag<string>();
        var doh = new FakeTransport("Google", DnsResolverKind.Doh, (n, t, o, _) =>
        {
            var subnet = o!.ClientSubnet!;
            seen.Add($"{subnet}/{t}");
            if (subnet.Address.Equals(IPAddress.Parse("198.51.100.0")))
                throw new TimeoutException("slow");
            var last = subnet.Address.GetAddressBytes()[0];
            return Task.FromResult(DnsKit.Message(n, t, 0, $"192.0.2.{last % 200}"));
        });
        var subnets = new[] { DnsClientSubnet.Parse("203.0.113.0/24"), DnsClientSubnet.Parse("198.51.100.0/24"), DnsClientSubnet.Parse("100.0.0.0/8") };
        var res = await DnsProbe.QueryWithSubnetsAsync("cdn.test", subnets, doh, includeIpv6: false, CancellationToken.None);
        Assert.Equal(3, res.Count);
        Assert.Equal([IPAddress.Parse("192.0.2.3")], res[0].Addresses);
        Assert.Null(res[0].Error);
        Assert.Empty(res[1].Addresses);
        Assert.Equal("slow", res[1].Error);
        Assert.Equal([IPAddress.Parse("192.0.2.100")], res[2].Addresses);
        Assert.Equal(3, seen.Count);
        Assert.Contains("100.0.0.0/8/A", seen);
    }
}
