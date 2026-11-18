using ZapretAutoTuner.Core.Diagnostics;

namespace ZapretAutoTuner.Core.Tests;

public sealed class ClassifierTests
{
    private const string Host = "blocked.example";

    private static ProbeResult Ok(string ip = "198.51.100.1", long body = 300_000) => new()
    {
        Host = Host, Address = ip, Sni = Host, ConnectOk = true, TlsOk = true, CertValid = true, HttpStatus = 200,
        BodyBytes = body, BytesIn = body + 300, Complete = true, TlsVersion = "1.3",
    };

    private static ProbeResult Fail(ProbeError e, string ip = "198.51.100.1", bool connect = true, bool tls = false, long bytes = 0) => new()
    {
        Host = Host, Address = ip, Sni = Host, ConnectOk = connect, TlsOk = tls, CertValid = tls, HttpStatus = tls ? 200 : null,
        Error = e, BytesIn = bytes, BodyBytes = bytes, StalledAt = e == ProbeError.Stalled ? bytes : null, RstSeen = e is ProbeError.TlsReset or ProbeError.HttpReset,
    };

    private static ProbeResult NoConnect(ProbeError e = ProbeError.ConnectTimeout, string ip = "198.51.100.1", int port = 443) =>
        Fail(e, ip, connect: false) with { Port = port };

    private static HelloProbeResult Hello(string spec, bool passed, bool kyber = false, bool ech = false) => new()
    {
        Address = "198.51.100.1", Spec = spec, Kyber = kyber, Ech = ech, HelloBytes = kyber ? 1800 : 520,
        Outcome = passed ? HelloOutcome.ServerHello : HelloOutcome.Reset,
    };

    private static ClassifierVerdict Run(params AddressObservation[] a) =>
        Classifier.Classify(new TargetObservation { Host = Host, Addresses = a });

    private static AddressObservation Addr(string ip = "198.51.100.1") => new() { Address = ip, Connect = Ok(ip) };

    [Fact]
    public void Open_resource_needs_nothing()
    {
        var v = Run(Addr() with { Baseline = [Ok(), Ok(), Ok()] });
        Assert.Equal(BlockLabel.Open, v.Primary);
        Assert.Equal(NextStep.Nothing, v.Next);
        Assert.Equal("Открывается", v.SummaryRu);
    }

    [Fact]
    public void A_failure_no_rule_explains_is_unknown_not_open()
    {
        // data trickled until the time limit: blocked, but no label fits
        var v = Run(Addr() with { Baseline = [Fail(ProbeError.TimeLimit, tls: true, bytes: 40_000), Fail(ProbeError.TimeLimit, tls: true, bytes: 41_000)] });
        Assert.Equal(BlockLabel.Unknown, v.Primary);
        Assert.Equal(NextStep.NeedVpn, v.Next);

        var none = Classifier.Classify(new TargetObservation { Host = Host, Addresses = [] });
        Assert.Equal(BlockLabel.Unknown, none.Primary);
        Assert.NotEqual(NextStep.Nothing, none.Next);
    }

    [Fact]
    public void All_addresses_dead_is_an_ip_block_and_starts_the_other_ip_search()
    {
        var v = Run(
            new AddressObservation { Address = "198.51.100.1", Connect = NoConnect(), ConnectOtherPort = NoConnect(port: 80) },
            new AddressObservation { Address = "198.51.100.2", Connect = NoConnect(ip: "198.51.100.2") });
        Assert.Equal(BlockLabel.IpBlock, v.Primary);
        Assert.Equal(NextStep.FindOtherIp, v.Next);
        Assert.Empty(v.LiveAddresses);
        Assert.Equal(2, v.DeadAddresses.Count);
        Assert.Contains("VPN", v.SummaryRu, StringComparison.Ordinal);
    }

    [Fact]
    public void Other_port_alive_means_port_block()
    {
        var v = Run(new AddressObservation { Address = "198.51.100.1", Connect = NoConnect(), ConnectOtherPort = Ok() with { Port = 80 } });
        Assert.Equal(BlockLabel.PortBlock, v.Primary);
        Assert.Equal(NextStep.FindOtherIp, v.Next);
    }

    [Fact]
    public void Partly_dead_target_searches_only_on_live_addresses()
    {
        var v = Run(
            new AddressObservation { Address = "198.51.100.1", Connect = NoConnect() },
            Addr("198.51.100.2") with { Baseline = [Fail(ProbeError.TlsReset, "198.51.100.2")], NeutralSni = Ok("198.51.100.2") with { Sni = "iana.org" } });
        Assert.Equal(["198.51.100.2"], v.LiveAddresses);
        Assert.Equal(BlockLabel.SniBlock, v.Primary);
        Assert.Equal(NextStep.SearchStrategy, v.Next);
        Assert.Contains(BlockLabel.IpBlock, v.Labels);
    }

    [Fact]
    public void Reset_after_hello_with_neutral_sni_answering_is_sni_block()
    {
        var v = Run(Addr() with
        {
            Baseline = [Fail(ProbeError.TlsReset) with { RstOrigin = RstOrigin.Injected }],
            NeutralSni = Fail(ProbeError.TlsFailed) with { Sni = "iana.org", ErrorDetail = "alert 112" }, // the server's alert is an answer
        });
        var f = Assert.Single(v.Findings);
        Assert.Equal(BlockLabel.SniBlock, f.Label);
        Assert.Contains(f.Evidence, e => e.Contains("RST подделан", StringComparison.Ordinal));
        Assert.Contains(f.Evidence, e => e.Contains("iana.org", StringComparison.Ordinal));
    }

    [Fact]
    public void Forged_certificate_is_an_sni_block()
    {
        var v = Run(Addr() with
        {
            Baseline = [Ok() with { CertValid = false, CertIssuer = "CN=DPI", CertError = "сертификат не для blocked.example", Complete = true }],
            NeutralSni = Ok() with { Sni = "iana.org" },
        });
        Assert.Equal(BlockLabel.SniBlock, v.Primary);
        Assert.Contains(v.Findings[0].Evidence, e => e.Contains("подменённый", StringComparison.Ordinal));
    }

    [Fact]
    public void Neutral_sni_failing_here_but_working_elsewhere_is_partial_ip()
    {
        var v = Run(Addr() with
        {
            Baseline = [Fail(ProbeError.TlsTimeout)],
            NeutralSni = Fail(ProbeError.TlsTimeout) with { Sni = "iana.org" },
            NeutralControl = Ok("192.0.2.10") with { Host = "iana.org" },
        });
        Assert.Equal(BlockLabel.PartialIp, v.Primary);
        Assert.Equal(NextStep.SearchStrategy, v.Next);
    }

    [Fact]
    public void Nothing_answering_anywhere_is_unknown_and_needs_vpn()
    {
        var v = Run(Addr() with
        {
            Baseline = [Fail(ProbeError.TlsTimeout)],
            NeutralSni = Fail(ProbeError.TlsTimeout) with { Sni = "iana.org" },
            NeutralControl = Fail(ProbeError.TlsTimeout, "192.0.2.10"),
        });
        Assert.Equal(BlockLabel.Unknown, v.Primary);
        Assert.Equal(NextStep.NeedVpn, v.Next);
    }

    [Fact]
    public void Stall_after_16k_is_the_cutoff()
    {
        var v = Run(Addr() with { Baseline = [Fail(ProbeError.Stalled, tls: true, bytes: 16_400)] });
        Assert.Equal(BlockLabel.Cutoff16K, v.Primary);
        Assert.Contains("16 KB", v.SummaryRu, StringComparison.Ordinal);
    }

    [Fact]
    public void Cutoff_inside_a_tls_record_is_the_cutoff()
    {
        // only the headers decrypted, the wire stopped at ~16 KB (the stand's cut.test on CI)
        var v = Run(Addr() with { Baseline = [Fail(ProbeError.Stalled, tls: true, bytes: 176) with { WireBytesIn = 16_074 }] });
        Assert.Equal(BlockLabel.Cutoff16K, v.Primary);
        Assert.Contains(v.Findings.Single().Evidence, e => e.Contains("16074 B на проводе", StringComparison.Ordinal));
        // a slow server: a few KB decrypted, the handshake makes up the rest of the wire count
        var slow = Run(Addr() with { Baseline = [Fail(ProbeError.Stalled, tls: true, bytes: 3000) with { WireBytesIn = 9000 }] });
        Assert.DoesNotContain(BlockLabel.Cutoff16K, slow.Labels);
    }

    [Fact]
    public void Stall_far_from_16k_is_not_the_cutoff()
    {
        var v = Run(Addr() with { Baseline = [Fail(ProbeError.Stalled, tls: true, bytes: 900_000)] });
        Assert.DoesNotContain(BlockLabel.Cutoff16K, v.Labels);
    }

    [Fact]
    public void Small_page_but_padded_download_cut_is_the_cutoff()
    {
        // the 24 KB of padding goes out, the DPI counts it and kills the flow before the response
        var v = Run(Addr() with { Baseline = [Ok(body: 3000)], Padded = Fail(ProbeError.HttpTimeout, tls: true, bytes: 4_500) with { BytesOut = 26_000 } });
        Assert.Equal(BlockLabel.Cutoff16K, v.Primary);
        Assert.Contains(v.Findings.Single(f => f.Label == BlockLabel.Cutoff16K).Evidence, e => e.Contains("26000 B отправлено", StringComparison.Ordinal));

        // a padded probe that died before sending much is not a volume cut
        var early = Run(Addr() with { Baseline = [Ok(body: 3000)], Padded = Fail(ProbeError.HttpReset, tls: true, bytes: 0) with { BytesOut = 600 } });
        Assert.DoesNotContain(BlockLabel.Cutoff16K, early.Labels);
    }

    [Fact]
    public void Tls12_passing_and_tls13_not_is_a_tls13_block()
    {
        var v = Run(Addr() with { Baseline = [Fail(ProbeError.TlsReset)], NeutralSni = Ok(), Tls12 = Ok() with { TlsVersion = "1.2" }, Tls13 = Fail(ProbeError.TlsReset) });
        Assert.Contains(BlockLabel.Tls13Block, v.Labels);
        Assert.Contains(BlockLabel.SniBlock, v.Labels);
    }

    [Fact]
    public void Kyber_hello_failing_alone_is_the_multipacket_block()
    {
        var v = Run(Addr() with { Baseline = [Ok()], Hellos = [Hello("chrome141", false, kyber: true), Hello("chrome141", true, kyber: false), Hello("firefox", false, kyber: true)] });
        Assert.Equal(BlockLabel.KyberMultiPkt, v.Primary);
        Assert.DoesNotContain(BlockLabel.Fingerprint, v.Labels);
        Assert.Equal(NextStep.SearchStrategy, v.Next);
    }

    [Theory]
    [InlineData(1600, true)]   // OpenSSL 3.5+: the system hello carries kyber too (the stand's kyber.test on CI)
    [InlineData(520, false)]   // a small system hello failing too is a real IP-range block
    public void A_large_system_hello_is_explained_by_kyber(long systemHello, bool explained)
    {
        var big = Fail(ProbeError.TlsTimeout) with { BytesOut = systemHello };
        var v = Run(Addr() with
        {
            Baseline = [big, big],
            NeutralSni = big with { Sni = "iana.org" },
            NeutralControl = Ok("192.0.2.10") with { Host = "iana.org" },
            Tls12 = Ok() with { TlsVersion = "1.2" },
            Tls13 = big,
            Hellos = [Hello("chrome141", false, kyber: true), Hello("chrome141", true, kyber: false)],
        });
        Assert.Equal(explained ? BlockLabel.KyberMultiPkt : BlockLabel.PartialIp, v.Primary);
        Assert.Equal(explained, !v.Labels.Contains(BlockLabel.PartialIp) && !v.Labels.Contains(BlockLabel.Tls13Block));
        Assert.Contains(BlockLabel.KyberMultiPkt, v.Labels);
        if (explained)
            Assert.Contains(v.Findings.Single().Evidence, e => e.Contains("1600 B", StringComparison.Ordinal));
    }

    [Fact]
    public void Ech_hello_failing_alone_is_the_ech_block()
    {
        var v = Run(Addr() with { Baseline = [Ok()], Hellos = [Hello("firefox", false, ech: true), Hello("firefox", true, ech: false)] });
        Assert.Equal(BlockLabel.Ech, v.Primary);
    }

    [Fact]
    public void Some_client_shapes_blocked_is_a_fingerprint_block()
    {
        var v = Run(Addr() with { Baseline = [Ok()], Hellos = [Hello("safari", false), Hello("chrome_legacy", true)] });
        Assert.Equal(BlockLabel.Fingerprint, v.Primary);
        Assert.Contains(v.Findings[0].Evidence, e => e.Contains("safari", StringComparison.Ordinal));
    }

    [Fact]
    public void Http_redirect_to_a_foreign_domain_is_an_http_block()
    {
        var http = Ok() with { Port = 80, Tls = false, HttpStatus = 302, Location = "http://warning.rt.ru/?id=17&st=0", BodyBytes = 0 };
        var v = Run(Addr() with { Baseline = [Ok()], Http = http });
        Assert.Equal(BlockLabel.HttpBlock, v.Primary);
        var same = Run(Addr() with { Baseline = [Ok()], Http = http with { Location = "https://www." + Host + "/" } });
        Assert.Equal(BlockLabel.Open, same.Primary);
    }

    [Fact]
    public void Silent_quic_is_a_quic_block_only_when_http3_is_not_ruled_out()
    {
        var quic = new QuicProbeResult { Address = "198.51.100.1", Port = 443, Outcome = QuicOutcome.NoResponse, Sent = 2 };
        var a = Addr() with { Baseline = [Ok()], Quic = quic };
        Assert.Equal(BlockLabel.QuicBlock, Classifier.Classify(new TargetObservation { Host = Host, SupportsHttp3 = true, Addresses = [a] }).Primary);
        Assert.Equal(BlockLabel.Open, Classifier.Classify(new TargetObservation { Host = Host, SupportsHttp3 = false, Addresses = [a] }).Primary);
        Assert.Equal(BlockLabel.QuicBlock, Run(a with { Quic = quic with { Outcome = QuicOutcome.NoResponse } }).Primary);
        Assert.Equal(BlockLabel.Open, Run(a with { Quic = quic with { Outcome = QuicOutcome.ServerHello } }).Primary);
    }

    [Fact]
    public void Flapping_results_are_unstable()
    {
        var v = Run(Addr() with { Baseline = [Ok(), Fail(ProbeError.TlsReset), Ok(), Fail(ProbeError.TlsReset)], NeutralSni = Ok() });
        Assert.Contains(BlockLabel.Unstable, v.Labels);
        Assert.Contains(v.Findings, f => f.Evidence.Any(e => e.Contains("2 из 4", StringComparison.Ordinal)));
    }

    [Fact]
    public void Working_then_dead_even_for_syn_is_punishment()
    {
        var v = Run(Addr() with { Baseline = [Ok(), Ok(), NoConnect(), NoConnect()] });
        Assert.Equal(BlockLabel.Punish, v.Primary);
    }

    [Fact]
    public void Dns_poison_alone_suggests_doh()
    {
        var v = Classifier.Classify(new TargetObservation
        {
            Host = Host,
            Dns = new DnsObservation { Poisoned = true, Evidence = ["системный DNS вернул 127.0.0.1"] },
            Addresses = [Addr() with { Baseline = [Ok()] }],
        });
        Assert.Equal(NextStep.UseDoh, v.Next);
        Assert.Equal(BlockLabel.DnsPoison, v.Primary);
        Assert.Contains(v.Findings, f => f.Label == BlockLabel.DnsPoison && f.Address is null);
    }

    [Theory]
    [InlineData("www.youtube.com", "youtube.com")]
    [InlineData("warning.rt.ru", "rt.ru")]
    [InlineData("news.bbc.co.uk", "bbc.co.uk")]
    [InlineData("example.com", "example.com")]
    public void Registrable_domain(string host, string expected) => Assert.Equal(expected, Classifier.Registrable(host));

    [Fact]
    public void A_flat_shelf_below_the_link_is_a_shaper_with_a_speed_criterion()
    {
        var shelf = new RateReading(20_000, 0.03, 21_000, 5, 300_000);
        var obs = Addr() with { Baseline = [Ok(), Ok(), Ok()], Speed = Ok() with { Complete = false, Rate = shelf } };
        var v = Classifier.Classify(new TargetObservation { Host = Host, Addresses = [obs], Capacity = 2_000_000 });
        Assert.Equal(BlockLabel.Throttle, v.Primary);
        Assert.Equal(NextStep.SearchStrategy, v.Next);
        Assert.Equal(60_000, v.Criteria.MinRate);
        Assert.Equal(ProbeCriteria.TrialRateBytes, v.Criteria.RateBytes);
        // the same speed on a slow link is the link
        var slow = Classifier.Classify(new TargetObservation { Host = Host, Addresses = [obs], Capacity = 50_000 });
        Assert.Equal(BlockLabel.Open, slow.Primary);
        Assert.Equal(0, slow.Criteria.MinRate);
    }

    [Fact]
    public void A_cutoff_behind_a_small_page_pads_the_criterion()
    {
        var v = Run(Addr() with { Baseline = [Ok(body: 3000)], Padded = Fail(ProbeError.HttpTimeout, tls: true, bytes: 4_500) with { BytesOut = 26_000 } });
        Assert.Equal(128 * 1024, v.Criteria.MinBytes);
        Assert.Equal(ProbeCriteria.VolumePad, v.Criteria.PadBytes);
        var big = Run(Addr() with { Baseline = [Fail(ProbeError.Stalled, tls: true, bytes: 16_000)] });
        Assert.Contains(BlockLabel.Cutoff16K, big.Labels);
        Assert.Equal(128 * 1024, big.Criteria.MinBytes);
        Assert.Equal(0, big.Criteria.PadBytes);
    }
}
