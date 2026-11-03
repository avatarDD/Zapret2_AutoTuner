using System.Net;
using System.Text;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>geneva's "Авто" mode (skill geneva, §9): observation, the book's states, what is applied and how.</summary>
public class AutoTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static AutoSample Sample(string key, AutoHealth health, DateTime time, AutoKind kind = AutoKind.Web, L4Kind transport = L4Kind.Tcp,
        string ip = "203.0.113.5", int port = 443, string app = "tls", int localPort = 50000) => new()
        {
            Key = key,
            Kind = kind,
            Transport = transport,
            Name = key,
            Host = kind == AutoKind.Web ? "www.example.com" : null,
            App = app,
            Server = new IPEndPoint(IPAddress.Parse(ip), port),
            LocalPort = localPort,
            Time = time,
            Health = health,
            Why = health == AutoHealth.Ok ? "" : "сброс",
        };

    // ---- observation

    [Fact]
    public void Observer_reads_a_reset_TLS_flow_as_a_failed_site()
    {
        var hello = ClientHelloBuilder.BuildRecord(ClientHelloSpec.Get("chrome141"), new ClientHelloOptions { Sni = "www.example.com" });
        var packets = TestPackets.Capture(
            TestPackets.Tcp("192.168.1.2", 50001, "203.0.113.5", 443, TcpFlags.Syn, 1, 0),
            TestPackets.Tcp("203.0.113.5", 443, "192.168.1.2", 50001, TcpFlags.Syn | TcpFlags.Ack, 100, 2),
            TestPackets.Tcp("192.168.1.2", 50001, "203.0.113.5", 443, TcpFlags.Ack, 2, 101),
            TestPackets.Tcp("192.168.1.2", 50001, "203.0.113.5", 443, TcpFlags.Psh | TcpFlags.Ack, 2, 101, hello),
            TestPackets.Tcp("203.0.113.5", 443, "192.168.1.2", 50001, TcpFlags.Rst, 101, 0, ttl: 250));
        var flows = FlowAnalyzer.Analyze(packets);
        var samples = AutoObserver.Observe(flows, T0.AddSeconds(30));
        var s = Assert.Single(samples);
        Assert.Equal("web:example.com", s.Key);
        Assert.Equal(AutoKind.Web, s.Kind);
        Assert.Equal(AutoHealth.Failed, s.Health);
        Assert.Equal("www.example.com", s.Host);
        Assert.Empty(s.Replay);
    }

    [Fact]
    public void Observer_skips_the_LAN_and_the_searchs_own_ports()
    {
        var packets = TestPackets.Capture(
            TestPackets.Udp("192.168.1.2", 50002, "192.168.1.1", 53, TestPackets.DnsQuery("example.com")),
            TestPackets.Udp("192.168.1.2", GenevaArgv.LocalPortsBase, "203.0.113.9", 443, [1, 2, 3]));
        Assert.Empty(AutoObserver.Observe(FlowAnalyzer.Analyze(packets), T0.AddSeconds(30)));
    }

    [Fact]
    public void One_datagram_back_is_an_answer_and_one_unanswered_is_not_yet_a_failure()
    {
        var wg = new byte[148];
        wg[0] = 1;
        var answered = TestPackets.Capture(
            TestPackets.Udp("192.168.1.2", 50010, "203.0.113.7", 51820, wg),
            TestPackets.Udp("203.0.113.7", 51820, "192.168.1.2", 50010, new byte[92]));
        Assert.Equal(AutoHealth.Ok, Assert.Single(AutoObserver.Observe(FlowAnalyzer.Analyze(answered), T0.AddSeconds(30))).Health);
        var once = TestPackets.Capture(TestPackets.Udp("192.168.1.2", 50011, "203.0.113.7", 51820, wg));
        Assert.Empty(AutoObserver.Observe(FlowAnalyzer.Analyze(once), T0.AddSeconds(30)));
    }

    [Fact]
    public void Observer_keys_DNS_by_the_resolver_and_keeps_the_query_for_a_replay()
    {
        var packets = TestPackets.Capture(
            TestPackets.Udp("192.168.1.2", 50003, "8.8.8.8", 53, TestPackets.DnsQuery("example.com")),
            TestPackets.Udp("192.168.1.2", 50003, "8.8.8.8", 53, TestPackets.DnsQuery("example.com")));
        var s = Assert.Single(AutoObserver.Observe(FlowAnalyzer.Analyze(packets), T0.AddSeconds(30)));
        Assert.Equal("dns:8.8.8.8", s.Key);
        Assert.Equal(AutoKind.Dns, s.Kind);
        Assert.Equal(AutoHealth.Failed, s.Health);
        Assert.NotEmpty(s.Replay);
    }

    [Fact]
    public void Observer_keys_DHT_by_its_local_port()
    {
        var query = Encoding.ASCII.GetBytes("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe");
        var packets = TestPackets.Capture(TestPackets.Udp("192.168.1.2", 6881, "198.51.100.7", 51413, query));
        var s = Assert.Single(AutoObserver.Observe(FlowAnalyzer.Analyze(packets), T0.AddSeconds(30)));
        Assert.Equal("port:udp:6881", s.Key);
        Assert.Equal(AutoKind.LocalPort, s.Kind);
        Assert.Equal(AutoHealth.Failed, s.Health);
        Assert.Empty(s.Replay);
    }

    [Fact]
    public void OpenVpn_and_DHT_are_told_by_their_first_packet()
    {
        var reset = new byte[14];
        reset[0] = 7 << 3;
        Assert.True(AutoObserver.IsOpenVpn(reset, tcp: false));
        var tcp = new byte[16];
        tcp[1] = 14;
        tcp[2] = 7 << 3;
        Assert.True(AutoObserver.IsOpenVpn(tcp, tcp: true));
        reset[0] = (7 << 3) | 1;
        Assert.False(AutoObserver.IsOpenVpn(reset, tcp: false));
        Assert.True(AutoObserver.IsDht("d1:rd2:id20:abcdefghij0123456789e1:t2:aa1:y1:re"u8));
        Assert.False(AutoObserver.IsDht("GET / HTTP/1.1\r\n\r\n"u8));
    }

    [Fact]
    public void WireGuard_and_ICE_checks_are_not_replayed()
    {
        Assert.False(AutoObserver.CanReplay("wireguard", AppProtocol.WireGuard, [[1, 0, 0, 0]]));
        Assert.True(AutoObserver.CanReplay("openvpn", AppProtocol.Unknown, [[0x38, 1, 2]]));
        Assert.True(AutoObserver.CanReplay("stun", AppProtocol.Stun, [TestPackets.Stun()]));
        Assert.False(AutoObserver.CanReplay("udp", AppProtocol.Unknown, []));
    }

    // ---- the book

    [Fact]
    public void Three_failures_without_a_success_make_a_suspect_and_the_probe_decides()
    {
        var book = new AutoBook();
        book.Feed([Sample("web:a.com", AutoHealth.Failed, T0), Sample("web:a.com", AutoHealth.Failed, T0.AddSeconds(1))], T0.AddSeconds(2));
        book.Evaluate(T0.AddSeconds(2));
        Assert.Equal(AutoStatus.Watching, book.Find("web:a.com")!.Status);

        book.Feed([Sample("web:a.com", AutoHealth.Failed, T0.AddSeconds(3))], T0.AddSeconds(4));
        book.Evaluate(T0.AddSeconds(4));
        Assert.Equal(AutoStatus.Suspected, book.Find("web:a.com")!.Status);
        Assert.Equal("web:a.com", book.NextToConfirm(T0.AddSeconds(4))!.Key);

        book.Confirmed("web:a.com", AutoConfirm.Blocked, T0.AddSeconds(5));
        Assert.Equal(AutoStatus.Blocked, book.Find("web:a.com")!.Status);
        Assert.Equal("web:a.com", book.NextToSearch(T0.AddSeconds(5))!.Key);
    }

    [Fact]
    public void One_success_in_the_window_is_not_a_block()
    {
        var book = new AutoBook();
        book.Feed([.. Enumerable.Range(0, 5).Select(i => Sample("web:a.com", AutoHealth.Failed, T0.AddSeconds(i))), Sample("web:a.com", AutoHealth.Ok, T0.AddSeconds(6))], T0.AddSeconds(7));
        book.Evaluate(T0.AddSeconds(7));
        Assert.Equal(AutoStatus.Watching, book.Find("web:a.com")!.Status);
    }

    [Fact]
    public void An_open_site_waits_an_hour_and_an_address_block_six()
    {
        var book = new AutoBook();
        book.Feed([.. Enumerable.Range(0, 3).Select(i => Sample("web:a.com", AutoHealth.Failed, T0.AddSeconds(i))),
            .. Enumerable.Range(0, 3).Select(i => Sample("web:b.com", AutoHealth.NoConnection, T0.AddSeconds(i), ip: "203.0.113.6"))], T0.AddSeconds(3));
        book.Evaluate(T0.AddSeconds(3));
        book.Confirmed("web:a.com", AutoConfirm.NotBlocked, T0.AddSeconds(4));
        book.Confirmed("web:b.com", AutoConfirm.IpBlocked, T0.AddSeconds(4));
        Assert.Equal(AutoStatus.NotBlocked, book.Find("web:a.com")!.Status);
        Assert.Equal(T0.AddSeconds(4) + AutoRules.NotBlockedPause, book.Find("web:a.com")!.NextCheck);
        Assert.Equal(AutoStatus.IpBlocked, book.Find("web:b.com")!.Status);
        Assert.Equal(T0.AddSeconds(4) + AutoRules.IpBlockedPause, book.Find("web:b.com")!.NextCheck);
        Assert.Null(book.NextToSearch(T0.AddHours(1)));
    }

    [Fact]
    public void QUIC_failing_while_TCP_works_is_a_fallback()
    {
        var book = new AutoBook();
        book.Feed([Sample("web:a.com", AutoHealth.Ok, T0),
            Sample("quic:a.com", AutoHealth.Failed, T0, AutoKind.Quic, L4Kind.Udp, app: "quic"),
            Sample("quic:a.com", AutoHealth.Failed, T0.AddSeconds(1), AutoKind.Quic, L4Kind.Udp, app: "quic")], T0.AddSeconds(2));
        book.Evaluate(T0.AddSeconds(2));
        Assert.Equal(AutoStatus.Fallback, book.Find("quic:a.com")!.Status);
        Assert.Null(book.NextToConfirm(T0.AddSeconds(2)));
    }

    [Fact]
    public void A_service_without_a_probe_is_blocked_after_two_unknown_checks()
    {
        var book = new AutoBook();
        DateTime t = T0;
        void Fail(int n)
        {
            for (int i = 0; i < n; i++)
            {
                t = t.AddSeconds(1);
                book.Feed([Sample("ep:wireguard:udp:203.0.113.7:51820", AutoHealth.Failed, t, AutoKind.Endpoint, L4Kind.Udp, "203.0.113.7", 51820, "wireguard")], t);
            }
            book.Evaluate(t);
        }
        Fail(2);
        Assert.Equal(AutoStatus.Suspected, book.Find("ep:wireguard:udp:203.0.113.7:51820")!.Status);
        Assert.Equal("", book.Confirmed("ep:wireguard:udp:203.0.113.7:51820", AutoConfirm.Unknown, t));
        Assert.Equal(AutoStatus.Suspected, book.Find("ep:wireguard:udp:203.0.113.7:51820")!.Status);
        Fail(1);
        book.Confirmed("ep:wireguard:udp:203.0.113.7:51820", AutoConfirm.Unknown, t.AddMinutes(1));
        Assert.Equal(AutoStatus.Blocked, book.Find("ep:wireguard:udp:203.0.113.7:51820")!.Status);
    }

    [Fact]
    public void An_applied_strategy_that_fails_again_is_degraded_then_searched_again()
    {
        var book = new AutoBook();
        book.Feed([.. Enumerable.Range(0, 3).Select(i => Sample("web:a.com", AutoHealth.Failed, T0.AddSeconds(i)))], T0.AddSeconds(3));
        book.Evaluate(T0.AddSeconds(3));
        book.Confirmed("web:a.com", AutoConfirm.Blocked, T0.AddSeconds(4));
        book.Searching("web:a.com", T0.AddSeconds(5));
        book.Applied("web:a.com", AutoCandidates.Tcp[0], 400, T0.AddSeconds(6));
        Assert.True(book.Find("web:a.com")!.IsActive);

        var t = T0.AddMinutes(1);
        book.Feed([.. Enumerable.Range(0, 3).Select(i => Sample("web:a.com", AutoHealth.Failed, t.AddSeconds(i)))], t.AddSeconds(3));
        book.Evaluate(t.AddSeconds(3));
        var s = book.Find("web:a.com")!;
        Assert.Equal(AutoStatus.Degraded, s.Status);
        Assert.True(s.IsActive);

        book.Confirmed("web:a.com", AutoConfirm.Blocked, t.AddSeconds(4));
        Assert.Equal(AutoStatus.Blocked, s.Status);
        Assert.False(s.IsActive);
    }

    [Fact]
    public void A_search_that_found_nothing_backs_off_doubling_up_to_a_day()
    {
        var book = new AutoBook();
        book.Feed([Sample("web:a.com", AutoHealth.Failed, T0)], T0);
        var s = book.Find("web:a.com")!;
        var pauses = new List<TimeSpan>();
        for (int i = 0; i < 7; i++)
        {
            book.NotFound("web:a.com", T0);
            pauses.Add(s.NextCheck!.Value - T0);
        }
        Assert.Equal([1, 2, 4, 8, 16, 24, 24], pauses.Select(p => (int)p.TotalHours));
        book.Evaluate(T0.AddHours(25));
        Assert.Equal(AutoStatus.Blocked, s.Status);
    }

    [Fact]
    public void Reset_forgets_the_strategy()
    {
        var book = new AutoBook();
        book.Feed([Sample("web:a.com", AutoHealth.Failed, T0)], T0);
        book.Applied("web:a.com", AutoCandidates.Tcp[0], 400, T0);
        book.Reset("web:a.com", T0.AddSeconds(1));
        var s = book.Find("web:a.com")!;
        Assert.Equal(AutoStatus.Watching, s.Status);
        Assert.Null(s.Strategy);
        Assert.False(s.IsActive);
    }

    // ---- what is applied

    [Fact]
    public void Groups_join_services_of_one_strategy_and_the_trial_comes_first()
    {
        var book = new AutoBook();
        book.Feed([Sample("web:a.com", AutoHealth.Ok, T0), Sample("web:b.com", AutoHealth.Ok, T0, ip: "203.0.113.6"),
            Sample("dns:8.8.8.8", AutoHealth.Failed, T0, AutoKind.Dns, L4Kind.Udp, "8.8.8.8", 53, "dns")], T0);
        book.Applied("web:a.com", AutoCandidates.Tcp[0], 400, T0);
        book.Applied("web:b.com", AutoCandidates.Tcp[0], 400, T0);
        var groups = AutoPlan.Groups(book.Services, (book.Find("dns:8.8.8.8")!, AutoCandidates.Dns[0]));
        Assert.Equal(2, groups.Count);
        Assert.Equal(AutoCandidates.Dns[0], groups[0].Strategy);
        Assert.Equal("53", groups[0].Targets[0].TcpPorts);
        Assert.Equal("53", groups[0].Targets[0].UdpPorts);
        Assert.Equal(["web:a.com", "web:b.com"], groups[1].Services.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void A_peer_to_peer_program_is_aimed_at_by_its_local_port()
    {
        var s = new AutoService { Key = "port:udp:6881", Kind = AutoKind.LocalPort, Transport = L4Kind.Udp, LocalPort = 6881 };
        var t = AutoPlan.Target(s)!;
        Assert.True(t.ByLocalPort);
        Assert.Equal("6881", t.UdpPorts);
        Assert.Empty(t.Addresses);
        var f = AutoPlan.WinDivertFilter([t]);
        Assert.Contains("udp.SrcPort == 6881", f, StringComparison.Ordinal);
        Assert.Contains("udp.DstPort == 6881", f, StringComparison.Ordinal);
    }

    [Fact]
    public void WinDivert_filter_names_the_addresses_ports_and_both_directions()
    {
        var t = new AutoTarget { Addresses = [IPAddress.Parse("203.0.113.5"), IPAddress.Parse("2001:db8::5")], TcpPorts = "443" };
        var f = AutoPlan.WinDivertFilter([t]);
        Assert.Contains("outbound", f, StringComparison.Ordinal);
        Assert.Contains("inbound", f, StringComparison.Ordinal);
        Assert.Contains("ip.DstAddr == 203.0.113.5", f, StringComparison.Ordinal);
        Assert.Contains("ipv6.DstAddr == 2001:db8::5", f, StringComparison.Ordinal);
        Assert.Contains("tcp.DstPort == 443", f, StringComparison.Ordinal);
        Assert.Contains("tcp.SrcPort == 443", f, StringComparison.Ordinal);
        Assert.Equal("false", AutoPlan.WinDivertFilter([]));
    }

    [Fact]
    public void Candidates_are_valid_strategies_and_fit_the_transport()
    {
        foreach (var c in AutoCandidates.Tcp.Concat(AutoCandidates.Udp).Concat(AutoCandidates.Dns))
            Assert.Null(GenevaStrategyText.Problem(c));
        var udp = new AutoService { Kind = AutoKind.Endpoint, Transport = L4Kind.Udp };
        var list = AutoCandidates.For(udp, [AutoCandidates.Tcp[0], AutoCandidates.Udp[3]], []);
        Assert.Equal(AutoCandidates.Udp[3], list[0]);
        Assert.DoesNotContain(AutoCandidates.Tcp[0], list);
        Assert.True(list.Count <= AutoRules.MaxQuickCandidates);
        Assert.Equal("UDP,IP,DNS,DNSQR", AutoCandidates.Protos(new AutoService { Kind = AutoKind.Dns, Transport = L4Kind.Udp }));
        Assert.Equal("TCP", AutoCandidates.Protos(new AutoService { Kind = AutoKind.Web }));
    }

    // ---- the firewall of the groups

    private static readonly NftQueueRule AutoRule = new()
    {
        QueueNum = 340,
        TcpPorts = "443",
        Targets = [IPAddress.Parse("203.0.113.5")],
        Incoming = true,
        SkipMark = 0x20000000,
    };

    [Fact]
    public void Nft_rules_of_a_group_skip_genevas_own_packets()
    {
        var s = NftRuleset.Build([AutoRule]);
        Assert.Contains("meta mark & 0x20000000 == 0 ", s, StringComparison.Ordinal);
        Assert.Contains("tcp dport", s, StringComparison.Ordinal);
        Assert.Contains("queue num 340", s, StringComparison.Ordinal);
    }

    [Fact]
    public void Rules_by_local_port_match_the_source_port_going_out()
    {
        var r = AutoRule with { Targets = [], TcpPorts = "", UdpPorts = "6881", BySourcePort = true };
        var nft = NftRuleset.Build([r]);
        Assert.Contains("udp sport { 6881 }", nft, StringComparison.Ordinal);
        Assert.Contains("udp dport { 6881 }", nft, StringComparison.Ordinal);
        var ipt = IptablesRuleset.Build([r], ipv6: false);
        Assert.Contains("-A ztuner_post -m mark ! --mark 0x20000000/0x20000000 -p udp -m multiport --sports 6881", ipt, StringComparison.Ordinal);
        Assert.Contains("--dports 6881", ipt, StringComparison.Ordinal);
    }

    [Fact]
    public void Replay_searches_name_their_target_apart_from_the_page()
    {
        Assert.NotEqual(GenevaArgv.TargetKey("8.8.8.8", 53, GenevaArgv.WebProbe), GenevaArgv.TargetKey("8.8.8.8", 53, GenevaArgv.ReplayProbe));
        var settings = new GenevaSearchSettings { Host = "8.8.8.8", Port = 53, Probe = GenevaArgv.ReplayProbe, Protos = "UDP,IP,DNS,DNSQR" };
        Assert.Empty(settings.Problems());
        Assert.NotEmpty((settings with { Probe = "exec" }).Problems());
        Assert.NotEmpty((settings with { Protos = "TCP,HTTP" }).Problems());
    }
}
