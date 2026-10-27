using System.Net;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Monitor;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Core.Tests;

public sealed class SessionClassifierTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static Flow Tcp(long bytesIn = 0, long bytesOut = 500, double lastSeen = 1, double? lastDataIn = null, int retrans = 0, bool synAck = true) => new()
    {
        Protocol = "tcp",
        Client = new IPEndPoint(IPAddress.Parse("192.168.1.2"), 50000),
        Server = new IPEndPoint(IPAddress.Parse("203.0.113.5"), 443),
        FirstSeen = T0,
        LastSeen = T0.AddSeconds(lastSeen),
        BytesIn = bytesIn,
        BytesOut = bytesOut,
        PacketsIn = bytesIn > 0 ? 10 : 1,
        PacketsOut = 5,
        SynTime = T0,
        SynAckTime = synAck ? T0.AddMilliseconds(20) : null,
        LastDataIn = lastDataIn is { } d ? T0.AddSeconds(d) : null,
        Retransmissions = retrans,
    };

    private static Flow Udp(int packetsOut, int packetsIn) => new()
    {
        Protocol = "udp",
        Client = new IPEndPoint(IPAddress.Parse("192.168.1.2"), 50001),
        Server = new IPEndPoint(IPAddress.Parse("203.0.113.5"), 443),
        FirstSeen = T0,
        LastSeen = T0.AddSeconds(1),
        PacketsOut = packetsOut,
        PacketsIn = packetsIn,
        BytesOut = packetsOut * 1200,
        BytesIn = packetsIn * 1200,
    };

    private static TlsClientHello Hello(string sni)
    {
        var record = ClientHelloBuilder.BuildRecord(ClientHelloSpec.Get("chrome141"), new ClientHelloOptions { Sni = sni });
        Assert.Equal(TlsParseStatus.Ok, TlsClientHello.TryParseRecords(record, out var ch));
        return ch!;
    }

    [Theory]
    [InlineData(5, 2, SessionOutcome.Ok)]
    [InlineData(1, 3, SessionOutcome.Ok)]
    [InlineData(5, 1, SessionOutcome.NoReply)]
    [InlineData(4, 0, SessionOutcome.NoReply)]
    [InlineData(3, 0, SessionOutcome.Unknown)]
    [InlineData(1, 1, SessionOutcome.Unknown)]
    public void Udp_outcome_by_packet_counts(int outPackets, int inPackets, SessionOutcome expected)
    {
        Assert.Equal(expected, SessionClassifier.Outcome(Udp(outPackets, inPackets), T0.AddSeconds(30)));
    }

    [Fact]
    public void Injected_rst_from_the_server_is_a_reset_and_a_genuine_one_is_not()
    {
        var f = Tcp(bytesIn: 100_000, lastSeen: 2, lastDataIn: 2);
        f.Rsts.Add(new RstInfo(T0.AddSeconds(2), 64, 0, true, RstOrigin.Server, []));
        Assert.Equal(SessionOutcome.Ok, SessionClassifier.Outcome(f, T0.AddSeconds(30)));

        // a client RST says nothing about the DPI
        f.Rsts.Add(new RstInfo(T0.AddSeconds(2), 64, 0, false, RstOrigin.Injected, []));
        Assert.Equal(SessionOutcome.Ok, SessionClassifier.Outcome(f, T0.AddSeconds(30)));

        f.Rsts.Add(new RstInfo(T0.AddSeconds(2), 120, 0, true, RstOrigin.Injected, ["TTL"]));
        Assert.Equal(SessionOutcome.Reset, SessionClassifier.Outcome(f, T0.AddSeconds(30)));
    }

    [Fact]
    public void Handshake_without_data_that_hung_is_stalled()
    {
        Assert.Equal(SessionOutcome.Stalled, SessionClassifier.Outcome(Tcp(lastSeen: 5), T0.AddSeconds(10)));
        // still young at the end of the capture: not judged
        Assert.Equal(SessionOutcome.Unknown, SessionClassifier.Outcome(Tcp(lastSeen: 5), T0.AddSeconds(3)));
        Assert.Equal(SessionOutcome.Unknown, SessionClassifier.Outcome(Tcp(lastSeen: 1), T0.AddSeconds(10)));
        // no SYN,ACK: not even a handshake, and no client data: nothing was asked
        Assert.Equal(SessionOutcome.Unknown, SessionClassifier.Outcome(Tcp(lastSeen: 5, synAck: false), T0.AddSeconds(10)));
        Assert.Equal(SessionOutcome.Unknown, SessionClassifier.Outcome(Tcp(lastSeen: 5, bytesOut: 0), T0.AddSeconds(10)));
    }

    [Theory]
    [InlineData(16_000, 6, 2, SessionOutcome.Stalled16k)]
    [InlineData(8 * 1024, 6, 1, SessionOutcome.Stalled16k)]
    [InlineData(32 * 1024, 6, 1, SessionOutcome.Stalled16k)]
    [InlineData(16_000, 6, 0, SessionOutcome.Ok)]       // no retransmissions: the client just went quiet
    [InlineData(16_000, 2, 3, SessionOutcome.Ok)]       // data still flowing a moment ago
    [InlineData(7_000, 6, 3, SessionOutcome.Ok)]
    [InlineData(100_000, 6, 3, SessionOutcome.Ok)]
    public void Cutoff_between_8_and_32_kb_with_retransmissions_is_stalled16k(long bytesIn, double lastSeen, int retrans, SessionOutcome expected)
    {
        var f = Tcp(bytesIn: bytesIn, lastSeen: lastSeen, lastDataIn: 1, retrans: retrans);
        Assert.Equal(expected, SessionClassifier.Outcome(f, T0.AddSeconds(30)));
    }

    [Fact]
    public void Normal_download_is_ok()
    {
        Assert.Equal(SessionOutcome.Ok, SessionClassifier.Outcome(Tcp(bytesIn: 2_000_000, lastSeen: 3, lastDataIn: 3), T0.AddSeconds(30)));
    }

    [Fact]
    public void Classify_names_the_flow_by_sni_first()
    {
        var f = Tcp(bytesIn: 2_000_000, lastSeen: 3, lastDataIn: 3);
        f.ClientHellos.Add(Hello("WWW.Example.com"));
        var s = SessionClassifier.Classify(f, T0.AddSeconds(30), _ => "other.org");
        Assert.NotNull(s);
        Assert.Equal("www.example.com", s.Domain);
        Assert.Equal(L4Kind.Tcp, s.L4);
        Assert.Equal(T0, s.Time);
        Assert.Equal(SessionOutcome.Ok, s.Outcome);
        Assert.Equal(2_000_000, s.BytesIn);
        Assert.False(s.Failed);
    }

    [Fact]
    public void Classify_falls_back_to_the_dns_name_and_skips_unnamed_flows()
    {
        var f = Udp(6, 0);
        IPAddress? asked = null;
        var s = SessionClassifier.Classify(f, T0.AddSeconds(30), a =>
        {
            asked = a;
            return "Video.Example.ORG.";
        });
        Assert.Equal(IPAddress.Parse("203.0.113.5"), asked);
        Assert.NotNull(s);
        Assert.Equal("video.example.org", s.Domain);
        Assert.Equal(L4Kind.Udp, s.L4);
        Assert.Equal(SessionOutcome.NoReply, s.Outcome);
        Assert.True(s.Failed);

        Assert.Null(SessionClassifier.Classify(f, T0.AddSeconds(30)));
        Assert.Null(SessionClassifier.Classify(f, T0.AddSeconds(30), _ => null));
        Assert.Null(SessionClassifier.Classify(f, T0.AddSeconds(30), _ => ""));
    }

    [Theory]
    [InlineData("example.com", "example.com", true)]
    [InlineData("Example.COM", "example.com", true)]
    [InlineData("www.example.com", "example.com", true)]
    [InlineData("a.b.example.com", "example.com", true)]
    [InlineData("notexample.com", "example.com", false)]
    [InlineData("example.com.evil.net", "example.com", false)]
    [InlineData("example.com", "www.example.com", false)]
    [InlineData("com", "example.com", false)]
    public void Matches_uses_hostlist_semantics(string name, string domain, bool expected)
    {
        Assert.Equal(expected, SessionClassifier.Matches(name, domain));
    }

    [Fact]
    public void DomainOf_takes_the_longest_match()
    {
        string[] domains = ["example.com", "cdn.example.com", "youtube.com"];
        Assert.Equal("cdn.example.com", SessionClassifier.DomainOf("a.cdn.example.com", domains));
        Assert.Equal("example.com", SessionClassifier.DomainOf("www.example.com", domains));
        Assert.Equal("youtube.com", SessionClassifier.DomainOf("youtube.com", domains));
        Assert.Null(SessionClassifier.DomainOf("notexample.com", domains));
        Assert.Null(SessionClassifier.DomainOf("ggpht.com", domains));
    }
}

public sealed class DegradationDetectorTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static readonly DetectorOptions Opts = new() { Window = TimeSpan.FromMinutes(10), MinSessions = 3, ConsecutiveWindows = 2, FailureThreshold = 0.5 };

    private static SessionSample S(DateTime t, SessionOutcome o, string domain = "example.com", int retrans = 0) => new(domain, L4Kind.Tcp, t, o, 1000, retrans);

    /// <summary>Fills the window that starts at <paramref name="start"/>: <paramref name="bad"/> resets and <paramref name="good"/> ok sessions.</summary>
    private static List<HealthEvent> Fill(DegradationDetector d, DateTime start, int bad, int good, string domain = "example.com")
    {
        var events = new List<HealthEvent>();
        int i = 0;
        for (; i < bad; i++)
            events.AddRange(d.Add(S(start.AddSeconds(10 + i), SessionOutcome.Reset, domain, 2)));
        for (int j = 0; j < good; j++, i++)
            events.AddRange(d.Add(S(start.AddSeconds(10 + i), SessionOutcome.Ok, domain)));
        return events;
    }

    [Fact]
    public void Windows_are_aligned_to_the_window_length()
    {
        var d = new DegradationDetector(Opts);
        var closed = new List<WindowStats>();
        d.WindowClosed += closed.Add;
        Fill(d, T0.AddMinutes(13), 0, 3);
        Assert.Empty(d.Tick(T0.AddMinutes(19).AddSeconds(59)));
        Assert.Empty(closed);
        d.Tick(T0.AddMinutes(20));
        var w = Assert.Single(closed);
        Assert.Equal(T0.AddMinutes(10), w.Start);
        Assert.Equal(3, w.Sessions);
        Assert.Equal(3, w.Ok);
        Assert.Equal(DateTimeKind.Utc, w.Start.Kind);
    }

    [Fact]
    public void Two_bad_windows_degrade_once_and_two_good_ones_recover()
    {
        var d = new DegradationDetector(Opts);
        Assert.Empty(Fill(d, T0, 3, 1));
        Assert.Empty(Fill(d, T0.AddMinutes(10), 4, 0));   // closes window 1 (bad)
        Assert.False(d.IsDegraded("example.com"));

        var e = Assert.Single(Fill(d, T0.AddMinutes(20), 3, 0));    // closes window 2 (bad)
        Assert.Equal(HealthChange.Degraded, e.Change);
        Assert.Equal("example.com", e.Domain);
        Assert.Equal(T0.AddMinutes(20), e.Time);
        Assert.Equal(2, e.Windows.Count);
        Assert.Equal(SessionOutcome.Reset, e.Windows[^1].MainFailure);
        Assert.Equal(8, e.Windows[^1].Retransmissions);
        Assert.True(d.IsDegraded("EXAMPLE.com"));

        // a third bad window says nothing new
        Assert.Empty(Fill(d, T0.AddMinutes(30), 0, 3));
        // first good window: still degraded
        Assert.Empty(Fill(d, T0.AddMinutes(40), 0, 3));
        Assert.True(d.IsDegraded("example.com"));

        var r = Assert.Single(d.Tick(T0.AddMinutes(50)));
        Assert.Equal(HealthChange.Recovered, r.Change);
        Assert.False(d.IsDegraded("example.com"));
        Assert.Equal(5, d.History("example.com").Count);
    }

    [Fact]
    public void Exactly_the_threshold_is_not_bad()
    {
        var d = new DegradationDetector(Opts);
        Fill(d, T0, 2, 2);
        Fill(d, T0.AddMinutes(10), 2, 2);
        Assert.Empty(d.Tick(T0.AddMinutes(20)));
        Assert.All(d.History("example.com"), w => Assert.Equal(0.5, w.FailureRate));
        Assert.False(d.IsDegraded("example.com"));
    }

    [Fact]
    public void Windows_with_too_few_sessions_keep_the_state()
    {
        var d = new DegradationDetector(Opts);
        var closed = new List<WindowStats>();
        d.WindowClosed += closed.Add;
        Fill(d, T0, 3, 0);
        Fill(d, T0.AddMinutes(10), 0, 2);       // 2 good sessions: below MinSessions, not a good window
        Fill(d, T0.AddMinutes(20), 3, 0);
        var e = Assert.Single(d.Tick(T0.AddMinutes(30)));
        Assert.Equal(HealthChange.Degraded, e.Change);
        Assert.Equal(2, closed.Count);          // the thin window was not reported

        Fill(d, T0.AddMinutes(30), 0, 3);
        Fill(d, T0.AddMinutes(40), 2, 0);       // thin bad window does not break the good run either
        Fill(d, T0.AddMinutes(50), 0, 3);
        var r = Assert.Single(d.Tick(T0.AddMinutes(60)));
        Assert.Equal(HealthChange.Recovered, r.Change);
    }

    [Fact]
    public void A_long_gap_is_jumped_over()
    {
        var d = new DegradationDetector(Opts);
        var closed = new List<WindowStats>();
        d.WindowClosed += closed.Add;
        Fill(d, T0, 3, 0);
        // five hours of silence, then traffic again: one closed window, then the new one starts at the aligned time
        var later = T0.AddHours(5).AddMinutes(3);
        Assert.Empty(d.Add(S(later, SessionOutcome.Reset)));
        Assert.Single(closed);
        Assert.Equal(T0, closed[0].Start);
        d.Add(S(later.AddSeconds(1), SessionOutcome.Reset));
        d.Add(S(later.AddSeconds(2), SessionOutcome.Reset));
        // the bad run survives the silence (thin windows keep the state)
        var e = Assert.Single(d.Tick(T0.AddHours(5).AddMinutes(10)));
        Assert.Equal(HealthChange.Degraded, e.Change);
        Assert.Equal(2, closed.Count);
        Assert.Equal(T0.AddHours(5), closed[1].Start);
    }

    [Fact]
    public void Tick_closes_windows_without_new_samples()
    {
        var d = new DegradationDetector(Opts);
        Fill(d, T0, 3, 0, "a.com");
        Fill(d, T0, 0, 3, "b.com");
        Assert.Empty(d.Tick(T0.AddMinutes(9)));
        Assert.Empty(d.Tick(T0.AddMinutes(10)));
        Assert.Single(d.History("a.com"));
        Assert.Single(d.History("b.com"));
        Fill(d, T0.AddMinutes(10), 3, 0, "a.com");
        var e = Assert.Single(d.Tick(T0.AddMinutes(25)));
        Assert.Equal("a.com", e.Domain);
        Assert.Equal(["a.com", "b.com"], d.Domains.Order());
        // a repeated tick does not close anything again
        Assert.Empty(d.Tick(T0.AddMinutes(25)));
        Assert.Equal(2, d.History("a.com").Count);
    }

    [Fact]
    public void Late_samples_of_a_closed_window_are_dropped()
    {
        var d = new DegradationDetector(Opts);
        Fill(d, T0, 0, 3);
        d.Tick(T0.AddMinutes(10));
        d.Add(S(T0.AddMinutes(5), SessionOutcome.Reset));
        d.Tick(T0.AddMinutes(20));
        Assert.Single(d.History("example.com"));
        Assert.Equal(0, d.History("example.com")[0].Failures);
    }

    [Fact]
    public void Reset_forgets_the_domain()
    {
        var d = new DegradationDetector(Opts);
        Fill(d, T0, 3, 0);
        Fill(d, T0.AddMinutes(10), 3, 0);
        d.Tick(T0.AddMinutes(20));
        Assert.True(d.IsDegraded("example.com"));
        d.Reset("Example.com");
        Assert.False(d.IsDegraded("example.com"));
        Assert.Empty(d.History("example.com"));
        Assert.Empty(d.Domains);
        // counting starts over
        Fill(d, T0.AddMinutes(20), 3, 0);
        Assert.Empty(d.Tick(T0.AddMinutes(30)));
    }

    [Fact]
    public void Window_stats_count_outcomes_and_pick_the_main_failure()
    {
        var w = WindowStats.Of("x", T0,
        [
            S(T0, SessionOutcome.Ok), S(T0, SessionOutcome.Unknown), S(T0, SessionOutcome.Stalled16k, retrans: 3),
            S(T0, SessionOutcome.Stalled16k, retrans: 1), S(T0, SessionOutcome.Reset), S(T0, SessionOutcome.NoReply), S(T0, SessionOutcome.Stalled),
        ]);
        Assert.Equal(6, w.Sessions);                // unknown is not judged
        Assert.Equal(5, w.Failures);
        Assert.Equal(4, w.Retransmissions);
        Assert.Equal(SessionOutcome.Stalled16k, w.MainFailure);
        Assert.Equal(SessionOutcome.Unknown, WindowStats.Of("x", T0, [S(T0, SessionOutcome.Ok)]).MainFailure);
        Assert.Equal(0, WindowStats.Of("x", T0, []).FailureRate);
    }
}

public sealed class AutoHostlistLogTests
{
    // the exact lines of nfq2/desync.c (HOSTLIST_DEBUGLOG_APPEND → LOG_APPEND: fprint_localtime + " : " + message)
    private const string Log = """
        20.10.2026 10:00:01 : rutracker.org : profile 1 (noname) : client 192.168.1.33:51234 : proto tls : rseq 123 : incoming RST
        20.10.2026 10:00:01 : rutracker.org : profile 1 (noname) : client 192.168.1.33:51234 : proto tls : fail counter 1/3
        20.10.2026 10:00:05 : rutracker.org : profile 1 (noname) : client 192.168.1.33:51240 : proto tls : retrans threshold reached
        20.10.2026 10:00:05 : rutracker.org : profile 1 (noname) : client 192.168.1.33:51240 : proto tls : fail counter 2/3
        garbage line
        nfqws2: something else entirely
        20.10.2026 10:00:09 : RuTracker.org : profile 1 (noname) : client 192.168.1.33:51250 : proto tls : fail counter 3/3
        20.10.2026 10:00:09 : rutracker.org : profile 1 (noname) : client 192.168.1.33:51250 : proto tls : adding to /opt/etc/nfqws2/lists/auto.list
        20.10.2026 10:01:00 : youtube.com : profile 2 (my quic) : client [fd00::2]:40000 : proto quic : udp_in 1<=1 udp_out 5>=4
        20.10.2026 10:01:00 : youtube.com : profile 2 (my quic) : client [fd00::2]:40000 : proto quic : fail counter 1/3
        20.10.2026 10:01:30 : youtube.com : profile 2 (my quic) : client [fd00::2]:40002 : proto quic : fail counter reset. website is working.
        20.10.2026 10:02:00 : example.com : profile 1 (noname) : client 192.168.1.40:50000 : proto tls : fail counter reset. website is working.
        20.10.2026 10:03:00 : rutracker.org : profile 1 (noname) : client 192.168.1.33:51260 : proto tls : NOT adding, duplicate detected
        32.13.2026 10:03:00 : bad.date : profile 1 (noname) : client 1.2.3.4:1 : proto tls : fail counter 1/3
        """;

    [Fact]
    public void Parses_every_kind_of_line_and_skips_garbage()
    {
        var e = AutoHostlistLog.Parse(Log.Replace("\n", "\r\n", StringComparison.Ordinal));
        Assert.Equal(11, e.Count);

        Assert.Equal(new DateTime(2026, 10, 20, 10, 0, 1), e[0].Time);
        Assert.Equal("rutracker.org", e[0].Host);
        Assert.Equal(1, e[0].Profile);
        Assert.Equal("noname", e[0].ProfileName);
        Assert.Equal("192.168.1.33:51234", e[0].Client);
        Assert.Equal("tls", e[0].Proto);
        Assert.Equal(AutoHostlistEvent.Failure, e[0].Event);
        Assert.Equal("rseq 123 : incoming RST", e[0].Detail);

        Assert.Equal(AutoHostlistEvent.FailCounter, e[1].Event);
        Assert.Equal("fail counter 1/3", e[1].Detail);
        Assert.Equal(AutoHostlistEvent.Failure, e[2].Event);
        Assert.Equal("rutracker.org", e[4].Host);     // lower-cased
        Assert.Equal(AutoHostlistEvent.Added, e[5].Event);
        Assert.EndsWith("/opt/etc/nfqws2/lists/auto.list", e[5].Detail, StringComparison.Ordinal);

        Assert.Equal(AutoHostlistEvent.Failure, e[6].Event);
        Assert.Equal(2, e[6].Profile);
        Assert.Equal("my quic", e[6].ProfileName);
        Assert.Equal("[fd00::2]:40000", e[6].Client);
        Assert.Equal("quic", e[6].Proto);
        Assert.Equal("udp_in 1<=1 udp_out 5>=4", e[6].Detail);

        Assert.Equal(AutoHostlistEvent.Working, e[8].Event);
        Assert.Equal(AutoHostlistEvent.Working, e[9].Event);
        Assert.Equal(AutoHostlistEvent.Duplicate, e[10].Event);
        Assert.DoesNotContain(e, x => x.Host == "bad.date");
    }

    [Fact]
    public void Redirect_line_is_a_failure()
    {
        var e = Assert.Single(AutoHostlistLog.Parse("01.02.2026 03:04:05 : a.ru : profile 3 (x) : client 10.0.0.1:1 : proto http : rseq 7 : redirect to another domain"));
        Assert.Equal(AutoHostlistEvent.Failure, e.Event);
        Assert.Equal(new DateTime(2026, 2, 1, 3, 4, 5), e.Time);
        Assert.Equal("http", e.Proto);
    }

    [Fact]
    public void Summary_puts_failing_hosts_first_and_honours_since()
    {
        var e = AutoHostlistLog.Parse(Log);
        var s = AutoHostlistLog.Summary(e, DateTime.MinValue);
        Assert.Equal(["rutracker.org", "youtube.com", "example.com"], s.Select(x => x.Host));
        Assert.Equal(("rutracker.org", 2, 0, true), s[0]);
        Assert.Equal(("youtube.com", 1, 1, false), s[1]);
        Assert.Equal(("example.com", 0, 1, false), s[2]);

        var later = AutoHostlistLog.Summary(e, new DateTime(2026, 10, 20, 10, 1, 0));
        Assert.Equal(["youtube.com", "rutracker.org", "example.com"], later.Select(x => x.Host));
        Assert.Equal(("rutracker.org", 0, 0, false), later.Single(x => x.Host == "rutracker.org"));
    }
}
