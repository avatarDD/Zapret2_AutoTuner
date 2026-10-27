using System.Buffers.Binary;
using System.Net;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Monitor;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>Repair steps answered from fields; every call is recorded.</summary>
internal sealed class FakeRepairSteps : IRepairSteps
{
    public List<string> Calls { get; } = [];

    public bool Baseline { get; set; }

    public Efficiency Check { get; set; } = new(0, 5);

    public bool Reachable { get; set; } = true;

    public StrategyCandidate? Local { get; set; }

    public StrategyCandidate? Full { get; set; }

    /// <summary>When set, the baseline waits for it (to hold a repair in flight).</summary>
    public TaskCompletionSource? Gate { get; set; }

    public async Task<bool> BaselineWorksAsync(string domain, CancellationToken ct)
    {
        Calls.Add("baseline " + domain);
        if (Gate is not null)
            await Gate.Task.WaitAsync(ct);
        return Baseline;
    }

    public Task<bool> ReachableAsync(string domain, CancellationToken ct)
    {
        Calls.Add("reachable " + domain);
        return Task.FromResult(Reachable);
    }

    public Task<Efficiency> CheckAsync(string domain, StrategyCandidate current, CancellationToken ct)
    {
        Calls.Add("check " + domain);
        return Task.FromResult(Check);
    }

    public Task<StrategyCandidate?> LocalSearchAsync(string domain, StrategyCandidate current, CancellationToken ct)
    {
        Calls.Add("local " + domain);
        return Task.FromResult(Local);
    }

    public Task<StrategyCandidate?> FullSearchAsync(string domain, CancellationToken ct)
    {
        Calls.Add("full " + domain);
        return Task.FromResult(Full);
    }
}

internal sealed class SyncProgress<T>(Action<T> a) : IProgress<T>
{
    public void Report(T value) => a(value);
}

public sealed class RepairRunnerTests
{
    private static readonly StrategyCandidate Current = ProgramFixtures.Candidate("--payload=tls_client_hello --lua-desync=multisplit:pos=midsld", L4Kind.Tcp);
    private static readonly StrategyCandidate Neighbour = ProgramFixtures.Candidate("--payload=tls_client_hello --lua-desync=multisplit:pos=midsld+1", L4Kind.Tcp);
    private static readonly StrategyCandidate Other = ProgramFixtures.Candidate("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5", L4Kind.Tcp);

    private static async Task<(RepairResult Result, List<string> Stages, List<string> Calls)> Run(FakeRepairSteps steps)
    {
        var stages = new List<string>();
        var r = await RepairRunner.RunAsync("example.com", Current, steps, new SyncProgress<string>(stages.Add));
        return (r, stages, steps.Calls.Select(c => c.Split(' ')[0]).ToList());
    }

    [Fact]
    public async Task Block_lifted_stops_at_the_baseline()
    {
        var (r, stages, calls) = await Run(new FakeRepairSteps { Baseline = true });
        Assert.Equal(RepairVerdict.BlockLifted, r.Verdict);
        Assert.Null(r.Strategy);
        Assert.Equal("example.com", r.Domain);
        Assert.Equal(["baseline"], stages);
        Assert.Equal(["baseline"], calls);
        Assert.NotEmpty(r.ReasonRu);
        Assert.NotEmpty(r.ReasonEn);
    }

    [Fact]
    public async Task Current_strategy_that_passes_means_it_still_works()
    {
        var (r, stages, calls) = await Run(new FakeRepairSteps { Check = new(5, 5) });
        Assert.Equal(RepairVerdict.StillWorks, r.Verdict);
        Assert.Same(Current, r.Strategy);
        Assert.Contains("5/5", r.ReasonRu, StringComparison.Ordinal);
        Assert.Equal(["baseline", "check"], stages);
        Assert.Equal(["baseline", "check"], calls);
    }

    [Fact]
    public async Task A_check_without_attempts_or_with_one_failure_goes_on()
    {
        var (r, _, calls) = await Run(new FakeRepairSteps { Check = new(0, 0), Reachable = false });
        Assert.Equal(RepairVerdict.SiteDown, r.Verdict);
        Assert.Equal(["baseline", "check", "reachable"], calls);
        (r, _, _) = await Run(new FakeRepairSteps { Check = new(4, 5), Reachable = false });
        Assert.Equal(RepairVerdict.SiteDown, r.Verdict);
    }

    [Fact]
    public async Task Unreachable_server_is_site_down_without_any_search()
    {
        var (r, stages, calls) = await Run(new FakeRepairSteps { Reachable = false, Local = Neighbour, Full = Other });
        Assert.Equal(RepairVerdict.SiteDown, r.Verdict);
        Assert.Null(r.Strategy);
        Assert.Equal(["baseline", "check", "reachability"], stages);
        Assert.DoesNotContain("local", calls);
    }

    [Fact]
    public async Task Local_search_result_is_taken_before_the_full_search()
    {
        var (r, stages, calls) = await Run(new FakeRepairSteps { Local = Neighbour, Full = Other });
        Assert.Equal(RepairVerdict.Replaced, r.Verdict);
        Assert.Same(Neighbour, r.Strategy);
        Assert.Equal(["baseline", "check", "reachability", "local"], stages);
        Assert.Equal(["baseline", "check", "reachable", "local"], calls);
    }

    [Fact]
    public async Task Full_search_is_the_last_resort()
    {
        var (r, stages, calls) = await Run(new FakeRepairSteps { Full = Other });
        Assert.Equal(RepairVerdict.Replaced, r.Verdict);
        Assert.Same(Other, r.Strategy);
        Assert.Equal(["baseline", "check", "reachability", "local", "full"], stages);
        Assert.Equal(["baseline", "check", "reachable", "local", "full"], calls);
    }

    [Fact]
    public async Task Nothing_found_is_not_found()
    {
        var (r, stages, _) = await Run(new FakeRepairSteps());
        Assert.Equal(RepairVerdict.NotFound, r.Verdict);
        Assert.Null(r.Strategy);
        Assert.Equal(5, stages.Count);
    }

    [Fact]
    public async Task Runs_without_a_progress_sink()
    {
        var r = await RepairRunner.RunAsync("example.com", Current, new FakeRepairSteps { Baseline = true });
        Assert.Equal(RepairVerdict.BlockLifted, r.Verdict);
    }

    [Theory]
    [InlineData(RepairVerdict.BlockLifted, "block_lifted")]
    [InlineData(RepairVerdict.StillWorks, "recovered")]
    [InlineData(RepairVerdict.SiteDown, "site_down")]
    [InlineData(RepairVerdict.Replaced, "repaired")]
    [InlineData(RepairVerdict.NotFound, "not_found")]
    public void Journal_kind_of_each_verdict(RepairVerdict v, string kind)
    {
        Assert.Equal(kind, RepairRunner.JournalKind(v));
    }
}

public sealed class RepairCoordinatorTests
{
    private static readonly StrategyCandidate Current = ProgramFixtures.Candidate("--payload=tls_client_hello --lua-desync=multisplit:pos=midsld", L4Kind.Tcp);
    private static readonly StrategyCandidate Neighbour = ProgramFixtures.Candidate("--payload=tls_client_hello --lua-desync=multisplit:pos=midsld+1", L4Kind.Tcp);

    private static HealthEvent Degraded(string domain = "example.com") =>
        new(domain, HealthChange.Degraded, new DateTime(2026, 1, 1, 0, 20, 0, DateTimeKind.Utc),
        [
            new WindowStats(domain, new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), 4, 1, 3, 0, 0, 0, 2),
            new WindowStats(domain, new DateTime(2026, 1, 1, 0, 10, 0, DateTimeKind.Utc), 5, 1, 1, 3, 0, 0, 7),
        ]);

    private static (RepairCoordinator C, List<(string Domain, string Kind, string Reason)> Journal, List<(RepairResult R, bool Apply)> Finished) Make(
        FakeRepairSteps steps, ApplyPolicy policy = ApplyPolicy.Ask, Func<string, StrategyCandidate?>? currentOf = null)
    {
        var c = new RepairCoordinator(steps, currentOf ?? (_ => Current), policy);
        var journal = new List<(string, string, string)>();
        var finished = new List<(RepairResult, bool)>();
        c.Journal += (d, k, r, en) =>
        {
            Assert.NotEmpty(en);
            journal.Add((d, k, r));
        };
        c.Finished += (r, apply) => finished.Add((r, apply));
        return (c, journal, finished);
    }

    [Fact]
    public async Task Recovery_is_only_journalled()
    {
        var steps = new FakeRepairSteps();
        var (c, journal, finished) = Make(steps);
        var r = await c.OnEventAsync(new HealthEvent("example.com", HealthChange.Recovered, DateTime.UtcNow, []), CancellationToken.None);
        Assert.Null(r);
        var j = Assert.Single(journal);
        Assert.Equal(("example.com", "recovered"), (j.Domain, j.Kind));
        Assert.Empty(steps.Calls);
        Assert.Empty(finished);
    }

    [Fact]
    public async Task Degradation_runs_the_repair_and_journals_both_ends()
    {
        var steps = new FakeRepairSteps { Local = Neighbour };
        var (c, journal, finished) = Make(steps);
        var r = await c.OnEventAsync(Degraded(), CancellationToken.None);
        Assert.NotNull(r);
        Assert.Equal(RepairVerdict.Replaced, r.Verdict);
        Assert.Equal(["degraded", "repaired"], journal.Select(j => j.Kind));
        Assert.Contains("4/5", journal[0].Reason, StringComparison.Ordinal);       // the last window: 4 failures of 5
        Assert.Contains("Stalled16k", journal[0].Reason, StringComparison.Ordinal);
        Assert.Equal(r.ReasonRu, journal[1].Reason);
        var (fr, apply) = Assert.Single(finished);
        Assert.Same(r, fr);
        Assert.False(apply);                      // Ask: the user decides
        Assert.False(c.IsRunning("example.com"));
    }

    [Fact]
    public async Task Domain_without_a_strategy_is_ignored()
    {
        var steps = new FakeRepairSteps();
        var (c, journal, _) = Make(steps, currentOf: _ => null);
        Assert.Null(await c.OnEventAsync(Degraded(), CancellationToken.None));
        Assert.Empty(journal);
        Assert.Empty(steps.Calls);
    }

    [Fact]
    public async Task A_second_event_for_a_domain_under_repair_is_skipped()
    {
        var steps = new FakeRepairSteps { Gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously) };
        var (c, _, finished) = Make(steps);
        var first = c.OnEventAsync(Degraded(), CancellationToken.None);
        Assert.True(c.IsRunning("EXAMPLE.com"));
        Assert.Null(await c.OnEventAsync(Degraded("Example.com"), CancellationToken.None));
        Assert.Null(await c.OnUserReportAsync("example.com", CancellationToken.None));
        // another domain is not held up
        steps.Gate.SetResult();
        Assert.NotNull(await c.OnEventAsync(Degraded("other.com"), CancellationToken.None));
        Assert.NotNull(await first);
        Assert.Equal(2, finished.Count);
        Assert.Single(steps.Calls, s => s == "baseline example.com");
        Assert.False(c.IsRunning("example.com"));
    }

    [Fact]
    public async Task Running_flag_is_cleared_when_the_repair_throws()
    {
        var steps = new FakeRepairSteps { Gate = new TaskCompletionSource() };
        var (c, _, _) = Make(steps);
        using var cts = new CancellationTokenSource();
        var t = c.OnEventAsync(Degraded(), cts.Token);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => t);
        Assert.False(c.IsRunning("example.com"));
    }

    [Theory]
    [InlineData(ApplyPolicy.Auto, true, true)]
    [InlineData(ApplyPolicy.Auto, false, false)]
    [InlineData(ApplyPolicy.Ask, true, false)]
    [InlineData(ApplyPolicy.Ask, false, false)]
    public async Task Auto_apply_only_for_a_replaced_strategy_under_the_auto_policy(ApplyPolicy policy, bool found, bool expected)
    {
        var (c, _, finished) = Make(new FakeRepairSteps { Full = found ? Neighbour : null }, policy);
        await c.OnEventAsync(Degraded(), CancellationToken.None);
        Assert.Equal(expected, Assert.Single(finished).Apply);
    }

    [Fact]
    public async Task Auto_apply_is_also_withheld_for_block_lifted_and_still_works()
    {
        var (c, _, finished) = Make(new FakeRepairSteps { Baseline = true }, ApplyPolicy.Auto);
        await c.OnEventAsync(Degraded(), CancellationToken.None);
        Assert.False(finished[0].Apply);
        var (c2, _, finished2) = Make(new FakeRepairSteps { Check = new(5, 5) }, ApplyPolicy.Auto);
        await c2.OnEventAsync(Degraded(), CancellationToken.None);
        Assert.Equal(RepairVerdict.StillWorks, finished2[0].R.Verdict);
        Assert.False(finished2[0].Apply);
        // the policy can change at run time
        c2.Policy = ApplyPolicy.Ask;
        Assert.Equal(ApplyPolicy.Ask, c2.Policy);
    }

    [Fact]
    public async Task User_report_starts_the_repair_at_once()
    {
        var steps = new FakeRepairSteps { Check = new(5, 5) };
        var (c, journal, finished) = Make(steps);
        var r = await c.OnUserReportAsync("example.com", CancellationToken.None);
        Assert.NotNull(r);
        Assert.Equal(RepairVerdict.StillWorks, r.Verdict);
        Assert.Equal("degraded", journal[0].Kind);
        Assert.Contains("пользователь", journal[0].Reason, StringComparison.Ordinal);
        Assert.Equal("recovered", journal[1].Kind);
        Assert.Single(finished);
    }
}

public sealed class HotSwapTests
{
    private sealed class OrderedEngine : IEngineControl
    {
        public List<string> Log { get; } = [];

        public bool Fail { get; set; }

        public Task<string> StartAsync(IReadOnlyList<string> argv, QueueRule? queue, string tag, CancellationToken ct)
        {
            Assert.False(ct.CanBeCanceled);
            if (Fail)
                throw EngineRefusedException.FromAgent("engine: queue busy");
            Log.Add("start " + tag);
            return Task.FromResult("new");
        }

        public Task StopAsync(string engineId, CancellationToken ct)
        {
            Assert.False(ct.CanBeCanceled);
            Log.Add("stop " + engineId);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task New_instance_starts_before_the_old_one_stops()
    {
        var e = new OrderedEngine();
        using var cts = new CancellationTokenSource();
        var id = await HotSwap.ReplaceAsync(e, "old", ["--lua-desync=multisplit:pos=2"], null, "example.com", cts.Token);
        Assert.Equal("new", id);
        Assert.Equal(["start example.com", "stop old"], e.Log);
    }

    [Fact]
    public async Task First_start_has_nothing_to_stop()
    {
        var e = new OrderedEngine();
        Assert.Equal("new", await HotSwap.ReplaceAsync(e, null, ["--lua-desync=multisplit:pos=2"], null, "t", CancellationToken.None));
        Assert.Equal(["start t"], e.Log);
    }

    [Fact]
    public async Task Old_instance_keeps_running_when_the_start_fails()
    {
        var e = new OrderedEngine { Fail = true };
        await Assert.ThrowsAsync<EngineRefusedException>(() => HotSwap.ReplaceAsync(e, "old", ["--lua-desync=multisplit:pos=2"], null, "t", CancellationToken.None));
        Assert.Empty(e.Log);
    }
}

public sealed class LiveMonitorTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private const string Client = "192.168.1.2";
    private const string Server = "203.0.113.5";
    private const string Elsewhere = "198.51.100.7";

    private static byte[] Ipv4(string src, string dst, int proto, byte[] l4)
    {
        var p = new byte[20 + l4.Length];
        p[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), 1);
        p[8] = 64;
        p[9] = (byte)proto;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(p, 12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(p, 16);
        l4.CopyTo(p, 20);
        return p;
    }

    private static byte[] Tcp(string src, int sport, string dst, int dport, TcpFlags flags, uint seq, uint ack, byte[]? payload = null)
    {
        payload ??= [];
        var l4 = new byte[20 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(l4, (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(l4.AsSpan(2), (ushort)dport);
        BinaryPrimitives.WriteUInt32BigEndian(l4.AsSpan(4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(l4.AsSpan(8), ack);
        l4[12] = 5 << 4;
        l4[13] = (byte)flags;
        BinaryPrimitives.WriteUInt16BigEndian(l4.AsSpan(14), 65535);
        payload.CopyTo(l4, 20);
        return Ipv4(src, dst, 6, l4);
    }

    private static byte[] DnsAnswer(string name, string address)
    {
        var ms = new MemoryStream();
        ms.Write([0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        foreach (var label in name.Split('.'))
        {
            ms.WriteByte((byte)label.Length);
            ms.Write(System.Text.Encoding.ASCII.GetBytes(label));
        }
        ms.Write([0, 0, 1, 0, 1]);
        ms.Write([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        ms.Write(IPAddress.Parse(address).GetAddressBytes());
        return ms.ToArray();
    }

    /// <summary>A handshake, one request, no answer, and the request retransmitted five seconds later: a stalled session.</summary>
    private static IEnumerable<CapturedPacket> Stalled(DateTime t, int port, string server = Server)
    {
        var request = System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        yield return new(t, Tcp(Client, port, server, 443, TcpFlags.Syn, 1000, 0), 40);
        yield return new(t.AddMilliseconds(20), Tcp(server, 443, Client, port, TcpFlags.Syn | TcpFlags.Ack, 5000, 1001), 40);
        yield return new(t.AddMilliseconds(30), Tcp(Client, port, server, 443, TcpFlags.Ack | TcpFlags.Psh, 1001, 5001, request), 40 + request.Length);
        yield return new(t.AddSeconds(5), Tcp(Client, port, server, 443, TcpFlags.Ack | TcpFlags.Psh, 1001, 5001, request), 40 + request.Length);
    }

    private static List<CapturedPacket> Slice(DateTime start, int sessions)
    {
        var packets = new List<CapturedPacket>();
        var dns = Ipv4("192.168.1.1", Client, 17, Udp(53, 5353, DnsAnswer("www.example.com", Server)));
        var dnsOther = Ipv4("192.168.1.1", Client, 17, Udp(53, 5354, DnsAnswer("notexample.com", Elsewhere)));
        packets.Add(new(start, dns, dns.Length));
        packets.Add(new(start, dnsOther, dnsOther.Length));
        for (int i = 0; i < sessions; i++)
        {
            packets.AddRange(Stalled(start.AddSeconds(1 + i), 50000 + (start.Minute * 100) + i));
            // the same failure to a domain outside the strategy must not count
            packets.AddRange(Stalled(start.AddSeconds(1 + i), 51000 + (start.Minute * 100) + i, Elsewhere));
        }
        return packets;
    }

    private static byte[] Udp(int sport, int dport, byte[] payload)
    {
        var l4 = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(l4, (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(l4.AsSpan(2), (ushort)dport);
        BinaryPrimitives.WriteUInt16BigEndian(l4.AsSpan(4), (ushort)l4.Length);
        payload.CopyTo(l4, 8);
        return l4;
    }

    private static LiveMonitorOptions Options() => new()
    {
        Domains = ["example.com"],
        Detector = new DetectorOptions { Window = TimeSpan.FromMinutes(1), MinSessions = 3, ConsecutiveWindows = 2 },
    };

    [Fact]
    public void Two_bad_windows_of_real_flows_degrade_the_strategy_domain()
    {
        var monitor = new LiveMonitor(new FakeMonitor([], new Dictionary<int, ObservedSocket[]>()), Options());
        var changed = new List<HealthEvent>();
        var windows = new List<WindowStats>();
        monitor.Changed += changed.Add;
        monitor.WindowClosed += windows.Add;

        Assert.Empty(monitor.Feed(Slice(T0, 3), T0.AddMinutes(1)));
        var w = Assert.Single(windows);
        Assert.Equal("example.com", w.Domain);
        Assert.Equal(3, w.Sessions);
        Assert.Equal(3, w.Stalled);
        Assert.Equal(3, w.Retransmissions);

        var events = monitor.Feed(Slice(T0.AddMinutes(1), 4), T0.AddMinutes(2));
        var e = Assert.Single(events);
        Assert.Equal(HealthChange.Degraded, e.Change);
        Assert.Equal("example.com", e.Domain);
        Assert.Equal(SessionOutcome.Stalled, e.Windows[^1].MainFailure);
        Assert.Equal(events, changed);
        Assert.Equal(2, windows.Count);
        Assert.True(monitor.Detector.IsDegraded("example.com"));
        Assert.Equal(["example.com"], monitor.Detector.Domains);
    }

    [Fact]
    public void Traffic_without_a_name_is_not_judged()
    {
        var monitor = new LiveMonitor(new FakeMonitor([], new Dictionary<int, ObservedSocket[]>()), Options());
        // the stalled sessions without their DNS answers have no name: nothing is judged
        var unnamed = Slice(T0, 3).Where(p => p.Parse()!.IsTcp).ToList();
        Assert.Empty(monitor.Feed(unnamed, T0.AddMinutes(1)));
        Assert.Empty(monitor.Feed(unnamed.Select(p => p with { TimestampUtc = p.TimestampUtc.AddMinutes(1) }).ToList(), T0.AddMinutes(2)));
        Assert.Empty(monitor.Detector.Domains);
    }

    [Fact]
    public async Task Run_captures_slice_after_slice_and_always_stops_the_capture()
    {
        var capture = new FakeMonitor(Slice(T0, 3), new Dictionary<int, ObservedSocket[]>());
        var monitor = new LiveMonitor(capture, Options() with { Slice = TimeSpan.FromMilliseconds(5) });
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await monitor.RunAsync(cts.Token);
        Assert.True(capture.Starts >= 1);
        Assert.Equal(capture.Starts, capture.Stops.Count);
        Assert.All(capture.Stops, s => Assert.False(s.Cancellable));
        // the slices are from January: the clock closed their windows
        Assert.NotEmpty(monitor.Detector.History("example.com"));
    }
}

public sealed class SearchRepairStepsTests
{
    private sealed class Executor(Func<string, int, TrialOutcome> rule) : ITrialExecutor
    {
        public List<string> Runs { get; } = [];

        public List<int> AttemptsAsked { get; } = [];

        public bool Reachable { get; set; } = true;

        public Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
        {
            Runs.Add(candidate.Key);
            AttemptsAsked.Add(attempts);
            var list = new List<TrialOutcome>();
            for (int i = 0; i < attempts && !stopEarly(list); i++)
                list.Add(rule(candidate.Key, i));
            return Task.FromResult<IReadOnlyList<TrialOutcome>>(list);
        }

        public Task<bool> TargetReachableAsync(CancellationToken ct) => Task.FromResult(Reachable);
    }

    private static readonly StrategyCandidate Current = new(Strategy.Parse("--payload=tls_client_hello --lua-desync=multisplit:pos=midsld"), "multi", 3, ["standard"], L4Kind.Tcp);

    private static readonly SearchOptions Opts = new() { Generator = new GeneratorOptions { Mode = SearchMode.Standard }, PunishPause = TimeSpan.FromMilliseconds(1) };

    private static SearchRepairSteps Steps(Executor e, Func<string, bool>? baseline = null, List<string>? asked = null) =>
        new((d, _) =>
        {
            asked?.Add(d);
            return Task.FromResult<ITrialExecutor>(e);
        }, (d, _) => Task.FromResult(baseline?.Invoke(d) ?? false), Opts, checkAttempts: 5);

    [Fact]
    public async Task Check_stops_at_the_first_failure()
    {
        var e = new Executor((_, i) => i < 2 ? TrialOutcome.Success() : TrialOutcome.Fail(TrialFailure.Reset));
        var asked = new List<string>();
        var eff = await Steps(e, asked: asked).CheckAsync("example.com", Current, CancellationToken.None);
        Assert.Equal(new Efficiency(2, 3), eff);
        Assert.Equal([5], e.AttemptsAsked);
        Assert.Equal(["example.com"], asked);

        var all = new Executor((_, _) => TrialOutcome.Success());
        Assert.Equal(new Efficiency(5, 5), await Steps(all).CheckAsync("example.com", Current, CancellationToken.None));
    }

    [Fact]
    public async Task Baseline_and_reachability_are_delegated()
    {
        var e = new Executor((_, _) => TrialOutcome.Success()) { Reachable = false };
        var steps = Steps(e, d => d == "open.com");
        Assert.True(await steps.BaselineWorksAsync("open.com", CancellationToken.None));
        Assert.False(await steps.BaselineWorksAsync("example.com", CancellationToken.None));
        Assert.False(await steps.ReachableAsync("example.com", CancellationToken.None));
        Assert.Empty(e.Runs);
    }

    [Fact]
    public async Task Local_search_tries_the_current_strategys_mutations_first()
    {
        var mutations = StrategyMutator.Mutate(Current.Strategy, Opts.Generator, l4: L4Kind.Tcp);
        Assert.True(mutations.Count > 3);
        var target = mutations[2];
        var e = new Executor((key, _) => key == target.Strategy.ToString() ? TrialOutcome.Success() : TrialOutcome.Fail(TrialFailure.Reset));
        var found = await Steps(e).LocalSearchAsync("example.com", Current, CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal(target.Strategy.ToString(), found.Key);
        Assert.Equal("multi", found.Family);
        Assert.Equal(L4Kind.Tcp, found.L4);
        Assert.Contains("repair:" + target.What, found.Tags);
        Assert.Contains("standard", found.Tags);
        // the neighbours in mutation order, the current one is not re-run, and the search stops at the first find
        Assert.Equal(mutations.Take(3).Select(m => m.Strategy.ToString()), e.Runs.Distinct());
        Assert.DoesNotContain(Current.Key, e.Runs);
    }

    [Fact]
    public async Task Local_search_of_a_udp_strategy_keeps_udp_mutations()
    {
        var quic = new StrategyCandidate(Strategy.Parse("--lua-desync=fake:blob=fake_default_quic:repeats=6"), "quic_fake", 1, [], L4Kind.Udp);
        var mutations = StrategyMutator.Mutate(quic.Strategy, Opts.Generator, l4: L4Kind.Udp);
        Assert.NotEmpty(mutations);
        var e = new Executor((key, _) => key == mutations[0].Strategy.ToString() ? TrialOutcome.Success() : TrialOutcome.Fail(TrialFailure.Timeout));
        var found = await Steps(e).LocalSearchAsync("youtube.com", quic, CancellationToken.None);
        Assert.NotNull(found);
        Assert.Equal(mutations[0].Strategy.ToString(), found.Key);
        Assert.Equal(L4Kind.Udp, found.L4);
        Assert.Equal(mutations[0].Strategy.ToString(), e.Runs[0]);
    }

    [Fact]
    public async Task Full_search_returns_the_first_working_strategy_or_null()
    {
        var any = new Executor((_, _) => TrialOutcome.Success());
        var found = await Steps(any).FullSearchAsync("example.com", CancellationToken.None);
        Assert.NotNull(found);
        Assert.Equal(any.Runs[0], found.Key);

        var none = new Executor((_, _) => TrialOutcome.Fail(TrialFailure.Reset));
        Assert.Null(await Steps(none).FullSearchAsync("example.com", CancellationToken.None));
        Assert.NotEmpty(none.Runs);
    }
}
