using System.Net;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Tuning.Tests;

public sealed class LiveMonitorFailureTests
{
    /// <summary>A capture whose first starts fail like a dropped Agent, then works with an empty slice.</summary>
    private sealed class FlakyCapture(int failures) : IProgramMonitor
    {
        public int Starts { get; private set; }

        public int Stops { get; private set; }

        public Task<string> StartCaptureAsync(CancellationToken ct)
        {
            if (++Starts <= failures)
                throw new Grpc.Core.RpcException(new Grpc.Core.Status(Grpc.Core.StatusCode.Unavailable, "agent gone"));
            return Task.FromResult("cap" + Starts);
        }

        public Task<(byte[] Pcapng, long Dropped)> StopCaptureAsync(string captureId, CancellationToken ct)
        {
            Stops++;
            return Task.FromResult((PcapNgWriter.ToBytes([]), 0L));
        }

        public Task<IReadOnlyList<ObservedSocket>> ListConnectionsAsync(int pid, CancellationToken ct) => throw new NotSupportedException();
    }

    private static LiveMonitorOptions Options() => new()
    {
        Domains = ["example.com"],
        Slice = TimeSpan.FromMilliseconds(5),
        RetryDelay = TimeSpan.FromMilliseconds(1),
        MaxRetryDelay = TimeSpan.FromMilliseconds(4),
    };

    [Fact]
    public async Task A_failed_slice_is_reported_and_the_watch_goes_on()
    {
        var capture = new FlakyCapture(2);
        var monitor = new LiveMonitor(capture, Options());
        var failed = new List<(string Message, int InARow)>();
        monitor.Failed += (e, n) => failed.Add((e.Message, n));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        await monitor.RunAsync(cts.Token);
        Assert.Equal([1, 2], failed.Select(f => f.InARow));
        Assert.All(failed, f => Assert.Contains("agent gone", f.Message, StringComparison.Ordinal));
        Assert.True(capture.Starts > 3);
        Assert.Equal(capture.Starts - 2, capture.Stops);
    }

    [Fact]
    public async Task A_broken_pcap_is_a_failed_slice_too()
    {
        var capture = new BrokenPcap();
        var monitor = new LiveMonitor(capture, Options());
        int failed = 0;
        monitor.Failed += (_, _) => failed++;
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await monitor.RunAsync(cts.Token);
        Assert.True(failed >= 1);
    }

    [Fact]
    public void Backoff_doubles_up_to_the_cap()
    {
        var m = new LiveMonitor(new FlakyCapture(0), Options() with { RetryDelay = TimeSpan.FromSeconds(5), MaxRetryDelay = TimeSpan.FromSeconds(30) });
        Assert.Equal([5, 10, 20, 30, 30], new[] { 1, 2, 3, 4, 50 }.Select(n => m.Backoff(n).TotalSeconds));
    }

    private sealed class BrokenPcap : IProgramMonitor
    {
        public Task<string> StartCaptureAsync(CancellationToken ct) => Task.FromResult("c");

        public Task<(byte[] Pcapng, long Dropped)> StopCaptureAsync(string captureId, CancellationToken ct) => Task.FromResult((new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 }, 0L));

        public Task<IReadOnlyList<ObservedSocket>> ListConnectionsAsync(int pid, CancellationToken ct) => throw new NotSupportedException();
    }
}

public sealed class PipelineErrorTests
{
    private sealed class Services(Func<string, ITrialExecutor> executor) : IPipelineServices
    {
        public Task<ClassifierVerdict> ClassifyAsync(string host, IProgress<(string Ru, string En)> progress, CancellationToken ct) =>
            Task.FromResult(new ClassifierVerdict
            {
                Host = host,
                Findings = [new LabelFinding(BlockLabel.SniBlock, "203.0.113.5", ["reset"])],
                LiveAddresses = ["203.0.113.5"],
                Next = NextStep.SearchStrategy,
                Primary = BlockLabel.SniBlock,
            });

        public ITrialExecutor ExecutorFor(string host, IReadOnlyList<IPAddress> addresses) => executor(host);
    }

    private sealed class Executor(Exception? fail) : ITrialExecutor
    {
        public Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
        {
            if (fail is not null)
                throw fail;
            return Task.FromResult<IReadOnlyList<TrialOutcome>>([.. Enumerable.Range(0, attempts).Select(_ => TrialOutcome.Success())]);
        }

        public Task<bool> TargetReachableAsync(CancellationToken ct) => Task.FromResult(true);
    }

    private static PipelineOptions Options() => new()
    {
        Unify = false,
        Search = new SearchOptions { Generator = new GeneratorOptions { Mode = SearchMode.Quick }, StopAfterFound = 1, PunishPause = TimeSpan.FromMilliseconds(1) },
    };

    [Fact]
    public async Task One_target_that_throws_does_not_discard_the_others()
    {
        var services = new Services(h => h switch
        {
            "agentless.com" => throw new IOException("the Agent dropped"),
            "refused.com" => new Executor(EngineRefusedException.FromAgent("firewall: очередь 300 уже занята")),
            _ => new Executor(null),
        });
        var stages = new List<StageChanged>();
        var pipeline = new TuningPipeline(services, Options());
        pipeline.Event += e =>
        {
            if (e is StageChanged s)
                stages.Add(s);
        };
        var r = await pipeline.RunAsync(["ok1.com", "agentless.com", "refused.com", "ok2.com"]);

        Assert.Equal(["ok1.com", "agentless.com", "refused.com", "ok2.com"], r.Targets.Select(t => t.Host));
        Assert.NotNull(r.Targets[0].Best);
        Assert.NotNull(r.Targets[3].Best);
        Assert.Equal("the Agent dropped", r.Targets[1].Error);
        Assert.NotNull(r.Targets[1].Verdict);
        Assert.Contains("очередь 300", r.Targets[2].Error, StringComparison.Ordinal);
        Assert.NotNull(r.Solution);
        Assert.Contains(stages, s => s.Target == "agentless.com" && s.Stage == PipelineStage.Failed);
    }

    [Fact]
    public async Task Cancellation_still_stops_the_run()
    {
        using var cts = new CancellationTokenSource();
        var services = new Services(h =>
        {
            cts.Cancel();
            return new Executor(new OperationCanceledException(cts.Token));
        });
        var r = await new TuningPipeline(services, Options()).RunAsync(["a.com", "b.com"], cts.Token);
        // the stop is a stop, not an error of the target, and the next target is not started
        Assert.DoesNotContain(r.Targets, t => t.Host == "b.com");
        Assert.All(r.Targets, t => Assert.Null(t.Error));
    }
}

public sealed class RouterTrialFixTests
{
    private static StrategyCandidate Tcp(string s) => ProgramFixtures.Candidate(s, L4Kind.Tcp);

    private static RouterTrialOptions Options(Func<RouterTrialOptions, RouterTrialOptions>? tweak = null)
    {
        var o = new RouterTrialOptions { Targets = ["rutracker.org", "example.com"], Poll = TimeSpan.FromMilliseconds(1) };
        return tweak?.Invoke(o) ?? o;
    }

    [Fact]
    public async Task An_oversized_candidate_fails_without_being_sent()
    {
        var gui = new RouterGui { Probe = (_, _) => (true, "ok", 3) };
        var big = "0x" + new string('a', 2100);
        var x = new RouterTrialExecutor(gui.Experiments(), Options(o => o with { Blobs = new Dictionary<string, string> { ["huge"] = big } }));
        var r = await x.RunBatchAsync([Tcp("--payload=tls_client_hello --lua-desync=fake:blob=huge"), Tcp("--lua-desync=multisplit:pos=1")], 3, CancellationToken.None);

        var refused = Assert.Single(r[0]);
        Assert.False(refused.Ok);
        Assert.Contains("2000", refused.Detail, StringComparison.Ordinal);
        Assert.All(r[1], o => Assert.True(o.Ok));
        var start = Assert.Single(gui.StartArgs);
        var variant = Assert.Single((JsonArray)start["variants"]!);
        Assert.All((JsonArray)variant!["profiles"]!, p => Assert.True(((string)p!["args"]!).Length <= RouterTrialExecutor.MaxArgsLength));
    }

    [Fact]
    public async Task A_batch_the_gui_refuses_fails_and_the_next_one_runs()
    {
        var gui = new RouterGui { Probe = (_, _) => (true, "ok", 3), RefuseStart = (1, "движок занят сканером") };
        var x = new RouterTrialExecutor(gui.Experiments(), Options(o => o with { BatchSize = 1 }));
        var r = await x.RunBatchAsync([Tcp("--lua-desync=multisplit:pos=1"), Tcp("--lua-desync=multisplit:pos=2")], 3, CancellationToken.None);
        Assert.Contains("движок занят сканером", Assert.Single(r[0]).Detail, StringComparison.Ordinal);
        Assert.All(r[1], o => Assert.True(o.Ok));
        // the refused batch rolled back; the second started
        Assert.Equal(["strategy_experiment_start", "strategy_experiment_rollback", "strategy_experiment_start"],
            gui.Calls.Select(c => c.Tool).Where(t => t is "strategy_experiment_start" or "strategy_experiment_rollback"));
    }

    [Fact]
    public async Task Baseline_is_measured_once_per_session_and_its_open_targets_stay_left_out()
    {
        var gui = new RouterGui { OpenWithoutBypass = ["example.com"], Probe = (_, _) => (false, "tls_rst", 0) };
        var x = new RouterTrialExecutor(gui.Experiments(), Options(o => o with { BatchSize = 1 }));
        var r = await x.RunBatchAsync([Tcp("--lua-desync=multisplit:pos=1"), Tcp("--lua-desync=multisplit:pos=2")], 3, CancellationToken.None);
        Assert.Equal([true, false], gui.StartArgs.Select(a => (bool)a["baseline"]!));
        // the second report has no baseline of its own; the session's still leaves example.com out
        gui.OpenWithoutBypass = [];
        Assert.All(r, o => Assert.All(o, t => Assert.Contains("rutracker.org", t.Detail, StringComparison.Ordinal)));
        var more = await x.RunAsync(Tcp("--lua-desync=multisplit:pos=3"), 3, _ => false, CancellationToken.None);
        Assert.All(more, t => Assert.Contains("rutracker.org", t.Detail, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Results_come_without_logs_and_page_until_every_label_is_in()
    {
        var gui = new RouterGui { Probe = (args, _) => args.Contains("pos=5", StringComparison.Ordinal) ? (true, "ok", 3) : (false, "tls_rst", 0), PageSize = 2 };
        var x = new RouterTrialExecutor(gui.Experiments(), Options(o => o with { BatchSize = 5 }));
        var r = await x.RunBatchAsync([.. Enumerable.Range(1, 5).Select(i => Tcp($"--lua-desync=multisplit:pos={i}"))], 3, CancellationToken.None);
        var results = gui.Calls.Where(c => c.Tool == "strategy_experiment_result").Select(c => c.Args).ToList();
        Assert.Equal([0, 2, 4], results.Select(a => (int)a["offset"]!));
        Assert.All(results, a => Assert.False((bool)a["include_log"]!));
        Assert.Equal([false, false, false, false, true], r.Select(o => o.All(t => t.Ok)));
        Assert.Equal(5, x.LastReport!.Variants.Count);
    }
}

public sealed class FailureReportMaskTests
{
    [Theory]
    [InlineData("connect [2a00:1450:4010:c05::8a]:443 failed", "connect [2a00:1450:4010::x]:443 failed")]
    [InlineData("to 2a00:1450:4010:c05:0:0:0:8a now", "to 2a00:1450:4010::x now")]
    [InlineData("dst:93.184.216.34:443", "dst:93.184.216.x:443")]
    [InlineData("ip 93.184.216.34.", "ip 93.184.216.x.")]
    [InlineData("at 12:30:45 std::vector 1.2 v1.0", "at 12:30:45 std::vector 1.2 v1.0")]
    public void Addresses_are_masked_in_any_form(string line, string expected)
    {
        Assert.Equal(expected, new FailureReport.Masker(false).Line(line));
    }

    [Fact]
    public void Local_addresses_become_lan_n_including_link_local_v6()
    {
        var m = new FailureReport.Masker(false);
        var s = m.Line("from fe80::1c2b:3cff:fe4d:5e6f%eth0 and 192.168.1.10, again fe80::1c2b:3cff:fe4d:5e6f");
        Assert.DoesNotContain("fe80", s, StringComparison.Ordinal);
        Assert.DoesNotContain("192.168", s, StringComparison.Ordinal);
        Assert.Equal("from lan-1%eth0 and lan-2, again lan-1", s);
    }

    [Fact]
    public void Environment_lines_naming_a_target_are_masked_with_the_target()
    {
        var target = new TargetOutcome("rutracker.org", null, null, [], "timeout to 2a00:1450:4010:c05::8a");
        var text = FailureReport.Text([target], new ReportOptions { MaskDomains = true, Environment = ["DoH для rutracker.org через 2a00:1450:4010:c05::8a"] });
        Assert.DoesNotContain("rutracker", text, StringComparison.Ordinal);
        Assert.DoesNotContain("c05", text, StringComparison.Ordinal);
        Assert.Contains("DoH для d1 через 2a00:1450:4010::x", text, StringComparison.Ordinal);
        Assert.Contains("## d1", text, StringComparison.Ordinal);
    }
}
