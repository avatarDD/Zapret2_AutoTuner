using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Validation;
using ZapretAutoTuner.Protocol;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.Tuning.Tests;

public sealed class TrialExecutorTests
{
    /// <summary>Records what the executor asks the Agent for.</summary>
    private sealed class FakeEngine : IEngineControl
    {
        public List<(IReadOnlyList<string> Argv, QueueRule? Queue)> Started { get; } = [];

        public List<string> Stopped { get; } = [];

        public string? Refuse { get; set; }

        public Task<string> StartAsync(IReadOnlyList<string> argv, QueueRule? queue, string tag, CancellationToken ct)
        {
            if (Refuse is not null)
                throw new EngineRefusedException(Refuse);
            Started.Add((argv, queue));
            return Task.FromResult("e" + Started.Count);
        }

        public Task StopAsync(string engineId, CancellationToken ct)
        {
            Stopped.Add(engineId);
            return Task.CompletedTask;
        }
    }

    private static StrategyCandidate Candidate(string s, L4Kind l4 = L4Kind.Tcp) => new(Strategy.Parse(s), "test", 1, [], l4);

    private static readonly IPAddress Target = IPAddress.Parse("10.124.0.21");

    private static AgentTrialExecutor Executor(FakeEngine engine, EnginePlatform platform, IPAddress? address = null, int port = 443) =>
        new(engine, new TrialTarget { Host = "flaky.test", Addresses = [address ?? Target], Port = port }, new AgentTrialOptions
        {
            LuaDir = "/opt/zapret2/lua",
            Platform = platform,
            QueueNum = 333,
            Warmup = TimeSpan.Zero,
            Pause = TimeSpan.Zero,
            Blobs = new Dictionary<string, string> { ["tls_white"] = "0x1603", ["unused"] = "0x00" },
            TweakHttp = o => o with { ConnectTimeout = TimeSpan.FromSeconds(1) },
        });

    [Fact]
    public void Linux_launch_leaves_the_queue_to_the_agent_and_limits_it_to_the_target()
    {
        var (argv, queue) = Executor(new FakeEngine(), EnginePlatform.Linux).BuildLaunch(Candidate("--payload=tls_client_hello --lua-desync=fake:blob=tls_white:tcp_md5"));

        Assert.DoesNotContain(argv, a => a.StartsWith("--qnum", StringComparison.Ordinal) || a.StartsWith("--fwmark", StringComparison.Ordinal));
        Assert.Contains("--lua-init=@/opt/zapret2/lua/zapret-lib.lua", argv);
        Assert.Contains("--blob=tls_white:0x1603", argv);
        Assert.DoesNotContain(argv, a => a.StartsWith("--blob=unused", StringComparison.Ordinal));
        Assert.Contains("--filter-tcp=443", argv);
        Assert.Contains("--lua-desync=fake:blob=tls_white:tcp_md5", argv);
        Assert.NotNull(queue);
        Assert.Equal(333, queue.QueueNum);
        Assert.Equal("443", queue.TcpPorts);
        Assert.Equal(["10.124.0.21"], queue.Targets);
        Assert.False(queue.Incoming);
    }

    [Fact]
    public void Windows_launch_filters_by_the_target_address()
    {
        var (argv, queue) = Executor(new FakeEngine(), EnginePlatform.Windows).BuildLaunch(Candidate("--payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6", L4Kind.Udp));

        Assert.Null(queue);
        Assert.Contains("--wf-udp-out=443", argv);
        Assert.Contains(argv, a => a.StartsWith("--wf-raw-filter=", StringComparison.Ordinal) && a.Contains("10.124.0.21", StringComparison.Ordinal));
        Assert.Contains("--filter-udp=443", argv);
    }

    [Theory]
    [InlineData(ProbeError.ConnectTimeout, TrialFailure.NoConnect)]
    [InlineData(ProbeError.ConnectRefused, TrialFailure.NoConnect)]
    [InlineData(ProbeError.TlsReset, TrialFailure.Reset)]
    [InlineData(ProbeError.HttpReset, TrialFailure.Reset)]
    [InlineData(ProbeError.TlsTimeout, TrialFailure.Timeout)]
    [InlineData(ProbeError.Stalled, TrialFailure.Stalled)]
    [InlineData(ProbeError.Truncated, TrialFailure.Stalled)]
    [InlineData(ProbeError.TlsFailed, TrialFailure.Other)]
    public void Probe_errors_map_to_trial_failures(ProbeError error, TrialFailure expected)
    {
        var o = AgentTrialExecutor.ToOutcome(new ProbeResult { Host = "h", Address = "1.1.1.1", ConnectOk = error > ProbeError.Unreachable, Error = error }, 65536);
        Assert.False(o.Ok);
        Assert.Equal(expected, o.Failure);
    }

    [Fact]
    public void Success_is_a_full_body_not_a_handshake()
    {
        var handshake = new ProbeResult { Host = "h", Address = "1.1.1.1", ConnectOk = true, TlsOk = true, CertValid = true, HttpStatus = 200, BodyBytes = 1000, Error = ProbeError.Stalled, StalledAt = 1000 };
        Assert.False(AgentTrialExecutor.ToOutcome(handshake, 65536).Ok);
        var full = handshake with { BodyBytes = 70000, Error = ProbeError.None, StalledAt = null };
        Assert.True(AgentTrialExecutor.ToOutcome(full, 65536).Ok);
        var badCert = handshake with { BodyBytes = 70000, Error = ProbeError.None, StalledAt = null, CertValid = false, CertError = "name mismatch" };
        Assert.Equal(TrialFailure.BadCertificate, AgentTrialExecutor.ToOutcome(badCert, 65536).Failure);
    }

    [Fact]
    public async Task Series_runs_inside_one_engine_instance_and_stops_it()
    {
        // a closed loopback port: every attempt fails at once without the network
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        var engine = new FakeEngine();
        var ex = Executor(engine, EnginePlatform.Linux, IPAddress.Loopback, port);

        var outcomes = await ex.RunAsync(Candidate("--payload=tls_client_hello --lua-desync=multisplit:pos=2"), 5, o => o.Count >= 2, CancellationToken.None);

        Assert.Equal(2, outcomes.Count);
        Assert.All(outcomes, o => Assert.Equal(TrialFailure.NoConnect, o.Failure));
        Assert.Single(engine.Started);
        Assert.Equal(["e1"], engine.Stopped);
        Assert.False(await ex.TargetReachableAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Refused_strategy_fails_without_probes()
    {
        var engine = new FakeEngine { Refuse = "validator: bad" };
        var outcomes = await Executor(engine, EnginePlatform.Linux).RunAsync(Candidate("--payload=tls_client_hello --lua-desync=multisplit:pos=2"), 3, _ => false, CancellationToken.None);
        var o = Assert.Single(outcomes);
        Assert.Equal(TrialFailure.Other, o.Failure);
        Assert.Contains("validator", o.Detail, StringComparison.Ordinal);
        Assert.Empty(engine.Stopped);
    }

    [Fact]
    public async Task Engine_is_stopped_when_the_search_is_cancelled()
    {
        var engine = new FakeEngine();
        var ex = Executor(engine, EnginePlatform.Linux);
        using var cts = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ex.WithEngineAsync<int>(Candidate("--payload=tls_client_hello --lua-desync=multisplit:pos=2"), async ct =>
        {
            await cts.CancelAsync();
            ct.ThrowIfCancellationRequested();
            return 0;
        }, cts.Token));
        Assert.Equal(["e1"], engine.Stopped);
    }

    /// <summary>Strategy → outcome per attempt, like the stand's balancing DPI.</summary>
    private sealed class Sim(Func<string, int, bool> ok) : ITrialExecutor
    {
        private readonly Dictionary<string, int> _n = [];

        public Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
        {
            var list = new List<TrialOutcome>();
            for (int i = 0; i < attempts && !stopEarly(list); i++)
            {
                int n = _n.GetValueOrDefault(candidate.Key);
                _n[candidate.Key] = n + 1;
                list.Add(ok(candidate.Key, n) ? TrialOutcome.Success(70000) : TrialOutcome.Fail(TrialFailure.Reset, "TlsReset"));
            }
            return Task.FromResult<IReadOnlyList<TrialOutcome>>(list);
        }

        public Task<bool> TargetReachableAsync(CancellationToken ct) => Task.FromResult(true);
    }

    [Fact]
    public async Task Knowledge_base_keeps_trials_refinement_and_resumes_the_session()
    {
        const string midsld = "--payload=tls_client_hello --lua-desync=multisplit:pos=midsld";
        const string midsld1 = "--payload=tls_client_hello --lua-desync=multisplit:pos=midsld+1";
        using var kb = KnowledgeBase.OpenInMemory();
        long net = kb.Network(new NetworkInfo(64500, "Test ISP"));
        var target = new TrialTarget { Host = "flaky.test", Addresses = [Target] };
        long session = kb.StartSession(target.Host, "standard", net, "SNI_BLOCK");
        var log = new KnowledgeBaseSearchLog(kb, session, target, net, "SNI_BLOCK");
        var options = TuningSession.Prepare(kb, new SearchOptions { Generator = new GeneratorOptions { Mode = SearchMode.Standard }, StopAfterFound = 1 }, session, 64500);
        Assert.Empty(options.Priors);

        var sim = new Sim((s, n) => s == midsld1 || (s == midsld && n % 2 == 1));
        var r = await new StrategySearch(sim, options, log).RunAsync();
        TuningSession.Finish(kb, session, target.Host, r, net);

        Assert.Equal(midsld1, r.Best!.Candidate.Key);
        Assert.Equal("done", kb.Session(session)!.State);
        Assert.NotNull(kb.Session(session)!.Checkpoint);
        var steps = kb.TuningSteps(session);
        Assert.Contains(steps, s => s.Parent == midsld && s.Child == midsld1 && s.Accepted);
        var stored = kb.Results(target.Host, net);
        Assert.Equal(midsld1, stored[0].Args);
        Assert.Equal("working", stored[0].Status);
        Assert.NotNull(stored[0].Score);
        Assert.Contains(stored, x => x.Args == midsld && x.Status == "partial");

        // a resumed session does not run what it already tried; the next search on this provider starts from it
        var resumed = TuningSession.Prepare(kb, new SearchOptions(), session, 64500);
        Assert.True(resumed.AlreadyTried[midsld].Attempts >= 5);
        Assert.Equal(midsld1, resumed.Priors[0].Key);
        Assert.Equal("multisplit", resumed.Priors[0].Family);
    }
}

public sealed class CheckerHistoryTests
{
    [Fact]
    public void Checker_runs_round_trip_through_the_knowledge_base()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        var report = new ZapretAutoTuner.Probes.Diagnostics.CheckerReport
        {
            Started = DateTimeOffset.UtcNow.AddMinutes(-1),
            Duration = TimeSpan.FromSeconds(12),
            Rows =
            [
                new() { Resource = new() { Id = "youtube", Kind = "service" }, Primary = BlockLabel.SniBlock, Light = ZapretAutoTuner.Probes.Diagnostics.TrafficLight.Yellow },
                new() { Resource = new() { Id = "control", Kind = "control" }, Primary = BlockLabel.Open, Light = ZapretAutoTuner.Probes.Diagnostics.TrafficLight.Green },
            ],
        };
        CheckerHistory.Save(kb, report);

        var run = Assert.Single(CheckerHistory.Load(kb));
        Assert.Equal(TimeSpan.FromSeconds(12), run.Duration);
        Assert.False(run.NetworkProblem);
        Assert.Equal(new CheckerHistoryRow("youtube", "service", BlockLabel.SniBlock, ZapretAutoTuner.Probes.Diagnostics.TrafficLight.Yellow), run.Rows[0]);
        Assert.Equal(2, run.Rows.Count);
    }
}
