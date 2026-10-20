using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Validation;
using ZapretAutoTuner.Probes.Raw;
using static ZapretAutoTuner.Tuning.Tests.ProgramFixtures;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>Trials for program endpoints without a page (PLAN 6.3): engine on one address and port, replay probe.</summary>
public sealed class EndpointTrialExecutorTests
{
    private const string UdpFake = "--payload=stun --lua-desync=fake:blob=0x00000000000000000000000000000000:repeats=6";
    private const string MtSplit = "--payload=mtproto_initial --lua-desync=multisplit:pos=1";

    private static AgentTrialOptions Options(EnginePlatform platform = EnginePlatform.Linux) => new()
    {
        LuaDir = "/opt/zapret2/lua",
        Platform = platform,
        QueueNum = 310,
        Warmup = TimeSpan.Zero,
        Pause = TimeSpan.Zero,
        ReachTimeout = TimeSpan.FromMilliseconds(500),
    };

    private sealed class ScriptedProbe(params ReplayProbeResult[] results)
    {
        public List<ReplayProbeOptions> Calls { get; } = [];

        public Task<ReplayProbeResult> Run(ReplayProbeOptions o, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Calls.Add(o);
            return Task.FromResult(results[Math.Min(Calls.Count - 1, results.Length - 1)]);
        }
    }

    private static ReplayProbeResult Ok() => new(true, 4, 1, 100, null, TimeSpan.FromMilliseconds(20));

    private static ReplayProbeResult Fail(string? error) => new(false, 4, 0, 0, error, TimeSpan.FromMilliseconds(20));

    [Fact]
    public async Task Series_replays_inside_one_engine_limited_to_the_endpoint()
    {
        var engine = new RecordingEngine();
        var probe = new ScriptedProbe(Fail("нет ответа"), Ok(), Ok());
        var ep = Endpoint("198.51.100.7", 3478, L4Kind.Udp, AppProtocol.Stun, host: "stun.example.com");
        var ex = new EndpointTrialExecutor(engine, ep, Options(), probe.Run);

        var outcomes = await ex.RunAsync(Candidate(UdpFake, L4Kind.Udp), 5, o => o.Count(x => x.Ok) >= 2, CancellationToken.None);

        Assert.Equal([false, true, true], outcomes.Select(o => o.Ok));
        Assert.Equal(TrialFailure.Timeout, outcomes[0].Failure);
        Assert.Equal(100, outcomes[1].BytesIn);
        Assert.Equal(3, probe.Calls.Count);
        var o = probe.Calls[0];
        Assert.Equal(IPAddress.Parse("198.51.100.7"), o.Address);
        Assert.Equal(3478, o.Port);
        Assert.True(o.Udp);
        Assert.Equal(AppProtocol.Stun, o.App);
        Assert.Equal(4, o.Rounds); // the UDP detector wants four datagrams out
        Assert.Same(ep.InitialPayloads, o.Payloads);

        var (argv, queue, tag) = Assert.Single(engine.Started);
        Assert.Equal(["e1"], engine.Stopped);
        Assert.Equal("trial:stun.example.com", tag);
        Assert.Contains("--filter-udp=3478", argv);
        Assert.DoesNotContain(argv, a => a.StartsWith("--filter-tcp", StringComparison.Ordinal));
        Assert.DoesNotContain(argv, a => a.StartsWith("--qnum", StringComparison.Ordinal));
        Assert.NotNull(queue);
        Assert.Equal("3478", queue.UdpPorts);
        Assert.Equal(["198.51.100.7"], queue.Targets);
    }

    [Fact]
    public void Tcp_endpoint_target_and_windows_filter()
    {
        var ep = Endpoint("149.154.167.51", 443, L4Kind.Tcp, AppProtocol.Mtproto);
        var t = EndpointTrialExecutor.Target(ep);
        Assert.Equal("149.154.167.51", t.Host); // no name: the address
        Assert.False(t.Tls);
        Assert.Equal(443, t.Port);
        Assert.Equal([IPAddress.Parse("149.154.167.51")], t.Addresses);

        var ex = new EndpointTrialExecutor(new RecordingEngine(), ep, Options(), new ScriptedProbe(Ok()).Run);
        Assert.False(ex.ProbeOptions().Udp);
        Assert.Equal(AppProtocol.Mtproto, ex.ProbeOptions().App);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("149.154.167.51"), 443), EndpointTrialExecutor.Key(ep));
    }

    [Fact]
    public async Task Windows_engine_is_filtered_by_the_endpoint_address()
    {
        var engine = new RecordingEngine();
        var ep = Endpoint("149.154.167.51", 443, L4Kind.Tcp, AppProtocol.Mtproto);
        await new EndpointTrialExecutor(engine, ep, Options(EnginePlatform.Windows), new ScriptedProbe(Ok()).Run)
            .RunAsync(Candidate(MtSplit, L4Kind.Tcp), 1, _ => false, CancellationToken.None);
        var (argv, queue, _) = Assert.Single(engine.Started);
        Assert.Null(queue);
        Assert.Contains("--filter-tcp=443", argv);
        Assert.Contains(argv, a => a.StartsWith("--wf-raw-filter=", StringComparison.Ordinal) && a.Contains("149.154.167.51", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(null, TrialFailure.Timeout)]
    [InlineData("нет ответа", TrialFailure.Timeout)]
    [InlineData("сброс (RST)", TrialFailure.Reset)]
    [InlineData("ConnectionReset", TrialFailure.Reset)]
    [InlineData("нет соединения", TrialFailure.NoConnect)]
    [InlineData("ConnectionRefused", TrialFailure.NoConnect)]
    [InlineData("TimedOut", TrialFailure.NoConnect)]
    [InlineData("HostUnreachable", TrialFailure.NoConnect)]
    [InlineData("NetworkUnreachable", TrialFailure.NoConnect)]
    [InlineData("сервер закрыл соединение", TrialFailure.Other)]
    [InlineData("нечего отправить: в записи нет первых пакетов", TrialFailure.Other)]
    public void Probe_errors_map_to_trial_failures(string? error, TrialFailure expected)
    {
        var o = EndpointTrialExecutor.ToOutcome(Fail(error));
        Assert.False(o.Ok);
        Assert.Equal(expected, o.Failure);
        Assert.Equal(error, o.Detail);
    }

    [Fact]
    public void Answer_is_success()
    {
        var o = EndpointTrialExecutor.ToOutcome(Ok());
        Assert.True(o.Ok);
        Assert.Equal(TrialFailure.None, o.Failure);
        Assert.Equal(TimeSpan.FromMilliseconds(20), o.Duration);
    }

    [Fact]
    public async Task Refused_strategy_fails_without_probes()
    {
        var engine = new RecordingEngine { Refuse = "validator: bad blob" };
        var probe = new ScriptedProbe(Ok());
        var outcomes = await new EndpointTrialExecutor(engine, Endpoint("198.51.100.7", 3478, L4Kind.Udp, AppProtocol.Stun), Options(), probe.Run)
            .RunAsync(Candidate(UdpFake, L4Kind.Udp), 3, _ => false, CancellationToken.None);
        var o = Assert.Single(outcomes);
        Assert.Equal(TrialFailure.Other, o.Failure);
        Assert.Empty(probe.Calls);
        Assert.Empty(engine.Stopped);
    }

    [Fact]
    public async Task Engine_is_stopped_when_the_search_is_cancelled()
    {
        var engine = new RecordingEngine();
        using var cts = new CancellationTokenSource();
        var ex = new EndpointTrialExecutor(engine, Endpoint("198.51.100.7", 3478, L4Kind.Udp, AppProtocol.Stun), Options(), async (o, ct) =>
        {
            await cts.CancelAsync();
            ct.ThrowIfCancellationRequested();
            return Ok();
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ex.RunAsync(Candidate(UdpFake, L4Kind.Udp), 3, _ => false, cts.Token));
        Assert.Equal(["e1"], engine.Stopped);
    }

    [Fact]
    public async Task Udp_is_always_reachable_tcp_needs_a_connect()
    {
        // nothing listens there: UDP has no handshake to check
        var udp = new EndpointTrialExecutor(new RecordingEngine(), Endpoint("192.0.2.1", 9, L4Kind.Udp, AppProtocol.Unknown), Options());
        Assert.True(await udp.TargetReachableAsync(CancellationToken.None));

        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        var tcp = new EndpointTrialExecutor(new RecordingEngine(), Endpoint("127.0.0.1", port, L4Kind.Tcp, AppProtocol.Mtproto), Options());
        Assert.True(await tcp.TargetReachableAsync(CancellationToken.None));
        l.Stop();
        Assert.False(await tcp.TargetReachableAsync(CancellationToken.None));
    }

    [Theory]
    [InlineData(AppProtocol.Stun, L4Kind.Udp, TargetProtocol.Stun)]
    [InlineData(AppProtocol.Unknown, L4Kind.Udp, TargetProtocol.Udp)]
    [InlineData(AppProtocol.Mtproto, L4Kind.Tcp, TargetProtocol.Mtproto)]
    [InlineData(AppProtocol.Unknown, L4Kind.Tcp, TargetProtocol.Tls)]
    public void Generator_options_follow_the_endpoint_protocol(AppProtocol app, L4Kind l4, TargetProtocol expected)
    {
        var g = EndpointTrialExecutor.Generator(Endpoint("198.51.100.7", 1000, l4, app), new GeneratorOptions { Mode = SearchMode.Quick });
        Assert.Equal(expected, g.Protocol);
        Assert.Equal(SearchMode.Quick, g.Mode);
    }
}
