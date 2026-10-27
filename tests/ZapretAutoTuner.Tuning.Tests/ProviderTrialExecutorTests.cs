using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Validation;
using ZapretAutoTuner.Probes.Http;
using ZapretAutoTuner.Probes.Providers;
using static ZapretAutoTuner.Tuning.Tests.ProgramFixtures;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>Trials for a provider as a whole (PLAN 6.4): every sampled range, each with its own SNI.</summary>
public sealed class ProviderTrialExecutorTests
{
    private const string Split = "--payload=tls_client_hello --lua-desync=multisplit:pos=1";

    private static readonly ProviderTarget[] Targets =
    [
        new() { Provider = "hetzner", Host = "fsn1-speed.hetzner.com", Address = IPAddress.Parse("88.198.248.254"), Path = "/100MB.bin", MinBytes = 1 << 20, Source = "endpoint" },
        new() { Provider = "hetzner", Host = "www.a.test", Address = IPAddress.Parse("5.9.10.20"), MinBytes = 1, PadBytes = 32768, Source = "5.9.0.0/16" },
        new() { Provider = "hetzner", Host = "b.test", Address = IPAddress.Parse("2a01:4f8::77"), MinBytes = 1, PadBytes = 32768, Source = "2a01:4f8::/32" },
        new() { Provider = "hetzner", Host = "c.test", Address = IPAddress.Parse("5.9.10.20"), MinBytes = 1, Source = "5.9.0.0/16" },
    ];

    private static AgentTrialOptions Options(EnginePlatform platform = EnginePlatform.Linux) => new()
    {
        LuaDir = "/opt/zapret2/lua",
        Platform = platform,
        Warmup = TimeSpan.Zero,
        Pause = TimeSpan.Zero,
        TweakHttp = o => o with { ConnectTimeout = TimeSpan.FromSeconds(1) },
    };

    private sealed class FakeHttp(Func<HttpProbeOptions, bool> ok)
    {
        public List<HttpProbeOptions> Calls { get; } = [];

        public Task<ProbeResult> Run(HttpProbeOptions o, CancellationToken ct)
        {
            Calls.Add(o);
            var r = new ProbeResult { Host = o.Host, Address = o.Address.ToString(), ConnectOk = true };
            return Task.FromResult(ok(o)
                ? r with { TlsOk = true, CertValid = true, HttpStatus = 200, BodyBytes = o.MinBytes + 10, Complete = true }
                : r with { Error = ProbeError.TlsReset });
        }
    }

    [Fact]
    public async Task Every_target_is_tried_round_robin_with_its_own_sni()
    {
        var engine = new RecordingEngine();
        var http = new FakeHttp(_ => true);
        var ex = new ProviderTrialExecutor(engine, Targets, Options(), http.Run);

        var outcomes = await ex.RunAsync(Candidate(Split, L4Kind.Tcp), 1, _ => false, CancellationToken.None);

        // at least one attempt per sampled address: N/N means every range
        Assert.Equal(4, outcomes.Count);
        Assert.All(outcomes, o => Assert.True(o.Ok));
        Assert.Equal(Targets.Select(t => t.Host), http.Calls.Select(c => c.Host));
        Assert.Equal(Targets.Select(t => t.Address), http.Calls.Select(c => c.Address));
        Assert.Equal("/100MB.bin", http.Calls[0].Path);
        Assert.Equal(1 << 20, http.Calls[0].MinBytes);
        Assert.Equal(32768, http.Calls[1].PadBytes);
        Assert.All(http.Calls, c => Assert.Equal(TimeSpan.FromSeconds(1), c.ConnectTimeout));

        http.Calls.Clear();
        await ex.RunAsync(Candidate(Split, L4Kind.Tcp), 6, _ => false, CancellationToken.None);
        Assert.Equal(["fsn1-speed.hetzner.com", "www.a.test", "b.test", "c.test", "fsn1-speed.hetzner.com", "www.a.test"], http.Calls.Select(c => c.Host));
        Assert.Equal(["e1", "e2"], engine.Stopped);
    }

    [Fact]
    public async Task One_engine_limited_to_all_the_addresses()
    {
        var engine = new RecordingEngine();
        await new ProviderTrialExecutor(engine, Targets, Options(), new FakeHttp(_ => true).Run).RunAsync(Candidate(Split, L4Kind.Tcp), 1, _ => false, CancellationToken.None);
        var (argv, queue, tag) = Assert.Single(engine.Started);
        Assert.Equal("trial:hetzner", tag);
        Assert.Contains("--filter-tcp=443", argv);
        Assert.NotNull(queue);
        Assert.Equal("443", queue.TcpPorts);
        Assert.Equal(["88.198.248.254", "5.9.10.20", "2a01:4f8::77"], queue.Targets);

        var win = new RecordingEngine();
        await new ProviderTrialExecutor(win, Targets, Options(EnginePlatform.Windows), new FakeHttp(_ => true).Run).RunAsync(Candidate(Split, L4Kind.Tcp), 1, _ => false, CancellationToken.None);
        var filter = Assert.Single(win.Started[0].Argv, a => a.StartsWith("--wf-raw-filter=", StringComparison.Ordinal));
        Assert.Contains("88.198.248.254", filter, StringComparison.Ordinal);
        Assert.Contains("5.9.10.20", filter, StringComparison.Ordinal);
        Assert.Contains("2a01:4f8::77", filter, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_strategy_working_on_one_range_does_not_get_full_marks()
    {
        var http = new FakeHttp(o => o.Address.Equals(IPAddress.Parse("5.9.10.20")));
        var outcomes = await new ProviderTrialExecutor(new RecordingEngine(), Targets, Options(), http.Run).RunAsync(Candidate(Split, L4Kind.Tcp), 4, _ => false, CancellationToken.None);
        Assert.Equal([false, true, false, true], outcomes.Select(o => o.Ok));
        Assert.Equal(TrialFailure.Reset, outcomes[0].Failure);
    }

    [Fact]
    public async Task Stop_early_cuts_the_series()
    {
        var http = new FakeHttp(_ => false);
        var outcomes = await new ProviderTrialExecutor(new RecordingEngine(), Targets, Options(), http.Run).RunAsync(Candidate(Split, L4Kind.Tcp), 4, o => o.Count >= 2, CancellationToken.None);
        Assert.Equal(2, outcomes.Count);
        Assert.Equal(2, http.Calls.Count);
    }

    [Fact]
    public async Task Refusal_and_no_targets()
    {
        var engine = new RecordingEngine { Refuse = "policy: forbidden" };
        var http = new FakeHttp(_ => true);
        var o = Assert.Single(await new ProviderTrialExecutor(engine, Targets, Options(), http.Run).RunAsync(Candidate(Split, L4Kind.Tcp), 3, _ => false, CancellationToken.None));
        Assert.Equal(TrialFailure.Other, o.Failure);
        Assert.Empty(http.Calls);
        Assert.Throws<ArgumentException>(() => new ProviderTrialExecutor(new RecordingEngine(), [], Options()));
    }
}
