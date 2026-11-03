using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Protocol;
using ZapretAutoTuner.Tuning.Geneva;
using static ZapretAutoTuner.Tuning.Tests.ProgramFixtures;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>geneva's "Авто" mode end to end with fakes: a blocked resolver is found, confirmed, bypassed, saved.</summary>
public sealed class GenevaAutoTests
{
    private const string Me = "192.168.1.2";

    /// <summary>The probe: blocked until the strategy that "works" is applied.</summary>
    private sealed class FakeProbes(FakeGenevaAgent agent, string works) : IAutoProbes
    {
        public List<(string Key, string? Applied)> Checks { get; } = [];

        public Task<AutoConfirm> CheckAsync(AutoService s, CancellationToken ct)
        {
            GenevaAutoApplyRequest? last;
            lock (agent.AutoApplied)
                last = agent.AutoApplied.LastOrDefault();
            var on = last?.Groups.FirstOrDefault(g => g.Targets.Any(t => t.Addresses.Contains(s.Address?.ToString() ?? "-")))?.Strategy;
            lock (Checks)
                Checks.Add((s.Key, on));
            return Task.FromResult(on == works ? AutoConfirm.NotBlocked : AutoConfirm.Blocked);
        }

        public GenevaJudge? Judge(AutoService s) => null;
    }

    private static async Task Until(Func<bool> done, int seconds = 20)
    {
        for (int i = 0; i < seconds * 40 && !done(); i++)
            await Task.Delay(25);
        Assert.True(done());
    }

    private static (GenevaController Controller, GenevaAuto Auto, FakeGenevaAgent Agent, FakeProbes Probes, MemoryGenevaStore Store) Make(
        Action<GenevaController, FakeGenevaAgent>? before = null)
    {
        // a resolver that never answers: every slice holds the same unanswered query
        var monitor = new FakeMonitor(Capture(
            Udp(Me, 50003, "8.8.8.8", 53, DnsQuery("example.com")),
            Udp(Me, 50003, "8.8.8.8", 53, DnsQuery("example.com"))), new Dictionary<int, ObservedSocket[]>());
        var agent = new FakeGenevaAgent();
        var store = new MemoryGenevaStore();
        var controller = new GenevaController(_ => Task.FromResult<IGenevaAgent>(agent), store, (h, p, t, l, ct) => Task.FromResult(new ProbeResult { Host = h, Address = "" }));
        before?.Invoke(controller, agent);
        var probes = new FakeProbes(agent, AutoCandidates.Dns[1]);
        var auto = new GenevaAuto(controller, _ => Task.FromResult<IGenevaAgent>(agent), monitor, probes,
            () => new DateTime(2026, 1, 1, 0, 0, 30, DateTimeKind.Utc))
        {
            Slice = TimeSpan.FromMilliseconds(30),
        };
        return (controller, auto, agent, probes, store);
    }

    [Fact]
    public async Task A_blocked_resolver_is_confirmed_bypassed_with_its_own_strategy_and_saved()
    {
        var (controller, auto, agent, probes, store) = Make();
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);
        Assert.True(auto.Running);
        Assert.True(controller.State.Auto.Enabled);

        await Until(() => auto.View.Services.Any(s => s.Key == "dns:8.8.8.8" && s.Status == AutoStatus.Applied));
        var s = auto.View.Services.Single(x => x.Key == "dns:8.8.8.8");
        Assert.Equal(AutoCandidates.Dns[1], s.Strategy);

        // the baseline came first, without a bypass (AGENTS.md rule 5)
        Assert.Equal(("dns:8.8.8.8", (string?)null), probes.Checks[0]);
        // the strategy is applied to the resolver alone
        GenevaAutoApplyRequest last;
        lock (agent.AutoApplied)
            last = agent.AutoApplied[^1];
        var g = Assert.Single(last.Groups);
        Assert.Equal(AutoCandidates.Dns[1], g.Strategy);
        var t = Assert.Single(g.Targets);
        Assert.Equal(["8.8.8.8"], t.Addresses);
        Assert.Equal("53", t.UdpPorts);

        Assert.Contains("dns:8.8.8.8", store.Json, StringComparison.Ordinal);
        var saved = GenevaState.Parse(store.Json);
        Assert.True(saved.Auto.Enabled);
        Assert.Equal(AutoStatus.Applied, saved.Auto.Services.Single(x => x.Key == "dns:8.8.8.8").Status);
    }

    [Fact]
    public async Task A_trial_whose_group_did_not_start_is_not_taken_for_a_working_strategy()
    {
        // a site's group runs; the group of the strategy that would "work" for the resolver never starts
        var (controller, auto, agent, probes, _) = Make((c, a) =>
        {
            a.AutoRefused.Add(AutoCandidates.Dns[1]);
            c.SaveAuto(new GenevaAutoState
            {
                Services =
                [
                    new AutoService
                    {
                        Key = "web:a.com", Kind = AutoKind.Web, Transport = Core.Model.L4Kind.Tcp, Name = "a.com", App = "tls",
                        Addresses = [new AutoAddress("203.0.113.5", new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc))],
                        Ports = [443], Status = AutoStatus.Applied, Strategy = AutoCandidates.Tcp[0],
                    },
                ],
            });
        });
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);

        // the quick check went past the refused strategy without a probe and never applied it
        await Until(() => { lock (probes.Checks) return probes.Checks.Any(c => c.Applied == AutoCandidates.Udp[0]); });
        lock (probes.Checks)
            Assert.DoesNotContain(probes.Checks, c => c.Applied == AutoCandidates.Dns[1]);
        Assert.NotEqual(AutoCandidates.Dns[1], auto.View.Services.Single(x => x.Key == "dns:8.8.8.8").Strategy);
    }

    [Fact]
    public async Task Turning_it_off_stops_every_group_and_the_single_bypass_waits_while_it_runs()
    {
        var (controller, auto, agent, _, store) = Make();
        await using var c = controller;
        await using var a = auto;
        await auto.EnableAsync(default);
        await Assert.ThrowsAsync<GenevaRefusedException>(() => controller.StartRunAsync(AutoCandidates.Tcp[0], "443", false, default));

        await auto.DisableAsync();
        Assert.False(auto.Running);
        Assert.False(controller.State.Auto.Enabled);
        lock (agent.AutoApplied)
            Assert.Empty(agent.AutoApplied[^1].Groups);
        Assert.False(GenevaState.Parse(store.Json).Auto.Enabled);
    }

    [Fact]
    public async Task It_does_not_start_while_something_else_bypasses()
    {
        var (controller, auto, _, _, _) = Make();
        await using var c = controller;
        await using var a = auto;
        auto.Busy = () => "работает защита";
        await Assert.ThrowsAsync<GenevaRefusedException>(() => auto.EnableAsync(default));
        Assert.False(auto.Running);
        Assert.False(await auto.RestoreAsync(default));
    }
}
