using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Tuning.Geneva;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>geneva's search and bypass from the UI's side: the probe answers geneva, progress and results are kept.</summary>
public sealed class GenevaControllerTests
{
    private static ProbeResult Loaded(string host) => new()
    {
        Host = host,
        Address = "192.0.2.1",
        ConnectOk = true,
        TlsOk = true,
        CertValid = true,
        HttpStatus = 200,
        Complete = true,
        BodyBytes = 200_000,
    };

    private static ProbeResult Reset(string host) => new() { Host = host, Address = "192.0.2.1", ConnectOk = true, Error = ProbeError.TlsReset };

    private sealed class Rig
    {
        public FakeGenevaAgent Agent { get; } = new();

        public MemoryGenevaStore Store { get; } = new();

        public List<int> LocalPorts { get; } = [];

        /// <summary>The probe's answer per call: the baseline first.</summary>
        public Func<int, string, ProbeResult> Probe { get; set; } = (n, host) => n == 0 ? Reset(host) : n == 2 ? Loaded(host) : Reset(host);

        public GenevaController Make()
        {
            int calls = 0;
            return new GenevaController(_ => Task.FromResult<IGenevaAgent>(Agent), Store, (host, port, tls, local, ct) =>
            {
                lock (LocalPorts)
                    LocalPorts.Add(local);
                return Task.FromResult(Probe(Interlocked.Increment(ref calls) - 1, host));
            });
        }
    }

    private static async Task Until(Func<bool> done)
    {
        for (int i = 0; i < 200 && !done(); i++)
            await Task.Delay(25);
        Assert.True(done());
    }

    [Fact]
    public async Task A_search_probes_every_strategy_from_its_ports_and_keeps_what_loaded()
    {
        var rig = new Rig();
        await using var g = rig.Make();
        await g.StartSearchAsync(new GenevaSearchSettings { Host = "blocked.example", Population = 10, Generations = 3 }, default);
        await Until(() => !g.SearchRunning);

        // baseline + two strategies, each answered with Geneva's fitness for the probe
        Assert.Equal([-360, -360, 400], rig.Agent.Answers.Select(a => a.Fitness));
        Assert.All(rig.LocalPorts, p => Assert.InRange(p, 30000, 30063));
        Assert.Equal(rig.LocalPorts.Count, rig.LocalPorts.Distinct().Count());
        var start = Assert.Single(rig.Agent.Started);
        Assert.Equal("evolve", start.Mode);
        Assert.Equal("blocked.example", start.Host);

        var s = g.Search;
        Assert.True(s.Blocked);
        Assert.Equal(0, s.Generation);
        Assert.Equal(400, s.BestFitness);
        Assert.Equal("finished", s.Ended?.En);
        Assert.Equal(2, s.Evaluated);
        Assert.Equal(1, s.Succeeded);

        // kept: a new controller (the next start of the program) sees them
        var again = GenevaState.Parse(rig.Store.Json);
        var found = Assert.Single(again.Found);
        Assert.Equal("[TCP:flags:PA]-fragment{tcp:8:True}-| \\/", found.Strategy);
        Assert.Equal("blocked.example", found.Host);
        var progress = again.ProgressOf("blocked.example", 443);
        Assert.NotNull(progress);
        Assert.True(progress.Finished);
        Assert.Equal("blocked.example", again.LastHost);
        Assert.Equal(10, again.Population);
    }

    [Fact]
    public async Task An_open_site_is_not_searched()
    {
        var rig = new Rig { Probe = (n, host) => Loaded(host) };
        await using var g = rig.Make();
        await g.StartSearchAsync(new GenevaSearchSettings { Host = "open.example" }, default);
        await Until(() => !g.SearchRunning);
        Assert.False(g.Search.Blocked);
        Assert.Contains("nothing to search", g.Search.Ended?.En, StringComparison.Ordinal);
        Assert.Single(rig.Agent.Answers);
        Assert.Empty(GenevaState.Parse(rig.Store.Json).Found);
    }

    [Fact]
    public async Task A_probe_that_throws_still_answers_geneva()
    {
        var rig = new Rig { Probe = (n, host) => n == 0 ? Reset(host) : throw new InvalidOperationException("broken probe") };
        await using var g = rig.Make();
        await g.StartSearchAsync(new GenevaSearchSettings { Host = "blocked.example", Population = 10, Generations = 3 }, default);
        await Until(() => !g.SearchRunning);
        Assert.Equal([-360, -400, -400], rig.Agent.Answers.Select(a => a.Fitness));
        Assert.Contains("broken probe", rig.Agent.Answers[1].Detail, StringComparison.Ordinal);
        Assert.Empty(GenevaState.Parse(rig.Store.Json).Found);
    }

    [Fact]
    public async Task A_stopped_search_can_be_continued()
    {
        var rig = new Rig();
        // the probe never answers until the search is stopped
        var gate = new TaskCompletionSource();
        await using var g = new GenevaController(_ => Task.FromResult<IGenevaAgent>(rig.Agent), rig.Store, async (host, port, tls, local, ct) =>
        {
            await gate.Task.WaitAsync(ct);
            return Reset(host);
        });
        await g.StartSearchAsync(new GenevaSearchSettings { Host = "blocked.example", Population = 10, Generations = 3 }, default);
        await g.StopSearchAsync();
        gate.SetResult();
        await Until(() => !g.SearchRunning);
        Assert.Equal("stopped", g.Search.Ended?.En);
        var p = GenevaState.Parse(rig.Store.Json).ProgressOf("blocked.example", 443);
        Assert.NotNull(p);
        Assert.False(p.Finished);

        // the population of the saved search, whatever the fields say now: geneva refuses a changed one
        await g.StartSearchAsync(new GenevaSearchSettings { Host = "blocked.example", Population = 50, Generations = 2, Resume = true }, default);
        Assert.True(rig.Agent.Started[^1].Resume);
        Assert.Equal(10, rig.Agent.Started[^1].Population);
        Assert.Equal(3, rig.Agent.Started[^1].Generations);
        await g.StopSearchAsync();
    }

    [Fact]
    public async Task Busy_local_ports_stop_the_search_instead_of_failing_strategies()
    {
        var rig = new Rig
        {
            Probe = (n, host) => n == 0 ? Reset(host) : new ProbeResult { Host = host, Address = "", Error = ProbeError.Other, ErrorDetail = ProbeDetail.LocalPortPrefix + "30001 AccessDenied" },
        };
        await using var g = rig.Make();
        await g.StartSearchAsync(new GenevaSearchSettings { Host = "blocked.example", Population = 10, Generations = 3 }, default);
        await Until(() => !g.SearchRunning);
        Assert.Single(rig.Agent.Answers); // the baseline only
        Assert.Contains("local ports", g.Search.Ended?.En, StringComparison.Ordinal);
        Assert.Equal(1 + GenevaController.MaxPortAttempts, rig.LocalPorts.Count);
    }

    [Fact]
    public async Task Busy_refuses_and_one_search_at_a_time()
    {
        var rig = new Rig();
        await using var g = rig.Make();
        g.Busy = () => "protection runs";
        var e = await Assert.ThrowsAsync<GenevaRefusedException>(() => g.StartSearchAsync(new GenevaSearchSettings { Host = "blocked.example" }, default));
        Assert.Equal("protection runs", e.Message);
        await Assert.ThrowsAsync<GenevaRefusedException>(() => g.StartRunAsync("\\/", "443", false, default));
        Assert.Empty(rig.Agent.Started);
        await Assert.ThrowsAsync<GenevaRefusedException>(() => g.StartSearchAsync(new GenevaSearchSettings { Host = "not a host" }, default));
    }

    [Fact]
    public async Task The_bypass_shows_live_counters_and_comes_back_after_a_restart()
    {
        var rig = new Rig();
        await using (var g = rig.Make())
        {
            await g.StartRunAsync("[TCP:flags:PA]-fragment{tcp:8:True}-| \\/", "443", autoStart: true, default);
            await Until(() => g.Run.Ready);
            Assert.Equal("nft", g.Run.Firewall);
            Assert.Equal(BypassEngine.Geneva, g.Engine);
            var id = rig.Agent.Started[0].Mode == "run" ? "g1" : throw new InvalidOperationException();
            rig.Agent.Push(id, new JsonObject { ["ev"] = "stats", ["uptime_ms"] = 2000, ["pkts_out"] = 100, ["pkts_in"] = 80, ["triggered"] = 5, ["out_trees"] = new JsonArray(new JsonObject { ["tree"] = "[TCP:flags:PA]-fragment{tcp:8:True}-|", ["fired"] = 5 }) });
            rig.Agent.Push(id, new JsonObject { ["ev"] = "stats", ["uptime_ms"] = 4000, ["pkts_out"] = 300, ["pkts_in"] = 180, ["triggered"] = 9 });
            await Until(() => g.Run.Stats?.PktsOut == 300);
            Assert.Equal(100, g.Run.RateOut, 1);
            Assert.Equal([5, 4], g.Run.TriggeredHistory);

            await g.PauseRunAsync(true, default);
            Assert.Equal(["pause"], rig.Agent.Commands);

            // the program closes: the Agent stops geneva; the choice to bring it back stays
        }
        await using (var g = rig.Make())
        {
            Assert.True(await g.RestoreAsync(default));
            Assert.Equal("run", rig.Agent.Started[^1].Mode);
            Assert.Equal("443", rig.Agent.Started[^1].Ports);
            await g.StopRunAsync(forget: true);
            await Until(() => !g.RunRunning);
            Assert.Equal("stopped", g.Run.Ended?.En);
        }
        await using (var g = rig.Make())
        {
            // turned off by the user: it does not come back
            Assert.False(await g.RestoreAsync(default));
        }
    }

    [Fact]
    public void A_damaged_state_starts_fresh_and_found_strategies_merge()
    {
        Assert.Equal(BypassEngine.Nfqws2, GenevaState.Parse("{not json").Engine);
        var s = new GenevaState()
            .WithFound([new GenevaFoundStrategy { Host = "a.example", Strategy = "x \\/", Fitness = 300, Runs = 1 }])
            .WithFound([new GenevaFoundStrategy { Host = "A.example", Strategy = "x \\/", Fitness = 390, Runs = 3 }]);
        var f = Assert.Single(s.Found);
        Assert.Equal(390, f.Fitness);
        Assert.Equal(3, f.Runs);
        var round = GenevaState.Parse((s with { Engine = BypassEngine.Geneva }).Serialize());
        Assert.Equal(BypassEngine.Geneva, round.Engine);
        Assert.Single(round.Found);
    }
}
