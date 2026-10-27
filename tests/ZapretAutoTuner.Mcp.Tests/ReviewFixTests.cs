using System.Text.Json.Nodes;
using ZapretAutoTuner.Tuning;
using ZapretAutoTuner.Tuning.Tests;

namespace ZapretAutoTuner.Mcp.Tests;

/// <summary>Regression tests of the code review (M1–M4, M6) on the MCP tools.</summary>
public sealed class ReviewFixTests
{
    private const string Variants = """{"variants":[{"label":"A","strategy":"--lua-desync=multidisorder:pos=1"},{"label":"B","strategy":"--lua-desync=multisplit:pos=1"}],"targets":["blocked.example"],"repeats":2}""";

    private static (Rig Rig, RouterGui Gui) Router(Action<RouterGui>? tweak = null)
    {
        var gui = new RouterGui
        {
            Probe = (args, _) => args.Contains("multisplit", StringComparison.Ordinal) ? (true, "ok", 3) : (false, "tls_rst", 0),
            Active = ("yt_quic", [("QUIC", "--filter-udp=443 --lua-desync=fake:blob=fake_default_quic", true)]),
        };
        tweak?.Invoke(gui);
        var rig = new Rig(Rig.All);
        rig.Host.Router = gui.Experiments();
        rig.Session.Router.Poll = TimeSpan.FromMilliseconds(1);
        return (rig, gui);
    }

    private static async Task<JsonObject> Settled(Rig rig, string tool, string args)
    {
        JsonObject? done = null;
        await Rig.Until(async () =>
        {
            done = (await rig.Call(tool, args)).Data;
            return (string?)done["status"] is not ("pending_confirmation" or "confirmed_running");
        });
        return done!;
    }

    /// <summary>M1: zapret-gui runs one experiment at a time; the model's router experiment waits for the wizard's.</summary>
    [Fact]
    public async Task RouterExperimentsRefuseWhileTheWizardTunesOnTheRouter()
    {
        var (rig, gui) = Router();
        using var _ = rig;
        rig.Host.RouterTuningRunning = true;
        var r = await rig.Call("router_experiment_start", Variants);
        Assert.True(r.IsError);
        Assert.Contains("wizard", (string?)r.Data["error"]);
        Assert.Empty(rig.Confirm.Asked);
        Assert.Empty(gui.Calls);
    }

    /// <summary>M2: a Stop while the start is on its way reverts the router and reports stopped.</summary>
    [Fact]
    public async Task AStopDuringTheRouterStartRevertsAndReportsStopped()
    {
        var (rig, gui) = Router(g => g.BeforeStart = ct => Task.Delay(Timeout.Infinite, ct));
        using var _ = rig;
        await rig.Call("router_experiment_start", Variants);
        rig.Confirm.Answer(true);
        await Rig.Until(() => Task.FromResult(gui.Starts == 1));
        await rig.Session.StopAllAsync();
        await Rig.Until(() => Task.FromResult(gui.Calls.Any(c => c.Tool == "strategy_experiment_rollback")));
        await Rig.Until(async () => (string?)(await rig.Call("router_experiment_status")).Data["state"] == "reverted");
        Assert.False(rig.Session.Router.Running);
        Assert.False(rig.Session.Busy);
    }

    /// <summary>M3: the candidate and the router's current profiles must fit zapret-gui's 8; nothing is cut silently.</summary>
    [Fact]
    public async Task TooManyRouterProfilesAreRefusedAndNamed()
    {
        var current = Enumerable.Range(1, 8).Select(i => ($"P{i}", $"--filter-tcp=44{i} --lua-desync=multisplit", true)).ToList();
        var (rig, gui) = Router(g => g.Active = ("big", current));
        using var _ = rig;
        await rig.Call("router_experiment_start", Variants);
        rig.Confirm.Answer(true);
        var done = await Settled(rig, "router_experiment_start", Variants);
        Assert.Contains("P8", (string?)done["error"]);
        Assert.Contains("8", (string?)done["error"]);
        Assert.Empty(gui.StartArgs);

        Assert.Equal(["P8"], RouterTuning.DroppedProfiles([("AutoTuner", "")], [.. current.Select(c => (c.Item1, c.Item2))]));
        Assert.Empty(RouterTuning.DroppedProfiles([("AutoTuner", "")], [.. current.Take(7).Select(c => (c.Item1, c.Item2))]));
    }

    /// <summary>M3: the trial executor refuses a candidate whose variant would not fit, without sending it.</summary>
    [Fact]
    public async Task TheRouterExecutorDoesNotSendAVariantThatWouldNotFit()
    {
        var gui = new RouterGui();
        var current = Enumerable.Range(1, 8).Select(i => ($"P{i}", "--filter-tcp=443 --lua-desync=multisplit")).ToList();
        var x = new RouterTrialExecutor(gui.Experiments(), new RouterTrialOptions { Targets = ["blocked.example"], CurrentProfiles = current, Poll = TimeSpan.FromMilliseconds(1) });
        var r = await x.RunAsync(new Core.Search.StrategyCandidate(Core.Model.Strategy.Parse("--lua-desync=multisplit:pos=1"), "t", 0, [], Core.Model.L4Kind.Tcp), 3, _ => false, CancellationToken.None);
        Assert.Contains("P8", Assert.Single(r).Detail, StringComparison.Ordinal);
        Assert.Empty(gui.StartArgs);
    }

    /// <summary>M4: a target open without bypass proves nothing: a variant that "opened" only such targets is not kept.</summary>
    [Fact]
    public async Task ARouterCommitIgnoresTargetsThatOpenWithoutBypass()
    {
        var (rig, gui) = Router(g => g.OpenWithoutBypass = ["blocked.example"]);
        using var _ = rig;
        await rig.Call("router_experiment_start", Variants);
        rig.Confirm.Answer(true);
        await Rig.Until(async () => (string?)(await rig.Call("router_experiment_status")).Data["state"] is "finished" or "failed");
        var commit = await rig.Call("router_experiment_commit", """{"label":"B"}""");
        Assert.True(commit.IsError);
        Assert.Contains("blocked without bypass", (string?)commit.Data["error"]);
        Assert.Single(rig.Confirm.Asked);
        Assert.DoesNotContain(gui.Calls, c => c.Tool == "strategy_experiment_commit");
    }

    /// <summary>Review 2: like the local Keepable, a variant that breaks a target open without bypass is not committed.</summary>
    [Fact]
    public async Task ARouterCommitRefusesAVariantThatBreaksAnOpenTarget()
    {
        var (rig, gui) = Router(g =>
        {
            g.OpenWithoutBypass = ["open.example"];
            g.Breaks = (args, t) => t == "open.example" && args.Contains("multisplit", StringComparison.Ordinal);
        });
        using var _ = rig;
        var two = Variants.Replace("[\"blocked.example\"]", "[\"blocked.example\",\"open.example\"]", StringComparison.Ordinal);
        await rig.Call("router_experiment_start", two);
        rig.Confirm.Answer(true);
        await Rig.Until(async () => (string?)(await rig.Call("router_experiment_status")).Data["state"] is "finished" or "failed");
        var commit = await rig.Call("router_experiment_commit", """{"label":"B"}""");
        Assert.True(commit.IsError);
        Assert.Contains("open.example", (string?)commit.Data["error"]);
        Assert.Single(rig.Confirm.Asked);
        Assert.DoesNotContain(gui.Calls, c => c.Tool == "strategy_experiment_commit");
    }

    /// <summary>
    /// Review 2: while the Agent is starting the model's trial and search already count as busy for the wizard, and if
    /// the wizard started meanwhile they give way instead of running next to it.
    /// </summary>
    [Fact]
    public async Task TrialAndSearchAreBusyWhileTheAgentStartsAndYieldToTheWizard()
    {
        using var rig = new Rig(Rig.All, new BudgetOptions { PerMinute = 10_000 });
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        var gate = new TaskCompletionSource();
        rig.Host.AgentStarting = () => gate.Task;

        var trial = rig.Call("trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit:pos=1"}""");
        await Rig.Until(() => Task.FromResult(rig.Session.Busy));
        rig.Host.LocalTuningRunning = true;
        gate.SetResult();
        var t = await trial;
        Assert.True(t.IsError);
        Assert.Contains("wizard", (string?)t.Data["error"]);
        Assert.False(rig.Session.Busy);

        rig.Host.LocalTuningRunning = false;
        gate = new TaskCompletionSource();
        var search = rig.Call("search_start", """{"target":"blocked.example","mode":"quick"}""");
        await Rig.Until(() => Task.FromResult(rig.Session.Search.Running));
        var second = await rig.Call("search_start", """{"target":"blocked.example","mode":"quick"}""");
        Assert.True(second.IsError);
        rig.Host.LocalTuningRunning = true;
        gate.SetResult();
        var s = await search;
        Assert.True(s.IsError);
        Assert.Contains("wizard", (string?)s.Data["error"]);
        Assert.False(rig.Session.Busy);
        Assert.Empty(rig.Host.Engine.Started);
    }

    /// <summary>M4: an experiment without a baseline is refused (AGENTS.md rule 5).</summary>
    [Fact]
    public async Task AnExperimentWithoutBaselineIsRefused()
    {
        using var rig = new Rig(Rig.All);
        var r = await rig.Call("strategy_experiment_start", Variants.Replace("\"repeats\":2", "\"repeats\":2,\"baseline\":false", StringComparison.Ordinal));
        Assert.True(r.IsError);
        Assert.Contains("baseline", (string?)r.Data["error"]);
        Assert.Empty(rig.Confirm.Asked);
    }

    /// <summary>M4: only a variant that fixed a blocked target and broke none can be committed.</summary>
    [Fact]
    public async Task OnlyAVariantThatFixedSomethingCanBeCommitted()
    {
        using var rig = new Rig(Rig.All, new BudgetOptions { PerMinute = 10_000 });
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        await rig.Call("strategy_experiment_start", Variants);
        rig.Confirm.Answer(true);
        await Rig.Until(async () => (string?)(await rig.Call("strategy_experiment_status")).Data["state"] is "finished" or "failed");
        var commitA = await rig.Call("strategy_experiment_commit", """{"label":"A"}""");
        Assert.True(commitA.IsError);
        Assert.Contains("baseline", (string?)commitA.Data["error"]);
        Assert.Single(rig.Confirm.Asked);
        Assert.Empty(rig.Host.Committed);
    }

    /// <summary>M4: an L1 handshake is not success; L1 trials stay out of the knowledge base.</summary>
    [Fact]
    public async Task L1TrialsDoNotFeedTheKnowledgeBase()
    {
        using var rig = new Rig(Rig.All, new BudgetOptions { PerMinute = 10_000 });
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        var r = await rig.Call("trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit:pos=1","level":"L1"}""");
        Assert.False(r.IsError, r.Text);
        Assert.Empty(rig.Host.Kb.LearningHistory(DateTimeOffset.UtcNow.AddDays(-1)));
        var l2 = await rig.Call("trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit:pos=1"}""");
        Assert.False(l2.IsError, l2.Text);
        Assert.NotEmpty(rig.Host.Kb.LearningHistory(DateTimeOffset.UtcNow.AddDays(-1)));
    }

    /// <summary>M6: the model's trials, search and experiments wait for the wizard's local tuning and the protection.</summary>
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task LocalWorkIsRefusedWhileTheWizardOrTheProtectionRuns(bool wizard, bool protection)
    {
        using var rig = new Rig(Rig.All, new BudgetOptions { PerMinute = 10_000 });
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        rig.Host.LocalTuningRunning = wizard;
        rig.Host.ProtectionActive = protection;
        foreach (var (tool, args) in new[]
        {
            ("trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit:pos=1"}"""),
            ("search_start", """{"target":"blocked.example","mode":"quick"}"""),
            ("strategy_experiment_start", Variants),
        })
        {
            var r = await rig.Call(tool, args);
            Assert.True(r.IsError, tool);
            Assert.Contains("busy", (string?)r.Data["error"]);
        }
        Assert.Empty(rig.Host.Engine.Started);
        Assert.Empty(rig.Confirm.Asked);
    }
}
