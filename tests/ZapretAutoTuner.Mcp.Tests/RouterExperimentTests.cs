using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Tuning;
using ZapretAutoTuner.Tuning.Tests;

namespace ZapretAutoTuner.Mcp.Tests;

/// <summary>router_experiment_* over zapret-gui's experiments in memory (PLAN 4a.4, 7.6).</summary>
public sealed class RouterExperimentTests
{
    private const string TwoVariants = """{"variants":[{"label":"A","strategy":"--lua-desync=multidisorder:pos=1"},{"label":"B","strategy":"--lua-desync=multisplit:pos=1"}],"targets":["blocked.example"],"repeats":2}""";

    private static (Rig Rig, RouterGui Gui) Setup(McpPermissions? permissions = null, Action<RouterGui>? tweak = null)
    {
        var gui = new RouterGui
        {
            Probe = (args, _) => args.Contains("multisplit", StringComparison.Ordinal) ? (true, "ok", 3) : (false, "tls_rst", 0),
            Active = ("yt_quic", [("QUIC", "--filter-udp=443 --lua-desync=fake:blob=fake_default_quic", true)]),
        };
        tweak?.Invoke(gui);
        var rig = new Rig(permissions ?? Rig.All);
        rig.Host.Router = gui.Experiments();
        rig.Session.Router.Poll = TimeSpan.FromMilliseconds(1);
        return (rig, gui);
    }

    private static async Task<string?> State(Rig rig) => (string?)(await rig.Call("router_experiment_status")).Data["state"];

    [Fact]
    public async Task TheRouterPermissionIsOffByDefaultAndNeedsControlAndProbes()
    {
        var (rig, gui) = Setup(new McpPermissions());
        using var _ = rig;
        Assert.DoesNotContain(rig.Tools.ListTools(), t => t.Scope == McpScope.Router);
        var denied = await rig.Call("router_experiment_start", TwoVariants);
        Assert.True(denied.IsError);
        Assert.Equal("router", (string?)denied.Data["permission"]);

        rig.Permissions = new McpPermissions(Router: true);
        var half = await rig.Call("router_experiment_status");
        Assert.True(half.IsError);
        Assert.Equal(["control", "probes"], half.Data["missing"]!.AsArray().Select(x => (string?)x).Order());

        rig.Permissions = new McpPermissions(Probes: true, Control: true, Router: true);
        Assert.Equal(5, rig.Tools.ListTools().Count(t => t.Scope == McpScope.Router));
        Assert.DoesNotContain(rig.Tools.ListTools(), t => t.Scope == McpScope.Experiments);
        Assert.Empty(gui.Calls);
    }

    [Fact]
    public async Task WithoutZapretGuiSetUpNothingIsAsked()
    {
        using var rig = new Rig(Rig.All);
        var r = await rig.Call("router_experiment_start", TwoVariants);
        Assert.True(r.IsError);
        Assert.Contains("not set up", (string?)r.Data["error"]);
        Assert.Empty(rig.Confirm.Asked);
        Assert.False((bool)(await rig.Call("router_experiment_status")).Data["configured"]!);
    }

    [Fact]
    public async Task StrategiesPassThePolicyAndTheValidatorBeforeTheUserIsAsked()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        var lua = await rig.Call("router_experiment_start", """{"variants":[{"label":"A","strategy":"--lua-desync=luaexec:code=os.exit()"}]}""");
        Assert.True(lua.IsError);
        Assert.Equal("A", (string?)lua.Data["variant"]);
        var unknown = await rig.Call("router_experiment_start", """{"variants":[{"label":"A","strategy":"--lua-desync=my_func"}]}""");
        Assert.True(unknown.IsError);
        var stranger = await rig.Call("router_experiment_start", """{"variants":[{"label":"A","strategy":"--lua-desync=multisplit"}],"targets":["evil.example"]}""");
        Assert.True(stranger.IsError);
        Assert.Empty(rig.Confirm.Asked);
        Assert.Empty(gui.Calls);
    }

    [Fact]
    public async Task AnExperimentWaitsForTheYesMeasuresOnTheRouterAndFeedsTheKnowledgeBase()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        var r = await rig.Call("router_experiment_start", TwoVariants);
        Assert.True((string?)r.Data["status"] == "pending_confirmation", r.Text);
        Assert.Equal("awaiting_confirmation", await State(rig));
        Assert.Empty(gui.StartArgs);
        Assert.Contains("multisplit:pos=1", rig.Confirm.Asked[0].TextEn);
        Assert.Contains("reverts by itself", rig.Confirm.Asked[0].TextEn);

        rig.Confirm.Answer(true);
        await Rig.Until(async () => await State(rig) is "finished" or "failed");
        var start = Assert.Single(gui.StartArgs);
        Assert.True((bool)start["baseline"]!);
        var profiles = (JsonArray)start["variants"]![1]!["profiles"]!;
        Assert.Equal(2, profiles.Count);
        Assert.Contains("--hostlist-domains=blocked.example", (string)profiles[0]!["args"]!);
        Assert.Contains("--lua-desync=multisplit:pos=1", (string)profiles[0]!["args"]!);
        Assert.Equal("QUIC", (string)profiles[1]!["name"]!);

        var result = await rig.Call("router_experiment_result");
        Assert.False(result.IsError, result.Text);
        Assert.Equal("B", (string?)result.Data["best"]);
        var b = result.Data["variants"]!.AsArray().First(v => (string?)v!["label"] == "B")!;
        Assert.Equal(3, (int)b["per_target"]![0]!["ok_count"]!);
        Assert.Equal("--lua-desync=multisplit:pos=1", (string?)b["strategy"]);

        // the router's measurements are trials of the knowledge base with source router
        var history = rig.Host.Kb.LearningHistory(DateTimeOffset.UtcNow.AddDays(-1));
        Assert.Contains(history, h => h.Strategy == "--lua-desync=multisplit:pos=1" && h.Successes == 3 && h.Source == CandidateSource.Router && h.ClientProfile == RouterTuning.ClientProfile);
        Assert.Contains(history, h => h.Strategy == "--lua-desync=multidisorder:pos=1" && h.Successes == 0);
        Assert.DoesNotContain(gui.Calls, c => c.Tool == "strategy_experiment_commit");
    }

    [Fact]
    public async Task CommittingNeedsAnotherYesKeepsTheVariantFirstAndStartsTheFeedback()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        await rig.Call("router_experiment_start", TwoVariants);
        rig.Confirm.Answer(true);
        await Rig.Until(async () => await State(rig) is "finished" or "failed");

        var commit = await rig.Call("router_experiment_commit", """{"save":true}""");
        Assert.Equal("pending_confirmation", (string?)commit.Data["status"]);
        Assert.Contains("zt_router_", rig.Confirm.Asked[^1].TextEn);
        Assert.DoesNotContain(gui.Calls, c => c.Tool == "strategy_experiment_commit");
        Assert.Empty(rig.Host.RouterCommits);

        rig.Confirm.Answer(true);
        await Rig.Until(async () => await State(rig) == "committed");
        // the run had no kept variant: B is applied alone with keep_best, then committed and saved
        Assert.Equal(2, gui.StartArgs.Count);
        Assert.True((bool)gui.StartArgs[1]["keep_best"]!);
        var c = gui.Calls.Single(x => x.Tool == "strategy_experiment_commit").Args;
        Assert.Equal(RouterTuning.KeepLabel, (string)c["label"]!);
        Assert.StartsWith("zt_router_", (string)c["save_as"]!, StringComparison.Ordinal);
        var (targets, strategy) = Assert.Single(rig.Host.RouterCommits);
        Assert.Equal(["blocked.example"], targets);
        Assert.Equal("--lua-desync=multisplit:pos=1", strategy);
        Assert.Contains(rig.Host.Kb.Changes(), x => x.Domain == "blocked.example" && x.Kind == "router_applied" && x.Applied);

        // a committed variant is not rolled back
        var back = await rig.Call("router_experiment_rollback");
        Assert.Contains("committed", (string?)back.Data["note"]);
        Assert.DoesNotContain(gui.Calls, x => x.Tool == "strategy_experiment_rollback");
    }

    [Fact]
    public async Task AKeptWinnerIsCommittedDirectlyAndADeclineChangesNothing()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        await rig.Call("router_experiment_start", TwoVariants.Replace("\"repeats\":2", "\"repeats\":2,\"keep_best\":true", StringComparison.Ordinal));
        rig.Confirm.Answer(true);
        await Rig.Until(async () => await State(rig) is "finished" or "failed");
        Assert.True((bool)(await rig.Call("router_experiment_status")).Data["awaiting_commit"]!);

        await rig.Call("router_experiment_commit", """{"label":"B"}""");
        rig.Confirm.Answer(false);
        await Rig.Until(async () => (string?)(await rig.Call("router_experiment_commit", """{"label":"B"}""")).Data["status"] == "declined");
        Assert.DoesNotContain(gui.Calls, c => c.Tool == "strategy_experiment_commit");

        await rig.Call("router_experiment_commit", """{"label":"B"}""");
        rig.Confirm.Answer(true);
        await Rig.Until(async () => await State(rig) == "committed");
        Assert.Single(gui.StartArgs);
        var c = gui.Calls.Single(x => x.Tool == "strategy_experiment_commit").Args;
        Assert.Equal("B", (string)c["label"]!);
        Assert.Null(c["save_as"]);
    }

    [Fact]
    public async Task RollbackAndStopRevertTheRouter()
    {
        var (rig, gui) = Setup(tweak: g => g.States = ["running"]);
        using var _ = rig;
        await rig.Call("router_experiment_start", TwoVariants);
        rig.Confirm.Answer(true);
        await Rig.Until(async () => await State(rig) == "running");
        Assert.True(rig.Session.Busy);
        var back = await rig.Call("router_experiment_rollback");
        Assert.Equal("reverted", (string?)back.Data["state"]);
        Assert.Equal("strategy_experiment_rollback", gui.Calls[^1].Tool);

        await rig.Call("router_experiment_start", TwoVariants.Replace("\"repeats\":2", "\"repeats\":3", StringComparison.Ordinal));
        rig.Confirm.Answer(true);
        await Rig.Until(async () => await State(rig) == "running");
        await rig.Session.StopAllAsync();
        Assert.Equal("strategy_experiment_rollback", gui.Calls[^1].Tool);
        Assert.False(rig.Session.Router.Running);
    }

    [Fact]
    public async Task ATokenWithoutTheExperimentToolsIsExplained()
    {
        var (rig, gui) = Setup(tweak: g => g.Tools = ["strategy_get"]);
        using var _ = rig;
        await rig.Call("router_experiment_start", TwoVariants);
        rig.Confirm.Answer(true);
        JsonObject? done = null;
        await Rig.Until(async () =>
        {
            var r = await rig.Call("router_experiment_start", TwoVariants);
            done = r.Data;
            return (string?)r.Data["status"] is not ("pending_confirmation" or "confirmed_running");
        });
        Assert.Contains("strategy_experiment_start", (string?)done!["error"]);
        Assert.Contains("experiments permission", (string?)done["hint"]);
        Assert.Empty(gui.StartArgs);
    }
}
