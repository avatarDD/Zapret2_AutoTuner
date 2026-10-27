using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Mcp.Tests;

public sealed class SearchTests
{
    [Fact]
    public async Task TheSearchRunsTheModelsCandidatesFirstAndFindsAStrategy()
    {
        using var rig = new Rig(new McpPermissions(Probes: true, Control: true), new BudgetOptions { PerMinute = 10_000 });
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        var q = await rig.Call("search_enqueue", """{"strategies":["--lua-desync=multisplit:pos=2"]}""");
        Assert.False(q.IsError);
        Assert.Equal("first in the next search_start", (string?)q.Data["when"]);
        var bad = await rig.Call("search_enqueue", """{"strategies":["--lua-desync=multisplit:pos=1","--lua-desync=luaexec:code=x"]}""");
        Assert.True(bad.IsError);
        Assert.Equal(1, (int)bad.Data["index"]!);

        var start = await rig.Call("search_start", """{"target":"blocked.example","mode":"quick"}""");
        Assert.False(start.IsError, start.Text);
        Assert.Equal(1, (int)start.Data["queued_first"]!);
        await Rig.Until(async () => (string?)(await rig.Call("search_status")).Data["state"] is "done" or "stopped" or "failed", 60);
        var status = await rig.Call("search_status");
        Assert.Equal("done", (string?)status.Data["state"]);
        Assert.NotEmpty(status.Data["found"]!.AsArray());
        Assert.Contains("multisplit:pos=2", rig.Host.Engine.Started[0].First(a => a.StartsWith("--lua-desync=", StringComparison.Ordinal)));
        Assert.Empty(rig.Host.Engine.Running);
    }

    [Fact]
    public async Task PausePruneAndStop()
    {
        using var rig = new Rig(new McpPermissions(Probes: true, Control: true), new BudgetOptions { PerMinute = 10_000 });
        rig.Host.Engine.WorkingFunction = "nothing-works";
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        Assert.True((await rig.Call("search_prune_family", """{"family":"no_such_family"}""")).IsError);
        await rig.Call("search_start", """{"target":"blocked.example","mode":"full"}""");
        var paused = await rig.Call("search_pause");
        Assert.Equal("paused", (string?)paused.Data["state"]);
        int started = rig.Host.Engine.Started.Count;
        await Task.Delay(200);
        Assert.InRange(rig.Host.Engine.Started.Count, started, started + 1);
        var family = (string?)(await rig.Call("search_status")).Data["families"]![0];
        Assert.False((await rig.Call("search_prune_family", new JsonObject { ["family"] = family }.ToJsonString())).IsError);
        Assert.Equal("running", (string?)(await rig.Call("search_pause", """{"resume":true}""")).Data["state"]);
        var stopped = await rig.Call("search_stop");
        Assert.Equal("stopped", (string?)stopped.Data["state"]);
        Assert.Empty(rig.Host.Engine.Running);
    }
}

public sealed class ExperimentTests
{
    [Fact]
    public async Task AnExperimentWaitsForTheUserMeasuresAndCommitsOnlyAfterAnotherYes()
    {
        using var rig = new Rig(Rig.All, new BudgetOptions { PerMinute = 10_000 });
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        var args = """{"variants":[{"label":"A","strategy":"--lua-desync=multidisorder:pos=1"},{"label":"B","strategy":"--lua-desync=multisplit:pos=1"}],"targets":["blocked.example"],"repeats":2}""";
        var r = await rig.Call("strategy_experiment_start", args);
        Assert.Equal("pending_confirmation", (string?)r.Data["status"]);
        Assert.Equal("awaiting_confirmation", (string?)(await rig.Call("strategy_experiment_status")).Data["state"]);
        Assert.Empty(rig.Host.Engine.Started);
        Assert.Contains("multisplit:pos=1", rig.Confirm.Asked[0].TextEn);

        rig.Confirm.Answer(true);
        await Rig.Until(async () => (string?)(await rig.Call("strategy_experiment_status")).Data["state"] is "finished" or "failed");
        var result = await rig.Call("strategy_experiment_result");
        Assert.Equal("B", (string?)result.Data["best"]);
        var b = result.Data["variants"]!.AsArray().First(v => (string?)v!["label"] == "B")!;
        Assert.Equal(["blocked.example"], b["delta_vs_baseline"]!["fixed"]!.AsArray().Select(x => (string?)x));
        Assert.Empty(rig.Host.Engine.Running);
        Assert.Contains(rig.Host.Engine.Started, a => a.Any(x => x.Contains("--hostlist-domains=blocked.example", StringComparison.Ordinal)));

        var commit = await rig.Call("strategy_experiment_commit");
        Assert.Equal("pending_confirmation", (string?)commit.Data["status"]);
        Assert.Empty(rig.Host.Committed);
        rig.Confirm.Answer(true);
        await Rig.Until(async () => (string?)(await rig.Call("strategy_experiment_commit")).Data["committed"] is "B" || rig.Host.Committed.Count > 0);
        Assert.Contains("multisplit", rig.Host.Committed.Single().Profiles[0].Strategy.ToString());
    }

    [Fact]
    public async Task AKeptVariantRevertsByItselfAndRollbackStopsIt()
    {
        using var rig = new Rig(Rig.All, new BudgetOptions { PerMinute = 10_000 });
        var args = """{"variants":[{"label":"B","strategy":"--lua-desync=multisplit:pos=1"}],"targets":["blocked.example"],"repeats":1,"keep_best":true,"ttl_sec":30}""";
        await rig.Call("strategy_experiment_start", args);
        rig.Confirm.Answer(true);
        await Rig.Until(async () => (bool?)(await rig.Call("strategy_experiment_status")).Data["awaiting_commit"] == true);
        Assert.Single(rig.Host.Engine.Running);
        var back = await rig.Call("strategy_experiment_rollback");
        Assert.Equal("reverted", (string?)back.Data["state"]);
        Assert.Empty(rig.Host.Engine.Running);
        Assert.Empty(rig.Host.Committed);
    }

    [Fact]
    public async Task NoExperimentWhileProtectionRuns()
    {
        using var rig = new Rig(Rig.All);
        rig.Host.ProtectionActive = true;
        var r = await rig.Call("strategy_experiment_start", """{"variants":[{"label":"A","strategy":"--lua-desync=multisplit"}]}""");
        Assert.True(r.IsError);
        Assert.Contains("busy", (string?)r.Data["error"]);
        Assert.Empty(rig.Confirm.Asked);
    }

    [Fact]
    public async Task ExportIsADryRunAndSavingAsks()
    {
        using var rig = new Rig(Rig.All);
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        var none = await rig.Call("export_preview", """{"format":"zapret2"}""");
        Assert.Contains("nothing to export", (string?)none.Data["error"]);
        await rig.Call("trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit:pos=1"}""");
        var p = await rig.Call("export_preview", """{"format":"zapret2"}""");
        Assert.False(p.IsError, p.Text);
        Assert.True((bool)p.Data["dry_run"]!);
        Assert.NotEmpty(p.Data["files"]!.AsArray());
        Assert.Empty(rig.Host.Saved);
        var save = await rig.Call("export_preview", """{"format":"keenetic","save":true}""");
        Assert.Equal("pending_confirmation", (string?)save.Data["status"]);
        rig.Confirm.Answer(true);
        await Rig.Until(() => Task.FromResult(rig.Host.Saved.Count == 1));
        Assert.EndsWith(".zip", rig.Host.Saved[0]);
    }
}
