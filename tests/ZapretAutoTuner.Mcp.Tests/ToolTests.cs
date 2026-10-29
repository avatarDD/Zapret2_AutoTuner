using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Mcp.Tests;

public sealed class PermissionTests
{
    [Fact]
    public void OnlyReadingIsListedByDefault()
    {
        using var rig = new Rig();
        Assert.Equal(["targets_list", "diagnose", "trials_history", "catalog_functions", "strategy_validate", "kb_query", "bug_report_draft", "geneva_status", "geneva_library", "geneva_check"], rig.Tools.ListTools().Select(t => t.Name));
        rig.Permissions = new McpPermissions(Probes: true);
        Assert.Contains("trial_run", rig.Tools.ListTools().Select(t => t.Name));
        Assert.DoesNotContain("search_start", rig.Tools.ListTools().Select(t => t.Name));
    }

    [Fact]
    public async Task AHiddenToolCalledByNameSaysWhichSwitchToTurnOn()
    {
        using var rig = new Rig();
        var r = await rig.Call("trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit:pos=1"}""");
        Assert.True(r.IsError);
        Assert.Equal("probes", (string?)r.Data["permission"]);
        Assert.Contains("probes", (string?)r.Data["hint"]);
        Assert.Empty(rig.Host.Engine.Started);
    }

    [Fact]
    public async Task ExperimentsWithoutTheirDependenciesAreExplained()
    {
        using var rig = new Rig(new McpPermissions(Experiments: true, Probes: true));
        Assert.DoesNotContain("strategy_experiment_start", rig.Tools.ListTools().Select(t => t.Name));
        var r = await rig.Call("strategy_experiment_status");
        Assert.True(r.IsError);
        Assert.Equal(["control"], r.Data["missing"]!.AsArray().Select(x => (string?)x));
        Assert.Equal(["control", "probes"], r.Data["requires"]!.AsArray().Select(x => (string?)x));
        Assert.Contains("does not act without control", (string?)r.Data["error"]);
    }

    [Fact]
    public async Task RefreshingADiagnosisNeedsProbes()
    {
        using var rig = new Rig();
        var r = await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        Assert.Equal("probes", (string?)r.Data["permission"]);
        Assert.Equal(0, rig.Host.Classified);
        var cached = await rig.Call("diagnose", """{"target":"blocked.example"}""");
        Assert.False(cached.IsError);
        Assert.False((bool)cached.Data["diagnosed"]!);
    }

    [Fact]
    public void EveryToolHasAHandler()
    {
        using var rig = new Rig();
        Assert.All(McpTools.All, t => Assert.True(rig.Tools.HasHandler(t.Name), t.Name));
    }

    [Fact]
    public async Task EveryCallIsAudited()
    {
        using var rig = new Rig();
        await rig.Call("targets_list");
        await rig.Call("trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit"}""");
        var lines = rig.Session.Audit.Lines();
        Assert.Equal(2, lines.Count);
        Assert.Contains("targets_list", lines[0]);
        Assert.Contains("error", lines[1]);
    }
}

public sealed class StrategyTests
{
    [Theory]
    [InlineData("--lua-desync=nosuchfunction", "policy.function")]
    [InlineData("--dpi-desync=fake", "policy.syntax")]
    [InlineData("--lua-desync=luaexec:code=os.execute('id')", "policy.category")]
    [InlineData("--lua-desync=pcap:file=/tmp/x.pcap", "policy.category")]
    [InlineData("--lua-desync=condition:iff=cond_lua:cond_code=os.exit()", "policy.arg")]
    [InlineData("--lua-desync=circular:failure_detector=os_execute", "policy.arg")]
    [InlineData("--wf-tcp=80 --lua-desync=multisplit", "policy.syntax")]
    [InlineData("--lua-desync=fake:blob=fake_default_tls", "fake.nofooling")]
    [InlineData("--lua-desync=multisplit:pos=1:nosucharg=1", "arg.unknown")]
    public async Task TheValidatorRefusesWithAClearError(string strategy, string code)
    {
        using var rig = new Rig(new McpPermissions(Probes: true));
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        var r = await rig.Call("trial_run", new JsonObject { ["target"] = "blocked.example", ["strategy"] = strategy }.ToJsonString());
        Assert.True(r.IsError);
        Assert.Contains("Validator", (string?)r.Data["error"]);
        Assert.Contains(r.Data["errors"]!.AsArray(), e => (string?)e!["code"] == code);
        Assert.Empty(rig.Host.Engine.Started);
    }

    [Fact]
    public async Task AGoodStrategyValidatesWithAnId()
    {
        using var rig = new Rig();
        var r = await rig.Call("strategy_validate", """{"strategy":"--payload=tls_client_hello --lua-desync=multisplit:pos=1,midsld"}""");
        Assert.False(r.IsError);
        Assert.Matches(McpTools.StrategyIdPattern, (string?)r.Data["strategy_id"]);
        var bad = await rig.Call("strategy_validate", """{"strategy":"--lua-desync=luaexec:code=x"}""");
        Assert.True(bad.IsError);
        Assert.Contains("not available over MCP", (string?)bad.Data["error"]);
    }

    [Fact]
    public async Task TheCatalogHidesWhatTheModelMayNotUse()
    {
        using var rig = new Rig();
        var r = await rig.Call("catalog_functions");
        var names = r.Data["functions"]!.AsArray().Select(f => (string?)f!["name"]).ToList();
        Assert.Contains("multisplit", names);
        Assert.DoesNotContain("luaexec", names);
        Assert.DoesNotContain("pcap", names);
        Assert.DoesNotContain("wgobfs", names);
        var one = await rig.Call("catalog_functions", """{"name":"fake"}""");
        Assert.Contains(one.Data["functions"]![0]!["args"]!.AsArray(), a => (string?)a!["name"] == "blob");
    }
}

public sealed class ConfirmationTests
{
    [Fact]
    public async Task AddingATargetWaitsForTheUserAndTheModelCannotConfirm()
    {
        using var rig = new Rig(new McpPermissions(Probes: true));
        var r = await rig.Call("target_add", """{"target":"new.example","reason":"the user mentioned it"}""");
        Assert.False(r.IsError);
        Assert.Equal("pending_confirmation", (string?)r.Data["status"]);
        Assert.DoesNotContain("new.example", rig.Host.Targets);
        Assert.Single(rig.Confirm.Asked);
        Assert.Contains("new.example", rig.Confirm.Asked[0].TextEn);

        var again = await rig.Call("target_add", """{"target":"new.example","reason":"the user mentioned it"}""");
        Assert.Equal("pending_confirmation", (string?)again.Data["status"]);
        Assert.Single(rig.Confirm.Asked);
        Assert.DoesNotContain(McpTools.All, t => t.Name.Contains("confirm", StringComparison.Ordinal));

        rig.Confirm.Answer(true);
        await Rig.Until(async () => (string?)(await rig.Call("target_add", """{"target":"new.example"}""")).Data["status"] is "added" or "already_listed");
        Assert.Contains("new.example", rig.Host.Targets);
    }

    [Fact]
    public async Task ADeclinedRequestIsReportedOnce()
    {
        using var rig = new Rig(new McpPermissions(Probes: true));
        await rig.Call("target_add", """{"target":"new.example"}""");
        rig.Confirm.Answer(false);
        McpToolResult? r = null;
        await Rig.Until(async () => (string?)(r = await rig.Call("target_add", """{"target":"new.example"}""")).Data["status"] == "declined");
        Assert.True(r!.IsError);
        Assert.DoesNotContain("new.example", rig.Host.Targets);
        var next = await rig.Call("target_add", """{"target":"new.example"}""");
        Assert.Equal("pending_confirmation", (string?)next.Data["status"]);
    }

    [Fact]
    public async Task TheStopButtonCancelsWaitingDialogs()
    {
        using var rig = new Rig(new McpPermissions(Probes: true));
        await rig.Call("target_add", """{"target":"new.example"}""");
        await rig.Session.StopAllAsync();
        Assert.Equal(0, rig.Session.Confirmations.PendingCount);
        Assert.DoesNotContain("new.example", rig.Host.Targets);
    }
}

public sealed class BudgetTests
{
    [Fact]
    public void TrialsPerMinuteAndPerSession()
    {
        var time = new ManualTime();
        var b = new TrialBudget(new BudgetOptions { PerMinute = 2, PerSession = 3 }, time);
        Assert.True(b.TryTake("a").Ok);
        Assert.True(b.TryTake("a").Ok);
        var (ok, why, retry) = b.TryTake("a");
        Assert.False(ok);
        Assert.Contains("a minute", why);
        Assert.True(retry > TimeSpan.Zero && retry <= TimeSpan.FromMinutes(1));
        time.Now += TimeSpan.FromSeconds(61);
        Assert.True(b.TryTake("a").Ok);
        time.Now += TimeSpan.FromSeconds(61);
        (ok, why, retry) = b.TryTake("a");
        Assert.False(ok);
        Assert.Contains("session", why);
        Assert.Equal(TimeSpan.Zero, retry);
    }

    [Fact]
    public void PunishmentPausesTheTarget()
    {
        var time = new ManualTime();
        var b = new TrialBudget(new BudgetOptions { PunishThreshold = 3, PunishPause = TimeSpan.FromSeconds(60) }, time);
        for (int i = 0; i < 3; i++)
            b.Observe("a", noConnect: true);
        var (ok, why, retry) = b.TryTake("a");
        Assert.False(ok);
        Assert.Contains("punishes", why);
        Assert.Equal(TimeSpan.FromSeconds(60), retry);
        Assert.True(b.TryTake("b").Ok);
        time.Now += TimeSpan.FromSeconds(61);
        Assert.True(b.TryTake("a").Ok);
    }

    [Fact]
    public async Task TrialRunRespectsTheBudget()
    {
        var time = new ManualTime();
        using var rig = new Rig(new McpPermissions(Probes: true), new BudgetOptions { PerMinute = 2 }, time);
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        var ok = await rig.Call("trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit:pos=1"}""");
        Assert.False(ok.IsError);
        var refused = await rig.Call("trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit:pos=2"}""");
        Assert.True(refused.IsError);
        Assert.NotNull(refused.Data["retry_after_sec"]);
    }
}

public sealed class TrialTests
{
    [Fact]
    public async Task ATrialNeedsABlockedTargetFromTheList()
    {
        using var rig = new Rig(new McpPermissions(Probes: true));
        var stranger = await rig.Call("trial_run", """{"target":"evil.example","strategy":"--lua-desync=multisplit"}""");
        Assert.Contains("not in the user's target list", (string?)stranger.Data["error"]);
        var undiagnosed = await rig.Call("trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit"}""");
        Assert.Contains("diagnose", (string?)undiagnosed.Data["error"]);
        await rig.Call("diagnose", """{"target":"open.example","refresh":true}""");
        var open = await rig.Call("trial_run", """{"target":"open.example","strategy":"--lua-desync=multisplit"}""");
        Assert.Contains("does not help", (string?)open.Data["error"]);
        Assert.Empty(rig.Host.Engine.Started);
    }

    [Fact]
    public async Task TheObservationIsCompactMaskedAndHasNoBody()
    {
        using var rig = new Rig(new McpPermissions(Probes: true));
        var d = await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        var dText = d.Text;
        Assert.DoesNotContain("192.168.1.10", dText);
        Assert.Contains("lan-1", dText);
        Assert.DoesNotContain("203.0.113.7", dText);
        Assert.Contains("203.0.113.x", dText);

        rig.Host.Engine.WorkingFunction = "nothing-works";
        var r = await rig.Call("trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit:pos=1","attempts":2}""");
        Assert.False(r.IsError);
        var text = r.Text;
        Assert.DoesNotContain("192.168.1.10", text);
        Assert.Contains("lan-", text);
        Assert.True(text.Length < AutoTunerTools.MaxAnswerChars);
        Assert.Equal("dpi_reset_on_client_hello", (string?)r.Data["reading"]);
        Assert.Equal(0, (int)r.Data["result"]!["successes"]!);
        Assert.Equal("unchanged", (string?)r.Data["result"]!["delta"]);
        Assert.Single(rig.Host.Engine.Started);
        Assert.Empty(rig.Host.Engine.Running);
    }

    [Fact]
    public async Task AWorkingStrategyIsFixedAndStoredAsLlm()
    {
        using var rig = new Rig(new McpPermissions(Probes: true));
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        var r = await rig.Call("trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit:pos=1"}""");
        Assert.Equal("L2", (string?)r.Data["result"]!["level_reached"]);
        Assert.Equal(3, (int)r.Data["result"]!["successes"]!);
        Assert.Equal("fixed", (string?)r.Data["result"]!["delta"]);
        Assert.Equal(new string('a', 64), (string?)r.Data["attempts"]![0]!["body_sha256"]);
        Assert.Single(rig.Host.Engine.Started);
        var stored = rig.Host.Kb.Results("blocked.example").Single();
        Assert.Equal("llm", stored.Family);
        Assert.Equal("3/3", stored.Efficiency.ToString());

        var history = await rig.Call("trials_history", """{"target":"blocked.example"}""");
        Assert.Equal("llm", (string?)history.Data["results"]![0]!["source"]);
        Assert.Equal((string?)r.Data["trial_id"], (string?)history.Data["session_trials"]![0]!["trial_id"]);
        var byId = await rig.Call("trial_run", new JsonObject { ["target"] = "blocked.example", ["strategy_id"] = (string?)r.Data["strategy_id"], ["attempts"] = 1 }.ToJsonString());
        Assert.False(byId.IsError);
    }

    [Fact]
    public void LongAnswersAreTrimmed()
    {
        var big = new JsonObject { ["ok"] = true, ["rows"] = new JsonArray([.. Enumerable.Range(0, 5000).Select(i => (JsonNode)JsonValue.Create("row " + i))]) };
        var bounded = AutoTunerTools.Bound(big, 2000);
        Assert.True(bounded.ToJsonString().Length <= 2000);
        Assert.True((bool)bounded["truncated"]!);
    }
}
