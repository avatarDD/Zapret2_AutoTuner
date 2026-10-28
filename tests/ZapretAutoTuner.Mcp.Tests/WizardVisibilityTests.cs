using ZapretAutoTuner.Core.Diagnostics;

namespace ZapretAutoTuner.Mcp.Tests;

/// <summary>The model sees the user's own search in the wizard: its progress and its diagnoses.</summary>
public sealed class WizardVisibilityTests
{
    [Fact]
    public async Task Search_status_shows_the_wizard_run()
    {
        using var rig = new Rig(Rig.All);
        rig.Host.LocalTuningRunning = true;
        rig.Host.Wizard = new WizardSnapshot(true, true, 42.5, "00:10:00", "≈ 00:14:00", "www.youtube.com: [multidisorder] --lua-desync=multidisorder:pos=midsld",
            [new WizardTargetView("www.youtube.com", "Search", "Подбираю стратегию", 2, null), new WizardTargetView("i.ytimg.com", "Waiting", "", 0, null)],
            ["www.youtube.com: 6/6 --lua-desync=multidisorder:pos=midsld"]);

        var status = (await rig.Call("search_status")).Data;

        Assert.Equal("idle", (string?)status["state"]);
        Assert.Contains("wizard", (string?)status["hint"]);
        var wizard = status["wizard"]!.AsObject();
        Assert.True((bool)wizard["running"]!);
        Assert.True((bool)wizard["paused"]!);
        Assert.Equal(42.5, (double)wizard["percent"]!);
        Assert.Equal(["www.youtube.com", "i.ytimg.com"], wizard["targets"]!.AsArray().Select(t => (string?)t!["target"]));
        Assert.Equal(2, (int)wizard["targets"]![0]!["found"]!);
        Assert.Single(wizard["found"]!.AsArray());
    }

    [Fact]
    public async Task Without_a_wizard_run_there_is_nothing_extra()
    {
        using var rig = new Rig(Rig.All);
        var status = (await rig.Call("search_status")).Data;
        Assert.Null(status["wizard"]);
        Assert.Null(status["hint"]);
    }

    [Fact]
    public async Task The_wizards_diagnosis_is_seen_by_the_tools()
    {
        using var rig = new Rig(Rig.All);
        rig.Host.WizardVerdicts["blocked.example"] = new ClassifierVerdict
        {
            Host = "blocked.example",
            Primary = BlockLabel.Cutoff16K,
            Next = NextStep.SearchStrategy,
            LiveAddresses = ["203.0.113.7"],
            Findings = [new LabelFinding(BlockLabel.Cutoff16K, "203.0.113.7", ["stalled at 16 KB"])],
        };

        var d = (await rig.Call("diagnose", """{"target":"blocked.example"}""")).Data;
        Assert.True((bool)d["diagnosed"]!);
        Assert.Equal("Cutoff16K", (string?)d["primary"]);
        var list = (await rig.Call("targets_list")).Data["targets"]!.AsArray();
        Assert.Equal("Cutoff16K", (string?)list.First(t => (string?)t!["target"] == "blocked.example")!["diagnosis"]!["primary"]);
        Assert.Equal(0, rig.Host.Classified);
    }
}
