using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.Mcp.Tests;

/// <summary>A slow diagnosis outlives the call and is kept; the export says what it left out; the bug draft is the model's.</summary>
public sealed class DiagnoseAndReportTests
{
    private static ClassifierVerdict Blocked(string host) => new()
    {
        Host = host,
        Primary = BlockLabel.SniBlock,
        Next = NextStep.SearchStrategy,
        LiveAddresses = ["203.0.113.7"],
    };

    [Fact]
    public async Task A_slow_diagnosis_answers_running_and_its_verdict_is_kept_for_the_next_call()
    {
        using var rig = new Rig(Rig.All);
        rig.Session.DiagnoseWait = TimeSpan.FromMilliseconds(50);
        var release = new TaskCompletionSource();
        rig.Host.Classifier = async (host, ct) =>
        {
            await release.Task.WaitAsync(ct);
            return Blocked(host);
        };

        var first = (await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""")).Data;
        Assert.Equal("running", (string?)first["state"]);
        Assert.False((bool)first["diagnosed"]!);

        // a second refresh joins the run: no new probes, no budget taken
        var again = (await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""")).Data;
        Assert.Equal("running", (string?)again["state"]);
        Assert.Equal(1, rig.Host.Classified);
        var search = await rig.Call("search_start", """{"target":"blocked.example"}""");
        Assert.Contains("still being diagnosed", (string?)search.Data["error"]);

        release.SetResult();
        await Rig.Until(() => Task.FromResult(!rig.Session.Classifying("blocked.example")));
        var done = (await rig.Call("diagnose", """{"target":"blocked.example"}""")).Data;
        Assert.True((bool)done["diagnosed"]!);
        Assert.Equal("SniBlock", (string?)done["primary"]);
        Assert.Null(done["state"]);
        Assert.Equal(1, rig.Host.Classified);
    }

    [Fact]
    public async Task A_client_that_gives_up_does_not_cancel_the_diagnosis()
    {
        using var rig = new Rig(Rig.All);
        var release = new TaskCompletionSource();
        rig.Host.Classifier = async (host, ct) =>
        {
            await release.Task.WaitAsync(ct);
            return Blocked(host);
        };
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            rig.Tools.CallAsync("diagnose", System.Text.Json.Nodes.JsonNode.Parse("""{"target":"blocked.example","refresh":true}""")!.AsObject(), "test", cts.Token));

        release.SetResult();
        await Rig.Until(() => Task.FromResult(rig.Session.Verdict("blocked.example") is not null));
        Assert.Equal(BlockLabel.SniBlock, rig.Session.Verdict("blocked.example")!.Primary);
    }

    [Fact]
    public async Task A_failed_diagnosis_is_reported_and_can_be_retried()
    {
        using var rig = new Rig(Rig.All);
        rig.Host.Classifier = (host, ct) => Task.FromException<ClassifierVerdict>(new TimeoutException("DNS timed out"));

        var failed = await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        Assert.True(failed.IsError);
        Assert.Contains("DNS timed out", (string?)failed.Data["error"]);
        var later = await rig.Call("diagnose", """{"target":"blocked.example"}""");
        Assert.True(later.IsError);
        Assert.Contains("refresh=true tries again", (string?)later.Data["error"]);

        rig.Host.Classifier = null;
        var retried = (await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""")).Data;
        Assert.True((bool)retried["diagnosed"]!);
    }

    [Fact]
    public async Task Export_preview_names_the_targets_it_left_out()
    {
        using var rig = new Rig(Rig.All);
        var none = await rig.Call("export_preview", """{"format":"zapret2"}""");
        Assert.True(none.IsError);
        var skipped = none.Data["skipped"]!.AsArray().Select(x => (string?)x).ToList();
        Assert.Equal(2, skipped.Count);
        Assert.Contains(skipped, s => s!.StartsWith("blocked.example: left out, not diagnosed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_bug_draft_is_built_from_the_models_words_and_the_named_target()
    {
        using var rig = new Rig(Rig.All);
        rig.Host.BugContext = new BugReportInput
        {
            Kind = BugKind.TuningFailed,
            Summary = "wizard summary",
            WhatDid = "wizard did",
            Exception = new InvalidOperationException("an old app error"),
            Verdict = Blocked("open.example"),
        };

        var d = (await rig.Call("bug_report_draft", """
            {"kind":"engine_behaviour","about":"blocked.example","summary":"final check drops found strategies",
             "what_did":"search found 3","expected":"one is kept","got":"none found"}
            """)).Data;

        var title = (string?)d["title"];
        var body = (string?)d["body"];
        Assert.Contains("final check drops found strategies", title);
        Assert.Contains("EngineBehaviour", body);
        Assert.Contains("search found 3", body);
        Assert.Contains("one is kept", body);
        Assert.Contains("none found", body);
        Assert.DoesNotContain("wizard did", body);
        Assert.DoesNotContain("an old app error", body);
        // blocked.example is not diagnosed: no verdict at all, never open.example's
        Assert.Null(d["verdict_of"]);
        Assert.DoesNotContain("open.example", body);
        Assert.Equal("blocked.example", (string?)d["about"]);

        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        var withVerdict = (await rig.Call("bug_report_draft", """{"kind":"tuning_failed","about":"blocked.example"}""")).Data;
        Assert.Equal("blocked.example", (string?)withVerdict["verdict_of"]);
    }
}
