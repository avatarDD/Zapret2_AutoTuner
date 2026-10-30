using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Probes.Http;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>The final check judges the strategy on its target and keeps one stray miss from dropping it.</summary>
public sealed class FinalCheckTests
{
    private static readonly FoundStrategy Found = new(
        new StrategyCandidate(Strategy.Parse("--lua-desync=multisplit:pos=1"), "multisplit", 0, [], L4Kind.Tcp),
        new Efficiency(3, 3), new ScoreBreakdown(1, []));

    private static AgentTrialExecutor Executor(params bool[] probes)
    {
        int i = 0;
        var target = new TrialTarget { Host = "www.example.test", Addresses = [IPAddress.Parse("203.0.113.7")] };
        return new AgentTrialExecutor(new RecordingEngine(), target, new AgentTrialOptions { LuaDir = "/lua", Platform = Core.Validation.EnginePlatform.Windows, Warmup = TimeSpan.Zero, Pause = TimeSpan.Zero })
        {
            Probe = (o, ct) => Task.FromResult(probes[Math.Min(i++, probes.Length - 1)]
                ? new ProbeResult { Host = o.Host, Address = o.Address.ToString(), ConnectOk = true, TlsOk = true, CertValid = true, HttpStatus = 200, BodyBytes = 200_000, BytesIn = 201_000, Complete = true, BodySha256 = new string('a', 64), Duration = TimeSpan.FromMilliseconds(100) }
                : new ProbeResult { Host = o.Host, Address = o.Address.ToString(), ConnectOk = true, Error = ProbeError.TlsReset, RstSeen = true, Duration = TimeSpan.FromMilliseconds(40) }),
        };
    }

    private static PageLoad Page(bool mainOk) => new()
    {
        Url = "https://www.example.test/",
        LoadFired = false,
        Requests =
        [
            new PageRequest { Url = "https://www.example.test/", ResourceType = "document", Status = mainOk ? 200 : null, Error = mainOk ? null : "net::ERR_CONNECTION_RESET", Bytes = 90_000, Duration = mainOk ? TimeSpan.FromMilliseconds(300) : null },
            new PageRequest { Url = "https://www.example.test/app.js", ResourceType = "script", Status = mainOk ? 200 : null, Error = mainOk ? null : "net::ERR_CONNECTION_RESET", Bytes = 400_000, Duration = mainOk ? TimeSpan.FromMilliseconds(300) : null },
            new PageRequest { Url = "https://static.cdn-images.test/player.js", ResourceType = "script", Error = "net::ERR_CONNECTION_RESET" },
        ],
    };

    [Fact]
    public async Task One_miss_in_five_does_not_drop_a_strategy_two_do()
    {
        var one = await FinalCheck.RunAsync(Executor(true, false, true, true, true), [Found], "www.example.test", null);
        Assert.True(one[0].Passed, one[0].L2.ToString());
        Assert.Equal(new Efficiency(4, 5), one[0].L2);

        var two = await FinalCheck.RunAsync(Executor(false, true, false, true, true), [Found], "www.example.test", null);
        Assert.False(two[0].Passed);
        Assert.Equal(3, two[0].L2.Attempts);
    }

    [Fact]
    public async Task A_page_whose_other_domains_break_still_confirms_the_strategy_for_its_target()
    {
        var r = await FinalCheck.RunAsync(Executor(true), [Found], "www.example.test", _ => Task.FromResult(Page(mainOk: true)));
        Assert.True(r[0].PageOk);
        Assert.True(r[0].Passed);
        Assert.DoesNotContain("www.example.test", r[0].OtherBrokenDomains);

        var outcome = new TargetOutcome("www.example.test", null, null, r, null);
        Assert.Same(Found, outcome.Best);
    }

    [Fact]
    public async Task A_page_where_the_target_itself_breaks_fails_and_the_summary_says_why()
    {
        var r = await FinalCheck.RunAsync(Executor(true), [Found], "www.example.test", _ => Task.FromResult(Page(mainOk: false)));
        Assert.False(r[0].Passed);

        var outcome = new TargetOutcome("www.example.test", null, null, r, null);
        Assert.Null(outcome.Best);
        var (ru, en) = TuningPipeline.Summary(outcome);
        Assert.Contains("финальная проверка их не подтвердила", ru);
        Assert.Contains("страница не открылась", ru);
        Assert.Contains("did not confirm", en);
    }
}
