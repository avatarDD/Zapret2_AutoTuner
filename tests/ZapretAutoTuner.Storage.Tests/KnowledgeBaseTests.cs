using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Storage.Tests;

public sealed class KnowledgeBaseTests
{
    private static readonly Strategy Split = Strategy.Parse("--lua-desync=multisplit:pos=midsld");
    private static readonly Strategy Fake = Strategy.Parse("--lua-desync=fake:blob=fake_default_tls:tcp_md5 --lua-desync=multisplit:pos=1");

    [Fact]
    public void Schema_is_created_once_and_reopened()
    {
        var dir = Directory.CreateTempSubdirectory("ztkb").FullName;
        var path = Path.Combine(dir, "kb", "autotuner.db");
        try
        {
            using (var kb = KnowledgeBase.Open(path))
            {
                Assert.Equal(Schema.Version, kb.SchemaVersion);
                kb.SetSetting("ui.language", "ru");
            }
            using (var again = KnowledgeBase.Open(path))
            {
                Assert.Equal("ru", again.GetSetting("ui.language"));
                Assert.Equal(Schema.Version, again.SchemaVersion);
            }
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Settings_round_trip()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        Assert.Null(kb.GetSetting("x"));
        kb.SetSetting("x", "1");
        kb.SetSetting("x", "2");
        kb.SetSetting("y", "3");
        Assert.Equal("2", kb.GetSetting("x"));
        Assert.Equal(2, kb.AllSettings().Count);
        kb.RemoveSetting("x");
        Assert.Null(kb.GetSetting("x"));
    }

    [Fact]
    public void Trials_fold_into_results_with_status()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        var net = kb.Network(new NetworkInfo(12389, "Rostelecom", "RU"));
        Assert.Equal(net, kb.Network(new NetworkInfo(12389, "Rostelecom")));

        Efficiency e = default;
        foreach (var ok in new[] { true, false, true })
            e = kb.RecordTrial(new TrialRecord { Strategy = Split, Family = "multi", Host = "YouTube.com", Ok = ok, NetworkId = net, BlockLabel = "SniBlock" });
        Assert.Equal(new Efficiency(2, 3), e);
        for (int i = 0; i < 3; i++)
            kb.RecordTrial(new TrialRecord { Strategy = Fake, Family = "fake", Host = "youtube.com", Ok = true, NetworkId = net });

        var results = kb.Results("youtube.com");
        Assert.Equal(2, results.Count);
        Assert.Equal(Fake.ToString(), results[0].Args); // working first
        Assert.Equal("working", results[0].Status);
        Assert.Equal("partial", results[1].Status);
        Assert.Equal(new Efficiency(2, 3), results[1].Efficiency);
        Assert.Equal("SniBlock", results[1].BlockLabel);
        Assert.Equal(12389, results[1].Asn);
        Assert.Equal(KnowledgeBase.HashOf(Split), results[1].StrategyHash);
        Assert.Equal(64, results[1].StrategyHash.Length);

        kb.SetScore(Fake, "youtube.com", 3.5, net);
        Assert.Equal(3.5, kb.Results("youtube.com", net)[0].Score);
    }

    [Fact]
    public void Unknown_network_still_aggregates()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        kb.RecordTrial(new TrialRecord { Strategy = Split, Host = "a.test", Ok = true });
        var e = kb.RecordTrial(new TrialRecord { Strategy = Split, Host = "a.test", Ok = true });
        Assert.Equal(new Efficiency(2, 2), e);
        Assert.Single(kb.Results("a.test"));
    }

    [Fact]
    public void Strategies_that_worked_on_the_same_provider_come_first()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        var rt = kb.Network(new NetworkInfo(12389, "Rostelecom"));
        var mts = kb.Network(new NetworkInfo(8359, "MTS"));
        foreach (var host in new[] { "a.test", "b.test" })
            kb.RecordTrial(new TrialRecord { Strategy = Fake, Host = host, Ok = true, NetworkId = rt, Family = "fake" });
        kb.RecordTrial(new TrialRecord { Strategy = Split, Host = "c.test", Ok = true, NetworkId = rt });
        kb.RecordTrial(new TrialRecord { Strategy = Split, Host = "c.test", Ok = true, NetworkId = mts });
        kb.RecordTrial(new TrialRecord { Strategy = Strategy.Parse("--lua-desync=fake:blob=0x00000000"), Host = "d.test", Ok = false, NetworkId = rt });

        var worked = kb.WorkedOnNetwork(12389);
        Assert.Equal([Fake, Split], worked.Select(w => w.Strategy));
        Assert.Equal(2, worked[0].Targets);
        Assert.Equal("fake", worked[0].Family);
        Assert.Equal([Split], kb.WorkedOnNetwork(8359).Select(w => w.Strategy));
    }

    [Fact]
    public void Sessions_resume_with_what_was_tried()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        var s = kb.StartSession("rutracker.org", "standard", blockLabel: "SniBlock");
        kb.RecordTrial(new TrialRecord { Strategy = Split, Host = "rutracker.org", Ok = false, SessionId = s });
        kb.RecordTrial(new TrialRecord { Strategy = Split, Host = "rutracker.org", Ok = true, SessionId = s });
        kb.UpdateSession(s, checkpoint: "{\"family\":\"multi\",\"index\":3}");

        var open = Assert.Single(kb.UnfinishedSessions());
        Assert.Equal("rutracker.org", open.Host);
        Assert.Equal("{\"family\":\"multi\",\"index\":3}", open.Checkpoint);
        Assert.Equal(new Efficiency(1, 2), kb.SessionTrials(s)[Split.ToString()]);

        kb.AddTuningStep(s, Split, Fake, "+fake", new Efficiency(5, 5), true);
        var step = Assert.Single(kb.TuningSteps(s));
        Assert.Equal((Split.ToString(), Fake.ToString(), "+fake", true), (step.Parent, step.Child, step.Mutation, step.Accepted));

        kb.UpdateSession(s, state: "done");
        Assert.Empty(kb.UnfinishedSessions());
        Assert.Equal("done", kb.Session(s)!.State);
        Assert.Equal("{\"family\":\"multi\",\"index\":3}", kb.Session(s)!.Checkpoint); // a state change keeps the checkpoint
    }

    [Fact]
    public void Checker_history_is_kept_newest_first()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        var t0 = DateTimeOffset.UtcNow.AddHours(-1);
        kb.AddCheckerRun(t0, TimeSpan.FromSeconds(40), false, "[1]");
        kb.AddCheckerRun(t0.AddMinutes(30), TimeSpan.FromSeconds(35), true, "[2]");
        var runs = kb.CheckerRuns();
        Assert.Equal(["[2]", "[1]"], runs.Select(r => r.Report));
        Assert.True(runs[0].NetworkProblem);
        Assert.Equal(TimeSpan.FromSeconds(40), runs[1].Duration);
    }

    [Fact]
    public void Wilson_interval_separates_lucky_from_reliable()
    {
        var twoOfFive = new Efficiency(2, 5);
        var twoOfTen = new Efficiency(2, 10);
        Assert.True(twoOfFive.WilsonUpper > twoOfTen.WilsonUpper);
        Assert.InRange(new Efficiency(5, 5).WilsonLower, 0.6, 0.7);
        // one success after one attempt is not clearly better than 2/5
        Assert.False(new Efficiency(1, 1).ClearlyBetterThan(twoOfFive));
        Assert.True(new Efficiency(5, 5).ClearlyBetterThan(twoOfFive));
        Assert.True(new Efficiency(9, 10).ClearlyBetterThan(twoOfFive));
        Assert.False(new Efficiency(3, 5).ClearlyBetterThan(twoOfFive));
        Assert.Equal(0, default(Efficiency).Rate);
    }

    [Fact]
    public async Task Settings_and_trials_from_two_threads_do_not_collide()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        var s = ZapretAutoTuner.Core.Model.Strategy.Parse("--payload=tls_client_hello --lua-desync=multisplit:pos=1");
        var trials = Task.Run(() =>
        {
            for (int i = 0; i < 200; i++)
                kb.RecordTrial(new TrialRecord { Strategy = s, Host = "a.example", Ok = i % 2 == 0 });
        });
        var settings = Task.Run(() =>
        {
            for (int i = 0; i < 200; i++)
            {
                kb.SetSetting("k", i.ToString(System.Globalization.CultureInfo.InvariantCulture));
                _ = kb.GetSetting("k");
                _ = kb.AllSettings();
            }
        });
        await Task.WhenAll(trials, settings);
        Assert.Equal("199", kb.GetSetting("k"));
        Assert.Equal(200, kb.Results("a.example")[0].Efficiency.Attempts);
    }
}
