using Microsoft.Data.Sqlite;

namespace ZapretAutoTuner.Storage.Tests;

public sealed class MonitorJournalTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 20, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Base_at_schema_v1_is_upgraded_to_v2_keeping_its_data()
    {
        var dir = Directory.CreateTempSubdirectory("ztkb").FullName;
        var path = Path.Combine(dir, "autotuner.db");
        try
        {
            using (var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
            {
                db.Open();
                using var c = db.CreateCommand();
                c.CommandText = Schema.Migrations.Single(m => m.Version == 1).Sql
                    + "\nINSERT INTO settings(key,value,updated_at) VALUES('ui.language','en','2026-01-01T00:00:00.0000000+00:00');\nPRAGMA user_version = 1;";
                c.ExecuteNonQuery();
            }
            using (var kb = KnowledgeBase.Open(path))
            {
                Assert.Equal(2, kb.SchemaVersion);
                Assert.Equal("en", kb.GetSetting("ui.language"));
                kb.AddMonitorWindow("example.com", T0, 5, 4, 1, 0, 0, 0, 2);
                kb.AddChange("example.com", "degraded", "неудач 3/5");
            }
            using (var again = KnowledgeBase.Open(path))
            {
                Assert.Equal(Schema.Version, again.SchemaVersion);
                Assert.Single(again.MonitorWindows(T0));
                Assert.Single(again.Changes());
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Monitor_window_is_upserted_by_domain_and_start()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        kb.AddMonitorWindow("example.com", T0, 3, 1, 2, 0, 0, 0, 0);
        // the same instant in another offset is the same window
        kb.AddMonitorWindow("example.com", T0.ToOffset(TimeSpan.FromHours(3)), 6, 5, 1, 0, 0, 0, 4);
        kb.AddMonitorWindow("other.com", T0, 4, 4, 0, 0, 0, 0, 0);
        var all = kb.MonitorWindows(T0);
        Assert.Equal(2, all.Count);
        var w = all.Single(x => x.Domain == "example.com");
        Assert.Equal(6, w.Sessions);
        Assert.Equal(5, w.Ok);
        Assert.Equal(T0, w.Start);
    }

    [Fact]
    public void Monitor_windows_filter_by_time_and_domain_oldest_first()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        kb.AddMonitorWindow("a.com", T0.AddMinutes(20), 3, 3, 0, 0, 0, 0, 0);
        kb.AddMonitorWindow("a.com", T0, 3, 0, 3, 0, 0, 0, 0);
        kb.AddMonitorWindow("b.com", T0.AddMinutes(10), 4, 2, 0, 2, 0, 0, 5);
        kb.AddMonitorWindow("a.com", T0.AddMinutes(10), 3, 1, 0, 0, 2, 0, 0);

        Assert.Equal([T0, T0.AddMinutes(10), T0.AddMinutes(10), T0.AddMinutes(20)], kb.MonitorWindows(T0).Select(w => w.Start));
        Assert.Equal([T0.AddMinutes(10), T0.AddMinutes(20)], kb.MonitorWindows(T0.AddMinutes(10), "a.com").Select(w => w.Start));
        Assert.Equal(["b.com"], kb.MonitorWindows(T0, "b.com").Select(w => w.Domain));
        Assert.Empty(kb.MonitorWindows(T0.AddMinutes(21)));
        Assert.Empty(kb.MonitorWindows(T0, "c.com"));
    }

    [Fact]
    public void Prune_drops_windows_before_the_cut()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        for (int i = 0; i < 5; i++)
            kb.AddMonitorWindow("a.com", T0.AddMinutes(10 * i), 3, 3, 0, 0, 0, 0, 0);
        kb.PruneMonitorWindows(T0.AddMinutes(20));
        Assert.Equal([T0.AddMinutes(20), T0.AddMinutes(30), T0.AddMinutes(40)], kb.MonitorWindows(DateTimeOffset.MinValue).Select(w => w.Start));
    }

    [Fact]
    public void Change_journal_is_newest_first_and_limited()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        var before = DateTimeOffset.UtcNow.AddSeconds(-1);
        kb.AddChange("a.com", "degraded", "неудач 4/5, чаще всего Reset");
        kb.AddChange("a.com", "repaired", "найдена соседняя стратегия", "--lua-desync=multisplit:pos=1", "--lua-desync=multisplit:pos=2", applied: true);
        kb.AddChange("b.com", "block_lifted", "открывается без обхода");

        var all = kb.Changes();
        Assert.Equal(["block_lifted", "repaired", "degraded"], all.Select(c => c.Kind));
        var repaired = all[1];
        Assert.Equal("a.com", repaired.Domain);
        Assert.Equal("--lua-desync=multisplit:pos=1", repaired.OldArgs);
        Assert.Equal("--lua-desync=multisplit:pos=2", repaired.NewArgs);
        Assert.Equal("найдена соседняя стратегия", repaired.Reason);
        Assert.True(repaired.Applied);
        Assert.False(all[0].Applied);
        Assert.Null(all[0].OldArgs);
        Assert.All(all, c => Assert.True(c.Time >= before && c.Time <= DateTimeOffset.UtcNow.AddSeconds(1)));

        Assert.Equal(["block_lifted", "repaired"], kb.Changes(2).Select(c => c.Kind));
    }
}
