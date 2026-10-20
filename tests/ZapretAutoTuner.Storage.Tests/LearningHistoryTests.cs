using Microsoft.Data.Sqlite;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Storage.Tests;

public sealed class LearningHistoryTests
{
    private static readonly Strategy Split = Strategy.Parse("--lua-desync=multisplit:pos=midsld");
    private static readonly Strategy Child = Strategy.Parse("--lua-desync=multisplit:pos=midsld+1");
    private static readonly Strategy Fake = Strategy.Parse("--lua-desync=fake:blob=fake_default_tls:tcp_md5");
    private static readonly DateTimeOffset T0 = new(2026, 10, 20, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Trials_are_counted_per_strategy_provider_label_source_and_day()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        long net = kb.Network(new NetworkInfo(12389, null));
        TrialRecord Rec(Strategy s, bool ok, DateTimeOffset at, string source = CandidateSource.Generator) => new()
        {
            Strategy = s, Family = "multisplit", Host = "example.com", Ok = ok, At = at, Source = source, NetworkId = net, BlockLabel = "SniBlock",
        };
        kb.RecordTrial(Rec(Split, true, T0));
        kb.RecordTrial(Rec(Split, false, T0.AddHours(1)));
        kb.RecordTrial(Rec(Split, true, T0.AddDays(-3)));
        kb.RecordTrial(Rec(Fake, true, T0, CandidateSource.Llm) with { Family = "fake" });
        kb.RecordTrial(Rec(Fake, false, T0.AddDays(-400), CandidateSource.Llm) with { Family = "fake" });

        var rows = kb.LearningHistory(T0.AddDays(-30));
        Assert.Equal(3, rows.Count);
        var today = Assert.Single(rows, r => r.Strategy == Split.ToString() && r.Day == new DateTimeOffset(2026, 10, 20, 0, 0, 0, TimeSpan.Zero));
        Assert.Equal((1, 2), (today.Successes, today.Attempts));
        Assert.Equal(12389, today.Asn);
        Assert.Equal("SniBlock", today.Label);
        Assert.Equal("multisplit", today.Family);
        Assert.Equal(CandidateSource.Generator, today.Source);
        var llm = Assert.Single(rows, r => r.Source == CandidateSource.Llm);
        Assert.Equal((1, 1), (llm.Successes, llm.Attempts));
        // the old attempt is only inside a wider window
        Assert.Equal(5, kb.LearningHistory(T0.AddDays(-500)).Sum(r => r.Attempts));
    }

    [Fact]
    public void Base_at_schema_v2_is_upgraded_with_labels_and_sources_backfilled()
    {
        var dir = Directory.CreateTempSubdirectory("ztkb").FullName;
        var path = Path.Combine(dir, "autotuner.db");
        try
        {
            using (var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
            {
                db.Open();
                using var c = db.CreateCommand();
                const string T = "'2026-10-19T10:00:00.0000000+00:00'";
                c.CommandText = string.Join('\n', Schema.Migrations.Where(m => m.Version <= 2).Select(m => m.Sql)) + $"""

                    INSERT INTO networks(id,uid,asn,first_seen,last_seen) VALUES(1,'n1',12389,{T},{T});
                    INSERT INTO targets(id,host) VALUES(1,'example.com');
                    INSERT INTO strategies(id,hash,args,family,created_at) VALUES(1,'h1','{Split}','multisplit',{T});
                    INSERT INTO strategies(id,hash,args,family,created_at) VALUES(2,'h2','{Child}','multisplit',{T});
                    INSERT INTO search_sessions(id,uid,target_id,network_id,mode,state,block_label,started_at,updated_at) VALUES(1,'s1',1,1,'Standard','done','SniBlock',{T},{T});
                    INSERT INTO trials(uid,session_id,strategy_id,target_id,network_id,level,ok,created_at) VALUES('t1',1,1,1,1,'L2',1,{T});
                    INSERT INTO trials(uid,session_id,strategy_id,target_id,network_id,level,ok,created_at) VALUES('t2',1,2,1,1,'L2',1,{T});
                    INSERT INTO trials(uid,session_id,strategy_id,target_id,network_id,level,ok,created_at) VALUES('t3',NULL,1,1,1,'L2',0,{T});
                    INSERT INTO tuning_steps(session_id,parent_strategy_id,strategy_id,mutation,successes,attempts,accepted,created_at) VALUES(1,1,2,'pos',1,1,1,{T});
                    PRAGMA user_version = 2;
                    """;
                c.ExecuteNonQuery();
            }
            using (var kb = KnowledgeBase.Open(path))
            {
                Assert.Equal(Schema.Version, kb.SchemaVersion);
                var rows = kb.LearningHistory(T0.AddDays(-30));
                var screened = Assert.Single(rows, r => r.Strategy == Split.ToString() && r.Label == "SniBlock");
                Assert.Equal(CandidateSource.Generator, screened.Source);
                Assert.Equal(12389, screened.Asn);
                Assert.Equal(CandidateSource.Mutation, Assert.Single(rows, r => r.Strategy == Child.ToString()).Source);
                // a trial outside any session has no label to inherit
                Assert.Single(rows, r => r.Strategy == Split.ToString() && r.Label is null);
                kb.RecordTrial(new TrialRecord { Strategy = Fake, Host = "example.com", Ok = true, Source = CandidateSource.Llm, At = T0 });
            }
            using (var again = KnowledgeBase.Open(path))
            {
                Assert.Equal(Schema.Version, again.SchemaVersion);
                Assert.Single(again.LearningHistory(T0.AddDays(-30)), r => r.Source == CandidateSource.Llm);
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(dir, true);
        }
    }
}
