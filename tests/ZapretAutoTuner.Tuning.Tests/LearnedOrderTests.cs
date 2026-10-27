using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>PLAN 4a.1 through the knowledge base: what one search learns orders the next one.</summary>
public sealed class LearnedOrderTests
{
    private sealed class Dpi(Func<string, bool> works) : ITrialExecutor
    {
        public List<string> Runs { get; } = [];

        public Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
        {
            Runs.Add(candidate.Key);
            var list = new List<TrialOutcome>();
            for (int i = 0; i < attempts && !stopEarly(list); i++)
                list.Add(works(candidate.Key) ? TrialOutcome.Success() : TrialOutcome.Fail(TrialFailure.Reset));
            return Task.FromResult<IReadOnlyList<TrialOutcome>>(list);
        }

        public Task<bool> TargetReachableAsync(CancellationToken ct) => Task.FromResult(true);
    }

    private const string Label = "SniBlock";

    private static async Task<(Dpi Dpi, SearchResult Result)> SearchAsync(KnowledgeBase kb, string host, long network, int asn, Func<string, bool> works, bool learning)
    {
        var target = new TrialTarget { Host = host, Addresses = [] };
        long session = kb.StartSession(host, "Quick", network, Label);
        var options = new SearchOptions
        {
            Generator = new GeneratorOptions { Mode = SearchMode.Quick },
            StopAfterFound = 1,
            Learning = learning ? TuningSession.Learning(kb, new LearningContext(asn, Label)) with { Seed = 3 } : null,
        };
        options = TuningSession.Prepare(kb, options, session, asn);
        var dpi = new Dpi(works);
        var result = await new StrategySearch(dpi, options, new KnowledgeBaseSearchLog(kb, session, target, network, Label)).RunAsync();
        TuningSession.Finish(kb, session, host, result, network);
        return (dpi, result);
    }

    [Fact]
    public async Task What_won_on_this_provider_is_tried_first_next_time()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        const int Asn = 12389;
        long network = kb.Network(new NetworkInfo(Asn, null));
        var set = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Quick });
        var winner = set.Candidates[^1];
        bool Works(string k) => k == winner.Key;

        // first time: the static order, the winner is found last
        var (first, r1) = await SearchAsync(kb, "a.example", network, Asn, Works, learning: true);
        Assert.Equal(winner.Key, r1.Best?.Candidate.Key);
        Assert.Equal(set.Candidates.Count, first.Runs.Count);

        // next site on the same provider: the winner's family goes first (as a prior and by the bandit)
        var (second, r2) = await SearchAsync(kb, "b.example", network, Asn, Works, learning: true);
        Assert.Equal(winner.Key, second.Runs[0]);
        Assert.Equal(1, r2.Tried);
        var rows = kb.LearningHistory(DateTimeOffset.UtcNow.AddDays(-1));
        Assert.Equal(6, rows.Where(r => r.Strategy == winner.Key && r.Asn == Asn && r.Label == Label).Sum(r => r.Successes));
    }

    [Fact]
    public async Task Outside_candidates_are_stored_with_their_source()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        long network = kb.Network(new NetworkInfo(64500, null));
        var target = new TrialTarget { Host = "c.example", Addresses = [] };
        long session = kb.StartSession(target.Host, "Quick", network, Label);
        var llm = new StrategyCandidate(Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:badsum"), "fake", 0, [], L4Kind.Tcp) { Source = CandidateSource.Llm };
        var options = new SearchOptions { Generator = new GeneratorOptions { Mode = SearchMode.Quick }, Priors = [llm], StopAfterFound = 1 };
        await new StrategySearch(new Dpi(k => k == llm.Key), options, new KnowledgeBaseSearchLog(kb, session, target, network, Label)).RunAsync();

        var row = Assert.Single(kb.LearningHistory(DateTimeOffset.UtcNow.AddDays(-1)));
        Assert.Equal((llm.Key, CandidateSource.Llm, 64500, Label), (row.Strategy, row.Source, row.Asn, row.Label));
        Assert.Equal((3, 3), (row.Successes, row.Attempts));
        Assert.True(new ThompsonOrder(new SearchLearning { History = [row], Context = new LearningContext(64500, Label) }).Source(CandidateSource.Llm).Mean > 0.5);
    }
}
