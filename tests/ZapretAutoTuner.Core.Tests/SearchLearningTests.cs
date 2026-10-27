using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Core.Tests;

public sealed class SearchLearningTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 20, 0, 0, 0, TimeSpan.Zero);
    private const int Asn = 12389;
    private const string Sni = "SniBlock";

    private sealed class SimDpi(Func<string, bool> works) : ITrialExecutor
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

    private static ArmStat Row(string strategy, int ok, int n, int? asn = null, string? label = null, int daysAgo = 0, string? family = "f", string source = CandidateSource.Generator, string profile = "default") =>
        new(strategy, family, source, asn, label, profile, T0.AddDays(-daysAgo), ok, n);

    private static SearchLearning L(IEnumerable<ArmStat> rows, LearningContext? context = null, int? seed = 1) =>
        new() { History = [.. rows], Context = context ?? new LearningContext(), Now = T0, Seed = seed };

    private static GeneratedSet Standard => StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Standard });

    /// <summary>A family the static order tries last, with its last strategy: kept winning on the user's ASN.</summary>
    private static (string Family, string Winner, List<ArmStat> History) WinnerOnAsn(GeneratedSet set)
    {
        var family = set.Candidates[^1].Family;
        var winner = set.OfFamily(family).Last().Key;
        var history = new List<ArmStat>();
        for (int d = 1; d <= 5; d++)
            history.Add(Row(winner, 3, 3, Asn, Sni, d, family));
        // what the static order tries first kept failing there
        foreach (var c in set.Candidates.Take(6))
            history.Add(Row(c.Key, 0, 2, Asn, Sni, 2, c.Family));
        return (family, winner, history);
    }

    [Fact]
    public void Posterior_adds_successes_and_failures_to_the_prior()
    {
        var order = new ThompsonOrder(L([Row("a", 8, 10)]));
        // the pool starts at 0.5 with 4 pseudo-attempts: Beta(2 + 8, 2 + 2)
        Assert.Equal(10, order.Pool.Alpha, 9);
        Assert.Equal(4, order.Pool.Beta, 9);
        // the arm's prior leaves its own trials out (they would count twice): with no other arm it is the neutral 0.5
        var a = order.Strategy("a");
        Assert.Equal(4 * 0.5 + 8, a.Alpha, 9);
        Assert.Equal(4 * 0.5 + 2, a.Beta, 9);
        // nothing known: the prior is the whole pool
        double m = order.Pool.Mean;
        var none = order.Strategy("nothing");
        Assert.Equal(m, none.Mean, 9);
        Assert.Equal(4, none.Alpha + none.Beta, 9);

        // with another arm, the prior is that arm's pool: b went 0/10, so a starts from Beta(2, 2 + 10)
        var two = new ThompsonOrder(L([Row("a", 8, 10), Row("b", 0, 10)]));
        double rest = 2.0 / 14;
        Assert.Equal(4 * rest + 8, two.Strategy("a").Alpha, 9);
        Assert.Equal(4 * (1 - rest) + 2, two.Strategy("a").Beta, 9);
    }

    /// <summary>
    /// PLAN 4a.3: on a provider where the search started with the right family and stopped at its winner, that family
    /// made nearly all of the provider's trials. Its own results must not set the bar it is compared with, or the untried
    /// families would jump ahead of it about every second draw (bandit ≈ 60 strategies against the static 3).
    /// </summary>
    [Fact]
    public void Family_that_made_the_providers_trials_is_not_its_own_bar()
    {
        var set = Standard;
        var first = set.Candidates[0].Family;
        var mine = set.OfFamily(first).ToList();
        var history = new List<ArmStat>();
        // this provider: the static order tried the first family, two variants failed, the third won
        history.Add(Row(mine[0].Key, 0, 2, Asn, Sni, 1, first));
        history.Add(Row(mine[1].Key, 0, 2, Asn, Sni, 1, first));
        history.Add(Row(mine[2].Key, 3, 3, Asn, Sni, 1, first));
        // other providers with the same label: long failed searches over many families, the first one included
        foreach (var c in set.Candidates.Take(150))
            history.Add(Row(c.Key, 0, 2, 3, Sni, 1, c.Family));

        var order = new ThompsonOrder(L(history, new LearningContext(Asn, Sni)));
        // the pool of this provider is the family's own 3/7; the other families have nothing here
        Assert.True(order.Pool.Mean > 0.2, order.Pool.ToString());
        Assert.True(order.Family(first).Mean > 0.3, order.Family(first).ToString());
        int familyFirst = 0, winnerFirst = 0;
        for (int seed = 0; seed < 100; seed++)
        {
            var plan = new ThompsonOrder(L(history, new LearningContext(Asn, Sni), seed)).Arrange([], set.Candidates);
            familyFirst += plan.Take(mine.Count).All(c => c.Family == first) ? 1 : 0;
            winnerFirst += plan[0].Key == mine[2].Key ? 1 : 0;
        }
        // Thompson sampling still explores now and then; with the family's own trials in its bar this was 61 and 57
        Assert.True(familyFirst >= 90, $"family first in {familyFirst}/100 draws");
        Assert.True(winnerFirst >= 80, $"winner first in {winnerFirst}/100 draws");
    }

    [Fact]
    public void Old_results_weigh_less()
    {
        var order = new ThompsonOrder(L([Row("a", 8, 10, daysAgo: 30)]));
        Assert.Equal(0.5, order.Weight(T0.AddDays(-30), T0), 9);
        Assert.Equal(0.25, order.Weight(T0.AddDays(-60), T0), 9);
        Assert.Equal(1, order.Weight(T0, T0), 9);
        // 8/10 a half-life ago counts as 4/5
        Assert.Equal(6, order.Pool.Alpha, 9);
        Assert.Equal(3, order.Pool.Beta, 9);

        var noDecay = new ThompsonOrder(L([Row("a", 8, 10, daysAgo: 30)]) with { HalfLife = TimeSpan.Zero });
        Assert.Equal(10, noDecay.Pool.Alpha, 9);

        // the same wins long ago and a fresh failure streak: the failures decide
        var mixed = new ThompsonOrder(L([Row("a", 10, 10, daysAgo: 120), Row("a", 0, 5)]));
        Assert.True(mixed.Strategy("a").Mean < 0.3);
    }

    [Fact]
    public void Sparse_context_is_shrunk_to_the_broader_ones()
    {
        var ctx = new LearningContext(Asn, Sni);
        // failed everywhere, one lucky success on this ASN: still a poor bet
        var lucky = new ThompsonOrder(L([Row("s", 0, 40, 3, Sni), Row("s", 1, 1, Asn, Sni)], ctx));
        Assert.True(lucky.Strategy("s").Mean < 0.3, lucky.Strategy("s").ToString());
        // a long streak on this ASN outweighs the rest of the world
        var streak = new ThompsonOrder(L([Row("s", 0, 40, 3, Sni), Row("s", 30, 30, Asn, Sni)], ctx));
        Assert.True(streak.Strategy("s").Mean > 0.8, streak.Strategy("s").ToString());
    }

    [Fact]
    public void Unknown_context_falls_back_to_label_then_global()
    {
        ArmStat[] rows = [Row("s", 20, 20, 2, Sni), Row("s", 0, 20, 3, "Cutoff16K")];
        double global = new ThompsonOrder(L(rows)).Strategy("s").Mean;
        double label = new ThompsonOrder(L(rows, new LearningContext(null, Sni))).Strategy("s").Mean;
        double unknownAsn = new ThompsonOrder(L(rows, new LearningContext(999, Sni))).Strategy("s").Mean;
        double unknownAll = new ThompsonOrder(L(rows, new LearningContext(999, "Ech"))).Strategy("s").Mean;
        Assert.InRange(global, 0.4, 0.6);
        Assert.True(label > 0.8);
        // levels without data keep the broader mean
        Assert.Equal(label, unknownAsn, 9);
        Assert.Equal(global, unknownAll, 9);
        // a client profile level only applies to a non-default profile
        double profile = new ThompsonOrder(L([.. rows, Row("s", 0, 10, 2, Sni, profile: "tv")], new LearningContext(2, Sni, "tv"))).Strategy("s").Mean;
        double asnLabel = new ThompsonOrder(L([.. rows, Row("s", 0, 10, 2, Sni, profile: "tv")], new LearningContext(2, Sni))).Strategy("s").Mean;
        Assert.True(profile < asnLabel);
    }

    [Fact]
    public void Without_history_the_static_order_is_kept()
    {
        var set = Standard;
        var prior = new StrategyCandidate(Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5"), "fake", 0, [], L4Kind.Tcp) { Source = CandidateSource.Llm };
        var plan = new ThompsonOrder(L([]) with { SourcePriors = new Dictionary<string, double>() }).Arrange([prior], set.Candidates);
        Assert.Equal([prior.Key, .. set.Candidates.Select(c => c.Key)], plan.Select(c => c.Key));
    }

    [Fact]
    public void Family_that_kept_winning_on_the_asn_is_screened_first()
    {
        var set = Standard;
        var (family, winner, history) = WinnerOnAsn(set);
        Assert.NotEqual(family, set.Candidates[0].Family);
        for (int seed = 0; seed < 20; seed++)
        {
            var plan = new ThompsonOrder(L(history, new LearningContext(Asn, Sni), seed)).Arrange([], set.Candidates);
            Assert.Equal(winner, plan[0].Key);
            Assert.All(plan.Take(set.OfFamily(family).Count()), c => Assert.Equal(family, c.Family));
        }
    }

    [Fact]
    public async Task Search_uses_the_learned_order_and_finds_the_winner_first()
    {
        var set = Standard;
        var (_, winner, history) = WinnerOnAsn(set);
        var dpi = new SimDpi(k => k == winner);
        var r = await new StrategySearch(dpi, new SearchOptions
        {
            StopAfterFound = 1,
            Learning = L(history, new LearningContext(Asn, Sni)),
        }).RunAsync();
        Assert.Equal(winner, dpi.Runs[0]);
        Assert.Equal(winner, r.Best?.Candidate.Key);
        Assert.Equal(1, r.Tried);

        // the bandit off: the static order, the winner comes last
        var stat = new SimDpi(k => k == winner);
        await new StrategySearch(stat, new SearchOptions { StopAfterFound = 1 }).RunAsync();
        Assert.Equal(set.Candidates[0].Key, stat.Runs[0]);
        Assert.Equal(winner, stat.Runs[^1]);
    }

    [Theory]
    [InlineData(SearchMode.Quick)]
    [InlineData(SearchMode.Standard)]
    [InlineData(SearchMode.Full)]
    public void Learned_order_is_a_permutation_in_every_mode(SearchMode mode)
    {
        var set = StrategyGenerator.Generate(new GeneratorOptions { Mode = mode });
        var (_, _, history) = WinnerOnAsn(set);
        var plan = new ThompsonOrder(L(history, new LearningContext(Asn, Sni))).Arrange([], set.Candidates);
        Assert.Equal(set.Candidates.Select(c => c.Key).Order(StringComparer.Ordinal), plan.Select(c => c.Key).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Every_family_is_still_screened()
    {
        var set = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Quick });
        var (_, _, history) = WinnerOnAsn(set);
        var dpi = new SimDpi(_ => false);
        var r = await new StrategySearch(dpi, new SearchOptions
        {
            Generator = new GeneratorOptions { Mode = SearchMode.Quick },
            Learning = L(history, new LearningContext(Asn, Sni)),
        }).RunAsync();
        Assert.Equal(SearchStopReason.Exhausted, r.Reason);
        Assert.Equal(set.Candidates.Select(c => c.Family).ToHashSet(), dpi.Runs.Select(k => set.Candidates.First(c => c.Key == k).Family).ToHashSet());
        Assert.Equal(set.Candidates.Count, dpi.Runs.Distinct().Count());
    }

    [Fact]
    public async Task Fixed_seed_gives_the_same_order()
    {
        var set = Standard;
        var (_, _, history) = WinnerOnAsn(set);
        // a noisy history so the draws matter
        history.AddRange(set.Candidates.Where((_, i) => i % 7 == 0).Select((c, i) => Row(c.Key, i % 3, 3, Asn, Sni, i % 20, c.Family)));
        var a = new ThompsonOrder(L(history, new LearningContext(Asn, Sni), 42)).Arrange([], set.Candidates);
        var b = new ThompsonOrder(L(history, new LearningContext(Asn, Sni), 42)).Arrange([], set.Candidates);
        Assert.Equal(a.Select(c => c.Key), b.Select(c => c.Key));

        var o = new SearchOptions { Generator = new GeneratorOptions { Mode = SearchMode.Quick }, Learning = L(history, new LearningContext(Asn, Sni), 7) };
        var d1 = new SimDpi(_ => false);
        var d2 = new SimDpi(_ => false);
        await new StrategySearch(d1, o).RunAsync();
        await new StrategySearch(d2, o).RunAsync();
        Assert.Equal(d1.Runs, d2.Runs);
    }

    [Fact]
    public void Outside_sources_are_arms_with_their_own_prior()
    {
        var set = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Quick });
        var llm = new StrategyCandidate(Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:badsum"), "fake", 0, [], L4Kind.Tcp) { Source = CandidateSource.Llm };
        // the generated families mostly fail here; nothing is known about the LLM yet
        var pool = set.Candidates.Select(c => Row(c.Key, 0, 2, Asn, Sni, 1, c.Family)).ToList();
        var ctx = new LearningContext(Asn, Sni);
        var fresh = new ThompsonOrder(L(pool, ctx));
        Assert.Equal(0.5, fresh.Source(CandidateSource.Llm).Mean, 1);
        for (int seed = 0; seed < 20; seed++)
            Assert.Equal(llm.Key, new ThompsonOrder(L(pool, ctx, seed)).Arrange([llm], set.Candidates)[0].Key);

        // its suggestions kept failing on this provider while a family kept winning: the family goes first now
        var (_, winner, wins) = WinnerOnAsn(set);
        List<ArmStat> failedLlm = [.. pool, .. wins, .. Enumerable.Range(1, 10).Select(d => Row("--lua-desync=x" + d, 0, 3, Asn, Sni, d, "fake", CandidateSource.Llm))];
        Assert.True(new ThompsonOrder(L(failedLlm, ctx)).Source(CandidateSource.Llm).Mean < 0.1);
        for (int seed = 0; seed < 20; seed++)
            Assert.Equal(winner, new ThompsonOrder(L(failedLlm, ctx, seed)).Arrange([llm], set.Candidates)[0].Key);
    }

    [Fact]
    public async Task Search_tags_outside_candidates_and_refinement_children()
    {
        const string Midsld = "--payload=tls_client_hello --lua-desync=multisplit:pos=midsld";
        const string MidsldPlus1 = "--payload=tls_client_hello --lua-desync=multisplit:pos=midsld+1";
        var prior = new StrategyCandidate(Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5"), "fake", 0, [], L4Kind.Tcp);
        int n = 0;
        var log = new List<(string Key, string Source)>();
        var dpi = new SimDpiLog(k => k == MidsldPlus1 || (k == Midsld && n++ % 2 == 1));
        await new StrategySearch(dpi, new SearchOptions { Priors = [prior], StopAfterFound = 1 }, new SourceLog(log)).RunAsync();
        Assert.Equal((prior.Key, CandidateSource.Prior), log[0]);
        Assert.Contains((Midsld, CandidateSource.Generator), log);
        Assert.Contains((MidsldPlus1, CandidateSource.Mutation), log);
    }

    private sealed class SimDpiLog(Func<string, bool> works) : ITrialExecutor
    {
        public Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
        {
            var list = new List<TrialOutcome>();
            for (int i = 0; i < attempts && !stopEarly(list); i++)
                list.Add(works(candidate.Key) ? TrialOutcome.Success() : TrialOutcome.Fail(TrialFailure.Reset));
            return Task.FromResult<IReadOnlyList<TrialOutcome>>(list);
        }

        public Task<bool> TargetReachableAsync(CancellationToken ct) => Task.FromResult(true);
    }

    private sealed class SourceLog(List<(string, string)> trials) : ISearchLog
    {
        public void Trial(StrategyCandidate candidate, TrialOutcome outcome) => trials.Add((candidate.Key, candidate.Source));

        public void Tuning(Strategy parent, Mutation child, Efficiency efficiency, bool accepted)
        {
        }

        public void Checkpoint(int index)
        {
        }
    }
}
