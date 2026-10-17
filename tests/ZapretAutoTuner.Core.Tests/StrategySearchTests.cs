using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Core.Tests;

public sealed class StrategySearchTests
{
    /// <summary>A DPI simulated by a rule per strategy: attempt number → success.</summary>
    private sealed class SimDpi(Func<string, int, TrialOutcome> rule) : ITrialExecutor
    {
        public List<string> Runs { get; } = [];

        public Dictionary<string, int> Attempts { get; } = [];

        public Func<bool> Reachable { get; set; } = () => true;

        public int ReachChecks { get; private set; }

        public Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Runs.Add(candidate.Key);
            var list = new List<TrialOutcome>();
            for (int i = 0; i < attempts && !stopEarly(list); i++)
            {
                int n = Attempts.TryGetValue(candidate.Key, out var a) ? a : 0;
                Attempts[candidate.Key] = n + 1;
                list.Add(rule(candidate.Key, n));
            }
            return Task.FromResult<IReadOnlyList<TrialOutcome>>(list);
        }

        public Task<bool> TargetReachableAsync(CancellationToken ct)
        {
            ReachChecks++;
            return Task.FromResult(Reachable());
        }
    }

    private sealed class Log : ISearchLog
    {
        public List<(string, bool)> Trials { get; } = [];

        public List<(string Parent, string Child, string What, Efficiency E, bool Accepted)> Tunings { get; } = [];

        public void Trial(StrategyCandidate candidate, TrialOutcome outcome) => Trials.Add((candidate.Key, outcome.Ok));

        public void Tuning(Strategy parent, Mutation child, Efficiency efficiency, bool accepted) =>
            Tunings.Add((parent.ToString(), child.Strategy.ToString(), child.What, efficiency, accepted));

        public void Checkpoint(int index)
        {
        }
    }

    private sealed class Sync<T>(Action<T> a) : IProgress<T>
    {
        public void Report(T value) => a(value);
    }

    private const string Midsld = "--payload=tls_client_hello --lua-desync=multisplit:pos=midsld";
    private const string MidsldPlus1 = "--payload=tls_client_hello --lua-desync=multisplit:pos=midsld+1";

    private static SearchOptions Quick(Func<SearchOptions, SearchOptions>? tweak = null)
    {
        var o = new SearchOptions { Generator = new GeneratorOptions { Mode = SearchMode.Standard }, PunishPause = TimeSpan.FromMilliseconds(1) };
        return tweak?.Invoke(o) ?? o;
    }

    [Fact]
    public async Task Balanced_dpi_partial_strategy_is_refined_to_full_without_leaving_the_family()
    {
        // PLAN 3.3: two DPI branches take connections in turn; pos=midsld passes only one of them (≈50%), pos=midsld+1 both
        var dpi = new SimDpi((s, n) => s == MidsldPlus1 ? TrialOutcome.Success() : s == Midsld && n % 2 == 1 ? TrialOutcome.Success() : TrialOutcome.Fail(TrialFailure.Reset));
        var log = new Log();
        var steps = new List<SearchProgress>();
        var r = await new StrategySearch(dpi, Quick(o => o with { StopAfterFound = 1 }), log, new Sync<SearchProgress>(steps.Add)).RunAsync();

        Assert.Equal(SearchStopReason.EnoughFound, r.Reason);
        var best = Assert.Single(r.Working);
        Assert.Equal(MidsldPlus1, best.Candidate.Key);
        Assert.Equal("multisplit", best.Candidate.Family);
        Assert.True(best.Refined);
        Assert.Contains("pos=midsld+1", best.MutationPath, StringComparison.Ordinal);
        Assert.Equal(new Efficiency(5, 5), best.Efficiency);
        // the parent got its 5 attempts before refining (2/5 is not 2/3), and no other family ran in between
        Assert.Equal(5, dpi.Attempts[Midsld]);
        int parentAt = dpi.Runs.IndexOf(Midsld);
        Assert.All(dpi.Runs.Skip(parentAt), k => Assert.Contains("multisplit", k, StringComparison.Ordinal));
        Assert.Contains(log.Tunings, t => t.Child == MidsldPlus1 && t.Accepted);
        Assert.Contains(steps, s => s.Stage == SearchStage.Refining);
    }

    [Fact]
    public async Task Dead_strategies_cost_two_attempts_and_standard_mode_cuts_dependent_families()
    {
        // multisplit:pos=2 works; everything else is dead
        const string Works = "--payload=tls_client_hello --lua-desync=multisplit:pos=2";
        var dpi = new SimDpi((s, _) => s == Works ? TrialOutcome.Success() : TrialOutcome.Fail(TrialFailure.Timeout));
        var r = await new StrategySearch(dpi, Quick(o => o with { StopAfterFound = 99 })).RunAsync();

        Assert.Equal(SearchStopReason.Exhausted, r.Reason);
        Assert.Equal(Works, Assert.Single(r.Working).Candidate.Key);
        Assert.All(dpi.Attempts.Where(kv => kv.Key != Works), kv => Assert.Equal(2, kv.Value));
        Assert.Equal(3, dpi.Attempts[Works]);
        // seqovl, fake and the combinations depend on multisplit: not tried once it works
        Assert.DoesNotContain(dpi.Runs, k => k.Contains("lua-desync=fake:", StringComparison.Ordinal) || k.Contains("seqovl=", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Priors_go_first_and_early_exit_asks_the_user()
    {
        var prior = new StrategyCandidate(Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5"), "prior", 0, [], L4Kind.Tcp);
        var dpi = new SimDpi((s, _) => s.Contains("fake:blob=fake_default_tls:tcp_md5", StringComparison.Ordinal) || s.EndsWith("pos=1", StringComparison.Ordinal) ? TrialOutcome.Success() : TrialOutcome.Fail(TrialFailure.Reset));
        int asked = 0;
        var r = await new StrategySearch(dpi, Quick(o => o with
        {
            Priors = [prior],
            StopAfterFound = 2,
            AskContinue = (found, _) =>
            {
                asked++;
                Assert.Equal(2, found.Count);
                return Task.FromResult(false);
            },
        })).RunAsync();

        Assert.Equal(prior.Key, dpi.Runs[0]);
        Assert.Equal(1, asked);
        Assert.Equal(SearchStopReason.EnoughFound, r.Reason);
        Assert.Equal(2, r.Working.Count);
        // ranking: the single split (1 instance, no fooling) beats the fake (§6.3: fewer instances first)
        Assert.True(r.Working[0].Score.Total <= r.Working[1].Score.Total);
    }

    [Fact]
    public async Task Punishment_pauses_then_continues()
    {
        int calls = 0;
        var dpi = new SimDpi((s, _) => ++calls <= 4 ? TrialOutcome.Fail(TrialFailure.NoConnect) : s.EndsWith("pos=midsld", StringComparison.Ordinal) ? TrialOutcome.Success() : TrialOutcome.Fail(TrialFailure.Reset));
        var steps = new List<SearchProgress>();
        var r = await new StrategySearch(dpi, Quick(o => o with { StopAfterFound = 1 }), null, new Sync<SearchProgress>(steps.Add)).RunAsync();
        Assert.Contains(steps, s => s.Stage == SearchStage.Paused && s.MessageRu.Contains("наказывает", StringComparison.Ordinal));
        Assert.Equal(1, dpi.ReachChecks);
        Assert.NotNull(r.Best);
    }

    [Fact]
    public async Task Punishment_that_does_not_lift_stops_the_search()
    {
        var dpi = new SimDpi((_, _) => TrialOutcome.Fail(TrialFailure.NoConnect)) { Reachable = () => false };
        var r = await new StrategySearch(dpi, Quick()).RunAsync();
        Assert.Equal(SearchStopReason.Punished, r.Reason);
        Assert.Equal(3, dpi.ReachChecks);
    }

    [Fact]
    public async Task Progress_shows_percent_elapsed_and_remaining()
    {
        var dpi = new SimDpi((_, _) => TrialOutcome.Fail(TrialFailure.Reset));
        var steps = new List<SearchProgress>();
        var r = await new StrategySearch(dpi, Quick(o => o with { Generator = new GeneratorOptions { Mode = SearchMode.Quick } }), null, new Sync<SearchProgress>(steps.Add)).RunAsync();

        Assert.Equal(SearchStage.Preparing, steps[0].Stage);
        var screening = steps.Where(s => s.Stage == SearchStage.Screening).ToList();
        Assert.True(screening.Count > 10);
        Assert.Null(screening[0].Remaining);
        Assert.NotNull(screening[^1].Remaining);
        Assert.True(screening[^1].Percent > screening[0].Percent);
        Assert.All(screening, s => Assert.InRange(s.Percent, 0, 100));
        Assert.Equal(screening[0].Total, screening[1].Total); // nothing found: the plan does not shrink
        Assert.Equal(SearchStage.Done, steps[^1].Stage);
        Assert.Equal(100, steps[^1].Percent);
        Assert.Equal("Рабочих стратегий не найдено", steps[^1].MessageRu);
        Assert.Equal(r.Tried, steps[^1].Done);
    }

    [Fact]
    public async Task Resumed_session_does_not_rerun_what_was_tried()
    {
        var tried = new Dictionary<string, Efficiency> { [Midsld] = new(0, 2), ["--payload=tls_client_hello --lua-desync=multisplit:pos=1"] = new(0, 2) };
        var dpi = new SimDpi((_, _) => TrialOutcome.Fail(TrialFailure.Reset));
        await new StrategySearch(dpi, Quick(o => o with { AlreadyTried = tried, Generator = new GeneratorOptions { Mode = SearchMode.Quick } })).RunAsync();
        Assert.DoesNotContain(Midsld, dpi.Runs);
        Assert.NotEmpty(dpi.Runs);
    }

    [Fact]
    public async Task Budget_spent_keeps_the_best_partial_with_its_rate()
    {
        // only pos=midsld works, half of the time; no mutation helps
        var dpi = new SimDpi((s, n) => s == Midsld && n % 2 == 1 ? TrialOutcome.Success() : TrialOutcome.Fail(TrialFailure.Reset));
        var r = await new StrategySearch(dpi, Quick(o => o with { RefineBudget = 6, Generator = new GeneratorOptions { Mode = SearchMode.Quick } })).RunAsync();
        Assert.Empty(r.Working);
        Assert.NotNull(r.BestPartial);
        Assert.Equal(Midsld, r.BestPartial!.Candidate.Key);
        Assert.Equal(new Efficiency(2, 5), r.BestPartial.Efficiency);
    }

    [Fact]
    public async Task Cancellation_ends_with_what_was_found()
    {
        using var cts = new CancellationTokenSource();
        int n = 0;
        var dpi = new SimDpi((_, _) =>
        {
            if (++n == 5)
                cts.Cancel();
            return TrialOutcome.Fail(TrialFailure.Reset);
        });
        var r = await new StrategySearch(dpi, Quick()).RunAsync(cts.Token);
        Assert.Equal(SearchStopReason.Cancelled, r.Reason);
    }

    [Fact]
    public void Mutations_change_one_thing_and_stay_valid()
    {
        var fake = Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5 --lua-desync=multisplit:pos=midsld");
        var m = StrategyMutator.Mutate(fake);
        var texts = m.Select(x => x.Strategy.ToString()).ToList();
        Assert.Contains("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=2 --lua-desync=multisplit:pos=midsld", texts);
        Assert.Contains("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_seq=-3000 --lua-desync=multisplit:pos=midsld", texts);
        Assert.Contains("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5 --lua-desync=multisplit:pos=midsld+1", texts);
        Assert.Contains("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5 --lua-desync=multidisorder:pos=midsld", texts);
        Assert.Contains("--payload=tls_client_hello --lua-desync=fake:blob=tls_white:tcp_md5 --lua-desync=multisplit:pos=midsld", texts);
        Assert.Contains(texts, t => t.Contains("seqovl=1:seqovl_pattern=0x1603030000", StringComparison.Ordinal));
        Assert.Contains(m, x => x.What.StartsWith("+второй fake", StringComparison.Ordinal));
        Assert.DoesNotContain(fake.ToString(), texts);
        Assert.Equal(texts.Count, texts.Distinct().Count());

        var ttl = StrategyMutator.Mutate(Strategy.Parse("--lua-desync=fake:blob=fake_default_tls:ip_ttl=5"));
        Assert.Contains(ttl, x => x.Strategy.ToString().EndsWith("ip_ttl=4", StringComparison.Ordinal));
        Assert.Contains(ttl, x => x.Strategy.ToString().EndsWith("ip_ttl=7", StringComparison.Ordinal));
        var auto = StrategyMutator.Mutate(Strategy.Parse("--lua-desync=fake:blob=fake_default_tls:ip_autottl=-2,3-20"));
        Assert.Contains(auto, x => x.Strategy.ToString().EndsWith("ip_autottl=-3,3-20", StringComparison.Ordinal));

        var split = StrategyMutator.Mutate(Strategy.Parse("--payload=tls_client_hello --lua-desync=multisplit:pos=1"));
        Assert.Contains(split, x => x.What == "+fake");
        Assert.Contains(split, x => x.Strategy.ToString().EndsWith("fakedsplit:pos=1:tcp_md5", StringComparison.Ordinal));
        Assert.Equal(["sniext+2", "sniext"], StrategyMutator.NeighbourPositions("sniext+1", single: true).Take(2));
    }

    [Fact]
    public void Score_prefers_simple_portable_strategies()
    {
        var full = new Efficiency(5, 5);
        double Score(string s, Efficiency? e = null, ExportTargets t = ExportTargets.Pc) => StrategyScore.Compute(Strategy.Parse(s), e ?? full, targets: t).Total;
        Assert.True(Score("--lua-desync=multisplit:pos=1") < Score("--lua-desync=fake:blob=fake_default_tls:tcp_md5 --lua-desync=multisplit:pos=1"));
        Assert.True(Score("--lua-desync=fake:blob=fake_default_tls:tcp_md5") < Score("--lua-desync=fake:blob=fake_default_tls:ip_ttl=5"));
        Assert.True(Score("--lua-desync=fake:blob=fake_default_tls:ip_autottl=-2,3-20") < Score("--lua-desync=fake:blob=fake_default_tls:ip_ttl=5"));
        Assert.True(Score("--lua-desync=fake:blob=fake_default_tls:tcp_md5") < Score("--lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=6"));
        Assert.True(Score("--lua-desync=multisplit:pos=1") < Score("--lua-desync=wssize:wsize=1:scale=6"));
        Assert.True(Score("--lua-desync=multisplit:pos=1") < Score("--lua-desync=multisplit:pos=1", new Efficiency(4, 5)));
        var b = StrategyScore.Compute(Strategy.Parse("--lua-desync=fake:blob=fake_default_tls:ip_ttl=5"), full);
        Assert.Contains(b.Parts, p => p.Ru.Contains("TTL", StringComparison.Ordinal));
    }
}
