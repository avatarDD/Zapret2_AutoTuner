using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Unify;

namespace ZapretAutoTuner.Tuning;

/// <summary>Runs one strategy on one domain for the cross-check (§7.4).</summary>
public interface ICrossChecker
{
    Task<Efficiency> CheckAsync(Strategy strategy, string domain, L4Kind l4, CancellationToken ct);
}

/// <summary>A cross-check through the trial executors of the domains: N attempts, the first failure ends it.</summary>
public sealed class ExecutorCrossChecker(Func<string, ITrialExecutor> executorFor, int attempts = 3) : ICrossChecker
{
    public async Task<Efficiency> CheckAsync(Strategy strategy, string domain, L4Kind l4, CancellationToken ct)
    {
        var outcomes = await executorFor(domain).RunAsync(new StrategyCandidate(strategy, "unify", 0, [], l4), attempts, o => o.Any(x => !x.Ok), ct).ConfigureAwait(false);
        return new Efficiency(outcomes.Count(o => o.Ok), outcomes.Count);
    }
}

public sealed record UnifyOptions
{
    /// <summary>How many of the best candidates per protocol are run on every domain of the group.</summary>
    public int MaxCandidates { get; init; } = 6;

    /// <summary>Upper bound on cross-check runs (each is one engine start and up to N probes).</summary>
    public int MaxChecks { get; init; } = 60;

    public ExportTargets ExportTargets { get; init; } = ExportTargets.Pc;
}

public sealed record UnifyProgress(int Done, int Total, string MessageRu, string MessageEn);

/// <summary>
/// Unification with the mandatory cross-check (PLAN 4.1, dpi-diagnostics §7.4): the best candidates from the
/// per-domain searches are run on every domain of their protocol, the fresh results override history, and then
/// <see cref="Unifier.Plan"/> picks the common strategy or the set cover.
/// </summary>
public static class UnifyRunner
{
    public static async Task<UnifyPlan> RunAsync(IReadOnlyList<DomainResult> history, IReadOnlyCollection<string> domains, ICrossChecker checker,
        UnifyOptions? options = null, IProgress<UnifyProgress>? progress = null, CancellationToken ct = default)
    {
        options ??= new UnifyOptions();
        var rows = history.ToList();
        var plan = new List<(Strategy Strategy, double Score, string Domain, L4Kind L4)>();
        foreach (var l4 in new[] { L4Kind.Tcp, L4Kind.Udp })
        {
            var group = domains.Where(d => rows.Any(r => r.L4 == l4 && r.Domain == d)).ToList();
            if (group.Count < 2)
                continue; // one domain: its own search already is the check
            var candidates = rows.Where(r => r.L4 == l4 && r.Efficiency.Working)
                .GroupBy(r => StrategyNormalizer.Key(r.Strategy))
                .Select(g => (Strategy: StrategyNormalizer.Canonical(g.First().Strategy), Coverage: g.Select(r => r.Domain).Distinct().Count(), Score: g.Min(r => r.Score)))
                .OrderByDescending(c => c.Coverage).ThenBy(c => c.Score)
                .Take(options.MaxCandidates)
                .ToList();
            foreach (var c in candidates)
                foreach (var d in group)
                    plan.Add((c.Strategy, c.Score, d, l4));
        }
        var checks = plan.Take(options.MaxChecks).ToList();
        var groupSize = checks.GroupBy(x => x.L4).ToDictionary(g => g.Key, g => g.Select(x => x.Domain).Distinct().Count());
        var fresh = new Dictionary<(string, L4Kind), Dictionary<string, bool>>();
        var commonFor = new Dictionary<L4Kind, double>();
        for (int i = 0; i < checks.Count; i++)
        {
            var (s, score, d, l4) = checks[i];
            // a strategy no better than one that already works everywhere cannot change the plan
            if (commonFor.TryGetValue(l4, out var best) && score >= best)
                continue;
            progress?.Report(new UnifyProgress(i, checks.Count, $"Перекрёстная проверка: {s} на {d}", $"Cross-check: {s} on {d}"));
            var eff = await checker.CheckAsync(s, d, l4, ct).ConfigureAwait(false);
            rows.Add(new DomainResult(d, l4, s, eff, score));
            var key = (StrategyNormalizer.Key(s), l4);
            if (!fresh.TryGetValue(key, out var cells))
                fresh[key] = cells = new Dictionary<string, bool>(StringComparer.Ordinal);
            cells[d] = eff.Working;
            if (cells.Count == groupSize[l4] && cells.Values.All(ok => ok))
                commonFor[l4] = Math.Min(score, commonFor.GetValueOrDefault(l4, double.MaxValue));
        }
        progress?.Report(new UnifyProgress(checks.Count, checks.Count, "Объединяю стратегии", "Unifying the strategies"));
        return Unifier.Plan(rows, domains);
    }
}
