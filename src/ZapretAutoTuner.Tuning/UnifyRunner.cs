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

    /// <summary>
    /// Upper bound on cross-check runs (each is one engine start and up to N probes), split between TCP and QUIC;
    /// what one protocol does not need goes to the other. Skipped checks do not count.
    /// </summary>
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
        var groups = new Dictionary<L4Kind, List<string>>();
        var queues = new Dictionary<L4Kind, List<(Strategy Strategy, double Score, string Domain)>>();
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
            groups[l4] = group;
            queues[l4] = [.. candidates.SelectMany(c => group.Select(d => (c.Strategy, c.Score, d)))];
        }
        // the budget is shared by the protocols, so QUIC is not starved by a long TCP queue
        var budget = new Dictionary<L4Kind, int>();
        int share = queues.Count == 0 ? 0 : options.MaxChecks / queues.Count, spare = options.MaxChecks - share * queues.Count;
        foreach (var (l4, q) in queues.OrderBy(q => q.Value.Count))
        {
            budget[l4] = Math.Min(q.Count, share + spare);
            spare += share - budget[l4];
        }
        int total = budget.Values.Sum(), done = 0;
        foreach (var (l4, queue) in queues)
        {
            var fresh = new Dictionary<string, Dictionary<string, bool>>(StringComparer.Ordinal);
            double? common = null;
            int used = 0;
            foreach (var (s, score, d) in queue)
            {
                if (used >= budget[l4])
                    break;
                // a strategy no better than one that already works everywhere cannot change the plan
                if (common is { } best && score >= best)
                    continue;
                progress?.Report(new UnifyProgress(done, total, $"Перекрёстная проверка: {s} на {d}", $"Cross-check: {s} on {d}"));
                var eff = await checker.CheckAsync(s, d, l4, ct).ConfigureAwait(false);
                used++;
                done++;
                rows.Add(new DomainResult(d, l4, s, eff, score));
                var key = StrategyNormalizer.Key(s);
                if (!fresh.TryGetValue(key, out var cells))
                    fresh[key] = cells = new Dictionary<string, bool>(StringComparer.Ordinal);
                cells[d] = eff.Working;
                if (cells.Count == groups[l4].Count && cells.Values.All(ok => ok))
                    common = Math.Min(score, common ?? double.MaxValue);
            }
        }
        total = done;
        progress?.Report(new UnifyProgress(total, total, "Объединяю стратегии", "Unifying the strategies"));
        return Unifier.Plan(rows, domains);
    }
}
