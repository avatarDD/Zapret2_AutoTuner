using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Tuning;

/// <summary>
/// <see cref="IRepairSteps"/> over the real search: the executor for a domain (on the PC through the Agent, or on the
/// router) is made by the caller; the baseline is the same probe without an engine.
/// </summary>
public sealed class SearchRepairSteps(
    Func<string, CancellationToken, Task<ITrialExecutor>> executorFor,
    Func<string, CancellationToken, Task<bool>> baselineWorks,
    SearchOptions options,
    int checkAttempts = 5) : IRepairSteps
{
    public Task<bool> BaselineWorksAsync(string domain, CancellationToken ct) => baselineWorks(domain, ct);

    public async Task<bool> ReachableAsync(string domain, CancellationToken ct) =>
        await (await executorFor(domain, ct).ConfigureAwait(false)).TargetReachableAsync(ct).ConfigureAwait(false);

    public async Task<Efficiency> CheckAsync(string domain, StrategyCandidate current, CancellationToken ct)
    {
        var executor = await executorFor(domain, ct).ConfigureAwait(false);
        var outcomes = await executor.RunAsync(current, checkAttempts, o => o.Any(x => !x.Ok), ct).ConfigureAwait(false);
        return new Efficiency(outcomes.Count(o => o.Ok), outcomes.Count);
    }

    /// <summary>The current strategy's mutations first, then the quick set (§6.2a: a changed block is often a neighbour).</summary>
    public async Task<StrategyCandidate?> LocalSearchAsync(string domain, StrategyCandidate current, CancellationToken ct)
    {
        var neighbours = StrategyMutator.Mutate(current.Strategy, options.Generator)
            .Select((m, i) => current with { Strategy = m.Strategy, Family = current.Family, Order = i, Tags = [.. current.Tags, "repair:" + m.What] })
            .ToList();
        return await SearchAsync(domain, options with
        {
            Generator = options.Generator with { Mode = SearchMode.Quick },
            Priors = neighbours,
            StopAfterFound = 1,
            AlreadyTried = new Dictionary<string, Efficiency> { [current.Key] = new(0, checkAttempts) },
        }, ct).ConfigureAwait(false);
    }

    public Task<StrategyCandidate?> FullSearchAsync(string domain, CancellationToken ct) =>
        SearchAsync(domain, options with { StopAfterFound = 1 }, ct);

    private async Task<StrategyCandidate?> SearchAsync(string domain, SearchOptions o, CancellationToken ct)
    {
        var executor = await executorFor(domain, ct).ConfigureAwait(false);
        var result = await new StrategySearch(executor, o).RunAsync(ct).ConfigureAwait(false);
        return result.Best?.Candidate;
    }
}
