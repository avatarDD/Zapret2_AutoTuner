using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Tuning;

/// <summary>The verdict of the final check of one strategy (PLAN 3.4).</summary>
public sealed record FinalCheckResult(FoundStrategy Strategy, Efficiency L2, bool? PageOk, IReadOnlyList<SecondaryDomain> Domains, string? Error)
{
    /// <summary>N/N at L2 and, when the page was opened, a full page load with its important domains (L3).</summary>
    public bool Passed => Error is null && L2.Working && L2.Successes == L2.Attempts && PageOk != false;
}

/// <summary>
/// Final check of found strategies (PLAN 3.4, dpi-diagnostics §6.4): one engine instance per strategy, N/N L2
/// attempts, then the page in a browser with the engine still up; the page passes only when it loads and none of its
/// important domains broke. Strategies that fail are dropped, the rest keep their ranking.
/// </summary>
public static class FinalCheck
{
    /// <param name="openPage">Opens the page through the running engine (BrowserProbe); null skips L3.</param>
    public static async Task<IReadOnlyList<FinalCheckResult>> RunAsync(AgentTrialExecutor executor, IEnumerable<FoundStrategy> found, string mainHost,
        Func<CancellationToken, Task<PageLoad>>? openPage, int attempts = 5, CancellationToken ct = default)
    {
        var results = new List<FinalCheckResult>();
        foreach (var f in found)
        {
            try
            {
                results.Add(await executor.WithEngineAsync(f.Candidate, async ct =>
                {
                    var series = await executor.ProbeSeriesAsync(attempts, o => o.Any(x => !x.Ok), ct).ConfigureAwait(false);
                    var l2 = new Efficiency(series.Count(o => o.Ok), series.Count);
                    // a failed L2 attempt already rules the strategy out: no browser for it
                    if (openPage is null || l2.Successes < attempts)
                        return new FinalCheckResult(f, l2, null, [], null);
                    var load = await openPage(ct).ConfigureAwait(false);
                    var domains = SecondaryDomains.Analyze(load, mainHost);
                    return new FinalCheckResult(f, l2, SecondaryDomains.PagePasses(load, domains), domains, null);
                }, ct).ConfigureAwait(false));
            }
            catch (EngineRefusedException e)
            {
                results.Add(new FinalCheckResult(f, default, null, [], e.Message));
            }
        }
        return results;
    }
}
