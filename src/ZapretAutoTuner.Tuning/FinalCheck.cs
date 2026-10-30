using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Tuning;

/// <summary>The verdict of the final check of one strategy (PLAN 3.4).</summary>
public sealed record FinalCheckResult(FoundStrategy Strategy, Efficiency L2, bool? PageOk, IReadOnlyList<SecondaryDomain> Domains, string? Error)
{
    /// <summary>
    /// Full loads at L2 with at most one miss in the series (one lost connection in five is the network, not the DPI)
    /// and, when the page was opened, the target's own part of it loading (L3).
    /// </summary>
    public bool Passed => Error is null && L2.Attempts > 0 && L2.Successes >= FinalCheck.Required(L2.Attempts) && PageOk != false;

    /// <summary>
    /// Important domains of the page that broke besides the target: the trial engine handles only the target's
    /// addresses, so they need targets of their own (the "Домены страницы" step adds them), not another strategy.
    /// </summary>
    public IReadOnlyList<string> OtherBrokenDomains => [.. Domains.Where(d => d.Important && d.Broken && !d.IsMain).Select(d => d.Host)];
}

/// <summary>
/// Final check of found strategies (PLAN 3.4, dpi-diagnostics §6.4): one engine instance per strategy, the L2 series,
/// then the page in a browser with the engine still up. The strategy is judged on the target: the trial engine handles
/// only the target's addresses, so the page's other domains (a CDN, an image host) go untouched and their failures are
/// reported for their own targets instead of dropping a strategy that works. Strategies that fail are dropped, the rest
/// keep their ranking.
/// </summary>
public static class FinalCheck
{
    /// <summary>Successes needed in a series of <paramref name="attempts"/>: all of them, less one miss from five on.</summary>
    public static int Required(int attempts) => attempts >= 5 ? attempts - 1 : attempts;

    /// <param name="openPage">Opens the page through the running engine (BrowserProbe); null skips L3.</param>
    public static async Task<IReadOnlyList<FinalCheckResult>> RunAsync(AgentTrialExecutor executor, IEnumerable<FoundStrategy> found, string mainHost,
        Func<CancellationToken, Task<PageLoad>>? openPage, int attempts = 5, CancellationToken ct = default)
    {
        var results = new List<FinalCheckResult>();
        int allowedMisses = attempts - Required(attempts);
        foreach (var f in found)
        {
            try
            {
                results.Add(await executor.WithEngineAsync(f.Candidate, async ct =>
                {
                    var series = await executor.ProbeSeriesAsync(attempts, o => o.Count(x => !x.Ok) > allowedMisses, ct).ConfigureAwait(false);
                    var l2 = new Efficiency(series.Count(o => o.Ok), series.Count);
                    // a strategy L2 already rules out gets no browser
                    if (openPage is null || l2.Successes < Required(attempts))
                        return new FinalCheckResult(f, l2, null, [], null);
                    var load = await openPage(ct).ConfigureAwait(false);
                    var domains = SecondaryDomains.Analyze(load, mainHost);
                    return new FinalCheckResult(f, l2, TargetPartLoads(load, domains), domains, null);
                }, ct).ConfigureAwait(false));
            }
            catch (EngineRefusedException e)
            {
                results.Add(new FinalCheckResult(f, default, null, [], e.Message));
            }
        }
        return results;
    }

    /// <summary>
    /// The document came and the target's own requests went through. The load event is not required: it waits for the
    /// other domains too, which this engine does not handle.
    /// </summary>
    internal static bool TargetPartLoads(PageLoad load, IReadOnlyList<SecondaryDomain> domains) =>
        load.Error is null && !domains.Any(d => d.IsMain && d.Broken);
}
