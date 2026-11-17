using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Tuning;

/// <summary>What a pasted strategy did on one site ("Эксперт" → «Проверить на сайте»).</summary>
public enum SiteCheckVerdict
{
    /// <summary>The site is blocked without a bypass and loads with the strategy every time.</summary>
    Works,

    /// <summary>Blocked without a bypass, loads with the strategy only sometimes.</summary>
    Unstable,

    /// <summary>Blocked without a bypass and with the strategy.</summary>
    Fails,

    /// <summary>The site loads without any bypass: nothing to check the strategy on (AGENTS.md rule 5).</summary>
    NotBlocked,
}

/// <param name="Baseline">Attempts without the engine.</param>
/// <param name="Outcomes">Attempts with the strategy.</param>
public sealed record SiteCheckResult(SiteCheckVerdict Verdict, IReadOnlyList<TrialOutcome> Baseline, IReadOnlyList<TrialOutcome> Outcomes)
{
    public int Ok => Outcomes.Count(o => o.Ok);

    /// <summary>The most frequent failure with the strategy, for the message.</summary>
    public TrialFailure MainFailure =>
        Outcomes.Where(o => !o.Ok).GroupBy(o => o.Failure).OrderByDescending(g => g.Count()).Select(g => g.Key).FirstOrDefault();
}

/// <summary>
/// One strategy checked on one site the way the search checks a candidate (dpi-diagnostics §3): first the baseline
/// without a bypass, which must fail (a strategy "works" only on a blocked site), then a series of full L2 loads
/// with the strategy. Nothing stays running: the engine instance lives only for the series.
/// </summary>
public static class StrategySiteCheck
{
    public const int BaselineAttempts = 2;

    public const int Attempts = 5;

    /// <summary>Linux NFQUEUE of the check: apart from the wizard (300), protection (310/311/320) and geneva (330+).</summary>
    public const int QueueNum = 325;

    /// <param name="baseline">The probe series without the engine (<see cref="AgentTrialExecutor.ProbeSeriesAsync"/>).</param>
    public static async Task<SiteCheckResult> RunAsync(ITrialExecutor executor, Func<int, CancellationToken, Task<IReadOnlyList<TrialOutcome>>> baseline,
        Strategy strategy, CancellationToken ct, int attempts = Attempts)
    {
        // one success without a bypass is enough to say the site is not blocked
        var before = await baseline(BaselineAttempts, ct).ConfigureAwait(false);
        if (before.Any(o => o.Ok))
            return new SiteCheckResult(SiteCheckVerdict.NotBlocked, before, []);
        var candidate = new StrategyCandidate(strategy, "expert", 0, [], L4Kind.Tcp);
        var outcomes = await executor.RunAsync(candidate, attempts, _ => false, ct).ConfigureAwait(false);
        int ok = outcomes.Count(o => o.Ok);
        var verdict = outcomes.Count > 0 && ok == outcomes.Count ? SiteCheckVerdict.Works
            : ok > 0 ? SiteCheckVerdict.Unstable
            : SiteCheckVerdict.Fails;
        return new SiteCheckResult(verdict, before, outcomes);
    }

    /// <summary>
    /// The strategy as a solution of its own for the site: one TCP 80,443 profile limited to the site by hostlist
    /// (and its subdomains), so "Использовать" and the export carry exactly what was checked.
    /// </summary>
    public static Solution SolutionFor(Strategy strategy, string site) => new()
    {
        Profiles =
        [
            new Profile
            {
                Name = "expert",
                TcpPorts = "80,443",
                HostlistDomains = [site],
                Strategy = strategy,
            },
        ],
        Meta = new() { Targets = [site], Title = site },
    };
}
