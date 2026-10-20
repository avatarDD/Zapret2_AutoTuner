using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Monitor;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Tuning;

public enum RepairVerdict
{
    /// <summary>The domain opens without bypass now: offer to drop it from the strategy.</summary>
    BlockLifted,

    /// <summary>The current strategy passes the synthetic check: the degradation was the site or the network.</summary>
    StillWorks,

    /// <summary>The site does not answer at all, with or without bypass.</summary>
    SiteDown,

    /// <summary>A new strategy was found.</summary>
    Replaced,

    NotFound,
}

public sealed record RepairResult(string Domain, RepairVerdict Verdict, StrategyCandidate? Strategy, string ReasonRu, string ReasonEn);

/// <summary>What the repair needs from the outside world; the Agent and the search do it for real, tests fake it.</summary>
public interface IRepairSteps
{
    /// <summary>The domain loads (L2) without any bypass.</summary>
    Task<bool> BaselineWorksAsync(string domain, CancellationToken ct);

    /// <summary>The domain's server answers at all (TCP connect to its addresses).</summary>
    Task<bool> ReachableAsync(string domain, CancellationToken ct);

    /// <summary>N L2 attempts with the strategy.</summary>
    Task<Efficiency> CheckAsync(string domain, StrategyCandidate current, CancellationToken ct);

    /// <summary>Neighbours of the current strategy (§6.2a mutations); the best working one or null.</summary>
    Task<StrategyCandidate?> LocalSearchAsync(string domain, StrategyCandidate current, CancellationToken ct);

    /// <summary>The full search for the domain; the best working one or null.</summary>
    Task<StrategyCandidate?> FullSearchAsync(string domain, CancellationToken ct);
}

/// <summary>
/// Auto-repair of a degraded domain (PLAN 7.3, dpi-diagnostics §9), cheapest step first: is the block gone, does the
/// current strategy still pass, is the site down for everyone, then a local search around the current strategy, then
/// the full search. Applying a result is the caller's business and follows the user's policy.
/// </summary>
public static class RepairRunner
{
    public static async Task<RepairResult> RunAsync(string domain, StrategyCandidate current, IRepairSteps steps, IProgress<string>? stage = null, CancellationToken ct = default)
    {
        stage?.Report("baseline");
        if (await steps.BaselineWorksAsync(domain, ct).ConfigureAwait(false))
            return new(domain, RepairVerdict.BlockLifted, null, "сайт открывается без обхода: блокировку сняли, домен можно убрать из стратегии",
                "the site opens without bypass: the block is gone, the domain can leave the strategy");

        stage?.Report("check");
        var eff = await steps.CheckAsync(domain, current, ct).ConfigureAwait(false);
        if (eff.Attempts > 0 && eff.Successes == eff.Attempts)
            return new(domain, RepairVerdict.StillWorks, current, $"текущая стратегия проходит проверку {eff.Successes}/{eff.Attempts}: сбой был у сайта или в сети",
                $"the current strategy passes {eff.Successes}/{eff.Attempts}: the failures were the site's or the network's");

        stage?.Report("reachability");
        if (!await steps.ReachableAsync(domain, ct).ConfigureAwait(false))
            return new(domain, RepairVerdict.SiteDown, null, "сервер сайта не отвечает даже на TCP: сайт лежит или заблокирован по IP, стратегия тут не поможет",
                "the site's server does not answer TCP: it is down or blocked by IP, no strategy helps");

        stage?.Report("local");
        if (await steps.LocalSearchAsync(domain, current, ct).ConfigureAwait(false) is { } local)
            return new(domain, RepairVerdict.Replaced, local, "блокировка изменилась; найдена соседняя стратегия", "the block changed; a neighbouring strategy works");

        stage?.Report("full");
        if (await steps.FullSearchAsync(domain, ct).ConfigureAwait(false) is { } full)
            return new(domain, RepairVerdict.Replaced, full, "блокировка изменилась; новая стратегия найдена полным перебором", "the block changed; the full search found a new strategy");

        return new(domain, RepairVerdict.NotFound, null, "рабочая стратегия не найдена: соберите отчёт", "no working strategy found: build a report");
    }

    /// <summary>The journal kind of a verdict (change_journal.kind).</summary>
    public static string JournalKind(RepairVerdict v) => v switch
    {
        RepairVerdict.BlockLifted => "block_lifted",
        RepairVerdict.StillWorks => "recovered",
        RepairVerdict.SiteDown => "site_down",
        RepairVerdict.Replaced => "repaired",
        _ => "not_found",
    };
}

public enum ApplyPolicy
{
    /// <summary>The default: a found strategy waits for the user's yes.</summary>
    Ask,

    /// <summary>"Применять сам": the user allowed it in the settings.</summary>
    Auto,
}

/// <summary>
/// Hot replacement of the strategy for one domain (PLAN 7.3.4): the new instance starts first, the old one stops only
/// when the new one runs, so the domain is never left without bypass. On Windows the two instances' filters differ
/// (the new one is limited to the domain's addresses), which keeps WinDivert's duplicate check happy.
/// </summary>
public static class HotSwap
{
    /// <returns>The new instance id; the old one keeps running when the start fails.</returns>
    public static async Task<string> ReplaceAsync(IEngineControl engine, string? oldId, IReadOnlyList<string> argv, Protocol.QueueRule? queue, string tag, CancellationToken ct)
    {
        var id = await engine.StartAsync(argv, queue, tag, CancellationToken.None).ConfigureAwait(false);
        if (oldId is not null)
            await engine.StopAsync(oldId, CancellationToken.None).ConfigureAwait(false);
        return id;
    }
}

/// <summary>Turns detector events into repair runs, one domain at a time, and records what happened.</summary>
public sealed class RepairCoordinator(IRepairSteps steps, Func<string, StrategyCandidate?> currentOf, ApplyPolicy policy)
{
    private readonly HashSet<string> _running = new(StringComparer.OrdinalIgnoreCase);

    public ApplyPolicy Policy { get; set; } = policy;

    /// <summary>A repair finished: the UI asks the user (Ask) or the caller applies it (Auto).</summary>
    public event Action<RepairResult, bool>? Finished;

    public event Action<string, string, string>? Journal;

    public bool IsRunning(string domain)
    {
        lock (_running)
            return _running.Contains(domain);
    }

    /// <summary>
    /// "Не работает сейчас" (PLAN 7.5): the user's word is the most precise signal, so the repair starts at once,
    /// without waiting for two bad windows.
    /// </summary>
    public Task<RepairResult?> OnUserReportAsync(string domain, CancellationToken ct) =>
        OnEventAsync(new HealthEvent(domain, HealthChange.Degraded, DateTime.UtcNow, []), ct, "пользователь сообщил, что не работает / the user reported it broken");

    /// <summary>Handles a degradation; a domain already being repaired is skipped.</summary>
    public async Task<RepairResult?> OnEventAsync(HealthEvent e, CancellationToken ct, string? why = null)
    {
        if (e.Change == HealthChange.Recovered)
        {
            Journal?.Invoke(e.Domain, "recovered", "доля неудач снова ниже порога / failures back under the threshold");
            return null;
        }
        if (currentOf(e.Domain) is not { } current)
            return null;
        lock (_running)
        {
            if (!_running.Add(e.Domain))
                return null;
        }
        try
        {
            var last = e.Windows.Count > 0 ? e.Windows[^1] : null;
            Journal?.Invoke(e.Domain, "degraded", why ?? (last is null ? "деградация" : $"неудач {last.Failures}/{last.Sessions}, чаще всего {last.MainFailure}"));
            var r = await RepairRunner.RunAsync(e.Domain, current, steps, null, ct).ConfigureAwait(false);
            Journal?.Invoke(e.Domain, RepairRunner.JournalKind(r.Verdict), r.ReasonRu);
            Finished?.Invoke(r, Policy == ApplyPolicy.Auto && r.Verdict == RepairVerdict.Replaced);
            return r;
        }
        finally
        {
            lock (_running)
                _running.Remove(e.Domain);
        }
    }
}
