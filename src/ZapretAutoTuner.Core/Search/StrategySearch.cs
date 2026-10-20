using System.Diagnostics;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Search;

public enum TrialFailure
{
    None,
    Reset,
    Timeout,
    Stalled,
    BadCertificate,

    /// <summary>Not even a TCP connection: the address stopped answering (a punishment sign).</summary>
    NoConnect,
    Other,
}

/// <summary>One attempt of a strategy against the target.</summary>
public sealed record TrialOutcome(bool Ok, TrialFailure Failure = TrialFailure.None, string? Detail = null, long BytesIn = 0, TimeSpan Duration = default)
{
    public static TrialOutcome Success(long bytes = 0) => new(true, TrialFailure.None, null, bytes);

    public static TrialOutcome Fail(TrialFailure f, string? detail = null) => new(false, f, detail);
}

/// <summary>
/// Runs a strategy for real: the engine for the target's addresses, then the probe. Implemented over the Agent in
/// ZapretAutoTuner.Tuning; tests use a simulated DPI.
/// </summary>
public interface ITrialExecutor
{
    /// <summary>
    /// Starts the engine with the strategy, probes the target up to <paramref name="attempts"/> times and stops the
    /// engine. <paramref name="stopEarly"/> sees the outcomes so far and may end the series.
    /// </summary>
    Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct);

    /// <summary>Whether the target answers a TCP connect without the engine (after a punishment pause).</summary>
    Task<bool> TargetReachableAsync(CancellationToken ct);
}

/// <summary>Where the search writes what it learns (the knowledge base); optional.</summary>
public interface ISearchLog
{
    void Trial(StrategyCandidate candidate, TrialOutcome outcome);

    void Tuning(Strategy parent, Mutation child, Efficiency efficiency, bool accepted);

    void Checkpoint(int index);
}

public enum SearchStage
{
    Preparing,

    /// <summary>Strategies that worked for others on this provider (§6.2 adaptive search).</summary>
    Priors,
    Screening,

    /// <summary>Refining a partly working strategy by mutations (§6.2a).</summary>
    Refining,

    /// <summary>The DPI punishes the address: waiting it out.</summary>
    Paused,
    Done,
}

public enum SearchStopReason
{
    Exhausted,
    EnoughFound,
    Cancelled,
    Punished,
}

public sealed record FoundStrategy(StrategyCandidate Candidate, Efficiency Efficiency, ScoreBreakdown Score, string? MutationPath = null)
{
    public bool Refined => MutationPath is not null;
}

/// <summary>What the user sees while the search runs: the stage, the current strategy, what was found, ≈% and time.</summary>
public sealed record SearchProgress
{
    public SearchStage Stage { get; init; }

    public string MessageRu { get; init; } = "";

    public string MessageEn { get; init; } = "";

    public int Done { get; init; }

    /// <summary>Done plus what is still planned (families cut by a success are no longer counted).</summary>
    public int Total { get; init; }

    public double Percent => Total == 0 ? 100 : Math.Min(100, 100.0 * Done / Total);

    public TimeSpan Elapsed { get; init; }

    /// <summary>Rough estimate from the average time per strategy so far; null before the first one finished.</summary>
    public TimeSpan? Remaining { get; init; }

    public StrategyCandidate? Current { get; init; }

    public IReadOnlyList<FoundStrategy> Found { get; init; } = [];

    public FoundStrategy? BestPartial { get; init; }
}

public sealed record SearchResult(IReadOnlyList<FoundStrategy> Working, FoundStrategy? BestPartial, int Tried, SearchStopReason Reason, TimeSpan Elapsed)
{
    public FoundStrategy? Best => Working.Count > 0 ? Working[0] : null;
}

public sealed record SearchOptions
{
    public GeneratorOptions Generator { get; init; } = new();

    /// <summary>Attempts per strategy while screening; N/N is "working".</summary>
    public int Attempts { get; init; } = 3;

    /// <summary>A partly working strategy gets this many attempts before refining (2/5 and 2/10 differ, §6.2a.1).</summary>
    public int PartialAttempts { get; init; } = 5;

    /// <summary>Refinement budget per strategy (§6.2a.4): mutations tried and wall time.</summary>
    public int RefineBudget { get; init; } = 30;

    public TimeSpan RefineTime { get; init; } = TimeSpan.FromMinutes(5);

    public int BeamWidth { get; init; } = 2;

    /// <summary>Stop after this many working strategies unless <see cref="AskContinue"/> says go on (§6.2 early exit).</summary>
    public int StopAfterFound { get; init; } = 3;

    /// <summary>"Found 3 working, continue?": true continues to the end.</summary>
    public Func<IReadOnlyList<FoundStrategy>, CancellationToken, Task<bool>>? AskContinue { get; init; }

    /// <summary>Consecutive attempts without even a TCP connect that mean punishment.</summary>
    public int PunishThreshold { get; init; } = 4;

    public TimeSpan PunishPause { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Pauses per punishment before the search gives up; the count starts again with every punishment.</summary>
    public int MaxPunishPauses { get; init; } = 3;

    /// <summary>Strategies that worked for others on this provider, tried first.</summary>
    public IReadOnlyList<StrategyCandidate> Priors { get; init; } = [];

    /// <summary>A resumed session: strategies already tried and their efficiency are not run again.</summary>
    public IReadOnlyDictionary<string, Efficiency> AlreadyTried { get; init; } = new Dictionary<string, Efficiency>();

    public ExportTargets ExportTargets { get; init; } = ExportTargets.Pc;
}

/// <summary>
/// The strategy search for one target (PLAN 3.2–3.3a, dpi-diagnostics §6): priors first, then the generated families in
/// order, standard-mode cut-offs by success, refinement of partly working strategies before moving on, a punishment
/// pause, early exit, ranking. The engine and the probe are behind <see cref="ITrialExecutor"/>.
/// </summary>
public sealed class StrategySearch(ITrialExecutor executor, SearchOptions options, ISearchLog? log = null, IProgress<SearchProgress>? progress = null)
{
    private readonly Stopwatch _sw = new();
    private readonly List<FoundStrategy> _found = [];
    private readonly HashSet<string> _tried = new(StringComparer.Ordinal);
    private FoundStrategy? _bestPartial;
    private int _done;
    private int _consecutiveNoConnect;
    private int _seriesRun;
    private int _nextAsk;
    private TimeSpan _strategyTime;
    private int _strategiesTimed;

    public async Task<SearchResult> RunAsync(CancellationToken ct = default)
    {
        _sw.Start();
        Report(SearchStage.Preparing, null, 0, "Готовлю список стратегий", "Preparing the strategy list");
        var set = StrategyGenerator.Generate(options.Generator);
        var plan = options.Priors.Concat(set.Candidates).ToList();
        var catalog = FamilyCatalog.Default;
        var reason = SearchStopReason.Exhausted;
        _nextAsk = options.StopAfterFound;
        try
        {
            for (int i = 0; i < plan.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var c = plan[i];
                if (!_tried.Add(c.Key) || Skipped(c.Family, catalog))
                    continue;
                var skippedFamilies = plan.Select(x => x.Family).Distinct().Where(f => Skipped(f, catalog)).ToHashSet();
                int remaining = plan.Skip(i + 1).Count(x => !_tried.Contains(x.Key) && !skippedFamilies.Contains(x.Family)) + 1;
                var stage = i < options.Priors.Count ? SearchStage.Priors : SearchStage.Screening;
                Report(stage, c, remaining,
                    stage == SearchStage.Priors ? $"Проверяю стратегию, которая сработала у вашего провайдера: {c.Family}" : $"Пробую {c.Family}: {c.Strategy}",
                    stage == SearchStage.Priors ? $"Trying a strategy that worked on your provider: {c.Family}" : $"Trying {c.Family}: {c.Strategy}");

                var started = _sw.Elapsed;
                int seriesBefore = _seriesRun;
                var eff = await ScreenAsync(c, ct).ConfigureAwait(false);
                if (eff.Partial)
                    await RefineAsync(c, eff, remaining, ct).ConfigureAwait(false);
                else if (eff.Working)
                    AddFound(new FoundStrategy(c, eff, Score(c.Strategy, eff)));
                _done++;
                // results taken from an interrupted session cost nothing and would make the estimate collapse
                if (_seriesRun > seriesBefore)
                {
                    _strategyTime += _sw.Elapsed - started;
                    _strategiesTimed++;
                }
                log?.Checkpoint(i);

                // asked once per StopAfterFound new strategies: "continue" means look for that many more
                if (options.StopAfterFound > 0 && _found.Count >= _nextAsk)
                {
                    bool more = options.AskContinue is not null && await options.AskContinue(Ranked(), ct).ConfigureAwait(false);
                    if (!more)
                    {
                        reason = SearchStopReason.EnoughFound;
                        break;
                    }
                    _nextAsk = _found.Count + options.StopAfterFound;
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            reason = SearchStopReason.Cancelled;
        }
        catch (PunishedException)
        {
            reason = SearchStopReason.Punished;
        }

        var ranked = Ranked();
        progress?.Report(new SearchProgress
        {
            Stage = SearchStage.Done,
            MessageRu = ranked.Count > 0 ? $"Готово: найдено рабочих стратегий: {ranked.Count}" : _bestPartial is not null ? $"Полностью рабочих нет, лучшая работает в {_bestPartial.Efficiency.Rate:P0} случаев" : "Рабочих стратегий не найдено",
            MessageEn = ranked.Count > 0 ? $"Done: {ranked.Count} working strategies found" : _bestPartial is not null ? $"Nothing fully works; the best works {_bestPartial.Efficiency.Rate:P0} of the time" : "No working strategy found",
            Done = _done,
            Total = _done,
            Elapsed = _sw.Elapsed,
            Remaining = TimeSpan.Zero,
            Found = ranked,
            BestPartial = _bestPartial,
        });
        return new SearchResult(ranked, _bestPartial, _done, reason, _sw.Elapsed);
    }

    /// <summary>Standard mode: a family is not tried once a family it depends on already works (SCANLEVEL=standard).</summary>
    private bool Skipped(string familyId, FamilyCatalog catalog)
    {
        if (options.Generator.Mode == SearchMode.Full || _found.Count == 0)
            return false;
        var family = catalog.Families.FirstOrDefault(f => f.Id == familyId);
        return family is not null && family.SkipIfWorking.Any(id => _found.Any(f => f.Candidate.Family == id));
    }

    /// <summary>Runs the screening attempts. Throws <see cref="PunishedException"/> when punishment did not lift.</summary>
    private async Task<Efficiency> ScreenAsync(StrategyCandidate c, CancellationToken ct)
    {
        if (options.AlreadyTried.TryGetValue(c.Key, out var known) && known.Attempts > 0)
        {
            if (!known.Partial || known.Attempts >= options.PartialAttempts)
                return known;
            // interrupted before the partial strategy got its extra attempts
            var rest = await RunAsync(c, options.PartialAttempts - known.Attempts, _ => false, ct).ConfigureAwait(false);
            return known.Add(Count(rest));
        }
        // a dead strategy costs two attempts: one failure may be a lost packet, two with no success are not
        var outcomes = await RunAsync(c, options.Attempts, o => o.Count(x => !x.Ok) >= 2 && !o.Any(x => x.Ok), ct).ConfigureAwait(false);
        var eff = Count(outcomes);
        if (eff.Partial && eff.Attempts < options.PartialAttempts)
        {
            var more = await RunAsync(c, options.PartialAttempts - eff.Attempts, _ => false, ct).ConfigureAwait(false);
            eff = eff.Add(Count(more));
        }
        return eff;
    }

    /// <summary>
    /// Hill-climbing with a small beam over same-family mutations (§6.2a.4): a child is accepted only when it is better
    /// with a margin (Wilson); the first N/N ends the refinement.
    /// </summary>
    private async Task RefineAsync(StrategyCandidate parent, Efficiency parentEff, int remaining, CancellationToken ct)
    {
        var best = new FoundStrategy(parent, parentEff, Score(parent.Strategy, parentEff));
        var beam = new List<(StrategyCandidate C, Efficiency E, string Path)> { (parent, parentEff, "") };
        int budget = options.RefineBudget;
        var deadline = _sw.Elapsed + options.RefineTime;
        try
        {
        while (budget > 0 && _sw.Elapsed < deadline && beam.Count > 0)
        {
            var next = new List<(StrategyCandidate C, Efficiency E, string Path)>();
            foreach (var (c, e, path) in beam)
            {
                foreach (var m in StrategyMutator.Mutate(c.Strategy, options.Generator, l4: c.L4))
                {
                    if (budget <= 0 || _sw.Elapsed >= deadline)
                        break;
                    if (!_tried.Add(m.Strategy.ToString()))
                        continue;
                    budget--;
                    var child = c with { Strategy = m.Strategy };
                    Report(SearchStage.Refining, child, remaining,
                        $"Довожу частично рабочую ({e}): {m.What}", $"Refining a partly working one ({e}): {m.What}");
                    Efficiency ce;
                    if (options.AlreadyTried.TryGetValue(child.Key, out var known) && known.Attempts > 0)
                        ce = known; // tried before the session was interrupted
                    else
                    {
                        // a child that can no longer beat the parent stops early
                        int allowedFailures = options.PartialAttempts - (int)Math.Ceiling(e.Rate * options.PartialAttempts);
                        ce = Count(await RunAsync(child, options.PartialAttempts, o => o.Count(x => !x.Ok) > allowedFailures, ct).ConfigureAwait(false));
                    }
                    bool accepted = ce.ClearlyBetterThan(e);
                    log?.Tuning(c.Strategy, m, ce, accepted);
                    var childPath = path.Length == 0 ? m.What : path + " → " + m.What;
                    if (ce.Working && ce.Attempts >= options.PartialAttempts)
                    {
                        AddFound(new FoundStrategy(child, ce, Score(child.Strategy, ce), childPath));
                        return;
                    }
                    if (accepted)
                        next.Add((child, ce, childPath));
                    if (ce.Rate > best.Efficiency.Rate)
                        best = new FoundStrategy(child, ce, Score(child.Strategy, ce), childPath);
                }
            }
            beam = [.. next.OrderByDescending(x => x.E.WilsonLower).Take(options.BeamWidth)];
        }
        }
        finally
        {
            // budget spent (or the search stopped) without N/N: remember the best as partial, honestly labelled (§6.2a.5)
            if (_bestPartial is null || best.Efficiency.Rate > _bestPartial.Efficiency.Rate)
                _bestPartial = best;
        }
    }

    /// <summary>
    /// Runs a series and watches for punishment. The series that trips it says nothing about the strategy: it is not
    /// logged and runs again once the address answers. Throws <see cref="PunishedException"/> when it does not come back
    /// after <see cref="SearchOptions.MaxPunishPauses"/> pauses.
    /// </summary>
    private async Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate c, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
    {
        for (bool retried = false; ; retried = true)
        {
            _seriesRun++;
            var outcomes = await executor.RunAsync(c, attempts, stopEarly, ct).ConfigureAwait(false);
            foreach (var o in outcomes)
                _consecutiveNoConnect = o.Failure == TrialFailure.NoConnect ? _consecutiveNoConnect + 1 : 0;
            // the address answered without the engine and the rerun still lost every SYN: that is the strategy
            if (_consecutiveNoConnect < options.PunishThreshold || retried)
            {
                if (retried)
                    _consecutiveNoConnect = 0;
                foreach (var o in outcomes)
                    log?.Trial(c, o);
                return outcomes;
            }

            // the DPI stopped answering even SYNs: wait it out, then check the address without the engine
            int pauses = 0;
            while (true)
            {
                if (pauses++ >= options.MaxPunishPauses)
                    throw new PunishedException();
                Report(SearchStage.Paused, c, 0, $"Провайдер «наказывает» адрес за попытки: пауза {options.PunishPause.TotalSeconds:0} с", $"The provider punishes the address for attempts: pausing {options.PunishPause.TotalSeconds:0} s");
                await Task.Delay(options.PunishPause, ct).ConfigureAwait(false);
                if (await executor.TargetReachableAsync(ct).ConfigureAwait(false))
                    break;
            }
            _consecutiveNoConnect = 0;
        }
    }

    /// <summary>The address stayed unreachable after every punishment pause: the search stops.</summary>
    private sealed class PunishedException : Exception;

    private void AddFound(FoundStrategy f)
    {
        if (_found.All(x => x.Candidate.Key != f.Candidate.Key))
            _found.Add(f);
    }

    private List<FoundStrategy> Ranked() => [.. _found.OrderBy(f => f.Score.Total).ThenBy(f => f.Candidate.Order)];

    private ScoreBreakdown Score(Strategy s, Efficiency e) =>
        StrategyScore.Compute(s, e, targets: options.ExportTargets, customBlobs: [StrategyGenerator.WhiteBlob]);

    private static Efficiency Count(IReadOnlyList<TrialOutcome> o) => new(o.Count(x => x.Ok), o.Count);

    private void Report(SearchStage stage, StrategyCandidate? c, int remaining, string ru, string en)
    {
        if (progress is null)
            return;
        TimeSpan? eta = _strategiesTimed == 0 ? null : _strategyTime / _strategiesTimed * remaining;
        progress.Report(new SearchProgress
        {
            Stage = stage,
            MessageRu = ru,
            MessageEn = en,
            Done = _done,
            Total = _done + remaining,
            Elapsed = _sw.Elapsed,
            Remaining = eta,
            Current = c,
            Found = Ranked(),
            BestPartial = _bestPartial,
        });
    }
}
