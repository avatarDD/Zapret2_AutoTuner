using System.Diagnostics;
using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Unify;

namespace ZapretAutoTuner.Tuning;

/// <summary>The stage ribbon of a target in the wizard (PLAN 8, step 3).</summary>
public enum PipelineStage
{
    Waiting,
    Classify,
    Search,
    Refine,
    FinalCheck,
    Unify,
    Done,
    Skipped,
    Failed,
}

/// <summary>What the runner publishes; the UI only subscribes (PLAN 8: StageChanged, TrialStarted, TrialResult, CandidateFound, FamilySkipped).</summary>
public abstract record PipelineEvent(string Target, DateTime Time);

public sealed record StageChanged(string Target, DateTime Time, PipelineStage Stage, string MessageRu, string MessageEn) : PipelineEvent(Target, Time);

public sealed record TrialStarted(string Target, DateTime Time, StrategyCandidate Candidate) : PipelineEvent(Target, Time);

public sealed record TrialResult(string Target, DateTime Time, StrategyCandidate Candidate, TrialOutcome Outcome) : PipelineEvent(Target, Time);

public sealed record CandidateFound(string Target, DateTime Time, FoundStrategy Found) : PipelineEvent(Target, Time);

public sealed record FamilySkipped(string Target, DateTime Time, string Family, string ReasonRu, string ReasonEn) : PipelineEvent(Target, Time);

/// <summary>Overall progress: percent done and an estimate of what is left, marked "≈" in the UI.</summary>
public sealed record OverallProgress(string Target, DateTime Time, double Percent, TimeSpan Elapsed, TimeSpan? Remaining, string MessageRu, string MessageEn) : PipelineEvent(Target, Time);

public sealed record TargetOutcome(string Host, ClassifierVerdict? Verdict, SearchResult? Search, IReadOnlyList<FinalCheckResult> Final, string? Error)
{
    /// <summary>The strategy that passed the final check (or, without one, the best found).</summary>
    public FoundStrategy? Best => Final.FirstOrDefault(f => f.Passed)?.Strategy ?? (Final.Count == 0 ? Search?.Best : null);
}

public sealed record PipelineResult(IReadOnlyList<TargetOutcome> Targets, UnifyPlan? Plan, Solution? Solution);

/// <summary>What the pipeline needs from the world; the app wires the Agent, the probes and the knowledge base.</summary>
public interface IPipelineServices
{
    Task<ClassifierVerdict> ClassifyAsync(string host, IProgress<(string Ru, string En)> progress, CancellationToken ct);

    /// <summary>The executor for a target at its live addresses (AgentTrialExecutor on the PC, RouterTrialExecutor on the router).</summary>
    ITrialExecutor ExecutorFor(string host, IReadOnlyList<IPAddress> addresses);

    /// <summary>The final check (PLAN 3.4); null skips it (the router mode checks on the router).</summary>
    Task<IReadOnlyList<FinalCheckResult>>? FinalCheckAsync(string host, ITrialExecutor executor, IReadOnlyList<FoundStrategy> found, CancellationToken ct) => null;

    /// <summary>Where the search writes what it learns; null for none.</summary>
    ISearchLog? LogFor(string host, ClassifierVerdict verdict) => null;

    /// <summary>Last say on a target's search options (priors from the knowledge base, a resumed session); called after <see cref="LogFor"/>.</summary>
    SearchOptions OptionsFor(string host, ClassifierVerdict verdict, SearchOptions options) => options;

    /// <summary>Called when a search ends, to store the ranking.</summary>
    void Finished(string host, SearchResult result)
    {
    }
}

public sealed record PipelineOptions
{
    public SearchOptions Search { get; init; } = new();

    /// <summary>Run the cross-check and build one config for all domains.</summary>
    public bool Unify { get; init; } = true;
}

/// <summary>
/// The whole tuning of a list of domains (PLAN 3–5 in one run): classify each (the baseline is mandatory: a domain
/// that opens is skipped), search a strategy where a strategy can help, check it, then unify everything into one
/// solution. Every step is published as an event; nothing here talks to the UI directly.
/// </summary>
public sealed class TuningPipeline(IPipelineServices services, PipelineOptions options)
{
    public event Action<PipelineEvent>? Event;

    public async Task<PipelineResult> RunAsync(IReadOnlyList<string> hosts, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var outcomes = new List<TargetOutcome>();
        var executors = new Dictionary<string, ITrialExecutor>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < hosts.Count; i++)
        {
            // "Остановить и взять лучшее": a stop ends the run, what was found so far still becomes a solution
            if (ct.IsCancellationRequested)
                break;
            var host = hosts[i];
            TargetOutcome outcome;
            ITrialExecutor? executor;
            try
            {
                (outcome, executor) = await TargetAsync(host, i, hosts.Count, sw, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                Stage(host, PipelineStage.Skipped, "Остановлено", "Stopped");
                break;
            }
            outcomes.Add(outcome);
            if (executor is not null)
                executors[host] = executor;
        }

        var results = outcomes.Where(o => o.Best is not null)
            .Select(o => new DomainResult(o.Host, o.Best!.Candidate.L4, o.Best.Candidate.Strategy, o.Best.Efficiency, o.Best.Score.Total))
            .ToList();
        if (results.Count == 0)
            return new PipelineResult(outcomes, null, null);
        UnifyPlan plan;
        if (options.Unify && results.Count > 1 && !ct.IsCancellationRequested)
        {
            Publish(new StageChanged("*", DateTime.UtcNow, PipelineStage.Unify, "Объединяю стратегии доменов", "Unifying the domains' strategies"));
            var checker = new ExecutorCrossChecker(d => executors[d]);
            plan = await UnifyRunner.RunAsync(results, results.Select(r => r.Domain).Distinct().ToList(), checker, null, null, ct).ConfigureAwait(false);
        }
        else
        {
            plan = Unifier.Plan(results);
        }
        var solution = Unifier.ToSolution(plan);
        Publish(new StageChanged("*", DateTime.UtcNow, PipelineStage.Done, "Готово", "Done"));
        return new PipelineResult(outcomes, plan, solution);
    }

    private async Task<(TargetOutcome, ITrialExecutor?)> TargetAsync(string host, int index, int count, Stopwatch sw, CancellationToken ct)
    {
        Stage(host, PipelineStage.Classify, $"Проверяю, что именно блокируется: {host}", $"Finding out what blocks {host}");
        ClassifierVerdict verdict;
        try
        {
            verdict = await services.ClassifyAsync(host, new Progress<(string Ru, string En)>(m => Stage(host, PipelineStage.Classify, m.Ru, m.En)), ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Stage(host, PipelineStage.Failed, "Диагностика не удалась: " + e.Message, "Diagnostics failed: " + e.Message);
            return (new TargetOutcome(host, null, null, [], e.Message), null);
        }
        if (verdict.Next != NextStep.SearchStrategy)
        {
            Stage(host, PipelineStage.Skipped, verdict.SummaryRu, verdict.SummaryEn);
            return (new TargetOutcome(host, verdict, null, [], null), null);
        }

        var addresses = verdict.LiveAddresses.Select(IPAddress.Parse).ToList();
        var executor = services.ExecutorFor(host, addresses);
        var searchOptions = options.Search with
        {
            Generator = options.Search.Generator with { Labels = verdict.Labels },
            Learning = options.Search.Learning is { } learning ? learning with { Context = learning.Context with { Label = verdict.Primary.ToString() } } : null,
        };
        var progress = new Progress<SearchProgress>(p => OnSearch(host, p, index, count, sw));
        var log = services.LogFor(host, verdict);
        searchOptions = services.OptionsFor(host, verdict, searchOptions);
        var search = new StrategySearch(new ObservedExecutor(executor, host, Publish), searchOptions, log, progress);
        Stage(host, PipelineStage.Search, $"Подбираю стратегию: {verdict.SummaryRu}", $"Searching a strategy: {verdict.SummaryEn}");
        var result = await search.RunAsync(ct).ConfigureAwait(false);
        services.Finished(host, result);
        foreach (var f in result.Working)
            Publish(new CandidateFound(host, DateTime.UtcNow, f));

        IReadOnlyList<FinalCheckResult> final = [];
        if (result.Working.Count > 0 && !ct.IsCancellationRequested && services.FinalCheckAsync(host, executor, result.Working, ct) is { } check)
        {
            Stage(host, PipelineStage.FinalCheck, "Финальная проверка найденных стратегий", "Final check of the found strategies");
            final = await check.ConfigureAwait(false);
        }
        var outcome = new TargetOutcome(host, verdict, result, final, null);
        Stage(host, outcome.Best is null ? PipelineStage.Failed : PipelineStage.Done,
            outcome.Best is null ? "Рабочая стратегия не найдена" : $"Найдено: {outcome.Best.Candidate.Strategy}",
            outcome.Best is null ? "No working strategy found" : $"Found: {outcome.Best.Candidate.Strategy}");
        return (outcome, executor);
    }

    private void OnSearch(string host, SearchProgress p, int index, int count, Stopwatch sw)
    {
        var stage = p.Stage == SearchStage.Refining ? PipelineStage.Refine : PipelineStage.Search;
        Stage(host, stage, p.MessageRu, p.MessageEn);
        // the targets share the bar evenly; within a target the search's own estimate counts
        double percent = (index + p.Percent / 100.0) / count * 100.0;
        TimeSpan? remaining = percent > 0.5 ? TimeSpan.FromTicks((long)(sw.Elapsed.Ticks * (100 - percent) / percent)) : null;
        Publish(new OverallProgress(host, DateTime.UtcNow, percent, sw.Elapsed, remaining, p.MessageRu, p.MessageEn));
    }

    private void Stage(string host, PipelineStage stage, string ru, string en) => Publish(new StageChanged(host, DateTime.UtcNow, stage, ru, en));

    private void Publish(PipelineEvent e) => Event?.Invoke(e);

    /// <summary>Publishes every trial of the wrapped executor.</summary>
    private sealed class ObservedExecutor(ITrialExecutor inner, string host, Action<PipelineEvent> publish) : ITrialExecutor
    {
        public async Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
        {
            publish(new TrialStarted(host, DateTime.UtcNow, candidate));
            var outcomes = await inner.RunAsync(candidate, attempts, stopEarly, ct).ConfigureAwait(false);
            foreach (var o in outcomes)
                publish(new TrialResult(host, DateTime.UtcNow, candidate, o));
            return outcomes;
        }

        public Task<bool> TargetReachableAsync(CancellationToken ct) => inner.TargetReachableAsync(ct);
    }
}
