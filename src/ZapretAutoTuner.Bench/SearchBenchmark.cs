using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Mcp;
using ZapretAutoTuner.Mcp.Advisor;

namespace ZapretAutoTuner.Bench;

/// <summary>Who orders the strategies in a run.</summary>
public enum BenchArm
{
    /// <summary>The generator's static order (families.yaml, labels first).</summary>
    Static,

    /// <summary>The learned order (Thompson sampling, PLAN 4a.1) warmed up on the other scenarios' searches.</summary>
    Bandit,

    /// <summary>The LLM advisor alone, through trial_run (MCP tools, permission probes).</summary>
    Model,

    /// <summary>The advisor's candidates (search_enqueue) inside the learned search (search_start, permission control).</summary>
    BanditModel,
}

public sealed record BenchOptions
{
    public IReadOnlyList<BenchScenario> Scenarios { get; init; } = BenchScenarios.All;

    /// <summary>Seeds of the static and bandit arms per scenario: the bandit's draws and the flaky DPIs' coin flips.</summary>
    public int Seeds { get; init; } = 5;

    /// <summary>Seeds of the model arms per scenario (each one is a paid conversation).</summary>
    public int ModelSeeds { get; init; } = 1;

    /// <summary>Distinct strategies a run may try; a run that has not succeeded by then failed.</summary>
    public int Budget { get; init; } = 200;

    public SearchMode Mode { get; init; } = SearchMode.Standard;

    /// <summary>The clock of the learned order; the warm-up history is dated a day before.</summary>
    public DateTimeOffset Now { get; init; } = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>How long the bandit+model arm waits for the search the model started after the model's last word.</summary>
    public TimeSpan SearchWait { get; init; } = TimeSpan.FromMinutes(2);
}

/// <summary>The model arms' provider: the advisor's conversation and its bounds. Null in <see cref="SearchBenchmark"/> skips both arms.</summary>
public sealed record ModelArms(string Name, AdvisorRunner.ChatFactory Chat, AdvisorLimits Limits, bool IncludeSkills = true);

/// <summary>One run: a scenario, an arm and a seed.</summary>
public sealed record BenchRun(string Scenario, int Asn, BenchArm Arm, int Seed, bool Warm, bool Success, int Strategies, int Attempts, string? Winner, string? Note = null,
    int Turns = 0, int ToolCalls = 0, long Tokens = 0);

/// <summary>Trials to success over a group of runs. A failed run counts as "more than the budget": a percentile that lands on one is null.</summary>
public sealed record ArmSummary(BenchArm Arm, int Runs, int Successes, int Failures, int? Median, int? P90, int? MedianAttempts, double MeanSuccessStrategies, long Tokens);

public sealed record BenchReport(BenchOptions Options, string? ModelName, IReadOnlyList<BenchRun> Runs)
{
    public IReadOnlyList<BenchArm> Arms => [.. Runs.Select(r => r.Arm).Distinct().Order()];

    public IReadOnlyList<ArmSummary> Summaries(Func<BenchRun, bool>? filter = null) =>
        [.. Arms.Select(a => Summarize(a, [.. Runs.Where(r => r.Arm == a && (filter?.Invoke(r) ?? true))])).Where(s => s.Runs > 0)];

    public static ArmSummary Summarize(BenchArm arm, IReadOnlyList<BenchRun> runs)
    {
        var ok = runs.Where(r => r.Success).ToList();
        return new ArmSummary(arm, runs.Count, ok.Count, runs.Count - ok.Count,
            Percentile(runs, 0.5, r => r.Strategies), Percentile(runs, 0.9, r => r.Strategies), Percentile(runs, 0.5, r => r.Attempts),
            ok.Count == 0 ? 0 : Math.Round(ok.Average(r => r.Strategies), 1), runs.Sum(r => r.Tokens));
    }

    /// <summary>Nearest-rank percentile; failures sort last as infinity, and a percentile that lands on one is null ("&gt; budget").</summary>
    public static int? Percentile(IReadOnlyList<BenchRun> runs, double q, Func<BenchRun, int> value)
    {
        if (runs.Count == 0)
            return null;
        var sorted = runs.Select(r => r.Success ? value(r) : int.MaxValue).Order().ToList();
        int rank = Math.Max(1, (int)Math.Ceiling(q * sorted.Count));
        var v = sorted[rank - 1];
        return v == int.MaxValue ? null : v;
    }
}

/// <summary>
/// The search benchmark (PLAN 4a.3, MCP stage M6 "Замер"): trials to success of the static order, the learned order,
/// the advisor and the advisor inside the learned search, on simulated DPIs. Deterministic for the first two arms; the
/// model arms run only with a provider the user configured explicitly (<see cref="ModelArms"/>), otherwise nothing
/// leaves the process.
/// </summary>
public sealed class SearchBenchmark(BenchOptions options, ModelArms? model = null)
{
    private const int HistorySeed = 7919;
    private readonly Dictionary<string, IReadOnlyList<ArmStat>> _history = new(StringComparer.Ordinal);

    public BenchOptions Options => options;

    public async Task<BenchReport> RunAsync(IProgress<BenchRun>? progress = null, CancellationToken ct = default)
    {
        var runs = new List<BenchRun>();
        void Add(BenchRun r)
        {
            runs.Add(r);
            progress?.Report(r);
        }
        foreach (var s in options.Scenarios)
        {
            for (int seed = 1; seed <= options.Seeds; seed++)
            {
                ct.ThrowIfCancellationRequested();
                Add(await RunSearchAsync(s, BenchArm.Static, seed, null).ConfigureAwait(false));
                Add(await RunSearchAsync(s, BenchArm.Bandit, seed, await LearningAsync(s, seed).ConfigureAwait(false)).ConfigureAwait(false));
            }
            if (model is null)
                continue;
            for (int seed = 1; seed <= options.ModelSeeds; seed++)
            {
                Add(await RunModelAsync(s, BenchArm.Model, seed, null, model, ct).ConfigureAwait(false));
                Add(await RunModelAsync(s, BenchArm.BanditModel, seed, await LearningAsync(s, seed).ConfigureAwait(false), model, ct).ConfigureAwait(false));
            }
        }
        return new BenchReport(options, model?.Name, runs);
    }

    /// <summary>
    /// The learned order for <paramref name="s"/>: the trials of the static searches on every other scenario of the set,
    /// with their provider and label, as the knowledge base would hold them a day later. Nothing of the scenario itself.
    /// </summary>
    public async Task<SearchLearning> LearningAsync(BenchScenario s, int seed)
    {
        var rows = new List<ArmStat>();
        for (int i = 0; i < options.Scenarios.Count; i++)
        {
            var other = options.Scenarios[i];
            if (other == s)
                continue;
            if (!_history.TryGetValue(other.Id, out var h))
            {
                var log = new RecordingLog();
                await RunSearchAsync(other, BenchArm.Static, HistorySeed + i, null, log).ConfigureAwait(false);
                _history[other.Id] = h = log.Rows(other, options.Now.AddDays(-1));
            }
            rows.AddRange(h);
        }
        return new SearchLearning
        {
            History = rows,
            Context = new LearningContext(s.Asn, s.Label),
            Seed = seed,
            Now = options.Now,
        };
    }

    /// <summary>One search of the Runner (<see cref="StrategySearch"/>) on a fresh simulated DPI, stopping at the first success.</summary>
    public async Task<BenchRun> RunSearchAsync(BenchScenario s, BenchArm arm, int seed, SearchLearning? learning, ISearchLog? log = null)
    {
        using var dpi = new SimulatedDpi(s, seed, options.Budget);
        var search = new StrategySearch(new SimTrialExecutor(dpi), new SearchOptions
        {
            Generator = s.Generator(options.Mode),
            StopAfterFound = 1,
            Learning = learning,
        }, log);
        var result = await search.RunAsync(dpi.Done).ConfigureAwait(false);
        return Result(s, arm, seed, dpi, dpi.FirstSuccess is null ? result.Reason == SearchStopReason.Exhausted ? "exhausted" : dpi.OverBudget ? "budget" : result.Reason.ToString() : null);
    }

    private BenchRun Result(BenchScenario s, BenchArm arm, int seed, SimulatedDpi dpi, string? note, AdvisorSummary? summary = null)
    {
        var first = dpi.FirstSuccess;
        return new BenchRun(s.Id, s.Asn, arm, seed, BenchScenarios.Warm(s, options.Scenarios), first is not null,
            first?.Strategies ?? dpi.Strategies, first?.Attempts ?? dpi.Attempts, first?.Strategy, note,
            summary?.Turns ?? 0, summary?.ToolCalls ?? 0, summary?.Tokens ?? 0);
    }

    /// <summary>
    /// One advisor session over the MCP tools on a fresh simulated DPI. The classifier's verdict is in place (the program
    /// diagnosed the target, AGENTS.md rule 5); the model acts through <see cref="AutoTunerTools.CallAsync"/> like any
    /// client, and the run ends at the first strategy that passes a full series or at the budget.
    /// </summary>
    public async Task<BenchRun> RunModelAsync(BenchScenario s, BenchArm arm, int seed, SearchLearning? learning, ModelArms m, CancellationToken ct, Action<AdvisorEvent>? onEvent = null)
    {
        using var dpi = new SimulatedDpi(s, seed, options.Budget);
        using var host = new BenchHost(dpi, arm == BenchArm.BanditModel ? learning : null);
        var permissions = arm == BenchArm.Model ? new McpPermissions(Probes: true) : new McpPermissions(Control: true);
        var session = new McpSession(host, new DeclineConfirm(), () => permissions, new BudgetOptions { PerMinute = 1_000_000, PerSession = 1_000_000 });
        session.SetVerdict(host.Verdict());
        var runner = new AdvisorRunner(new AutoTunerTools(session), m.Limits) { Client = "bench", IncludeSkills = m.IncludeSkills, Language = "en" };
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, dpi.Done);
        var summary = await runner.RunAsync(m.Chat, Prompt(arm, s), onEvent ?? (_ => { }), linked.Token).ConfigureAwait(false);
        if (arm == BenchArm.BanditModel)
        {
            // the search the model started goes on after its last word: it is part of the arm
            var end = DateTime.UtcNow + options.SearchWait;
            while (session.Search.Running && !dpi.Done.IsCancellationRequested && DateTime.UtcNow < end && !ct.IsCancellationRequested)
                await Task.Delay(10, CancellationToken.None).ConfigureAwait(false);
        }
        await session.StopAllAsync().ConfigureAwait(false);
        var note = dpi.FirstSuccess is not null ? null : dpi.OverBudget ? "budget" : summary.Outcome.ToString().ToLowerInvariant() + (summary.Error is null ? "" : ": " + summary.Error);
        return Result(s, arm, seed, dpi, note, summary);
    }

    /// <summary>The user's task of a model run: the same frame for every scenario, nothing of the hidden rule.</summary>
    public string Prompt(BenchArm arm, BenchScenario s) => arm == BenchArm.Model
        ? $"""
          {s.Host} is blocked; it is already diagnosed (diagnose shows the verdict). Find a strategy that fully downloads it.
          Use trial_run with level L2 and attempts 3: a strategy counts as working at 3/3. Every distinct strategy you run
          counts against a budget of {options.Budget}, so try the most likely ones first and stop at the first one that
          passes 3/3.
          """
        : $"""
          {s.Host} is blocked; it is already diagnosed (diagnose shows the verdict). Put your best candidate strategies for
          it (up to 10) into the search queue with search_enqueue, then start the search with search_start (mode
          {options.Mode.ToString().ToLowerInvariant()}) and poll search_status until it is done. The search orders your
          candidates among its own families by what worked on this provider before.
          """;

    /// <summary>The trials of a search as the knowledge base keeps them for the learned order (one row per strategy and day).</summary>
    public sealed class RecordingLog : ISearchLog
    {
        private readonly Dictionary<string, (string? Family, string Source, int Ok, int All)> _rows = new(StringComparer.Ordinal);

        public void Trial(StrategyCandidate candidate, TrialOutcome outcome)
        {
            var r = _rows.GetValueOrDefault(candidate.Key, (Family: candidate.Family, Source: candidate.Source, Ok: 0, All: 0));
            _rows[candidate.Key] = (r.Family, r.Source, r.Ok + (outcome.Ok ? 1 : 0), r.All + 1);
        }

        public void Tuning(Core.Model.Strategy parent, Mutation child, Efficiency efficiency, bool accepted)
        {
        }

        public void Checkpoint(int index)
        {
        }

        public IReadOnlyList<ArmStat> Rows(BenchScenario s, DateTimeOffset day) =>
            [.. _rows.Select(kv => new ArmStat(kv.Key, kv.Value.Family, kv.Value.Source, s.Asn, s.Label, "default", day, kv.Value.Ok, kv.Value.All))];
    }
}
