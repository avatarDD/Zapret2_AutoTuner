using System.Collections.Concurrent;
using System.Net;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// The search_* tools (M3): the Runner (<see cref="StrategySearch"/>) for one target in the background, steered
/// between trials: pause, a skipped family, and the model's own candidates, which run before the Runner's next trial
/// (or first in the next search) and are stored with family <c>llm</c>, so it shows whether the model helps at all.
/// </summary>
public sealed class SearchController(McpSession session)
{
    private readonly Lock _lock = new();
    private readonly ConcurrentQueue<StrategyCandidate> _queue = new();
    private readonly HashSet<string> _pruned = new(StringComparer.Ordinal);
    private readonly List<(StrategyCandidate Candidate, Efficiency Efficiency)> _modelResults = [];
    private readonly List<FoundStrategy> _modelFound = [];
    private CancellationTokenSource? _cts;
    private Task? _task;
    private TaskCompletionSource? _paused;
    private string? _target;
    private string _state = "idle";
    private string? _reason;
    private SearchProgress? _progress;
    private SearchResult? _result;
    private string? _error;
    private bool _budgetSpent;
    private DateTime? _started;

    private McpSession Session => session;

    public bool Running
    {
        get
        {
            lock (_lock)
                return _state is "running" or "paused";
        }
    }

    public async Task<JsonObject> StartAsync(string target, string mode, CancellationToken ct)
    {
        var (verdict, error) = TrialRunner.Blocked(session, target);
        if (error is not null)
            return error;
        if (session.Experiments.Running)
            return McpErrors.Error("busy: an experiment is running; roll it back first / занято: идёт эксперимент");
        if (session.LocalWorkRefusal() is { } localBusy)
            return localBusy;
        lock (_lock)
        {
            if (_state is "running" or "paused")
            {
                if (_state == "paused" && string.Equals(_target, target, StringComparison.OrdinalIgnoreCase))
                    return Resume();
                return McpErrors.Error($"a search is already running for {_target}; search_stop first / поиск уже идёт");
            }
            _state = "starting";
        }
        IEngineControl engine;
        try
        {
            engine = await session.Host.EngineAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            lock (_lock)
                _state = "idle";
            throw;
        }
        var trialTarget = new TrialTarget
        {
            Host = target,
            Addresses = [.. verdict!.LiveAddresses.Select(IPAddress.Parse)],
            MinBytes = verdict.Labels.Contains(Core.Diagnostics.BlockLabel.Cutoff16K) ? 128 * 1024 : 64 * 1024,
        };
        var kb = session.Host.Kb;
        var searchMode = mode switch { "quick" => SearchMode.Quick, "full" => SearchMode.Full, _ => SearchMode.Standard };
        long sessionId = kb.StartSession(target, searchMode.ToString(), blockLabel: verdict.Primary.ToString());
        var log = new KnowledgeBaseSearchLog(kb, sessionId, trialTarget, blockLabel: verdict.Primary.ToString());
        var queued = new List<StrategyCandidate>();
        while (_queue.TryDequeue(out var q))
            queued.Add(q);
        var options = TuningSession.Prepare(kb, new SearchOptions
        {
            Generator = new GeneratorOptions { Mode = searchMode, Labels = verdict.Labels },
            Priors = queued,
            Learning = session.Host.SearchLearning(verdict.Primary.ToString()),
        }, sessionId, null);
        var cts = CancellationTokenSource.CreateLinkedTokenSource(session.StopToken);
        var executor = new ControlledExecutor(this, new AgentTrialExecutor(engine, trialTarget, session.Host.TrialOptions) { Probe = session.Host.ProbeAsync }, target, log, options, cts);
        var search = new StrategySearch(executor, options, log, new DirectProgress<SearchProgress>(p =>
        {
            lock (_lock)
                _progress = p;
        }));
        lock (_lock)
        {
            _cts = cts;
            _target = target;
            _state = "running";
            _reason = null;
            _error = null;
            _result = null;
            _progress = null;
            _budgetSpent = false;
            _paused = null;
            _started = session.Time.GetUtcNow().UtcDateTime;
            _pruned.Clear();
            _modelResults.Clear();
            _modelFound.Clear();
            _task = Task.Run(async () =>
            {
                try
                {
                    var r = await search.RunAsync(cts.Token).ConfigureAwait(false);
                    TuningSession.Finish(kb, sessionId, target, r);
                    lock (_lock)
                    {
                        _result = r;
                        _reason = _budgetSpent ? "budget" : r.Reason.ToString().ToLowerInvariant();
                        _state = r.Reason == SearchStopReason.Cancelled ? "stopped" : "done";
                    }
                }
                catch (Exception e)
                {
                    kb.UpdateSession(sessionId, state: "cancelled");
                    lock (_lock)
                    {
                        _error = e.Message;
                        _state = "failed";
                    }
                }
            });
        }
        return new JsonObject
        {
            ["ok"] = true,
            ["state"] = "running",
            ["target"] = target,
            ["mode"] = mode,
            ["queued_first"] = queued.Count,
            ["hint"] = "poll search_status; trials run at the Runner's pace with punishment pauses",
        };
    }

    public JsonObject Status()
    {
        lock (_lock)
        {
            var found = (_result?.Working ?? _progress?.Found ?? []).Concat(_modelFound)
                .GroupBy(f => f.Candidate.Key).Select(g => g.First())
                .OrderBy(f => f.Score.Total).Take(5).ToList();
            var partial = _result?.BestPartial ?? _progress?.BestPartial;
            return new JsonObject
            {
                ["ok"] = true,
                ["state"] = _state,
                ["target"] = _target,
                ["stage"] = _progress?.Stage.ToString().ToLowerInvariant(),
                ["message"] = _progress?.MessageEn,
                ["message_ru"] = _progress?.MessageRu,
                ["percent"] = _progress is null ? null : Math.Round(_progress.Percent, 1),
                ["tried"] = _result?.Tried ?? _progress?.Done,
                ["elapsed_sec"] = _started is { } s ? (long)(session.Time.GetUtcNow().UtcDateTime - s).TotalSeconds : null,
                ["remaining_sec_estimate"] = _progress?.Remaining is { } rem ? (long)rem.TotalSeconds : null,
                ["current"] = _progress?.Current is { } c ? $"[{c.Family}] {c.Strategy}" : null,
                ["found"] = new JsonArray([.. found.Select(f => (JsonNode)Found(f))]),
                ["best_partial"] = partial is null ? null : Found(partial),
                ["queued"] = _queue.Count,
                ["model_results"] = new JsonArray([.. _modelResults.TakeLast(10).Select(m => (JsonNode)new JsonObject
                {
                    ["strategy_id"] = session.Remember(m.Candidate.Strategy, m.Candidate.L4),
                    ["efficiency"] = m.Efficiency.ToString(),
                })]),
                ["pruned_families"] = new JsonArray([.. _pruned.Select(p => (JsonNode)JsonValue.Create(p))]),
                ["families"] = new JsonArray([.. FamilyCatalog.Default.Families.Select(f => (JsonNode)JsonValue.Create(f.Id))]),
                ["stop_reason"] = _reason,
                ["error"] = _error,
                ["budget_used"] = session.Budget.Used,
            };
        }
    }

    public JsonObject Pause(bool resume)
    {
        lock (_lock)
        {
            if (resume)
                return Resume();
            if (_state != "running")
                return McpErrors.Error($"no running search (state: {_state})");
            _paused = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _state = "paused";
            return new JsonObject { ["ok"] = true, ["state"] = "paused", ["hint"] = "the trial in progress finishes; search_pause with resume=true continues" };
        }
    }

    private JsonObject Resume()
    {
        if (_state != "paused")
            return McpErrors.Error($"the search is not paused (state: {_state})");
        _state = "running";
        _paused?.TrySetResult();
        _paused = null;
        return new JsonObject { ["ok"] = true, ["state"] = "running" };
    }

    public async Task<JsonObject> StopAsync()
    {
        Task? task;
        lock (_lock)
        {
            task = _task;
            if (_state is not ("running" or "paused"))
                return new JsonObject { ["ok"] = true, ["state"] = _state };
            _cts?.Cancel();
            _paused?.TrySetResult();
        }
        if (task is not null)
            await task.ConfigureAwait(false);
        return Status();
    }

    public JsonObject Enqueue(IReadOnlyList<CheckedStrategy> strategies)
    {
        foreach (var s in strategies)
            _queue.Enqueue(new StrategyCandidate(s.Strategy!, "llm", 0, ["llm"], s.L4));
        bool running = Running;
        return new JsonObject
        {
            ["ok"] = true,
            ["queued"] = _queue.Count,
            ["strategy_ids"] = new JsonArray([.. strategies.Select(s => (JsonNode)JsonValue.Create(session.Remember(s.Strategy!, s.L4)))]),
            ["when"] = running ? "before the Runner's next trial" : "first in the next search_start",
        };
    }

    public JsonObject Prune(string family)
    {
        if (FamilyCatalog.Default.Families.All(f => f.Id != family))
            return McpErrors.Error($"unknown family {family}: search_status lists them");
        lock (_lock)
            _pruned.Add(family);
        return new JsonObject { ["ok"] = true, ["pruned_families"] = new JsonArray([.. _pruned.Select(p => (JsonNode)JsonValue.Create(p))]) };
    }

    private JsonObject Found(FoundStrategy f) => new()
    {
        ["strategy_id"] = session.Remember(f.Candidate.Strategy, f.Candidate.L4),
        ["strategy"] = f.Candidate.Strategy.ToString(),
        ["family"] = f.Candidate.Family,
        ["efficiency"] = f.Efficiency.ToString(),
        ["score"] = Math.Round(f.Score.Total, 2),
        ["refined"] = f.MutationPath,
    };

    /// <summary>The Runner's executor with the controls in front of each series.</summary>
    private sealed class ControlledExecutor(SearchController owner, ITrialExecutor inner, string target, ISearchLog log, SearchOptions options, CancellationTokenSource cts) : ITrialExecutor
    {
        public async Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
        {
            await WaitWhilePausedAsync(ct).ConfigureAwait(false);
            bool pruned;
            lock (owner._lock)
                pruned = owner._pruned.Contains(candidate.Family);
            if (pruned)
                return [];
            while (owner._queue.TryDequeue(out var queued))
                await ScreenAsync(queued, ct).ConfigureAwait(false);
            return await SeriesAsync(candidate, attempts, stopEarly, ct).ConfigureAwait(false);
        }

        public Task<bool> TargetReachableAsync(CancellationToken ct) => inner.TargetReachableAsync(ct);

        private async Task WaitWhilePausedAsync(CancellationToken ct)
        {
            while (true)
            {
                Task? gate;
                lock (owner._lock)
                    gate = owner._paused?.Task;
                if (gate is null)
                    return;
                await gate.WaitAsync(ct).ConfigureAwait(false);
            }
        }

        private async Task<IReadOnlyList<TrialOutcome>> SeriesAsync(StrategyCandidate c, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
        {
            if (!await owner.Session.Budget.TakeAsync(target, ct).ConfigureAwait(false))
            {
                lock (owner._lock)
                    owner._budgetSpent = true;
                await cts.CancelAsync().ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
            }
            var outcomes = await inner.RunAsync(c, attempts, stopEarly, ct).ConfigureAwait(false);
            foreach (var o in outcomes)
                owner.Session.Budget.Observe(target, o.Failure == TrialFailure.NoConnect);
            return outcomes;
        }

        /// <summary>A model candidate, screened like the Runner's own: two failures end it, a partial one gets more attempts.</summary>
        private async Task ScreenAsync(StrategyCandidate c, CancellationToken ct)
        {
            var outcomes = (await SeriesAsync(c, options.Attempts, o => o.Count(x => !x.Ok) >= 2 && !o.Any(x => x.Ok), ct).ConfigureAwait(false)).ToList();
            var eff = new Efficiency(outcomes.Count(o => o.Ok), outcomes.Count);
            if (eff.Partial && eff.Attempts < options.PartialAttempts)
                outcomes.AddRange(await SeriesAsync(c, options.PartialAttempts - eff.Attempts, _ => false, ct).ConfigureAwait(false));
            eff = new Efficiency(outcomes.Count(o => o.Ok), outcomes.Count);
            foreach (var o in outcomes)
                log.Trial(c, o);
            lock (owner._lock)
            {
                owner._modelResults.Add((c, eff));
                if (eff.Working)
                    owner._modelFound.Add(new FoundStrategy(c, eff, StrategyScore.Compute(c.Strategy, eff, targets: options.ExportTargets)));
            }
        }
    }
}

/// <summary>An <see cref="IProgress{T}"/> that calls back on the reporting thread (no synchronization context).</summary>
internal sealed class DirectProgress<T>(Action<T> report) : IProgress<T>
{
    public void Report(T value) => report(value);
}
