using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// strategy_experiment_* on this PC (M5) with zapret-gui's names and semantics: variants are applied one by one to the
/// live traffic to the targets, each measured against a baseline, and everything comes back by itself at the deadline
/// unless committed. <c>keep_best</c> is not a commit: the kept variant still reverts at the deadline. Starting and
/// committing need the user's yes in the AutoTuner window.
/// </summary>
public sealed class ExperimentRunner(McpSession session)
{
    /// <summary>The experiment's own queue, apart from the trials' (300) and the protection's (310).</summary>
    public const int QueueNum = 320;

    private sealed record Variant(string Label, Strategy Strategy, L4Kind L4, Solution Solution);

    private sealed record TargetProbe(string Target, int Ok, int Attempts, string Code, double LatencyMs, long Bytes);

    private sealed record VariantResult(string Label, string StrategyId, string? EngineError, IReadOnlyList<TargetProbe> PerTarget, double SuccessRate, double Score,
        IReadOnlyList<string> Fixed, IReadOnlyList<string> Broken, IReadOnlyList<string> Unchanged);

    private readonly Lock _lock = new();
    private readonly List<VariantResult> _results = [];
    private List<Variant> _variants = [];
    private List<TargetProbe> _baseline = [];
    private List<string> _targets = [];
    private string? _runId;
    private string _state = "idle";
    private string _phase = "";
    private int _variantIndex;
    private DateTime? _deadline;
    private bool _awaitingCommit;
    private bool _awaitingConfirmation;
    private bool _expired;
    private bool _committed;
    private string? _best;
    private string? _error;
    private string? _revertedReason;
    private string? _keptEngine;
    private IEngineControl? _engine;
    private CancellationTokenSource? _cts;
    private TaskCompletionSource? _decision;
    private Task? _task;

    public bool Running
    {
        get
        {
            lock (_lock)
                return _state == "running";
        }
    }

    public async Task<JsonObject> StartAsync(JsonObject args, CancellationToken ct)
    {
        lock (_lock)
        {
            if (_state == "running")
                return McpErrors.Error($"busy: experiment {_runId} is running; strategy_experiment_rollback first / занято: идёт эксперимент");
        }
        if (session.Search.Running)
            return McpErrors.Error("busy: the search is running; search_stop first / занято: идёт поиск");
        if (session.Host.ProtectionActive)
            return McpErrors.Error("busy: «Защита активна» runs on this PC; the user stops it first / занято: работает защита");

        var targets = (args["targets"] as JsonArray)?.Select(t => (string)t!).Distinct(StringComparer.OrdinalIgnoreCase).ToList() ?? [.. session.Host.Targets.Take(10)];
        if (targets.Count == 0)
            return McpErrors.Error("no targets: the user's target list is empty / список целей пуст");
        if (targets.FirstOrDefault(t => !session.IsTarget(t)) is { } stranger)
            return McpErrors.NotATarget(stranger);
        var variants = new List<Variant>();
        foreach (var v in (JsonArray)args["variants"]!)
        {
            var o = (JsonObject)v!;
            var label = (string)o["label"]!;
            if (variants.Any(x => x.Label == label))
                return McpErrors.Error($"variant label {label} is used twice");
            var (c, refusal) = McpErrors.StrategyFrom(session, o);
            if (refusal is not null)
            {
                refusal["variant"] = label;
                return refusal;
            }
            session.Remember(c!.Strategy!, c.L4);
            variants.Add(new Variant(label, c.Strategy!, c.L4, SolutionOf(label, c.Strategy!, c.L4, targets)));
        }
        int repeats = (int?)args["repeats"] ?? 3;
        bool baseline = (bool?)args["baseline"] ?? true;
        int ttl = (int?)args["ttl_sec"] ?? 300;
        bool keepBest = (bool?)args["keep_best"] ?? false;

        var key = "strategy_experiment_start:" + args.ToJsonString();
        var request = new ConfirmRequest("strategy_experiment_start",
            "Внешний агент хочет запустить эксперимент на живом трафике", "An external agent wants to run an experiment on live traffic",
            Describe(variants, targets, ttl, keepBest, ru: true), Describe(variants, targets, ttl, keepBest, ru: false));
        await Task.CompletedTask.ConfigureAwait(false);
        var answer = session.Confirmations.Request(key, request, _ => Task.FromResult(Begin(variants, targets, repeats, baseline, ttl, keepBest)));
        lock (_lock)
            _awaitingConfirmation = (string?)answer["status"] == "pending_confirmation";
        return answer;
    }

    private static string Describe(List<Variant> variants, List<string> targets, int ttl, bool keepBest, bool ru)
    {
        var lines = new List<string>
        {
            ru ? $"Цели: {string.Join(", ", targets)}" : $"Targets: {string.Join(", ", targets)}",
            ru ? $"Трафик к этим сайтам пойдёт через движок с каждым вариантом по очереди; всё вернётся само через {ttl} с."
               : $"Traffic to these sites goes through the engine with each variant in turn; everything reverts by itself after {ttl} s.",
        };
        if (keepBest)
            lines.Add(ru ? "Лучший вариант останется применённым до этого срока (без закрепления)." : "The best variant stays applied until then (not committed).");
        lines.AddRange(variants.Select(v => $"• {v.Label}: {v.Strategy}"));
        return string.Join("\n", lines);
    }

    private JsonObject Begin(List<Variant> variants, List<string> targets, int repeats, bool baseline, int ttl, bool keepBest)
    {
        lock (_lock)
        {
            if (_state == "running")
                return McpErrors.Error($"busy: experiment {_runId} is running");
            _awaitingConfirmation = false;
            _runId = "exp-" + session.Time.GetUtcNow().UtcDateTime.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            _state = "running";
            _phase = "starting";
            _variants = variants;
            _targets = targets;
            _results.Clear();
            _baseline = [];
            _variantIndex = 0;
            _deadline = session.Time.GetUtcNow().UtcDateTime.AddSeconds(ttl);
            _awaitingCommit = false;
            _expired = false;
            _committed = false;
            _best = null;
            _error = null;
            _revertedReason = null;
            _decision = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _cts = CancellationTokenSource.CreateLinkedTokenSource(session.StopToken);
            _cts.CancelAfter(TimeSpan.FromSeconds(ttl));
            var cts = _cts;
            _task = Task.Run(() => RunAsync(repeats, baseline, keepBest, cts.Token));
            return new JsonObject { ["ok"] = true, ["run_id"] = _runId, ["async"] = true, ["ttl_sec"] = ttl };
        }
    }

    private async Task RunAsync(int repeats, bool measureBaseline, bool keepBest, CancellationToken ct)
    {
        try
        {
            var engine = await session.Host.EngineAsync(ct).ConfigureAwait(false);
            lock (_lock)
                _engine = engine;
            var trialTargets = new List<TrialTarget>();
            foreach (var t in _targets)
            {
                var addresses = session.Verdict(t)?.LiveAddresses.Select(IPAddress.Parse).ToList() is { Count: > 0 } live ? live : [.. await session.Host.ResolveAsync(t, ct).ConfigureAwait(false)];
                trialTargets.Add(new TrialTarget { Host = t, Addresses = addresses });
            }
            var options = session.Host.TrialOptions with { QueueNum = QueueNum };
            if (measureBaseline)
            {
                SetPhase("baseline", 0);
                var b = await ProbeAllAsync(engine, trialTargets, options, repeats, ct).ConfigureAwait(false);
                lock (_lock)
                    _baseline = b;
            }
            for (int i = 0; i < _variants.Count; i++)
            {
                var v = _variants[i];
                SetPhase("variant", i + 1);
                string? engineError = null;
                List<TargetProbe> probes = [];
                var (argv, queue) = ConfigCheck.BuildLaunch(v.Solution, trialTargets, options);
                try
                {
                    var id = await engine.StartAsync(argv, queue, "experiment:" + v.Label, CancellationToken.None).ConfigureAwait(false);
                    try
                    {
                        await Task.Delay(options.Warmup, ct).ConfigureAwait(false);
                        probes = await ProbeAllAsync(engine, trialTargets, options, repeats, ct).ConfigureAwait(false);
                    }
                    finally
                    {
                        await engine.StopAsync(id, CancellationToken.None).ConfigureAwait(false);
                    }
                }
                catch (EngineRefusedException e) when (!e.Infrastructure)
                {
                    engineError = e.Message;
                }
                lock (_lock)
                    _results.Add(Measure(v, probes, engineError));
            }
            var best = Best();
            lock (_lock)
                _best = best?.Label;
            if (keepBest && best is not null)
            {
                var v = _variants.First(x => x.Label == best.Label);
                var (argv, queue) = ConfigCheck.BuildLaunch(v.Solution, trialTargets, options);
                var id = await engine.StartAsync(argv, queue, "experiment-keep:" + v.Label, CancellationToken.None).ConfigureAwait(false);
                Task decision;
                lock (_lock)
                {
                    _keptEngine = id;
                    _awaitingCommit = true;
                    _phase = "awaiting_commit";
                    decision = _decision!.Task;
                }
                try
                {
                    await decision.WaitAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    lock (_lock)
                    {
                        _expired = !session.StopToken.IsCancellationRequested;
                        _revertedReason ??= _expired ? "ttl expired / истёк срок" : "stopped / остановлено";
                    }
                }
                await StopKeptAsync().ConfigureAwait(false);
                lock (_lock)
                {
                    _awaitingCommit = false;
                    _state = _committed ? "committed" : "reverted";
                    _phase = "";
                }
                return;
            }
            lock (_lock)
            {
                _state = "finished";
                _phase = "";
            }
        }
        catch (OperationCanceledException)
        {
            await StopKeptAsync().ConfigureAwait(false);
            lock (_lock)
            {
                _expired = !session.StopToken.IsCancellationRequested && _revertedReason is null;
                _revertedReason ??= _expired ? "ttl expired / истёк срок" : "stopped / остановлено";
                _state = _committed ? "committed" : "reverted";
                _phase = "";
            }
        }
        catch (Exception e)
        {
            await StopKeptAsync().ConfigureAwait(false);
            lock (_lock)
            {
                _error = e.Message;
                _state = "failed";
                _phase = "";
            }
        }
    }

    private void SetPhase(string phase, int variant)
    {
        lock (_lock)
        {
            _phase = phase;
            _variantIndex = variant;
        }
    }

    private async Task<List<TargetProbe>> ProbeAllAsync(IEngineControl engine, List<TrialTarget> targets, AgentTrialOptions options, int repeats, CancellationToken ct)
    {
        var list = new List<TargetProbe>();
        foreach (var t in targets)
        {
            await session.Budget.TakeAsync(t.Host, ct).ConfigureAwait(false);
            var probe = new AgentTrialExecutor(engine, t, options);
            var results = new List<ProbeResult>();
            for (int i = 0; i < repeats; i++)
            {
                if (i > 0)
                    await Task.Delay(options.Pause, ct).ConfigureAwait(false);
                var r = await session.Host.ProbeAsync(probe.ProbeOptions(t.Addresses[i % t.Addresses.Count]), ct).ConfigureAwait(false);
                session.Budget.Observe(t.Host, !r.ConnectOk);
                results.Add(r);
            }
            int ok = results.Count(r => r.Passes(ProbeLevel.L2Body, t.MinBytes));
            var failing = results.FirstOrDefault(r => !r.Passes(ProbeLevel.L2Body, t.MinBytes));
            list.Add(new TargetProbe(t.Host, ok, results.Count, failing is null ? "ok" : Observation.ReadingOf(failing, t.MinBytes),
                Observation.Median(results.Select(r => r.Duration.TotalMilliseconds)), (long)Observation.Median(results.Select(r => (double)r.BodyBytes))));
        }
        return list;
    }

    private VariantResult Measure(Variant v, List<TargetProbe> probes, string? engineError)
    {
        int ok = probes.Sum(p => p.Ok), all = probes.Sum(p => p.Attempts);
        var eff = new Efficiency(ok, all);
        bool Works(TargetProbe p) => p.Attempts > 0 && p.Ok == p.Attempts;
        var fixedList = new List<string>();
        var broken = new List<string>();
        var unchanged = new List<string>();
        foreach (var p in probes)
        {
            var b = _baseline.FirstOrDefault(x => x.Target == p.Target);
            if (b is null)
                continue;
            if (Works(p) && !Works(b))
                fixedList.Add(p.Target);
            else if (!Works(p) && Works(b))
                broken.Add(p.Target);
            else
                unchanged.Add(p.Target);
        }
        return new VariantResult(v.Label, StrategyPolicy.IdOf(v.Strategy), engineError, probes, eff.Rate,
            Math.Round(StrategyScore.Compute(v.Strategy, eff).Total, 2), fixedList, broken, unchanged);
    }

    /// <summary>The winner must have fixed something when a baseline was measured (zapret-gui: a variant on an open site finds nothing).</summary>
    private VariantResult? Best()
    {
        lock (_lock)
        {
            return _results.Where(r => r.EngineError is null && r.SuccessRate > 0 && (_baseline.Count == 0 || r.Fixed.Count > 0) && r.Broken.Count == 0)
                .OrderByDescending(r => r.SuccessRate).ThenBy(r => r.Score).FirstOrDefault();
        }
    }

    public JsonObject Status()
    {
        lock (_lock)
        {
            return new JsonObject
            {
                ["ok"] = true,
                ["run_id"] = _runId,
                ["state"] = _awaitingConfirmation && _state != "running" ? "awaiting_confirmation" : _state,
                ["phase"] = _phase,
                ["variant"] = _variantIndex,
                ["variants"] = _variants.Count,
                ["ttl_left_sec"] = _deadline is { } d && _state == "running" ? Math.Max(0, (long)(d - session.Time.GetUtcNow().UtcDateTime).TotalSeconds) : null,
                ["awaiting_commit"] = _awaitingCommit,
                ["expired"] = _expired,
                ["committed"] = _committed,
                ["error"] = _error,
            };
        }
    }

    public JsonObject Result(string? runId)
    {
        lock (_lock)
        {
            if (_runId is null)
                return McpErrors.Error("no experiment yet / экспериментов не было");
            if (runId is not null && runId != _runId)
                return McpErrors.Error($"{runId} is not the last run ({_runId}); only the last one is kept");
            var ordered = _results.OrderBy(r => r.Label == _best ? 0 : 1).ThenByDescending(r => r.SuccessRate).ToList();
            return new JsonObject
            {
                ["ok"] = true,
                ["run_id"] = _runId,
                ["state"] = _state,
                ["targets"] = new JsonArray([.. _targets.Select(t => (JsonNode)JsonValue.Create(t))]),
                ["baseline"] = new JsonObject
                {
                    ["measured"] = _baseline.Count > 0,
                    ["per_target"] = Probes(_baseline),
                    ["open_without_bypass"] = new JsonArray([.. _baseline.Where(b => b.Attempts > 0 && b.Ok == b.Attempts).Select(b => (JsonNode)JsonValue.Create(b.Target))]),
                },
                ["variants"] = new JsonArray([.. ordered.Select(r => (JsonNode)new JsonObject
                {
                    ["label"] = r.Label,
                    ["strategy_id"] = r.StrategyId,
                    ["started_engine"] = r.EngineError is null,
                    ["engine_error"] = Observation.Short(r.EngineError, 300),
                    ["per_target"] = Probes(r.PerTarget),
                    ["success_rate"] = Math.Round(r.SuccessRate, 3),
                    ["score"] = r.Score,
                    ["delta_vs_baseline"] = new JsonObject
                    {
                        ["fixed"] = Strings(r.Fixed),
                        ["broken"] = Strings(r.Broken),
                        ["unchanged"] = Strings(r.Unchanged),
                        ["net"] = r.Fixed.Count - r.Broken.Count,
                    },
                })]),
                ["best"] = _best,
                ["awaiting_commit"] = _awaitingCommit,
                ["committed"] = _committed,
                ["reverted_reason"] = _revertedReason,
                ["error"] = _error,
            };
        }
    }

    public JsonObject Commit(string? label)
    {
        Variant? v;
        lock (_lock)
        {
            if (_runId is null || _state is not ("running" or "finished"))
                return McpErrors.Error($"nothing to commit (state: {_state}) / закреплять нечего");
            if (_state == "running" && !_awaitingCommit)
                return McpErrors.Error("the variants are still being measured; wait for the result / варианты ещё меряются");
            label ??= _best;
            v = _variants.FirstOrDefault(x => x.Label == label);
            if (v is null)
                return McpErrors.Error(label is null ? "no variant fixed anything: name one with label / победителя нет" : $"no variant {label}");
        }
        var request = new ConfirmRequest("strategy_experiment_commit",
            "Внешний агент предлагает закрепить стратегию", "An external agent proposes to keep a strategy",
            $"Вариант {v.Label} станет активной защитой на этом ПК для: {string.Join(", ", _targets)}\n{v.Strategy}",
            $"Variant {v.Label} becomes this PC's active protection for: {string.Join(", ", _targets)}\n{v.Strategy}");
        var runId = _runId;
        return session.Confirmations.Request($"strategy_experiment_commit:{runId}:{v.Label}", request, async ct =>
        {
            lock (_lock)
            {
                if (_runId != runId)
                    return McpErrors.Error("the experiment changed meanwhile / эксперимент сменился");
            }
            await StopKeptAsync().ConfigureAwait(false);
            await session.Host.CommitAsync(v.Solution, ct).ConfigureAwait(false);
            lock (_lock)
            {
                _committed = true;
                if (_state == "finished")
                    _state = "committed";
                _decision?.TrySetResult();
            }
            return new JsonObject { ["ok"] = true, ["committed"] = v.Label, ["run_id"] = runId };
        });
    }

    /// <summary>Reverts now: the kept variant's engine stops, a running measurement is cancelled.</summary>
    public async Task<JsonObject> RollbackAsync(string reason = "rollback")
    {
        Task? task;
        lock (_lock)
        {
            task = _task;
            if (_state != "running")
                return new JsonObject { ["ok"] = true, ["state"] = _state, ["note"] = "nothing applied / ничего не применено" };
            _revertedReason = reason;
            _cts?.Cancel();
        }
        if (task is not null)
            await task.ConfigureAwait(false);
        await StopKeptAsync().ConfigureAwait(false);
        return Status();
    }

    private async Task StopKeptAsync()
    {
        string? id;
        IEngineControl? engine;
        lock (_lock)
        {
            (id, engine) = (_keptEngine, _engine);
            _keptEngine = null;
        }
        if (id is not null && engine is not null)
        {
            try
            {
                await engine.StopAsync(id, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception e) when (e is InvalidOperationException or IOException or Grpc.Core.RpcException)
            {
            }
        }
    }

    private static Solution SolutionOf(string label, Strategy s, L4Kind l4, IReadOnlyList<string> targets)
    {
        var profile = new Profile { Name = "exp-" + label, HostlistDomains = [.. targets], Strategy = s };
        if (l4 == L4Kind.Udp)
            profile.UdpPorts = "443";
        else
            profile.TcpPorts = "80,443";
        var solution = new Solution { Profiles = [profile] };
        solution.Meta.Targets = [.. targets];
        solution.Meta.Title = "MCP experiment " + label;
        return solution;
    }

    private static JsonArray Probes(IEnumerable<TargetProbe> probes) => new([.. probes.Select(p => (JsonNode)new JsonObject
    {
        ["target"] = p.Target,
        ["ok"] = p.Attempts > 0 && p.Ok == p.Attempts,
        ["ok_count"] = p.Ok,
        ["attempts"] = p.Attempts,
        ["code"] = p.Code,
        ["latency_ms"] = (long)p.LatencyMs,
        ["bytes_read"] = p.Bytes,
    })]);

    private static JsonArray Strings(IEnumerable<string> items) => new([.. items.Select(i => (JsonNode)JsonValue.Create(i))]);
}
