using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;
using ZapretAutoTuner.Delivery;
using ZapretAutoTuner.Storage;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// router_experiment_* (PLAN 4a.4, 7.6): the model's variants run on the router through zapret-gui's own experiments,
/// with the address and token the user entered in AutoTuner. Each strategy passes <see cref="StrategyPolicy"/> and the
/// Validator for Linux (the router), the router measures its baseline first and reverts by itself unless committed.
/// Starting and committing need the user's yes in the AutoTuner window (AGENTS.md rule 7). The router's measurements go
/// to the knowledge base with source <c>router</c>, so the learned order knows them.
/// </summary>
public sealed class RouterExperimentRunner(McpSession session)
{
    private sealed record Variant(string Label, Strategy Strategy, L4Kind L4, string Args);

    private readonly Lock _lock = new();
    private string _state = "idle";
    private string _phase = "";
    private string? _runId;
    private string? _error;
    private string? _note;
    private bool _awaitingConfirmation;
    private bool _committed;
    private List<Variant> _variants = [];
    private List<string> _targets = [];
    private IReadOnlyList<(string Name, string Args)> _current = [];
    private ExperimentReport? _report;
    private ZapretGuiExperiments? _experiments;
    private CancellationTokenSource? _cts;
    private Task? _task;

    /// <summary>How often the router is asked for the state of a run.</summary>
    public TimeSpan Poll { get; set; } = TimeSpan.FromSeconds(2);

    public bool Running
    {
        get
        {
            lock (_lock)
                return _state == "running";
        }
    }

    public JsonObject Start(JsonObject args)
    {
        lock (_lock)
        {
            if (_state == "running")
                return McpErrors.Error($"busy: router experiment {_runId} is running; router_experiment_rollback first / занято: идёт эксперимент на роутере");
        }
        if (session.Host.RouterExperiments() is null)
            return NotSetUp();
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
            var (c, refusal) = McpErrors.StrategyFrom(session, o, platform: EnginePlatform.Linux);
            if (refusal is null && Problem(c!.Strategy!, c.L4, targets) is { } problem)
                refusal = problem;
            if (refusal is not null)
            {
                refusal["variant"] = label;
                return refusal;
            }
            session.Remember(c!.Strategy!, c.L4);
            variants.Add(new Variant(label, c.Strategy!, c.L4, RouterTrialExecutor.CandidateArgs(c.Strategy!, c.L4, targets)));
        }
        int repeats = (int?)args["repeats"] ?? 3;
        int ttl = (int?)args["ttl_sec"] ?? 300;
        bool keepBest = (bool?)args["keep_best"] ?? false;

        var request = new ConfirmRequest("router_experiment_start",
            "Внешний агент хочет испытать стратегии на роутере", "An external agent wants to try strategies on the router",
            Describe(variants, targets, ttl, keepBest, ru: true), Describe(variants, targets, ttl, keepBest, ru: false));
        var answer = session.Confirmations.Request("router_experiment_start:" + args.ToJsonString(), request, ct => BeginAsync(variants, targets, repeats, ttl, keepBest, ct));
        lock (_lock)
            _awaitingConfirmation = (string?)answer["status"] == "pending_confirmation";
        return answer;
    }

    /// <summary>The args the router gets must pass the Validator for Linux and fit zapret-gui's limit.</summary>
    private static JsonObject? Problem(Strategy s, L4Kind l4, IReadOnlyList<string> targets)
    {
        var args = RouterTrialExecutor.CandidateArgs(s, l4, targets);
        if (args.Length > RouterTrialExecutor.MaxArgsLength)
            return McpErrors.Error($"the router profile is longer than zapret-gui's {RouterTrialExecutor.MaxArgsLength} characters: fewer targets or a shorter strategy");
        // zapret-gui adds the standard --lua-init files itself: the profile's functions are those of the catalog
        var catalog = Core.Catalog.LuaCatalog.Default;
        var r = new StrategyValidator(new ValidationContext
        {
            Platform = EnginePlatform.Linux,
            Catalog = catalog,
            LoadedFunctions = catalog.Functions.Select(f => f.Name).ToHashSet(StringComparer.Ordinal),
        }).ValidateArgv(ArgTokenizer.Split(args));
        if (r.Ok)
            return null;
        return new JsonObject
        {
            ["ok"] = false,
            ["error"] = "the router profile was refused by the Validator / профиль для роутера отклонил Validator: "
                + string.Join("; ", r.Errors.Select(i => (i.Where is null ? "" : i.Where + ": ") + i.En)),
            ["errors"] = StrategyPolicy.Issues(r.Issues, Severity.Error),
        };
    }

    private static string Describe(List<Variant> variants, List<string> targets, int ttl, bool keepBest, bool ru)
    {
        var lines = new List<string>
        {
            ru ? $"Цели: {string.Join(", ", targets)}" : $"Targets: {string.Join(", ", targets)}",
            ru ? $"zapret-gui на роутере по очереди применит варианты и проверит цели с самого роутера (сначала без обхода). Профили текущей стратегии роутера остаются после варианта. Всё вернётся само через {ttl} с; навсегда ничего не сохраняется без отдельного подтверждения."
               : $"zapret-gui on the router applies the variants in turn and probes the targets from the router (first without bypass). The router's current strategy profiles stay after each variant. Everything reverts by itself after {ttl} s; nothing is kept without a separate confirmation.",
        };
        if (keepBest)
            lines.Add(ru ? "Лучший вариант останется применённым до этого срока (без закрепления)." : "The best variant stays applied until then (not committed).");
        lines.AddRange(variants.Select(v => $"• {v.Label}: {v.Strategy}"));
        return string.Join("\n", lines);
    }

    private async Task<JsonObject> BeginAsync(List<Variant> variants, List<string> targets, int repeats, int ttl, bool keepBest, CancellationToken ct)
    {
        var x = session.Host.RouterExperiments();
        if (x is null)
            return NotSetUp();
        lock (_lock)
        {
            if (_state == "running")
                return McpErrors.Error($"busy: router experiment {_runId} is running");
            _awaitingConfirmation = false;
        }
        // R1: the token must allow the trial tools; the active strategy's profiles stay after each candidate
        var (missing, _, current) = await RouterTuning.ConnectAsync(x, ct).ConfigureAwait(false);
        if (missing.Count > 0)
        {
            return new JsonObject
            {
                ["ok"] = false,
                ["error"] = "the zapret-gui token does not allow " + string.Join(", ", missing) + " / токен zapret-gui не даёт этих инструментов",
                ["hint"] = "the user enables the experiments permission (with control and probes) for the token in zapret-gui's MCP settings",
            };
        }
        var runId = await x.StartAsync(new ExperimentRequest
        {
            Variants = [.. variants.Select(v => new ExperimentVariant(v.Label, [(RouterTrialExecutor.ProfileName, v.Args), .. current]))],
            Targets = targets,
            Repeats = repeats,
            Baseline = true,
            TtlSec = ttl,
            KeepBest = keepBest,
        }, ct).ConfigureAwait(false);
        lock (_lock)
        {
            _cts?.Dispose();
            _cts = CancellationTokenSource.CreateLinkedTokenSource(session.StopToken);
            _experiments = x;
            _runId = runId;
            _state = "running";
            _phase = "starting";
            _variants = variants;
            _targets = targets;
            _current = current;
            _report = null;
            _error = null;
            _note = null;
            _committed = false;
            var token = _cts.Token;
            _task = Task.Run(() => WatchAsync(x, runId, token));
        }
        return new JsonObject { ["ok"] = true, ["run_id"] = runId, ["async"] = true, ["ttl_sec"] = ttl, ["current_profiles_kept"] = current.Count };
    }

    /// <summary>Follows the run on the router until it is measured, then stores the router's results in the knowledge base.</summary>
    private async Task WatchAsync(ZapretGuiExperiments x, string runId, CancellationToken ct)
    {
        try
        {
            while (true)
            {
                var (state, phase, awaiting) = await x.StatusAsync(ct).ConfigureAwait(false);
                lock (_lock)
                    _phase = phase;
                if (state != "running" || awaiting)
                    break;
                await Task.Delay(Poll, ct).ConfigureAwait(false);
            }
            var report = await x.ResultAsync(runId, [.. _variants.Select(v => v.Label)], includeLog: false, ct).ConfigureAwait(false);
            var byLabel = _variants.ToDictionary(v => v.Label, v => (v.Strategy, v.L4), StringComparer.Ordinal);
            RouterTuning.Record(session.Host.Kb, report, byLabel);
            lock (_lock)
            {
                _report = report;
                _phase = report.AwaitingCommit ? "awaiting_commit" : "";
                _state = report.State switch
                {
                    "failed" => "failed",
                    "reverted" => "reverted",
                    _ => "finished",
                };
                _error = report.Error.Length > 0 ? report.Error : null;
            }
        }
        catch (OperationCanceledException)
        {
            // Stop, rollback or exit: the router comes back now instead of at its deadline
            await RouterTuning.RollbackQuietlyAsync(x).ConfigureAwait(false);
            lock (_lock)
            {
                if (_state == "running")
                    _state = "reverted";
                _phase = "";
            }
        }
        catch (Exception e) when (e is ZapretGuiException or HttpRequestException or IOException)
        {
            await RouterTuning.RollbackQuietlyAsync(x).ConfigureAwait(false);
            lock (_lock)
            {
                _state = "failed";
                _phase = "";
                _error = e.Message;
            }
        }
    }

    public JsonObject Status()
    {
        lock (_lock)
        {
            return new JsonObject
            {
                ["ok"] = true,
                ["configured"] = session.Host.RouterExperiments() is not null,
                ["run_id"] = _runId,
                ["state"] = _awaitingConfirmation && _state != "running" ? "awaiting_confirmation" : _state,
                ["phase"] = _phase,
                ["variants"] = _variants.Count,
                ["awaiting_commit"] = _report?.AwaitingCommit ?? false,
                ["committed"] = _committed,
                ["error"] = _error,
                ["note"] = _note,
            };
        }
    }

    public JsonObject Result(string? runId)
    {
        lock (_lock)
        {
            if (_runId is null)
                return McpErrors.Error("no router experiment yet / экспериментов на роутере не было");
            if (runId is not null && runId != _runId)
                return McpErrors.Error($"{runId} is not the last run ({_runId}); only the last one is kept");
            if (_report is not { } r)
                return new JsonObject { ["ok"] = true, ["run_id"] = _runId, ["state"] = _state, ["phase"] = _phase, ["hint"] = "still measuring on the router; poll router_experiment_status" };
            return new JsonObject
            {
                ["ok"] = true,
                ["run_id"] = _runId,
                ["state"] = _state,
                ["targets"] = new JsonArray([.. _targets.Select(t => (JsonNode)JsonValue.Create(t))]),
                ["open_without_bypass"] = new JsonArray([.. r.OpenWithoutBypass.Select(t => (JsonNode)JsonValue.Create(t))]),
                ["variants"] = new JsonArray([.. r.Variants.OrderBy(v => v.Label == r.Best ? 0 : 1).ThenByDescending(v => v.SuccessRate).Select(v => (JsonNode)VariantJson(v))]),
                ["best"] = r.Best.Length > 0 ? r.Best : null,
                ["awaiting_commit"] = r.AwaitingCommit,
                ["committed"] = _committed,
                ["reverted_reason"] = r.RevertedReason.Length > 0 ? r.RevertedReason : null,
                ["error"] = _error,
                ["note"] = "measured on the router: the results are stored with source router and feed the learned search order",
            };
        }
    }

    private JsonObject VariantJson(ExperimentVariantResult v)
    {
        var known = _variants.FirstOrDefault(x => x.Label == v.Label);
        return new JsonObject
        {
            ["label"] = v.Label,
            ["strategy_id"] = known is null ? null : StrategyPolicy.IdOf(known.Strategy),
            ["strategy"] = known?.Strategy.ToString(),
            ["started"] = v.Started,
            ["skipped"] = v.Skipped ? true : null,
            ["skip_reason"] = v.SkipReason.Length > 0 ? Observation.Short(v.SkipReason, 200) : null,
            ["engine_error"] = Observation.Short(v.EngineError, 300),
            ["router_validation"] = v.ValidationErrors.Count == 0 ? null : new JsonArray([.. v.ValidationErrors.Take(5).Select(e => (JsonNode)JsonValue.Create(Observation.Short(e, 200)!))]),
            ["per_target"] = new JsonArray([.. v.PerTarget.Select(p => (JsonNode)new JsonObject
            {
                ["target"] = p.Target,
                ["ok"] = p.Ok,
                ["ok_count"] = p.OkCount,
                ["attempts"] = p.Attempts,
                ["code"] = p.Code,
                ["latency_ms"] = (long)p.LatencyMs,
                ["bytes_read"] = p.BytesRead,
            })]),
            ["success_rate"] = Math.Round(v.SuccessRate, 3),
            ["score"] = Math.Round(v.Score, 2),
            ["hints"] = new JsonArray([.. v.Hints.Take(5).Select(h => (JsonNode)JsonValue.Create(Observation.Short(h, 200)!))]),
        };
    }

    /// <summary>
    /// Keeps a variant on the router: after the user's yes the kept winner (or the named variant, kept first by a short
    /// experiment of its own) is committed; with <paramref name="save"/> it is also saved as a user strategy and made active.
    /// </summary>
    public JsonObject Commit(string? label, bool save)
    {
        Variant v;
        string runId;
        bool keptAlready;
        List<string> targets;
        IReadOnlyList<(string Name, string Args)> current;
        lock (_lock)
        {
            if (_runId is null || _report is null || _state is not ("finished" or "committed"))
                return McpErrors.Error($"nothing to commit (state: {_state}) / закреплять нечего");
            label ??= _report.Best.Length > 0 ? _report.Best : null;
            var found = _variants.FirstOrDefault(x => x.Label == label);
            if (found is null)
                return McpErrors.Error(label is null ? "no variant won on the router: name one with label / победителя нет" : $"no variant {label}");
            if (_report.Variants.FirstOrDefault(x => x.Label == found.Label) is not { Started: true } measured || measured.PerTarget.All(p => p.OkCount == 0))
                return McpErrors.Error($"variant {found.Label} opened nothing on the router; nothing to keep / вариант ничего не открыл");
            v = found;
            runId = _runId;
            keptAlready = _report.AwaitingCommit && _report.Best == found.Label;
            targets = _targets;
            current = _current;
        }
        var saveAs = save ? RouterTuning.SaveId(session.Time.GetUtcNow()) : null;
        var request = new ConfirmRequest("router_experiment_commit",
            "Внешний агент предлагает закрепить стратегию на роутере", "An external agent proposes to keep a strategy on the router",
            $"Вариант {v.Label} станет стратегией zapret-gui на роутере для: {string.Join(", ", targets)} (профили текущей стратегии остаются после него).\n"
                + (saveAs is null ? "Без сохранения: действует, пока в zapret-gui не применят другую стратегию." : $"Будет сохранён как пользовательская стратегия {saveAs} и сделан активным.")
                + $"\n{v.Strategy}",
            $"Variant {v.Label} becomes zapret-gui's strategy on the router for: {string.Join(", ", targets)} (the current strategy's profiles stay after it).\n"
                + (saveAs is null ? "Unsaved: it lasts until another strategy is applied in zapret-gui." : $"It is saved as the user strategy {saveAs} and made active.")
                + $"\n{v.Strategy}");
        return session.Confirmations.Request($"router_experiment_commit:{runId}:{v.Label}:{save}", request, async ct =>
        {
            var x = session.Host.RouterExperiments();
            if (x is null)
                return NotSetUp();
            lock (_lock)
            {
                if (_runId != runId)
                    return McpErrors.Error("the router experiment changed meanwhile / эксперимент сменился");
            }
            string commitLabel = v.Label;
            if (!keptAlready)
            {
                var (_, kept, problem) = await RouterTuning.KeepAsync(x, [(RouterTrialExecutor.ProfileName, v.Args), .. current], targets, 300, Poll, ct).ConfigureAwait(false);
                if (!kept)
                    return McpErrors.Error("the router did not keep the variant / роутер не оставил вариант: " + problem);
                commitLabel = RouterTuning.KeepLabel;
            }
            var (saved, note) = await RouterTuning.CommitAsync(x, confirmedByUser: true, saveAs, saveAs is null ? null : "AutoTuner: " + string.Join(", ", targets.Take(3)), ct, commitLabel).ConfigureAwait(false);
            foreach (var t in targets)
                session.Host.Kb.AddChange(t, "router_applied", JournalReason.Encode(
                    saved ? $"закреплено на роутере и сохранено как {saveAs}" : "закреплено на роутере (без сохранения)",
                    saved ? $"committed on the router and saved as {saveAs}" : "committed on the router (unsaved)"), null, v.Strategy.ToString(), applied: true);
            session.Host.RouterCommitted(targets, v.Strategy.ToString());
            lock (_lock)
            {
                _committed = true;
                _state = "committed";
                _phase = "";
                _note = note.Length > 0 ? note : null;
            }
            return new JsonObject { ["ok"] = true, ["committed"] = v.Label, ["run_id"] = runId, ["saved_as"] = saved ? saveAs : null, ["note"] = note.Length > 0 ? note : null };
        });
    }

    /// <summary>Reverts the router now: the running measurement or the kept variant goes, the router's previous state returns.</summary>
    public async Task<JsonObject> RollbackAsync(string reason = "rollback")
    {
        ZapretGuiExperiments? x;
        Task? task;
        lock (_lock)
        {
            if (_committed)
                return new JsonObject { ["ok"] = true, ["state"] = _state, ["note"] = "already committed; the user changes the router's strategy in zapret-gui / уже закреплено" };
            if (_experiments is null || _state is "idle" or "reverted" or "failed")
                return new JsonObject { ["ok"] = true, ["state"] = _state, ["note"] = "nothing applied on the router / на роутере ничего не применено" };
            x = _experiments;
            task = _task;
            _cts?.Cancel();
        }
        if (task is not null)
        {
            try
            {
                await task.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }
        await RouterTuning.RollbackQuietlyAsync(x).ConfigureAwait(false);
        lock (_lock)
        {
            _state = "reverted";
            _phase = "";
            _note = reason;
        }
        return Status();
    }

    private static JsonObject NotSetUp() => new()
    {
        ["ok"] = false,
        ["error"] = "zapret-gui is not set up in AutoTuner / zapret-gui не настроен в AutoTuner",
        ["hint"] = "the user enters zapret-gui's address and MCP token in AutoTuner (Settings → zapret-gui); the model never passes them",
    };
}
