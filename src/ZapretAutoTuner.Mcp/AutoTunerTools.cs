using System.Diagnostics;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Catalog;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.Mcp;

/// <summary>A tool's answer: structured data, and whether it is an error.</summary>
public sealed record McpToolResult(JsonObject Data, bool IsError)
{
    public string Text => Data.ToJsonString();
}

/// <summary>
/// The tool facade: a thin layer over Core and Tuning that every transport calls, and that the built-in advisor (M4)
/// can call in-process. It checks the permission, the arguments against the pinned schema, masks the user's addresses
/// with the report's masker, bounds the answer and writes every call to the audit log.
/// </summary>
public sealed class AutoTunerTools(McpSession session)
{
    /// <summary>About 6k tokens: an answer larger than this is trimmed (arrays first).</summary>
    public const int MaxAnswerChars = 24000;

    private IReadOnlyDictionary<string, Func<JsonObject, CancellationToken, Task<JsonObject>>>? _handlers;

    public McpSession Session => session;

    /// <summary>Our own tools the current permissions allow (tools/list without the router's relayed gui_* tools).</summary>
    public IReadOnlyList<McpToolDefinition> ListTools()
    {
        var p = session.Permissions();
        return [.. McpTools.All.Where(t => p.Granted(t.Scope))];
    }

    /// <summary>The router's zapret-gui tools relayed as gui_* (router_proxy on, zapret-gui set up), as tools/list shows them.</summary>
    public Task<IReadOnlyList<JsonObject>> ListRouterToolsAsync(CancellationToken ct = default) => session.Proxy.ListAsync(ct);

    public async Task<McpToolResult> CallAsync(string name, JsonObject? arguments, string client = "mcp", CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var args = arguments ?? [];
        JsonObject data;
        bool isError;
        var def = McpTools.Find(name);
        // our tools never start with gui_ (a test pins it): such a name is the router's zapret-gui tool (PLAN 4a.7)
        bool proxied = def is null && RouterProxy.IsProxied(name);
        var scope = proxied ? McpScope.RouterProxy : def?.Scope ?? McpScope.Read;
        var perms = session.Permissions();
        if (def is null && !proxied)
        {
            data = McpErrors.Error($"unknown tool {name}");
            isError = true;
        }
        else if (!perms.Granted(scope))
        {
            data = perms.Denial(scope);
            isError = true;
        }
        else if (def is not null && S.Check(def.InputSchema, args) is { } problem)
        {
            data = McpErrors.Error("invalid arguments: " + problem);
            isError = true;
        }
        else
        {
            session.Client = client;
            session.LastCall = session.Time.GetUtcNow().UtcDateTime;
            // Stop swaps the session's token for a fresh one: remember the one this call runs under
            var stop = session.StopToken;
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, stop);
            try
            {
                data = proxied
                    ? await session.Proxy.CallAsync(name, args, linked.Token).ConfigureAwait(false)
                    : await DispatchAsync(name, args, linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
                data = McpErrors.Error("stopped by the user in AutoTuner / остановлено пользователем");
            }
            catch (EngineRefusedException e)
            {
                data = McpErrors.Error($"the Agent refused to start the engine ({e.Stage}): {e.Message}");
            }
            catch (Exception e) when (e is InvalidOperationException or IOException or HttpRequestException or Grpc.Core.RpcException or TimeoutException
                                          or System.Net.Sockets.SocketException or FormatException or Core.Export.ExportException or Delivery.ZapretGuiException)
            {
                data = McpErrors.Error(e.Message);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // not the client's cancel and not Stop: a timeout inside (HttpClient, the Agent's channel)
                data = McpErrors.Error("timed out / превышено время ожидания");
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // the knowledge base (SqliteException), a malformed document (JsonException)…: an audited error answer,
                // not an exception that escapes the transport without a trace
                data = McpErrors.Error($"internal error ({e.GetType().Name}): {e.Message} / внутренняя ошибка");
            }
            isError = (bool?)data["ok"] == false && (string?)data["status"] is not ("pending_confirmation" or "confirmed_running");
        }
        data = Bound(Mask(data));
        session.Audit.Add(new McpAuditEntry(DateTime.UtcNow, client, name, Observation.Short(Mask(args.DeepClone().AsObject()).ToJsonString(), 300)!,
            isError ? "error: " + Observation.Short((string?)data["error"], 160) : (string?)data["status"] ?? "ok", sw.Elapsed));
        return new McpToolResult(data, isError);
    }

    /// <summary>
    /// One handler per tool of <see cref="McpTools.All"/>. A new tool group (typed resources such as blobs or hostlists,
    /// router tools) adds its definitions there and its handlers here; a confirmation-gated one goes through
    /// <see cref="PendingConfirmations.Request"/>.
    /// </summary>
    private IReadOnlyDictionary<string, Func<JsonObject, CancellationToken, Task<JsonObject>>> Handlers() => new Dictionary<string, Func<JsonObject, CancellationToken, Task<JsonObject>>>(StringComparer.Ordinal)
    {
        ["targets_list"] = (a, ct) => Task.FromResult(TargetsList()),
        ["diagnose"] = (a, ct) => DiagnoseAsync((string)a["target"]!, (bool?)a["refresh"] ?? false, ct),
        ["trials_history"] = (a, ct) => Task.FromResult(TrialsHistory((string?)a["target"], (int?)a["limit"] ?? 20)),
        ["catalog_functions"] = (a, ct) => Task.FromResult(CatalogFunctions((string?)a["category"], (string?)a["name"])),
        ["strategy_validate"] = (a, ct) => Task.FromResult(Validate(a)),
        ["kb_query"] = (a, ct) => Task.FromResult(KbQuery((string?)a["target"], (int?)a["asn"], (string?)a["l4"] ?? "tcp", (int?)a["limit"] ?? 20)),
        ["target_add"] = (a, ct) => Task.FromResult(TargetAdd((string)a["target"]!, (string?)a["reason"])),
        ["trial_run"] = (a, ct) => new TrialRunner(session).RunAsync(a, ct),
        ["search_start"] = (a, ct) => session.Search.StartAsync((string)a["target"]!, (string?)a["mode"] ?? "standard", ct),
        ["search_status"] = (a, ct) => Task.FromResult(session.Search.Status()),
        ["search_pause"] = (a, ct) => Task.FromResult(session.Search.Pause((bool?)a["resume"] ?? false)),
        ["search_stop"] = (a, ct) => session.Search.StopAsync(),
        ["search_enqueue"] = (a, ct) => Task.FromResult(Enqueue((JsonArray)a["strategies"]!)),
        ["search_prune_family"] = (a, ct) => Task.FromResult(session.Search.Prune((string)a["family"]!)),
        ["strategy_experiment_start"] = (a, ct) => session.Experiments.StartAsync(a, ct),
        ["strategy_experiment_status"] = (a, ct) => Task.FromResult(session.Experiments.Status()),
        ["strategy_experiment_result"] = (a, ct) => Task.FromResult(session.Experiments.Result((string?)a["run_id"])),
        ["strategy_experiment_commit"] = (a, ct) => Task.FromResult(session.Experiments.Commit((string?)a["label"])),
        ["strategy_experiment_rollback"] = (a, ct) => session.Experiments.RollbackAsync(),
        ["export_preview"] = (a, ct) => Task.FromResult(ExportPreview.Build(session, a)),
        ["router_experiment_start"] = (a, ct) => Task.FromResult(session.Router.Start(a)),
        ["router_experiment_status"] = (a, ct) => Task.FromResult(session.Router.Status()),
        ["router_experiment_result"] = (a, ct) => Task.FromResult(session.Router.Result((string?)a["run_id"])),
        ["router_experiment_commit"] = (a, ct) => Task.FromResult(session.Router.Commit((string?)a["label"], (bool?)a["save"] ?? false)),
        ["router_experiment_rollback"] = (a, ct) => session.Router.RollbackAsync(),
        ["bug_report_draft"] = (a, ct) => Task.FromResult(BugReportTool.Draft(session, a)),
    }.Concat(new ResourceTools(session).Handlers()).ToDictionary(StringComparer.Ordinal);

    internal bool HasHandler(string name) => (_handlers ??= Handlers()).ContainsKey(name);

    private Task<JsonObject> DispatchAsync(string name, JsonObject a, CancellationToken ct) =>
        (_handlers ??= Handlers()).TryGetValue(name, out var h) ? h(a, ct) : Task.FromResult(McpErrors.Error($"unknown tool {name}"));

    private JsonObject TargetsList() => new()
    {
        ["ok"] = true,
        ["targets"] = new JsonArray([.. session.Host.Targets.Select(t => (JsonNode)new JsonObject
        {
            ["target"] = t,
            ["diagnosis"] = session.Verdict(t) is { } v ? new JsonObject { ["primary"] = v.Primary.ToString(), ["next"] = v.Next.ToString(), ["summary"] = v.SummaryEn } : null,
        })]),
        ["hint"] = "diagnose with refresh=true classifies a target; target_add asks the user for a new one",
    };

    private async Task<JsonObject> DiagnoseAsync(string target, bool refresh, CancellationToken ct)
    {
        if (!session.IsTarget(target))
            return McpErrors.NotATarget(target);
        if (refresh && !session.Classifying(target))
        {
            var p = session.Permissions();
            if (!p.Granted(McpScope.Probes))
                return p.Denial(McpScope.Probes);
            var (ok, why, retry) = session.Budget.TryTake(target);
            if (!ok)
                return McpErrors.Budget(why!, retry);
        }
        if (refresh || session.Classifying(target))
        {
            var run = session.Classify(target, out _);
            // a new target's probes can outlast the client's call: the run goes on and the verdict waits in the cache
            await Task.WhenAny(run, Task.Delay(session.DiagnoseWait, ct)).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            if (!run.IsCompleted)
            {
                return new JsonObject
                {
                    ["ok"] = true,
                    ["target"] = target,
                    ["diagnosed"] = session.Verdict(target) is not null,
                    ["state"] = "running",
                    ["hint"] = "the classifier is still probing this target; call diagnose again with refresh=false in a few seconds for the verdict (no new probes are made) / классификатор ещё проверяет цель",
                };
            }
            if (!run.IsCompletedSuccessfully)
                return McpErrors.Error($"the classifier failed for {target}: {session.ClassifyError(target)} / классификатор не смог проверить цель");
        }
        if (session.Verdict(target) is not { } v)
        {
            return session.ClassifyError(target) is { } error
                ? McpErrors.Error($"the last classification of {target} failed: {error}; refresh=true tries again / последняя проверка не удалась")
                : new JsonObject { ["ok"] = true, ["target"] = target, ["diagnosed"] = false, ["hint"] = "refresh=true runs the classifier (needs the probes permission)" };
        }
        return new JsonObject
        {
            ["ok"] = true,
            ["target"] = target,
            ["diagnosed"] = true,
            ["primary"] = v.Primary.ToString(),
            ["next"] = v.Next.ToString(),
            ["summary"] = v.SummaryEn,
            ["summary_ru"] = v.SummaryRu,
            ["labels"] = new JsonArray([.. v.Labels.Select(l => (JsonNode)JsonValue.Create(l.ToString()))]),
            ["findings"] = new JsonArray([.. v.Findings.Take(12).Select(f => (JsonNode)new JsonObject
            {
                ["label"] = f.Label.ToString(),
                ["address"] = f.Address,
                ["evidence"] = new JsonArray([.. f.Evidence.Take(6).Select(e => (JsonNode)JsonValue.Create(Observation.Short(e, 200)!))]),
            })]),
            ["live_addresses"] = v.LiveAddresses.Count,
            ["dead_addresses"] = v.DeadAddresses.Count,
            ["strategy_can_help"] = v.Next == NextStep.SearchStrategy,
        };
    }

    private JsonObject TrialsHistory(string? target, int limit)
    {
        if (target is not null && !session.IsTarget(target))
            return McpErrors.NotATarget(target);
        IReadOnlyList<string> hosts = target is null ? session.Host.Targets : [target];
        var rows = hosts.SelectMany(h => session.Host.Kb.Results(h)).Take(limit).ToList();
        return new JsonObject
        {
            ["ok"] = true,
            ["results"] = new JsonArray([.. rows.Select(r => (JsonNode)Result(r))]),
            ["session_trials"] = new JsonArray([.. session.Trials.Where(t => target is null || string.Equals(t.Target, target, StringComparison.OrdinalIgnoreCase))
                .TakeLast(limit).Select(t => (JsonNode)new JsonObject
                {
                    ["trial_id"] = t.Id,
                    ["target"] = t.Target,
                    ["strategy_id"] = t.StrategyId,
                    ["level"] = t.Level,
                    ["efficiency"] = $"{t.Successes}/{t.Attempts}",
                    ["reading"] = t.Reading,
                    ["capture"] = t.Pcap is null ? null : McpResources.CaptureUri(t.Id),
                })]),
        };
    }

    private JsonObject Result(Storage.StoredResult r)
    {
        string? id = null;
        try
        {
            var s = Strategy.Parse(r.Args);
            id = session.Remember(s);
        }
        catch (FormatException)
        {
        }
        return new JsonObject
        {
            ["target"] = r.Host,
            ["strategy_id"] = id,
            ["strategy"] = r.Args,
            ["family"] = r.Family,
            ["source"] = r.Family == "llm" ? "llm" : r.Origin,
            ["efficiency"] = r.Efficiency.ToString(),
            ["status"] = r.Status,
            ["client"] = r.ClientProfile,
            ["block"] = r.BlockLabel,
            ["updated"] = r.Updated.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
        };
    }

    private static JsonObject CatalogFunctions(string? category, string? name)
    {
        var cat = LuaCatalog.Default;
        var fs = cat.Functions.Where(f => !StrategyPolicy.ForbiddenCategories.Contains(f.Category) && f.Name != "luaexec")
            .Where(f => category is null || f.Category == category).Where(f => name is null || f.Name == name)
            .OrderBy(f => f.Category).ThenBy(f => f.Name).ToList();
        if (name is not null && fs.Count == 0)
            return McpErrors.Error($"{name} is not a catalog function available over MCP");
        bool full = name is not null;
        return new JsonObject
        {
            ["ok"] = true,
            ["zapret2"] = cat.Data.Zapret2Version,
            ["functions"] = new JsonArray([.. fs.Select(f => (JsonNode)new JsonObject
            {
                ["name"] = f.Name,
                ["category"] = f.Category,
                ["en"] = f.En,
                ["ru"] = f.Ru,
                ["needs_fooling"] = f.NeedsFooling ? true : null,
                ["args"] = new JsonArray([.. (full ? cat.ArgsOf(f) : f.Args).Where(x => x.Kind != ArgKind.LuaCode && !StrategyPolicy.ForbiddenArgs.Contains(x.Name))
                    .Select(x => (JsonNode)(full ? Arg(x) : JsonValue.Create(x.Name)))]),
                ["blocks"] = f.Blocks.Count == 0 ? null : new JsonArray([.. f.Blocks.Select(b => (JsonNode)JsonValue.Create(b))]),
            })]),
            ["markers"] = full ? new JsonArray([.. cat.PositionMarkers.Order().Select(m => (JsonNode)JsonValue.Create(m))]) : null,
            ["builtin_blobs"] = new JsonArray([.. cat.BuiltinBlobs.Order().Select(b => (JsonNode)JsonValue.Create(b))]),
            ["hint"] = full ? null : "name=<function> gives every argument with ranges; ztuner://skills/nfqws2-lua explains them",
        };
    }

    private static JsonObject Arg(ArgSpec a) => new()
    {
        ["name"] = a.Name,
        ["kind"] = a.Kind.ToString().ToLowerInvariant(),
        ["values"] = a.Values is null ? null : new JsonArray([.. a.Values.Select(v => (JsonNode)JsonValue.Create(v))]),
        ["default"] = a.Default,
        ["min"] = a.Min,
        ["max"] = a.Max,
        ["required"] = a.Required ? true : null,
        ["en"] = a.En,
    };

    private JsonObject Validate(JsonObject a)
    {
        var client = ClientProfile.BuiltIn.FirstOrDefault(p => p.Id == (string?)a["client"]);
        var c = StrategyPolicy.Check((string)a["strategy"]!, (string?)a["l4"] == "udp" ? L4Kind.Udp : L4Kind.Tcp, client);
        if (c.Ok)
            session.Remember(c.Strategy!, c.L4);
        return new JsonObject
        {
            ["ok"] = c.Ok,
            ["strategy_id"] = c.Ok ? c.Id : null,
            ["canonical"] = c.Strategy?.ToString(),
            ["errors"] = StrategyPolicy.Issues(c.Issues, Severity.Error),
            ["warnings"] = StrategyPolicy.Issues(c.Issues, Severity.Warning),
            ["error"] = c.Ok ? null : StrategyPolicy.Refusal(c)["error"]?.DeepClone(),
        };
    }

    private JsonObject KbQuery(string? target, int? asn, string l4, int limit)
    {
        if (target is not null && !session.IsTarget(target))
            return McpErrors.NotATarget(target);
        var worked = session.Host.Kb.WorkedOnNetwork(asn, l4, limit);
        return new JsonObject
        {
            ["ok"] = true,
            ["target_results"] = target is null ? null : new JsonArray([.. session.Host.Kb.Results(target).Take(limit).Select(r => (JsonNode)Result(r))]),
            ["worked_on_network"] = new JsonArray([.. worked.Select(w => (JsonNode)new JsonObject
            {
                ["strategy_id"] = session.Remember(w.Strategy, l4 == "udp" ? L4Kind.Udp : L4Kind.Tcp),
                ["strategy"] = w.Strategy.ToString(),
                ["family"] = w.Family,
                ["targets_opened"] = w.Targets,
            })]),
            ["asn"] = asn,
            ["note"] = "only this user's local results; imported results arrive in release 2",
        };
    }

    private JsonObject TargetAdd(string target, string? reason)
    {
        if (session.IsTarget(target))
            return new JsonObject { ["ok"] = true, ["target"] = target, ["status"] = "already_listed" };
        var request = new ConfirmRequest("target_add",
            "Внешний агент предлагает добавить цель", "An external agent proposes a new target",
            $"Добавить {target} в список целей? Тогда к нему пойдут проверки.{(reason is null ? "" : "\nПричина: " + reason)}",
            $"Add {target} to the targets? Probes will then go to it.{(reason is null ? "" : "\nReason: " + reason)}");
        return session.Confirmations.Request("target_add:" + target.ToLowerInvariant(), request, _ =>
        {
            session.Host.AddTarget(target);
            return Task.FromResult(new JsonObject { ["ok"] = true, ["target"] = target, ["status"] = "added" });
        });
    }

    private JsonObject Enqueue(JsonArray strategies)
    {
        var list = new List<CheckedStrategy>();
        for (int i = 0; i < strategies.Count; i++)
        {
            var c = StrategyPolicy.Check((string)strategies[i]!);
            if (!c.Ok)
            {
                var r = StrategyPolicy.Refusal(c);
                r["index"] = i;
                return r;
            }
            list.Add(c);
        }
        return session.Search.Enqueue(list);
    }

    private static readonly HashSet<string> Unmasked = new(StringComparer.Ordinal) { "strategy", "canonical", "current", "body_sha256" };

    /// <summary>The user's addresses as in the report: private ones become lan-N, public ones keep their /24.</summary>
    internal static JsonObject Mask(JsonObject data)
    {
        var masker = new FailureReport.Masker(false);
        Walk(data, masker);
        return data;
    }

    private static void Walk(JsonNode? node, FailureReport.Masker masker)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var key in o.Select(kv => kv.Key).ToList())
                {
                    if (o[key] is JsonValue v && v.TryGetValue<string>(out var s))
                    {
                        if (!Unmasked.Contains(key))
                            o[key] = masker.Line(s);
                    }
                    else
                        Walk(o[key], masker);
                }
                break;
            case JsonArray a:
                for (int i = 0; i < a.Count; i++)
                {
                    if (a[i] is JsonValue v && v.TryGetValue<string>(out var s))
                        a[i] = masker.Line(s);
                    else
                        Walk(a[i], masker);
                }
                break;
        }
    }

    /// <summary>Halves the largest array until the answer fits, and says so.</summary>
    internal static JsonObject Bound(JsonObject data, int max = MaxAnswerChars)
    {
        for (int i = 0; i < 40 && data.ToJsonString().Length > max; i++)
        {
            var largest = Arrays(data).OrderByDescending(a => a.ToJsonString().Length).FirstOrDefault(a => a.Count > 1);
            if (largest is null)
                break;
            int keep = largest.Count / 2;
            while (largest.Count > keep)
                largest.RemoveAt(largest.Count - 1);
            data["truncated"] = true;
        }
        return data;
    }

    private static IEnumerable<JsonArray> Arrays(JsonNode? n)
    {
        switch (n)
        {
            case JsonArray a:
                yield return a;
                foreach (var x in a)
                    foreach (var y in Arrays(x))
                        yield return y;
                break;
            case JsonObject o:
                foreach (var (_, v) in o)
                    foreach (var y in Arrays(v))
                        yield return y;
                break;
        }
    }
}
