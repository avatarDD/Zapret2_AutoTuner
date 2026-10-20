using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Delivery;

/// <summary>One variant of a zapret-gui experiment: profiles like a saved strategy (<c>profiles[].args</c>).</summary>
public sealed record ExperimentVariant(string Label, IReadOnlyList<(string Name, string Args)> Profiles);

public sealed record ExperimentRequest
{
    public required IReadOnlyList<ExperimentVariant> Variants { get; init; }

    /// <summary>Host names without scheme or path (the GUI allows 10).</summary>
    public required IReadOnlyList<string> Targets { get; init; }

    /// <summary><c>body</c> is the volume probe (64 KB on the GUI side), the L2 of the router.</summary>
    public IReadOnlyList<string> Probes { get; init; } = ["tls", "body"];

    public int Repeats { get; init; } = 3;

    public bool Baseline { get; init; }

    /// <summary>The dead-man switch: the GUI restores its state by itself after this.</summary>
    public int TtlSec { get; init; } = 300;

    public bool KeepBest { get; init; }
}

/// <summary>A target's result in one variant.</summary>
public sealed record ExperimentProbe(string Target, bool Ok, string Code, string CodeDesc, double LatencyMs, long BytesRead, int Attempts, int OkCount);

public sealed record ExperimentVariantResult(string Label, bool Started, bool Skipped, string SkipReason, string? EngineError,
    IReadOnlyList<ExperimentProbe> PerTarget, double SuccessRate, double Score, IReadOnlyList<string> Hints, IReadOnlyList<string> Log, IReadOnlyList<string> ValidationErrors);

public sealed record ExperimentReport(string RunId, string State, IReadOnlyList<ExperimentVariantResult> Variants, IReadOnlyList<string> OpenWithoutBypass,
    string Best, bool AwaitingCommit, bool Committed, string? Restored, string RestoreError, string RevertedReason, string Error);

/// <summary>
/// zapret-gui's strategy experiments over MCP (PLAN 7.6; zapret-gui <c>core/strategy_experiment.py</c>): variants are
/// applied one by one, probed from the router, and the state comes back by itself unless committed. Committing is
/// the only lasting change and needs the user's confirmation (AGENTS.md rule 7).
/// </summary>
public sealed class ZapretGuiExperiments(ZapretGuiMcp mcp)
{
    /// <summary>The tools a trial session needs; the token's permissions must allow them.</summary>
    public static readonly string[] RequiredTools = ["strategy_experiment_start", "strategy_experiment_status", "strategy_experiment_result", "strategy_experiment_rollback", "strategy_experiment_stop"];

    public async Task<IReadOnlyList<string>> MissingToolsAsync(CancellationToken ct = default)
    {
        var have = await mcp.ToolsAsync(ct).ConfigureAwait(false);
        return RequiredTools.Where(t => !have.Contains(t)).ToList();
    }

    public async Task<string> StartAsync(ExperimentRequest r, CancellationToken ct = default)
    {
        var variants = new JsonArray();
        foreach (var v in r.Variants)
        {
            var profiles = new JsonArray();
            foreach (var (name, args) in v.Profiles)
                profiles.Add((JsonNode)new JsonObject { ["name"] = name, ["args"] = args, ["enabled"] = true });
            variants.Add((JsonNode)new JsonObject { ["label"] = v.Label, ["profiles"] = profiles });
        }
        var result = await mcp.CallAsync("strategy_experiment_start", new JsonObject
        {
            ["variants"] = variants,
            ["targets"] = new JsonArray([.. r.Targets.Select(t => (JsonNode)t!)]),
            ["probes"] = new JsonArray([.. r.Probes.Select(p => (JsonNode)p!)]),
            ["repeats"] = r.Repeats,
            ["baseline"] = r.Baseline,
            ["ttl_sec"] = r.TtlSec,
            ["keep_best"] = r.KeepBest,
        }, ct).ConfigureAwait(false);
        return (string?)result["run_id"] ?? "";
    }

    /// <summary>(state, phase, awaiting commit): state is running, finished, failed, reverted or idle.</summary>
    public async Task<(string State, string Phase, bool AwaitingCommit)> StatusAsync(CancellationToken ct = default)
    {
        var s = await mcp.CallAsync("strategy_experiment_status", new JsonObject(), ct).ConfigureAwait(false);
        return ((string?)s["state"] ?? "", (string?)s["phase"] ?? "", (bool?)s["awaiting_commit"] ?? false);
    }

    /// <summary>Polls until the run is no longer running (the variants are measured; a kept winner may still be applied).</summary>
    public async Task<ExperimentReport> WaitAsync(string runId, TimeSpan poll, CancellationToken ct = default)
    {
        while (true)
        {
            var (state, _, awaiting) = await StatusAsync(ct).ConfigureAwait(false);
            if (state != "running" || awaiting)
                return await ResultAsync(runId, ct).ConfigureAwait(false);
            await Task.Delay(poll, ct).ConfigureAwait(false);
        }
    }

    public async Task<ExperimentReport> ResultAsync(string runId, CancellationToken ct = default)
    {
        var r = await mcp.CallAsync("strategy_experiment_result", new JsonObject { ["run_id"] = runId, ["include_log"] = true, ["limit"] = 20 }, ct).ConfigureAwait(false);
        return Parse(r);
    }

    /// <summary>Reverts at once (a kept winner too); harmless when nothing is applied.</summary>
    public async Task RollbackAsync(CancellationToken ct = default) =>
        await mcp.CallAsync("strategy_experiment_rollback", new JsonObject(), ct).ConfigureAwait(false);

    /// <summary>
    /// Keeps a variant applied and cancels the auto-revert. Only after the user said so. With <paramref name="saveAs"/>
    /// the variant is also saved as a user strategy (and made active), which needs the token's <c>strategies_write</c>.
    /// </summary>
    public async Task CommitAsync(bool confirmedByUser, string label, string? saveAs = null, string? saveName = null, CancellationToken ct = default)
    {
        if (!confirmedByUser)
            throw new InvalidOperationException("закрепление на роутере без подтверждения запрещено / committing needs the user's confirmation");
        var args = new JsonObject { ["label"] = label };
        if (saveAs is not null)
        {
            args["save_as"] = saveAs;
            args["save_name"] = saveName ?? saveAs;
            args["make_active"] = true;
        }
        await mcp.CallAsync("strategy_experiment_commit", args, ct).ConfigureAwait(false);
    }

    internal static ExperimentReport Parse(JsonObject r)
    {
        // hints are {id, hint}; logs and lists are strings
        static List<string> Strings(JsonNode? n) => (n as JsonArray ?? []).Select(x => x switch
        {
            JsonValue v when v.TryGetValue<string>(out var s) => s,
            JsonObject o when o["hint"] is JsonNode h => $"{(string?)o["id"]}: {(string?)h}",
            _ => x?.ToJsonString(),
        }).OfType<string>().ToList();
        var variants = new List<ExperimentVariantResult>();
        foreach (var v in (r["items"] ?? r["variants"]) as JsonArray ?? [])
        {
            if (v is not JsonObject o)
                continue;
            var probes = (o["per_target"] as JsonArray ?? []).OfType<JsonObject>().Select(p => new ExperimentProbe(
                (string?)p["target"] ?? "", (bool?)p["ok"] ?? false, p["code"]?.ToString() ?? "", (string?)p["code_desc"] ?? "",
                (double?)p["latency_ms"] ?? 0, (long?)p["bytes_read"] ?? 0, (int?)p["attempts"] ?? 0, (int?)p["ok_count"] ?? 0)).ToList();
            var validation = o["validation"] as JsonObject;
            variants.Add(new ExperimentVariantResult((string?)o["label"] ?? "", (bool?)o["started_nfqws"] ?? false, (bool?)o["skipped"] ?? false,
                (string?)o["skip_reason"] ?? "", (string?)o["engine_error"], probes, (double?)o["success_rate"] ?? 0, (double?)o["score"] ?? 0,
                Strings(o["hints"]), Strings(o["nfqws_log"]), Strings(validation?["errors"])));
        }
        return new ExperimentReport((string?)r["run_id"] ?? "", (string?)r["state"] ?? "", variants, Strings(r["baseline"]?["open_without_bypass"]),
            (string?)r["best"] ?? "", (bool?)r["awaiting_commit"] ?? false, (bool?)r["committed"] ?? false, r["restored"]?.ToString(),
            (string?)r["restore_error"] ?? "", (string?)r["reverted_reason"] ?? "", (string?)r["error"] ?? "");
    }
}
