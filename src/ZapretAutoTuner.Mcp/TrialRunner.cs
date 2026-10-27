using System.Net;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Storage;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.Mcp;

/// <summary>The trial_run tool (M2): one strategy, one target, one series, and the observation.</summary>
internal sealed class TrialRunner(McpSession session)
{
    /// <summary>The verdict that allows a strategy trial, or the error that says why not (AGENTS.md rule 5).</summary>
    public static (ClassifierVerdict? Verdict, JsonObject? Error) Blocked(McpSession session, string target)
    {
        if (!session.IsTarget(target))
            return (null, McpErrors.NotATarget(target));
        var v = session.Verdict(target);
        if (v is null)
            return (null, McpErrors.Error($"{target} has no diagnosis yet: call diagnose with refresh=true first (a strategy is tried only on a resource shown to be blocked) / сначала diagnose с refresh=true"));
        if (v.Next != NextStep.SearchStrategy || v.LiveAddresses.Count == 0)
            return (null, McpErrors.Error($"{target}: {v.SummaryEn} — a strategy does not help here (next step: {v.Next}) / {v.SummaryRu}"));
        return (v, null);
    }

    public async Task<JsonObject> RunAsync(JsonObject args, CancellationToken ct)
    {
        var target = (string)args["target"]!;
        var (verdict, error) = Blocked(session, target);
        if (error is not null)
            return error;
        if (session.LocalWorkRefusal() is { } localBusy)
            return localBusy;
        var profile = ClientProfile.BuiltIn.FirstOrDefault(p => p.Id == ((string?)args["client"] ?? "curl")) ?? ClientProfile.BuiltIn[0];
        var (checkedStrategy, refusal) = McpErrors.StrategyFrom(session, args, profile);
        if (refusal is not null)
            return refusal;
        var strategy = checkedStrategy!.Strategy!;
        var level = (string?)args["level"] ?? "L2";
        int attempts = (int?)args["attempts"] ?? 3;
        if (level == "L3" && session.Host.OpenPage is null)
            return McpErrors.Error("L3 needs a browser, and none is available here: use L2 / для L3 нужен браузер");
        var (ok, why, retry) = session.Budget.TryTake(target);
        if (!ok)
            return McpErrors.Budget(why!, retry);

        var addresses = verdict!.LiveAddresses.Select(IPAddress.Parse).ToList();
        var trialTarget = new TrialTarget
        {
            Host = target,
            Addresses = addresses,
            MinBytes = verdict.Labels.Contains(BlockLabel.Cutoff16K) ? 128 * 1024 : 64 * 1024,
        };
        var probeLevel = level == "L1" ? ProbeLevel.L1Handshake : ProbeLevel.L2Body;
        var engine = await session.Host.EngineAsync(ct).ConfigureAwait(false);
        var executor = new AgentTrialExecutor(engine, trialTarget, session.Host.TrialOptions);
        var candidate = new StrategyCandidate(strategy, "llm", 0, ["llm"], checkedStrategy.L4);
        var strategyId = session.Remember(strategy, checkedStrategy.L4);

        session.TrialStarted();
        try
        {
            var baseline = session.Baseline(target);
            if (baseline is null)
            {
                var b = new List<ProbeResult>();
                for (int i = 0; i < Math.Min(attempts, 2); i++)
                    b.Add(await session.Host.ProbeAsync(executor.ProbeOptions(addresses[i % addresses.Count]) with { Level = probeLevel }, ct).ConfigureAwait(false));
                var best = b.MaxBy(r => Rank(Observation.LevelOf(r, trialTarget.MinBytes)))!;
                session.SetBaseline(target, b.Count(r => r.Passes(probeLevel, trialTarget.MinBytes)), b.Count, Observation.LevelOf(best, trialTarget.MinBytes), Observation.ReadingOf(b[^1], trialTarget.MinBytes));
                baseline = session.Baseline(target);
            }

            var capture = session.Host.Capture;
            string? captureId = null;
            if (capture is not null)
            {
                try
                {
                    captureId = await capture.StartAsync(addresses, trialTarget.Port, ct).ConfigureAwait(false);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    captureId = null;
                }
            }
            var results = new List<ProbeResult>();
            PageLoad? page = null;
            string? refused = null;
            try
            {
                await executor.WithEngineAsync(candidate, async c =>
                {
                    for (int i = 0; i < attempts; i++)
                    {
                        if (i > 0)
                            await Task.Delay(session.Host.TrialOptions.Pause, c).ConfigureAwait(false);
                        var r = await session.Host.ProbeAsync(executor.ProbeOptions(addresses[i % addresses.Count]) with { Level = probeLevel }, c).ConfigureAwait(false);
                        results.Add(r);
                        bool noConnect = !r.ConnectOk;
                        session.Budget.Observe(target, noConnect);
                        if (results.Count >= session.Budget.Options.PunishThreshold && results.TakeLast(session.Budget.Options.PunishThreshold).All(x => !x.ConnectOk))
                            break;
                    }
                    if (level == "L3" && results.Any(r => r.Passes(ProbeLevel.L2Body, trialTarget.MinBytes)))
                        page = await session.Host.OpenPage!(target, c).ConfigureAwait(false);
                    return true;
                }, ct).ConfigureAwait(false);
            }
            catch (EngineRefusedException e) when (!e.Infrastructure)
            {
                refused = e.Message;
            }
            finally
            {
                byte[]? pcap = null;
                if (captureId is not null)
                {
                    try
                    {
                        pcap = await capture!.StopAsync(captureId, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        pcap = null;
                    }
                }
                _pcap = pcap;
            }

            // AGENTS.md rule 5: success is a full download; an L1 handshake proves nothing, so L1 trials stay out of the
            // knowledge base (its statistics and the learned order); they are kept in trials_history only
            foreach (var r in level == "L1" ? new List<ProbeResult>() : results)
            {
                var o = AgentTrialExecutor.ToOutcome(r, trialTarget.MinBytes);
                session.Host.Kb.RecordTrial(new TrialRecord
                {
                    Strategy = strategy,
                    Family = "llm",
                    Host = target,
                    L4 = checkedStrategy.L4 == L4Kind.Udp ? "udp" : "tcp",
                    ClientProfile = profile.Id,
                    Level = level,
                    Ok = o.Ok,
                    Error = o.Ok ? null : $"{o.Failure}: {o.Detail}",
                    BytesIn = o.BytesIn,
                    Duration = o.Duration,
                    BlockLabel = verdict.Primary.ToString(),
                });
            }
            return Build(target, strategy, strategyId, level, profile, trialTarget.MinBytes, probeLevel, results, page, baseline, refused, checkedStrategy);
        }
        finally
        {
            session.TrialEnded();
        }
    }

    private byte[]? _pcap;

    private JsonObject Build(string target, Strategy strategy, string strategyId, string level, ClientProfile profile, long minBytes, ProbeLevel probeLevel,
        List<ProbeResult> results, PageLoad? page, (DateTime Time, int Successes, int Attempts, string Level, string Reading)? baseline, string? refused, CheckedStrategy checkedStrategy)
    {
        int successes = results.Count(r => r.Passes(probeLevel, minBytes));
        if (level == "L3")
            successes = page is { LoadFired: true, Error: null } ? successes : 0;
        var reached = results.Count == 0 ? "none" : results.Select(r => Observation.LevelOf(r, minBytes)).MaxBy(Rank)!;
        if (level == "L3" && page is { LoadFired: true, Error: null })
            reached = "L3";
        var reading = refused is not null ? "engine_refused" : results.Count == 0 ? "no_attempt" : Observation.ReadingOf(results.FirstOrDefault(r => !r.Passes(probeLevel, minBytes)) ?? results[^1], minBytes);
        string delta = baseline is not { } b ? "no_baseline"
            : successes == results.Count && results.Count > 0 && b.Successes < b.Attempts ? "fixed"
            : (double)successes / Math.Max(1, results.Count) > (double)b.Successes / Math.Max(1, b.Attempts) ? "improved"
            : (double)successes / Math.Max(1, results.Count) < (double)b.Successes / Math.Max(1, b.Attempts) ? "worse"
            : "unchanged";
        var obs = new JsonObject
        {
            ["ok"] = refused is null,
            ["target"] = target,
            ["strategy_id"] = strategyId,
            ["strategy"] = strategy.ToString(),
            ["client"] = profile.Id,
            ["level"] = level,
            ["result"] = new JsonObject
            {
                ["level_reached"] = reached,
                ["successes"] = successes,
                ["attempts"] = results.Count,
                ["body_bytes_median"] = (long)Observation.Median(results.Select(r => (double)r.BodyBytes)),
                ["time_ms_median"] = (long)Observation.Median(results.Select(r => r.Duration.TotalMilliseconds)),
                ["baseline"] = baseline is { } bb ? new JsonObject { ["successes"] = bb.Successes, ["attempts"] = bb.Attempts, ["level_reached"] = bb.Level, ["reading"] = bb.Reading } : null,
                ["delta"] = delta,
            },
            ["reading"] = reading,
            ["attempts"] = new JsonArray([.. results.Select((r, i) => (JsonNode)Observation.Attempt(i + 1, r, minBytes))]),
            ["warnings"] = StrategyPolicy.Issues(checkedStrategy.Issues, Core.Validation.Severity.Warning),
        };
        if (refused is not null)
            obs["engine_refused"] = Observation.Short(refused, 400);
        if (page is not null)
            obs["page"] = Observation.Page(page);
        if (_pcap is { Length: > 0 } pcap)
        {
            try
            {
                obs["wire"] = Observation.Wire(PcapReader.Read(pcap), 443);
            }
            catch (Exception e) when (e is FormatException or InvalidDataException or ArgumentException or IndexOutOfRangeException)
            {
                obs["wire"] = new JsonObject { ["error"] = "capture could not be read" };
            }
        }
        var trial = session.AddTrial(target, strategyId, level, successes, results.Count, reading, obs, _pcap);
        obs["trial_id"] = trial.Id;
        if (trial.Pcap is not null)
            obs["capture"] = McpResources.CaptureUri(trial.Id);
        return obs;
    }

    private static int Rank(string level) => level switch { "L3" => 4, "L2" => 3, "L1" => 2, "L0" => 1, _ => 0 };
}
