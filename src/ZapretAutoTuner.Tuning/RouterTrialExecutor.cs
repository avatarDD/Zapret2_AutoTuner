using System.Globalization;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Delivery;

namespace ZapretAutoTuner.Tuning;

public sealed record RouterTrialOptions
{
    /// <summary>The domains the strategy is for; the router probes them (zapret-gui allows 10 per experiment).</summary>
    public required IReadOnlyList<string> Targets { get; init; }

    /// <summary>The active strategy's profiles (<c>name</c>, <c>args</c>): they stay after the candidate's, so other sites keep their bypass.</summary>
    public IReadOnlyList<(string Name, string Args)> CurrentProfiles { get; init; } = [];

    /// <summary>Blobs the candidates use: name → <c>0x…</c> (inlined; the router has no files of ours).</summary>
    public IReadOnlyDictionary<string, string> Blobs { get; init; } = new Dictionary<string, string>();

    /// <summary>The dead-man switch of each experiment.</summary>
    public int TtlSec { get; init; } = 300;

    public TimeSpan Poll { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Most variants per experiment: each one restarts nfqws2 on the router.</summary>
    public int BatchSize { get; init; } = 5;
}

/// <summary>
/// Trials on the router (PLAN 7.6): candidates go to zapret-gui as variants of one MCP experiment, the router probes
/// the targets with each and reverts by itself. The search does not know the difference: it gets the same outcomes.
/// </summary>
public sealed class RouterTrialExecutor(ZapretGuiExperiments experiments, RouterTrialOptions options) : ITrialExecutor
{
    /// <summary>The last report: its engine log and hints go to the failure report.</summary>
    public ExperimentReport? LastReport { get; private set; }

    public async Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
    {
        var all = await RunBatchAsync([candidate], attempts, ct).ConfigureAwait(false);
        return all[0];
    }

    /// <summary>Several candidates in experiments of <see cref="RouterTrialOptions.BatchSize"/>; outcomes in input order.</summary>
    public async Task<IReadOnlyList<IReadOnlyList<TrialOutcome>>> RunBatchAsync(IReadOnlyList<StrategyCandidate> candidates, int attempts, CancellationToken ct)
    {
        var results = new List<IReadOnlyList<TrialOutcome>>();
        foreach (var chunk in candidates.Chunk(Math.Max(1, options.BatchSize)))
        {
            var variants = chunk.Select((c, i) => new ExperimentVariant(Label(i), Profiles(c))).ToList();
            ExperimentReport report;
            try
            {
                var runId = await experiments.StartAsync(new ExperimentRequest
                {
                    Variants = variants,
                    Targets = options.Targets.Take(10).ToList(),
                    Repeats = Math.Clamp(attempts, 1, 5),
                    TtlSec = options.TtlSec,
                }, ct).ConfigureAwait(false);
                report = await experiments.WaitAsync(runId, options.Poll, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // the router reverts by the dead-man switch anyway; ask it now so the user's sites come back at once
                await experiments.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
                throw;
            }
            LastReport = report;
            for (int i = 0; i < chunk.Length; i++)
                results.Add(Outcomes(report.Variants.FirstOrDefault(v => v.Label == Label(i)), report));
        }
        return results;
    }

    /// <summary>The router answers for its own reachability; a punishment pause has nothing to check from here.</summary>
    public Task<bool> TargetReachableAsync(CancellationToken ct) => Task.FromResult(true);

    internal static string Label(int i) => "zt" + i.ToString(CultureInfo.InvariantCulture);

    /// <summary>The candidate first, limited to the targets, with its blobs inlined; then the active strategy's profiles.</summary>
    internal List<(string Name, string Args)> Profiles(StrategyCandidate c)
    {
        var port = c.L4 == L4Kind.Udp ? "443" : "443,80";
        var p = new Profile { Name = "autotuner", Strategy = c.Strategy, HostlistDomains = [.. options.Targets] };
        if (c.L4 == L4Kind.Udp)
            p.UdpPorts = port;
        else
            p.TcpPorts = port;
        var used = c.Strategy.Calls.SelectMany(x => x.Args).Select(a => a.Value).Where(v => v is not null).ToHashSet(StringComparer.Ordinal);
        var blobs = options.Blobs.Where(b => used.Contains(b.Key) && b.Value.StartsWith("0x", StringComparison.Ordinal))
            .Select(b => $"--blob={b.Key}:{b.Value}");
        var args = string.Join(' ', blobs.Append(ZapretGuiExporter.ProfileArgs(p)));
        return [("AutoTuner", args), .. options.CurrentProfiles];
    }

    /// <summary>
    /// A variant's probes as trial outcomes: per target, <c>ok_count</c> of <c>attempts</c> succeeded. A target that
    /// opened without bypass says nothing about the strategy and is left out.
    /// </summary>
    internal static List<TrialOutcome> Outcomes(ExperimentVariantResult? v, ExperimentReport report)
    {
        if (v is null)
            return [TrialOutcome.Fail(TrialFailure.Other, report.Error.Length > 0 ? report.Error : "вариант не попал в отчёт / variant missing from the report")];
        if (v.Skipped || !v.Started)
        {
            var why = v.ValidationErrors.Count > 0 ? string.Join("; ", v.ValidationErrors) : v.EngineError ?? v.SkipReason;
            return [TrialOutcome.Fail(TrialFailure.Other, "роутер не запустил вариант / the router did not run it: " + why)];
        }
        var open = report.OpenWithoutBypass.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var outcomes = new List<TrialOutcome>();
        foreach (var p in v.PerTarget.Where(p => !open.Contains(p.Target)))
        {
            int attempts = Math.Max(p.Attempts, 1);
            for (int i = 0; i < attempts; i++)
            {
                bool ok = i < p.OkCount;
                outcomes.Add(ok
                    ? new TrialOutcome(true, TrialFailure.None, null, p.BytesRead, TimeSpan.FromMilliseconds(p.LatencyMs))
                    : new TrialOutcome(false, Failure(p.Code), $"{p.Target}: {p.Code} {p.CodeDesc}", p.BytesRead, TimeSpan.FromMilliseconds(p.LatencyMs)));
            }
        }
        return outcomes.Count > 0 ? outcomes : [TrialOutcome.Fail(TrialFailure.Other, "нет целей, заблокированных без обхода / no target is blocked without bypass")];
    }

    /// <summary>zapret-gui's probe codes (core/testers/probe.py PROBE_CODES) in the search's terms.</summary>
    internal static TrialFailure Failure(string code) => code switch
    {
        "tcp_reset" or "tls_rst" => TrialFailure.Reset,
        "tcp_timeout" or "tls_timeout" or "http_timeout" => TrialFailure.Timeout,
        "tcp_16_20" or "http_cutoff" or "throttled" => TrialFailure.Stalled,
        "tls_mitm" => TrialFailure.BadCertificate,
        "tcp_refused" => TrialFailure.NoConnect,
        _ => TrialFailure.Other,
    };
}
