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
    /// <summary>zapret-gui's limit on one profile's args (core/mcp/tools/experiments.py, VARIANT_SCHEMA <c>profiles[].args</c>).</summary>
    public const int MaxArgsLength = 2000;

    /// <summary>The targets that opened without bypass, measured by the first experiment of the session.</summary>
    private HashSet<string>? _openWithoutBypass;

    /// <summary>The last report: its hints go to the failure report.</summary>
    public ExperimentReport? LastReport { get; private set; }

    public async Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
    {
        var all = await RunBatchAsync([candidate], attempts, ct).ConfigureAwait(false);
        return all[0];
    }

    /// <summary>
    /// Several candidates in experiments of <see cref="RouterTrialOptions.BatchSize"/>; outcomes in input order. A
    /// candidate the GUI would refuse for its size fails without being sent, and a batch the GUI refuses fails as a
    /// whole: the search goes on with the next ones. Only a cancellation (or a fault of our own) ends it.
    /// </summary>
    public async Task<IReadOnlyList<IReadOnlyList<TrialOutcome>>> RunBatchAsync(IReadOnlyList<StrategyCandidate> candidates, int attempts, CancellationToken ct)
    {
        var results = new IReadOnlyList<TrialOutcome>[candidates.Count];
        var sendable = new List<(int Index, List<(string Name, string Args)> Profiles)>();
        for (int i = 0; i < candidates.Count; i++)
        {
            var profiles = Profiles(candidates[i]);
            if (RouterTuning.ProfileLimitProblem([profiles[0]], options.CurrentProfiles) is { } tooMany)
                results[i] = [TrialOutcome.Fail(TrialFailure.Other, tooMany + " (вариант не отправлен / not sent)")];
            else if (profiles.FirstOrDefault(p => p.Args.Length > MaxArgsLength) is { Args: not null } big)
                results[i] = [TrialOutcome.Fail(TrialFailure.Other,
                    $"профиль «{big.Name}» длиннее {MaxArgsLength} символов (лимит zapret-gui), вариант не отправлен / profile '{big.Name}' exceeds zapret-gui's {MaxArgsLength}-character limit, not sent")];
            else
                sendable.Add((i, profiles));
        }
        foreach (var chunk in sendable.Chunk(Math.Max(1, options.BatchSize)))
        {
            var variants = chunk.Select((c, j) => new ExperimentVariant(Label(j), c.Profiles)).ToList();
            // AGENTS.md rule 5: the router measures without bypass first, so a target that opens anyway is left out of
            // the outcomes (it says nothing about the strategy). Once per session: the block does not change per batch.
            bool measureBaseline = _openWithoutBypass is null;
            ExperimentReport report;
            // only a run this call started is rolled back: a refused start (another experiment runs on the router)
            // must not revert someone else's experiment; a cancel in flight is the exception (see below)
            string? runId = null;
            try
            {
                runId = await experiments.StartAsync(new ExperimentRequest
                {
                    Variants = variants,
                    Targets = options.Targets.Take(10).ToList(),
                    Repeats = Math.Clamp(attempts, 1, 5),
                    Baseline = measureBaseline,
                    TtlSec = options.TtlSec,
                }, ct).ConfigureAwait(false);
                report = await experiments.WaitAsync(runId, options.Poll, [.. variants.Select(v => v.Label)], includeLog: false, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // the router reverts by the dead-man switch anyway; ask it now so the user's sites come back at once.
                // A cancel during the start is ambiguous (the request may have reached the router): it is ours, revert it
                await RollbackQuietlyAsync().ConfigureAwait(false);
                throw;
            }
            catch (ZapretGuiException e)
            {
                if (runId is not null)
                    await RollbackQuietlyAsync().ConfigureAwait(false);
                foreach (var c in chunk)
                    results[c.Index] = [TrialOutcome.Fail(TrialFailure.Other, "zapret-gui: " + e.Message)];
                continue;
            }
            catch
            {
                if (runId is not null)
                    await RollbackQuietlyAsync().ConfigureAwait(false);
                throw;
            }
            LastReport = report;
            if (measureBaseline)
                _openWithoutBypass = report.OpenWithoutBypass.ToHashSet(StringComparer.OrdinalIgnoreCase);
            for (int j = 0; j < chunk.Length; j++)
                results[chunk[j].Index] = Outcomes(report.Variants.FirstOrDefault(v => v.Label == Label(j)), report, _openWithoutBypass);
        }
        return results;
    }

    private async Task RollbackQuietlyAsync()
    {
        try
        {
            await experiments.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception e) when (e is ZapretGuiException or HttpRequestException or IOException or OperationCanceledException)
        {
            // the dead-man switch reverts the router anyway
        }
    }

    /// <summary>The router answers for its own reachability; a punishment pause has nothing to check from here.</summary>
    public Task<bool> TargetReachableAsync(CancellationToken ct) => Task.FromResult(true);

    internal static string Label(int i) => "zt" + i.ToString(CultureInfo.InvariantCulture);

    /// <summary>The candidate first, limited to the targets, with its blobs inlined; then the active strategy's profiles.</summary>
    internal List<(string Name, string Args)> Profiles(StrategyCandidate c) =>
        [(ProfileName, CandidateArgs(c.Strategy, c.L4, options.Targets, options.Blobs)), .. options.CurrentProfiles];

    /// <summary>The name of the candidate's profile in a variant.</summary>
    public const string ProfileName = "AutoTuner";

    /// <summary>
    /// The args of a candidate's profile on the router: its ports, the targets as <c>--hostlist-domains</c> (the router
    /// has no list files of ours) and the inline blobs it uses (<c>0x…</c>; a blob from a file is left out).
    /// </summary>
    public static string CandidateArgs(Strategy strategy, L4Kind l4, IReadOnlyList<string> targets, IReadOnlyDictionary<string, string>? blobs = null)
    {
        var p = new Profile { Name = "autotuner", Strategy = strategy, HostlistDomains = [.. targets] };
        if (l4 == L4Kind.Udp)
            p.UdpPorts = "443";
        else
            p.TcpPorts = "443,80";
        var used = strategy.Calls.SelectMany(x => x.Args).Select(a => a.Value).Where(v => v is not null).ToHashSet(StringComparer.Ordinal);
        var inline = (blobs ?? new Dictionary<string, string>()).Where(b => used.Contains(b.Key) && b.Value.StartsWith("0x", StringComparison.Ordinal))
            .Select(b => $"--blob={b.Key}:{b.Value}");
        return string.Join(' ', inline.Append(ZapretGuiExporter.ProfileArgs(p)));
    }

    /// <summary>
    /// A variant's probes as trial outcomes: per target, <c>ok_count</c> of <c>attempts</c> succeeded. A target that
    /// opened without bypass says nothing about the strategy and is left out.
    /// </summary>
    internal static List<TrialOutcome> Outcomes(ExperimentVariantResult? v, ExperimentReport report, IReadOnlyCollection<string>? openWithoutBypass = null)
    {
        if (v is null)
            return [TrialOutcome.Fail(TrialFailure.Other, report.Error.Length > 0 ? report.Error : "вариант не попал в отчёт / variant missing from the report")];
        if (v.Skipped || !v.Started)
        {
            var why = v.ValidationErrors.Count > 0 ? string.Join("; ", v.ValidationErrors) : v.EngineError ?? v.SkipReason;
            return [TrialOutcome.Fail(TrialFailure.Other, "роутер не запустил вариант / the router did not run it: " + why)];
        }
        var open = (openWithoutBypass ?? report.OpenWithoutBypass).ToHashSet(StringComparer.OrdinalIgnoreCase);
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
