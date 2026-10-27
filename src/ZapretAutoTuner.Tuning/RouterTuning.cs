using System.Globalization;
using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Monitor;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Delivery;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.Tuning;

/// <summary>
/// Tuning on the router through zapret-gui (PLAN 4a.4 and 7.6), the closed loop R1–R5 shared by the wizard and the MCP
/// tools: R1 connect (the token's tools and the active strategy), R2 the user's yes to a trial session, R3 trials as
/// experiment variants with the router's own baseline, R4 the usual search over them (the router's results feed the
/// learned order), R5 keep the winner applied, commit only after another yes, then read the router's feedback.
/// </summary>
public static class RouterTuning
{
    /// <summary>Where the router's trials were measured: their own learning level (<see cref="LearningContext.ClientProfile"/>).</summary>
    public const string ClientProfile = "router";

    /// <summary>zapret-gui's limit on profiles per variant (core/mcp/tools/experiments.py, VARIANT_SCHEMA <c>maxItems</c>).</summary>
    public const int MaxProfiles = 8;

    /// <summary>
    /// The profiles that would not fit zapret-gui's <see cref="MaxProfiles"/> when <paramref name="ours"/> go first and
    /// the active strategy's <paramref name="current"/> after them; empty when all fit. Nothing is ever cut silently:
    /// the caller refuses and names these.
    /// </summary>
    public static IReadOnlyList<string> DroppedProfiles(IReadOnlyList<(string Name, string Args)> ours, IReadOnlyList<(string Name, string Args)> current) =>
        ours.Count + current.Count <= MaxProfiles ? [] : [.. ours.Concat(current).Skip(MaxProfiles).Select(p => p.Name)];

    /// <summary>The refusal (RU / EN) when <paramref name="ours"/> and <paramref name="current"/> exceed <see cref="MaxProfiles"/>, or null.</summary>
    public static string? ProfileLimitProblem(IReadOnlyList<(string Name, string Args)> ours, IReadOnlyList<(string Name, string Args)> current)
    {
        var dropped = DroppedProfiles(ours, current);
        if (dropped.Count == 0)
            return null;
        int total = ours.Count + current.Count;
        var names = string.Join(", ", dropped);
        return $"в zapret-gui помещается не больше {MaxProfiles} профилей, а вместе с текущей стратегией их {total}; не вошли бы: {names} / "
            + $"zapret-gui takes at most {MaxProfiles} profiles, and with the current strategy there are {total}; these would be dropped: {names}";
    }

    /// <summary>The learned order for the router: everything learned anywhere, the router's own trials as the narrowest level.</summary>
    public static SearchLearning? ForRouter(SearchLearning? learning) =>
        learning is null ? null : learning with { Context = learning.Context with { ClientProfile = ClientProfile } };

    /// <summary>R1: what the token lacks (empty when the trial tools are all there) and the active strategy's profiles.</summary>
    public static async Task<(IReadOnlyList<string> Missing, string ActiveId, IReadOnlyList<(string Name, string Args)> Current)> ConnectAsync(
        ZapretGuiExperiments experiments, CancellationToken ct)
    {
        var missing = await experiments.MissingToolsAsync(ct).ConfigureAwait(false);
        if (missing.Count > 0)
            return (missing, "", []);
        try
        {
            var (id, profiles) = await experiments.ActiveProfilesAsync(ct).ConfigureAwait(false);
            return ([], id, profiles);
        }
        catch (ZapretGuiException)
        {
            // strategy_get is a read tool; without it the variants carry only the candidate (other sites lose their bypass for a moment)
            return ([], "", []);
        }
    }

    /// <summary>
    /// A solution as variant profiles for the router: list references become inline <c>--hostlist-domains</c> and
    /// <c>--ipset-ip</c> (the router has no list files of ours), custom blobs go inline as <c>0x…</c>. What cannot be
    /// carried (an exclusion list, the auto hostlist, a profile over the GUI's size limit) is named in the problems.
    /// </summary>
    public static (List<(string Name, string Args)> Profiles, List<string> Problems) ProfilesOf(Solution s)
    {
        var profiles = new List<(string, string)>();
        var problems = new List<string>();
        foreach (var p in s.Profiles)
        {
            var q = p.Clone();
            var name = p.Name.Length > 0 ? p.Name : "autotuner";
            foreach (var h in q.Hostlists)
            {
                if (s.Hostlists.TryGetValue(h.Name, out var domains))
                    q.HostlistDomains.AddRange(domains.Where(d => !q.HostlistDomains.Contains(d, StringComparer.OrdinalIgnoreCase)));
                else
                    problems.Add($"{name}: список {h.Name} не найден / list {h.Name} not found");
            }
            foreach (var i in q.Ipsets)
            {
                if (s.Ipsets.TryGetValue(i.Name, out var ips))
                    q.IpsetIps.AddRange(ips.Where(x => !q.IpsetIps.Contains(x, StringComparer.Ordinal)));
                else
                    problems.Add($"{name}: ipset {i.Name} не найден / ipset {i.Name} not found");
            }
            if (q.HostlistExcludes.Count + q.IpsetExcludes.Count > 0 || q.HostlistAuto is not null)
                problems.Add($"{name}: исключения и автосписок не переносятся в эксперимент / exclusions and the auto hostlist are not carried into the experiment");
            q.Hostlists.Clear();
            q.Ipsets.Clear();
            q.HostlistExcludes.Clear();
            q.IpsetExcludes.Clear();
            q.HostlistAuto = null;
            var used = q.Strategy.Calls.SelectMany(c => c.Args).Select(a => a.Value).Where(v => v is not null).ToHashSet(StringComparer.Ordinal);
            var blobs = s.Blobs.Where(b => used.Contains(b.Key)).Select(b => $"--blob={b.Key}:0x{Convert.ToHexString(b.Value)}");
            var args = string.Join(' ', blobs.Append(ZapretGuiExporter.ProfileArgs(q)));
            if (args.Length > RouterTrialExecutor.MaxArgsLength)
                problems.Add($"{name}: профиль длиннее {RouterTrialExecutor.MaxArgsLength} символов (лимит zapret-gui) / the profile exceeds zapret-gui's {RouterTrialExecutor.MaxArgsLength}-character limit");
            profiles.Add((name, args));
        }
        if (profiles.Count > MaxProfiles)
            problems.Add($"профилей больше {MaxProfiles} (лимит zapret-gui) / more than {MaxProfiles} profiles (zapret-gui's limit)");
        return (profiles, problems);
    }

    /// <summary>The label of the variant a commit keeps.</summary>
    public const string KeepLabel = "zt-final";

    /// <summary>
    /// R5, first half: the profiles go to the router as the only variant with <c>keep_best</c>. The router measures them
    /// and leaves them applied, not committed: without a commit they revert by themselves after <paramref name="ttlSec"/>.
    /// A variant that the router could not run or that opened nothing is reverted at once.
    /// </summary>
    public static async Task<(ExperimentReport? Report, bool Kept, string Problem)> KeepAsync(ZapretGuiExperiments experiments,
        IReadOnlyList<(string Name, string Args)> profiles, IReadOnlyList<string> targets, int ttlSec, TimeSpan poll, CancellationToken ct)
    {
        if (profiles.Count > MaxProfiles)
            return (null, false, ProfileLimitProblem(profiles, [])!);
        ExperimentReport report;
        // only a run this call started is rolled back: a refused start (another experiment is running, say from the
        // wizard or an MCP client) must not revert someone else's experiment
        string? runId = null;
        try
        {
            runId = await experiments.StartAsync(new ExperimentRequest
            {
                Variants = [new ExperimentVariant(KeepLabel, profiles)],
                Targets = [.. targets.Take(10)],
                Repeats = 3,
                TtlSec = ttlSec,
                KeepBest = true,
            }, ct).ConfigureAwait(false);
            report = await experiments.WaitAsync(runId, poll, [KeepLabel], includeLog: false, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // a cancel during the start is ambiguous (the request may have reached the router): it is ours, revert it
            await RollbackQuietlyAsync(experiments).ConfigureAwait(false);
            throw;
        }
        catch (Exception e) when (e is ZapretGuiException or HttpRequestException or IOException)
        {
            if (runId is not null)
            {
                await RollbackQuietlyAsync(experiments).ConfigureAwait(false);
                return (null, false, "zapret-gui: " + e.Message + Reverted);
            }
            // no run id: the start may still have reached the router, and nothing here can name the run to revert
            return (null, false, "zapret-gui: " + e.Message + RevertsByTtl(ttlSec));
        }
        catch
        {
            if (runId is not null)
                await RollbackQuietlyAsync(experiments).ConfigureAwait(false);
            throw;
        }
        if (report.AwaitingCommit)
            return (report, true, "");
        await RollbackQuietlyAsync(experiments).ConfigureAwait(false);
        var v = report.Variants.FirstOrDefault(x => x.Label == KeepLabel);
        var why = v is null ? report.Error
            : v.ValidationErrors.Count > 0 ? string.Join("; ", v.ValidationErrors)
            : v.EngineError ?? (v.SkipReason.Length > 0 ? v.SkipReason : "роутер не оставил вариант: цели не открылись / the router kept nothing: the targets did not open");
        return (report, false, (why.Length > 0 ? why : report.Error) + Reverted);
    }

    private const string Reverted = " (прежнее состояние роутера возвращено / the router's previous state is restored)";

    private static string RevertsByTtl(int ttlSec) =>
        $" (если роутер всё же принял вариант, он вернёт прежнее состояние сам через {ttlSec} с / if the router did accept it, it reverts by itself within {ttlSec} s)";

    /// <summary>
    /// R5, second half, after the user's yes: commit the kept variant. With <paramref name="saveAs"/> it is also saved as
    /// a user strategy and made active (that needs <c>strategies_write</c> on the router's token); without that
    /// permission it is committed unsaved, which the answer says (it lasts until zapret-gui applies another strategy).
    /// </summary>
    public static async Task<(bool Saved, string Note)> CommitAsync(ZapretGuiExperiments experiments, bool confirmedByUser, string? saveAs, string? saveName, CancellationToken ct,
        string label = KeepLabel)
    {
        if (saveAs is not null)
        {
            try
            {
                await experiments.CommitAsync(confirmedByUser, label, saveAs, saveName, ct).ConfigureAwait(false);
                return (true, "");
            }
            catch (ZapretGuiException e) when (e.Message.Contains("strategies_write", StringComparison.Ordinal))
            {
                await experiments.CommitAsync(confirmedByUser, label, null, null, ct).ConfigureAwait(false);
                return (false, "у токена нет strategies_write: вариант закреплён без сохранения / the token lacks strategies_write: committed without saving");
            }
        }
        await experiments.CommitAsync(confirmedByUser, label, null, null, ct).ConfigureAwait(false);
        return (false, "");
    }

    /// <summary>An id zapret-gui accepts for a saved strategy (<c>[a-zA-Z0-9_-]{1,64}</c>), unique enough by the minute.</summary>
    public static string SaveId(DateTimeOffset now) => "zt_router_" + now.ToString("yyyyMMdd_HHmm", CultureInfo.InvariantCulture);

    public static async Task RollbackQuietlyAsync(ZapretGuiExperiments experiments)
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

    /// <summary>
    /// The router's measurements of an experiment as trials in the knowledge base, so they feed the learned order
    /// (source <see cref="CandidateSource.Router"/>, client profile <see cref="ClientProfile"/>). A target that opened
    /// without bypass says nothing about a strategy and is left out; so is a variant the router did not run.
    /// </summary>
    public static int Record(KnowledgeBase kb, ExperimentReport report, IReadOnlyDictionary<string, (Strategy Strategy, L4Kind L4)> byLabel, long? networkId = null)
    {
        var open = report.OpenWithoutBypass.ToHashSet(StringComparer.OrdinalIgnoreCase);
        int n = 0;
        foreach (var v in report.Variants)
        {
            if (!byLabel.TryGetValue(v.Label, out var s) || v.Skipped || !v.Started)
                continue;
            foreach (var p in v.PerTarget.Where(p => !open.Contains(p.Target)))
            {
                int attempts = Math.Max(p.Attempts, 1);
                for (int i = 0; i < attempts; i++)
                {
                    bool ok = i < p.OkCount;
                    kb.RecordTrial(new TrialRecord
                    {
                        Strategy = s.Strategy,
                        Host = p.Target,
                        L4 = s.L4 == L4Kind.Udp ? "udp" : "tcp",
                        ClientProfile = ClientProfile,
                        Ok = ok,
                        Error = ok ? null : $"{RouterTrialExecutor.Failure(p.Code)}: {p.Code} {p.CodeDesc}".Trim(),
                        BytesIn = p.BytesRead,
                        Duration = TimeSpan.FromMilliseconds(p.LatencyMs),
                        NetworkId = networkId,
                        Source = CandidateSource.Router,
                    });
                    n++;
                }
            }
        }
        return n;
    }
}

/// <summary>
/// The pipeline with the router as the place of trials (PLAN 7.6.3): each target gets a <see cref="RouterTrialExecutor"/>,
/// the router measures its own baseline in the first experiment, and the trials go to the knowledge base with source
/// <see cref="CandidateSource.Router"/>. The diagnosis runs on this PC (behind the router): a target that opens here
/// needs nothing on the router either.
/// </summary>
public sealed class RouterPipelineServices(
    ZapretGuiExperiments experiments,
    RouterTrialOptions template,
    Func<string, IProgress<(string Ru, string En)>, CancellationToken, Task<ClassifierVerdict>> classify,
    KnowledgeBase? kb = null,
    long? networkId = null,
    int? asn = null,
    string mode = "Standard") : IPipelineServices
{
    private readonly Dictionary<string, long> _sessions = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The executors handed out, by target: the wizard reads their last reports (hints) for the log.</summary>
    public Dictionary<string, RouterTrialExecutor> Executors { get; } = new(StringComparer.OrdinalIgnoreCase);

    public Task<ClassifierVerdict> ClassifyAsync(string host, IProgress<(string Ru, string En)> progress, CancellationToken ct) => classify(host, progress, ct);

    public ITrialExecutor ExecutorFor(string host, IReadOnlyList<IPAddress> addresses)
    {
        var x = new RouterTrialExecutor(experiments, template with { Targets = [host] });
        Executors[host] = x;
        return x;
    }

    public ISearchLog? LogFor(string host, ClassifierVerdict verdict)
    {
        if (kb is null)
            return null;
        var label = verdict.Primary.ToString();
        var id = kb.StartSession(host, mode, networkId, label);
        _sessions[host] = id;
        return new KnowledgeBaseSearchLog(kb, id, new TrialTarget { Host = host, Addresses = [] }, networkId, label, CandidateSource.Router, RouterTuning.ClientProfile);
    }

    public SearchOptions OptionsFor(string host, ClassifierVerdict verdict, SearchOptions options) =>
        kb is not null && _sessions.TryGetValue(host, out var id) ? TuningSession.Prepare(kb, options, id, asn) : options;

    public void Finished(string host, SearchResult result)
    {
        if (kb is not null && _sessions.TryGetValue(host, out var id))
            TuningSession.Finish(kb, id, host, result, networkId, RouterTuning.ClientProfile);
    }
}

/// <summary>
/// After a commit, zapret-gui stays the source of feedback (PLAN 7.4, 7.6.5): its engine log is read every few minutes
/// and what changed goes to the monitor's journal: a target that fails on the router, a new host the router's
/// detectors flag, a host that works again. Only reads (AGENTS.md rule 7).
/// </summary>
public sealed class RouterFeedbackWatcher(KnowledgeBase kb, Func<double, CancellationToken, Task<RouterFeedbackSnapshot>> read, IReadOnlyList<string> targets, TimeProvider? time = null)
{
    public static readonly TimeSpan DefaultInterval = TimeSpan.FromMinutes(5);

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly HashSet<string> _failing = new(StringComparer.OrdinalIgnoreCase);
    private double _since;

    /// <summary>The journal got new rows.</summary>
    public event Action? Changed;

    /// <summary>The last read's error, empty when it worked.</summary>
    public string LastError { get; private set; } = "";

    public IReadOnlyList<string> Targets => targets;

    /// <summary>One read of the router's log since the last one; returns the journal rows written.</summary>
    public async Task<int> PollOnceAsync(CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        var snapshot = await read(_since, ct).ConfigureAwait(false);
        _since = now.ToUnixTimeSeconds();
        int written = 0;
        foreach (var (host, failures, working, _) in AutoHostlistLog.Summary(snapshot.Entries, DateTime.MinValue))
        {
            bool ours = targets.Any(t => host.Equals(t, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + t, StringComparison.OrdinalIgnoreCase));
            if (failures > working)
            {
                if (!_failing.Add(host))
                    continue;
                kb.AddChange(host, ours ? "router_failing" : "router_new_host", ours
                    ? JournalReason.Encode($"на роутере: {failures} неудач, {working} успехов — стратегию стоит подобрать заново", $"on the router: {failures} failures, {working} successes — the strategy needs another search")
                    : JournalReason.Encode($"детектор роутера отмечает новый хост ({failures} неудач) — можно добавить его в подбор", $"the router's detector flags a new host ({failures} failures) — it can be added to the search"));
                written++;
            }
            else if (working > 0 && _failing.Remove(host))
            {
                kb.AddChange(host, "router_recovered", JournalReason.Encode("на роутере снова работает", "works on the router again"));
                written++;
            }
        }
        if (written > 0)
            Changed?.Invoke();
        return written;
    }

    /// <summary>Reads every <paramref name="interval"/> until cancelled; a failed read is kept in <see cref="LastError"/> and retried.</summary>
    public async Task RunAsync(TimeSpan interval, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await PollOnceAsync(ct).ConfigureAwait(false);
                LastError = "";
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception e)
            {
                // whatever a read throws (a bad answer, a parse error, a timeout), the watch goes on and says why
                LastError = e.Message;
            }
            try
            {
                await Task.Delay(interval, _time, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}
