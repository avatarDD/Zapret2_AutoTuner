using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Mcp;

/// <summary>A trial run over MCP, kept for trials_history and its capture resource.</summary>
public sealed record McpTrial(string Id, DateTime Time, string Target, string StrategyId, string Level, int Successes, int Attempts, string Reading, JsonObject Observation, byte[]? Pcap);

/// <summary>
/// The state the tools share for as long as the program runs: verdicts, baselines, trials, the strategies seen (so a
/// model can refer to them by id) and the permissions, limits and confirmations. One instance serves every transport
/// and the built-in advisor alike.
/// </summary>
public sealed class McpSession
{
    public const int MaxTrials = 50;
    public const int MaxPcapBytes = 2 << 20;

    private readonly ConcurrentDictionary<string, ClassifierVerdict> _verdicts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, (DateTime Time, int Successes, int Attempts, string Level, string Reading)> _baselines = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, (Strategy Strategy, L4Kind L4)> _strategies = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Task<ClassifierVerdict>> _classifying = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _classifyErrors = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<McpTrial> _trials = [];
    private readonly Lock _lock = new();
    private int _nextTrial;
    private CancellationTokenSource _stop = new();

    public McpSession(IAutoTunerHost host, IUserConfirm confirm, Func<McpPermissions> permissions, BudgetOptions? budget = null, TimeProvider? time = null)
    {
        Host = host;
        Permissions = permissions;
        Time = time ?? TimeProvider.System;
        Budget = new TrialBudget(budget ?? new BudgetOptions(), Time);
        Confirmations = new PendingConfirmations(confirm);
        Search = new SearchController(this);
        Experiments = new ExperimentRunner(this);
        Router = new RouterExperimentRunner(this);
        Proxy = new RouterProxy(this);
    }

    public IAutoTunerHost Host { get; }

    public Func<McpPermissions> Permissions { get; }

    public TimeProvider Time { get; }

    public TrialBudget Budget { get; }

    public PendingConfirmations Confirmations { get; }

    public SearchController Search { get; }

    public ExperimentRunner Experiments { get; }

    /// <summary>Experiments on the router through zapret-gui (router_experiment_*).</summary>
    public RouterExperimentRunner Router { get; }

    /// <summary>zapret-gui's own tools relayed as gui_* (router_proxy).</summary>
    public RouterProxy Proxy { get; }

    public McpAudit Audit { get; } = new();

    /// <summary>Cancelled by the Stop button: every call in flight ends with it.</summary>
    public CancellationToken StopToken => _stop.Token;

    /// <summary>The last client that called (shown on the banner); null when none.</summary>
    public string? Client { get; set; }

    public DateTime? LastCall { get; set; }

    /// <summary>A trial, the search or an experiment is running on the model's behalf.</summary>
    public bool Busy => Search.Running || Experiments.Running || Router.Running || _trialsRunning > 0;

    /// <summary>The router is in the model's hands: an experiment runs there, or its kept variant awaits a commit.</summary>
    public bool RouterBusy => Router.Running || Router.Holding;

    private int _trialsRunning;

    internal void TrialStarted() => Interlocked.Increment(ref _trialsRunning);

    internal void TrialEnded() => Interlocked.Decrement(ref _trialsRunning);

    /// <summary>
    /// Why the model's trials, search or experiments on this PC cannot run now, or null: the user tunes in the wizard,
    /// or «Защита активна» holds the traffic (two engines would fight for it).
    /// </summary>
    public JsonObject? LocalWorkRefusal()
    {
        if (Host.LocalTuningRunning)
            return McpErrors.Error("busy: the user is tuning in the AutoTuner wizard on this PC; wait until it finishes / занято: идёт подбор в мастере AutoTuner");
        if (Host.ProtectionActive)
            return McpErrors.Error("busy: «Защита активна» runs on this PC; the user stops it first / занято: работает защита");
        return null;
    }

    public bool IsTarget(string host) => Host.Targets.Contains(host, StringComparer.OrdinalIgnoreCase);

    /// <summary>The model's own diagnosis, else the one the wizard made in the user's search.</summary>
    public ClassifierVerdict? Verdict(string host) => _verdicts.GetValueOrDefault(host) ?? Host.WizardVerdict(host);

    public void SetVerdict(ClassifierVerdict v) => _verdicts[v.Host] = v;

    /// <summary>How long diagnose(refresh) waits for the classifier before answering "running" (probes of a new target take longer than a client's call timeout).</summary>
    public TimeSpan DiagnoseWait { get; set; } = TimeSpan.FromSeconds(20);

    /// <summary>
    /// The classification of <paramref name="host"/> in progress, started now when none runs. It lives on the session
    /// (the Stop button ends it), not on the call: a client that gives up waiting still gets the verdict cached for its
    /// next call, and a second call joins the run instead of probing again.
    /// </summary>
    public Task<ClassifierVerdict> Classify(string host, out bool started)
    {
        lock (_lock)
        {
            if (_classifying.TryGetValue(host, out var running))
            {
                started = false;
                return running;
            }
            var token = StopToken;
            var task = Task.Run(() => ClassifyAndKeepAsync(host, token));
            // the failure is kept in ClassifyError; a run nobody waits for any more must not end up unobserved
            _ = task.ContinueWith(t => _ = t.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
            _classifying[host] = task;
            started = true;
            return task;
        }
    }

    /// <summary>A classification of the host is running now.</summary>
    public bool Classifying(string host)
    {
        lock (_lock)
            return _classifying.ContainsKey(host);
    }

    /// <summary>Why the last classification of the host failed; null after a success.</summary>
    public string? ClassifyError(string host) => _classifyErrors.GetValueOrDefault(host);

    private async Task<ClassifierVerdict> ClassifyAndKeepAsync(string host, CancellationToken ct)
    {
        try
        {
            var v = await Host.ClassifyAsync(host, ct).ConfigureAwait(false);
            SetVerdict(v);
            _classifyErrors.TryRemove(host, out _);
            return v;
        }
        catch (Exception e)
        {
            _classifyErrors[host] = e is OperationCanceledException ? "stopped / остановлено" : $"{e.GetType().Name}: {e.Message}";
            throw;
        }
        finally
        {
            lock (_lock)
                _classifying.Remove(host);
        }
    }

    public (DateTime Time, int Successes, int Attempts, string Level, string Reading)? Baseline(string host) =>
        _baselines.TryGetValue(host, out var b) && Time.GetUtcNow().UtcDateTime - b.Time < TimeSpan.FromMinutes(10) ? b : null;

    public void SetBaseline(string host, int successes, int attempts, string level, string reading) =>
        _baselines[host] = (Time.GetUtcNow().UtcDateTime, successes, attempts, level, reading);

    /// <summary>Remembers a strategy so the model can name it by id; returns the id.</summary>
    public string Remember(Strategy s, L4Kind l4 = L4Kind.Tcp)
    {
        var id = StrategyPolicy.IdOf(s);
        _strategies[id] = (s, l4);
        return id;
    }

    public (Strategy Strategy, L4Kind L4)? Strategy(string id)
    {
        if (_strategies.TryGetValue(id, out var s))
            return s;
        return null;
    }

    public McpTrial AddTrial(string target, string strategyId, string level, int successes, int attempts, string reading, JsonObject observation, byte[]? pcap)
    {
        lock (_lock)
        {
            var t = new McpTrial("tr-" + (++_nextTrial).ToString(System.Globalization.CultureInfo.InvariantCulture), Time.GetUtcNow().UtcDateTime, target, strategyId, level,
                successes, attempts, reading, observation, pcap is { Length: <= MaxPcapBytes } ? pcap : null);
            _trials.Add(t);
            if (_trials.Count > MaxTrials)
                _trials.RemoveAt(0);
            return t;
        }
    }

    public IReadOnlyList<McpTrial> Trials
    {
        get
        {
            lock (_lock)
                return [.. _trials];
        }
    }

    public McpTrial? Trial(string id)
    {
        lock (_lock)
            return _trials.FirstOrDefault(t => t.Id == id);
    }

    /// <summary>The Stop button: the search and the experiments stop (engines with them, the router reverts), dialogs are cancelled.</summary>
    public async Task StopAllAsync()
    {
        Confirmations.CancelAll();
        var old = Interlocked.Exchange(ref _stop, new CancellationTokenSource());
        await old.CancelAsync().ConfigureAwait(false);
        await Search.StopAsync().ConfigureAwait(false);
        await Experiments.RollbackAsync("stopped by the user / остановлено пользователем").ConfigureAwait(false);
        await Router.RollbackAsync("stopped by the user / остановлено пользователем").ConfigureAwait(false);
        Client = null;
        LastCall = null;
    }
}
