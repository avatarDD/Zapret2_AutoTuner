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

    public McpAudit Audit { get; } = new();

    /// <summary>Cancelled by the Stop button: every call in flight ends with it.</summary>
    public CancellationToken StopToken => _stop.Token;

    /// <summary>The last client that called (shown on the banner); null when none.</summary>
    public string? Client { get; set; }

    public DateTime? LastCall { get; set; }

    /// <summary>A trial, the search or an experiment is running on the model's behalf.</summary>
    public bool Busy => Search.Running || Experiments.Running || Router.Running || _trialsRunning > 0;

    private int _trialsRunning;

    internal void TrialStarted() => Interlocked.Increment(ref _trialsRunning);

    internal void TrialEnded() => Interlocked.Decrement(ref _trialsRunning);

    public bool IsTarget(string host) => Host.Targets.Contains(host, StringComparer.OrdinalIgnoreCase);

    public ClassifierVerdict? Verdict(string host) => _verdicts.GetValueOrDefault(host);

    public void SetVerdict(ClassifierVerdict v) => _verdicts[v.Host] = v;

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
