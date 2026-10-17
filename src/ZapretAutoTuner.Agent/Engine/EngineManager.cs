using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using ZapretAutoTuner.Agent.Firewall;
using ZapretAutoTuner.Agent.Os;
using ZapretAutoTuner.Core.Catalog;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Agent.Engine;

internal sealed record CheckResult(bool Ok, string Stage, IReadOnlyList<string> Output);

/// <summary>
/// Starts and stops engine instances (PLAN 1.2). Every argv passes the Validator and the Agent policy before it
/// runs (AGENTS.md rule 4); on Linux each instance gets its queue rule in the firewall, removed when it stops.
/// </summary>
internal sealed class EngineManager : IDisposable
{
    public const uint FwMark = 0x40000000;

    private readonly ConcurrentDictionary<string, EngineInstance> _engines = new();
    private readonly ConcurrentDictionary<string, int> _queues = new();
    private readonly AgentOptions _options;
    private readonly FirewallManager? _firewall;
    private readonly AgentStateStore _state;
    private readonly WindowsJob? _job;
    private int _seq;

    public EngineManager(AgentOptions options, AgentStateStore state, FirewallManager? firewall)
    {
        _options = options;
        _state = state;
        _firewall = firewall;
        EnginePath = options.Engine ?? Tools.Zapret2Bundle.Locate().EnginePath;
        if (OperatingSystem.IsWindows())
            _job = new WindowsJob();
    }

    public string EnginePath { get; }

    public EnginePlatform Platform => OperatingSystem.IsWindows() ? EnginePlatform.Windows : EnginePlatform.Linux;

    public IReadOnlyList<string> Running => _engines.Values.Where(e => !e.HasExited).Select(e => e.Id).ToList();

    public IReadOnlyList<string> WriteRoots => [_options.DataDir!];

    /// <summary>Where blob files may come from: the data directory and the engine's own directory (files/fake).</summary>
    public IReadOnlyList<string> ReadRoots => [_options.DataDir!, Path.GetDirectoryName(EnginePath) ?? _options.DataDir!];

    public EngineInstance? Find(string id) => _engines.GetValueOrDefault(id);

    /// <summary>Validator + policy problems, or null if the argv may run.</summary>
    /// <param name="extraReadRoots">More directories the argv may read from (the winws2 service directory).</param>
    public CheckResult? Precheck(IReadOnlyList<string> argv, IReadOnlyList<string>? extraReadRoots = null)
    {
        var policy = EngineArgvPolicy.Check(argv, WriteRoots, [.. ReadRoots, .. extraReadRoots ?? []]);
        if (policy.Count > 0)
            return new CheckResult(false, "policy", policy);
        var ctx = new ValidationContext { Catalog = LuaCatalog.Default, Platform = Platform };
        var result = new StrategyValidator(ctx).ValidateArgv(argv, f => File.Exists(f) ? new FileInfo(f).Length : null);
        if (!result.Ok)
            return new CheckResult(false, "validator", result.Errors.Select(e => e.ToString()).ToList());
        return null;
    }

    /// <summary><c>--dry-run</c>, then <c>--intercept=0</c> (catches lua-init errors), nfqws2-engine §9.</summary>
    public async Task<CheckResult> CheckAsync(IReadOnlyList<string> argv, CancellationToken ct)
    {
        if (Precheck(argv) is { } bad)
            return bad;
        foreach (var (stage, extra) in new[] { ("dry-run", "--dry-run"), ("intercept=0", "--intercept=0") })
        {
            // nfqws2 refuses to start without --qnum even for --dry-run; nothing is intercepted here
            var full = WithManaged(argv, queueNum: 0).Append(extra).ToList();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(20));
            CmdResult r;
            try
            {
                r = await Cmd.RunAsync(EnginePath, full, ct: cts.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return new CheckResult(false, stage, ["движок не завершился за 20 с"]);
            }
            var lines = (r.Stdout + r.Stderr).Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
            if (!r.Ok)
                return new CheckResult(false, stage, lines);
            if (lines.Select(EngineLogParser.Parse).Any(e => e is not null && EngineLogParser.IsFatal(e)))
                return new CheckResult(false, stage, lines);
        }
        return new CheckResult(true, "", []);
    }

    /// <summary>Starts an instance. Throws <see cref="EngineStartException"/> with Russian text on refusal.</summary>
    public EngineInstance Start(IReadOnlyList<string> argv, NftQueueRule? queue, string tag)
    {
        if (Precheck(argv) is { } bad)
            throw new EngineStartException(bad.Stage, bad.Output);
        if (!File.Exists(EnginePath))
            throw new EngineStartException("engine", [$"не найден движок {EnginePath}"]);

        var id = "e" + Interlocked.Increment(ref _seq).ToString(CultureInfo.InvariantCulture);
        if (Platform == EnginePlatform.Linux)
        {
            if (queue is null)
                throw new EngineStartException("firewall", ["на Linux нужно правило очереди (queue)"]);
            if (_engines.Values.Any(e => !e.HasExited && _queues.TryGetValue(e.Id, out var q) && q == queue.QueueNum))
                throw new EngineStartException("firewall", [$"очередь {queue.QueueNum} уже занята другим экземпляром"]);
            if (_firewall is null)
                throw new EngineStartException("firewall", ["firewall недоступен"]);
            var err = _firewall.Set(id, queue);
            if (err is not null)
                throw new EngineStartException("firewall", [err]);
            _queues[id] = queue.QueueNum;
        }

        EngineInstance inst;
        try
        {
            inst = EngineInstance.Start(id, tag, EnginePath, WithManaged(argv, queue?.QueueNum), _job);
        }
        catch
        {
            _firewall?.Unset(id);
            _queues.TryRemove(id, out _);
            throw;
        }
        _engines[id] = inst;
        _state.Update(s => s.Engines.Add(new AgentState.EngineRecord(inst.Pid, EnginePath, inst.StartTimeUtc)));
        _ = inst.Exited.ContinueWith(_ => OnExited(inst), TaskScheduler.Default);
        return inst;
    }

    private void OnExited(EngineInstance inst)
    {
        _firewall?.Unset(inst.Id);
        _queues.TryRemove(inst.Id, out _);
        _state.Update(s => s.Engines.RemoveAll(e => e.Pid == inst.Pid));
    }

    public async Task<(bool WasRunning, int ExitCode)> StopAsync(string id)
    {
        if (!_engines.TryRemove(id, out var inst))
            return (false, 0);
        bool wasRunning = !inst.HasExited;
        int code = await inst.StopAsync(TimeSpan.FromSeconds(3));
        OnExited(inst);
        inst.Dispose();
        return (wasRunning, code);
    }

    public async Task StopAllAsync()
    {
        await Task.WhenAll(_engines.Keys.ToList().Select(StopAsync));
    }

    /// <summary>Adds the Agent-managed options: <c>--qnum</c> and <c>--fwmark</c> on Linux.</summary>
    private List<string> WithManaged(IReadOnlyList<string> argv, int? queueNum)
    {
        var a = new List<string>();
        if (Platform == EnginePlatform.Linux)
        {
            if (queueNum is not null)
                a.Add($"--qnum={queueNum}");
            a.Add($"--fwmark=0x{FwMark:X8}");
        }
        a.AddRange(argv);
        return a;
    }

    public static NftQueueRule ToRule(ZapretAutoTuner.Protocol.QueueRule q) => new()
    {
        QueueNum = q.QueueNum,
        TcpPorts = q.TcpPorts,
        UdpPorts = q.UdpPorts,
        Targets = q.Targets.Select(IPAddress.Parse).ToList(),
        Incoming = q.Incoming,
    };

    public void Dispose()
    {
        foreach (var e in _engines.Values)
            e.Dispose();
        if (OperatingSystem.IsWindows())
            _job?.Dispose();
    }
}

internal sealed class EngineStartException : Exception
{
    public EngineStartException(string stage, IReadOnlyList<string> problems)
        : base(stage + ": " + string.Join("; ", problems))
    {
        Stage = stage;
        Problems = problems;
    }

    public string Stage { get; }

    public IReadOnlyList<string> Problems { get; }
}
