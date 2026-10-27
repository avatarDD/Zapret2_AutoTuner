using System.Net;
using System.Text;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Mcp;
using ZapretAutoTuner.Probes.Http;
using ZapretAutoTuner.Protocol;
using ZapretAutoTuner.Storage;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.Bench;

/// <summary>Where a run stood when the first strategy passed a full series: strategies tried (that one included) and probes.</summary>
public readonly record struct SuccessMark(int Strategies, int Attempts, string Strategy);

/// <summary>
/// The simulated DPI of one run: no network, no engine, no rights. A strategy is "up" between <see cref="Begin"/> and
/// <see cref="End"/> (one engine instance, one series of probes); every probe passes with the scenario's rate for it,
/// drawn from a hash of (seed, strategy, attempt number), so a run is reproducible whatever the order of strategies.
/// The run ends at the first series of at least <see cref="ConfirmAttempts"/> probes that all passed (success: the full
/// download, as the Runner's N/N), or when a new strategy would exceed the budget.
/// </summary>
public sealed class SimulatedDpi(BenchScenario scenario, int seed, int budget, int confirmAttempts = 3) : IDisposable
{
    private readonly CancellationTokenSource _done = new();
    private readonly HashSet<string> _strategies = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _perStrategy = new(StringComparer.Ordinal);
    private readonly Lock _lock = new();
    private Strategy? _up;
    private string? _upKey;
    private int _seriesOk;
    private int _seriesAll;

    public BenchScenario Scenario => scenario;

    public int Budget => budget;

    public int ConfirmAttempts => confirmAttempts;

    /// <summary>Cancelled when the run is over (success or budget): the search and the advisor stop with it.</summary>
    public CancellationToken Done => _done.Token;

    public int Strategies
    {
        get
        {
            lock (_lock)
                return _strategies.Count;
        }
    }

    public int Attempts { get; private set; }

    public SuccessMark? FirstSuccess { get; private set; }

    /// <summary>A new strategy was refused because the budget was spent.</summary>
    public bool OverBudget { get; private set; }

    /// <summary>The identity of a strategy for counting: its lua-desync calls (the payload filter does not change what the DPI sees here).</summary>
    public static string KeyOf(Strategy s) => string.Join(' ', s.Calls.Select(c => c.ToString()));

    /// <summary>The engine starts with the strategy. Throws <see cref="OperationCanceledException"/> when the run is over.</summary>
    public void Begin(Strategy s)
    {
        bool stop;
        lock (_lock)
        {
            var key = KeyOf(s);
            stop = FirstSuccess is not null || (!_strategies.Contains(key) && _strategies.Count >= budget);
            if (stop)
                OverBudget |= FirstSuccess is null;
            else
            {
                _strategies.Add(key);
                _up = s;
                _upKey = key;
                _seriesOk = _seriesAll = 0;
            }
        }
        if (stop)
        {
            _done.Cancel();
            throw new OperationCanceledException(_done.Token);
        }
    }

    public void End()
    {
        lock (_lock)
        {
            _up = null;
            _upKey = null;
        }
    }

    /// <summary>One probe of the target: through the strategy that is up, or blocked when none is (the baseline).</summary>
    public bool Probe()
    {
        bool ok, finished = false;
        lock (_lock)
        {
            if (_up is null || _upKey is null)
                return false;
            int n = _perStrategy[_upKey] = _perStrategy.GetValueOrDefault(_upKey) + 1;
            double p = Math.Clamp(scenario.Rule(_up), 0, 1);
            ok = p >= 1 || (p > 0 && Uniform(seed, _upKey, n) < p);
            Attempts++;
            _seriesAll++;
            if (ok)
                _seriesOk++;
            if (FirstSuccess is null && _seriesOk == _seriesAll && _seriesAll >= confirmAttempts)
            {
                FirstSuccess = new SuccessMark(_strategies.Count, Attempts, _up.ToString());
                finished = true;
            }
        }
        if (finished)
            _done.Cancel();
        return ok;
    }

    public void Dispose() => _done.Dispose();

    /// <summary>A uniform number in [0, 1) from FNV-1a: stable across processes, unlike string.GetHashCode.</summary>
    internal static double Uniform(int seed, string key, int n)
    {
        ulong h = 14695981039346656037UL;
        foreach (var b in Encoding.UTF8.GetBytes($"{seed}|{key}|{n}"))
        {
            h ^= b;
            h *= 1099511628211UL;
        }
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdUL;
        h ^= h >> 33;
        return (h >> 11) * (1.0 / (1UL << 53));
    }

    public TrialFailure TrialFailure => scenario.Failure switch
    {
        SimFailure.Reset => Core.Search.TrialFailure.Reset,
        SimFailure.Drop => Core.Search.TrialFailure.Timeout,
        _ => Core.Search.TrialFailure.Stalled,
    };
}

/// <summary>The Runner's executor over the simulated DPI (arms static and bandit).</summary>
public sealed class SimTrialExecutor(SimulatedDpi dpi) : ITrialExecutor
{
    public Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        dpi.Begin(candidate.Strategy);
        try
        {
            var list = new List<TrialOutcome>();
            for (int i = 0; i < attempts; i++)
            {
                list.Add(dpi.Probe() ? TrialOutcome.Success(200_000) : TrialOutcome.Fail(dpi.TrialFailure, dpi.Scenario.Failure.ToString()));
                if (stopEarly(list))
                    break;
            }
            return Task.FromResult<IReadOnlyList<TrialOutcome>>(list);
        }
        finally
        {
            dpi.End();
        }
    }

    public Task<bool> TargetReachableAsync(CancellationToken ct) => Task.FromResult(true);
}

/// <summary>The engine as the Agent would run it, for the MCP tools: the strategy of the argv goes up in the simulated DPI.</summary>
public sealed class SimEngine(SimulatedDpi dpi) : IEngineControl
{
    private readonly Lock _lock = new();
    private readonly List<IReadOnlyList<string>> _started = [];
    private string? _running;
    private int _next;

    /// <summary>Every argv the tools started, in order.</summary>
    public IReadOnlyList<IReadOnlyList<string>> Started
    {
        get
        {
            lock (_lock)
                return [.. _started];
        }
    }

    public Task<string> StartAsync(IReadOnlyList<string> argv, QueueRule? queue, string tag, CancellationToken ct)
    {
        var strategy = Strategy.Parse(argv.Where(a => a.StartsWith("--lua-desync=", StringComparison.Ordinal)));
        lock (_lock)
        {
            if (_running is not null)
                throw new InvalidOperationException("the simulated engine runs one instance at a time");
            _started.Add(argv);
        }
        dpi.Begin(strategy);
        lock (_lock)
        {
            _running = "sim" + (++_next).ToString(System.Globalization.CultureInfo.InvariantCulture);
            return Task.FromResult(_running);
        }
    }

    public Task StopAsync(string engineId, CancellationToken ct)
    {
        lock (_lock)
        {
            if (_running == engineId)
            {
                _running = null;
                dpi.End();
            }
        }
        return Task.CompletedTask;
    }
}

/// <summary>Never asked in the benchmark (its arms change nothing); answers "no" if it ever is.</summary>
public sealed class DeclineConfirm : IUserConfirm
{
    public Task<bool> ConfirmAsync(ConfirmRequest request, CancellationToken ct) => Task.FromResult(false);
}

/// <summary>The program as the MCP tools see it, over one simulated DPI: one target, the scenario's verdict, no network.</summary>
public sealed class BenchHost : IAutoTunerHost, IDisposable
{
    public const string Address = "203.0.113.10";

    private readonly SimulatedDpi _dpi;
    private readonly SearchLearning? _learning;

    public BenchHost(SimulatedDpi dpi, SearchLearning? learning)
    {
        _dpi = dpi;
        _learning = learning;
        Engine = new SimEngine(dpi);
        Kb = KnowledgeBase.OpenInMemory();
        Targets = [dpi.Scenario.Host];
    }

    public KnowledgeBase Kb { get; }

    public SimEngine Engine { get; }

    public IReadOnlyList<string> Targets { get; }

    public AgentTrialOptions TrialOptions { get; } = new()
    {
        LuaDir = "/opt/zapret2/lua",
        Platform = Core.Validation.EnginePlatform.Linux,
        Warmup = TimeSpan.Zero,
        Pause = TimeSpan.Zero,
    };

    public Func<string, CancellationToken, Task<PageLoad>>? OpenPage => null;

    public ITrialCapture? Capture => null;

    public bool ProtectionActive => false;

    public void AddTarget(string host) => throw new InvalidOperationException("the benchmark has one target");

    /// <summary>The classifier's verdict as it would come out on this DPI (the baseline is blocked by construction).</summary>
    public ClassifierVerdict Verdict()
    {
        var s = _dpi.Scenario;
        return new ClassifierVerdict
        {
            Host = s.Host,
            Primary = s.Primary,
            Next = NextStep.SearchStrategy,
            LiveAddresses = [Address],
            Findings = [.. s.Labels.Select(l => new LabelFinding(l, Address, l == s.Primary ? [s.Evidence] : []))],
        };
    }

    public Task<ClassifierVerdict> ClassifyAsync(string host, CancellationToken ct) => Task.FromResult(Verdict());

    public Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken ct) => Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Parse(Address)]);

    public Task<IEngineControl> EngineAsync(CancellationToken ct) => Task.FromResult<IEngineControl>(Engine);

    public Task<ProbeResult> ProbeAsync(HttpProbeOptions options, CancellationToken ct)
    {
        var a = options.Address.ToString();
        if (_dpi.Probe())
        {
            return Task.FromResult(new ProbeResult
            {
                Host = options.Host, Address = a, ConnectOk = true, TlsOk = true, CertValid = true, HttpStatus = 200, BodyBytes = 200_000, BytesIn = 201_000,
                Complete = true, BodySha256 = new string('a', 64), Duration = TimeSpan.FromMilliseconds(150),
            });
        }
        return Task.FromResult(_dpi.Scenario.Failure switch
        {
            SimFailure.Reset => new ProbeResult
            {
                Host = options.Host, Address = a, ConnectOk = true, Error = ProbeError.TlsReset, RstSeen = true, RstOrigin = RstOrigin.Injected,
                ErrorDetail = "reset after the ClientHello", Duration = TimeSpan.FromMilliseconds(40),
            },
            SimFailure.Drop => new ProbeResult
            {
                Host = options.Host, Address = a, ConnectOk = true, Error = ProbeError.TlsTimeout, ErrorDetail = "no ServerHello", Duration = TimeSpan.FromSeconds(5),
            },
            _ => new ProbeResult
            {
                Host = options.Host, Address = a, ConnectOk = true, TlsOk = true, CertValid = true, HttpStatus = 200, BodyBytes = 16_000, BytesIn = 17_000,
                Error = ProbeError.Stalled, ErrorDetail = "no data after ~16 KB", Duration = TimeSpan.FromSeconds(8),
            },
        });
    }

    public Task CommitAsync(Solution solution, CancellationToken ct) => throw new InvalidOperationException("the benchmark commits nothing");

    public Task<string> SaveExportAsync(string name, byte[] zip, CancellationToken ct) => throw new InvalidOperationException("the benchmark saves nothing");

    public SearchLearning? SearchLearning(string blockLabel) => _learning;

    public void Dispose() => Kb.Dispose();
}
