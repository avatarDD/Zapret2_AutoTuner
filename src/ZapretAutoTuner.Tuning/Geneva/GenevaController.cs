using System.Globalization;
using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning.Geneva;

/// <summary>One strategy geneva's search tried, as the page's feed shows it.</summary>
public sealed record GenevaTrial(DateTimeOffset Time, string Strategy, double Fitness, string Outcome, string Detail);

/// <summary>The search as the page and MCP see it.</summary>
public sealed record GenevaSearchView
{
    public bool Running { get; init; }

    public string Host { get; init; } = "";

    public int Port { get; init; } = 443;

    public int Population { get; init; }

    public int Generation { get; init; } = -1;

    public int Generations { get; init; }

    /// <summary>Strategies scored in the current generation (the page's inner progress).</summary>
    public int EvaluatedInGeneration { get; init; }

    public int Evaluated { get; init; }

    public int Succeeded { get; init; }

    public double BestFitness { get; init; }

    public double AvgFitness { get; init; }

    public string? Best { get; init; }

    /// <summary>The probe without a strategy: null before it ran.</summary>
    public bool? Blocked { get; init; }

    public string? BaselineOutcome { get; init; }

    public DateTimeOffset? Started { get; init; }

    public bool Resumed { get; init; }

    /// <summary>Why the last search ended, in Russian and English; null while it runs or before the first.</summary>
    public (string Ru, string En)? Ended { get; init; }

    /// <summary>Best fitness per finished generation: the page's chart.</summary>
    public IReadOnlyList<double> BestByGeneration { get; init; } = [];

    public IReadOnlyList<double> AvgByGeneration { get; init; } = [];

    /// <summary>0..1 over all generations.</summary>
    public double Percent => Generations <= 0 ? 0
        : Math.Clamp((Math.Max(0, Generation + 1) + (Population > 0 ? (double)EvaluatedInGeneration / Population : 0)) / Generations, 0, 1);
}

/// <summary>The bypass with geneva as the page and MCP see it.</summary>
public sealed record GenevaRunView
{
    public bool Running { get; init; }

    public bool Ready { get; init; }

    public string Strategy { get; init; } = "";

    public string Ports { get; init; } = "";

    public string? Firewall { get; init; }

    public GenevaStats? Stats { get; init; }

    public DateTimeOffset? Started { get; init; }

    public (string Ru, string En)? Ended { get; init; }

    /// <summary>Packets per second out/in over the last stats interval.</summary>
    public double RateOut { get; init; }

    public double RateIn { get; init; }

    public IReadOnlyList<double> TriggeredHistory { get; init; } = [];
}

/// <summary>
/// geneva_c from the UI's side (skill <c>geneva</c>): the search runs in the Agent with <c>--probe external</c>, and every
/// strategy is judged here by the full download of the page from the strategy's local ports (AGENTS.md rule 5), the
/// same probe the wizard uses; the bypass is <c>geneva run</c> with live stats. Progress and the found strategies are
/// saved as they come (<see cref="GenevaState"/>), and the search continues from geneva's checkpoint after a restart.
/// Thread-safe; <see cref="Changed"/> is raised on a pool thread.
/// </summary>
public sealed class GenevaController : IAsyncDisposable
{
    public const int MaxTrials = 200;
    public const int MaxLog = 300;
    public const int MaxHistory = 300;

    private readonly Func<CancellationToken, Task<IGenevaAgent>> _agent;
    private readonly IGenevaStore _store;
    private readonly Func<string, int, bool, int, CancellationToken, Task<ProbeResult>> _probe;
    private readonly Lock _lock = new();
    private readonly List<GenevaTrial> _trials = [];
    private readonly List<string> _log = [];
    private readonly CancellationTokenSource _dispose = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private GenevaState _state;
    private GenevaSearchView _search = new();
    private GenevaRunView _run = new();
    private string? _searchId;
    private CancellationTokenSource? _probeCts;
    private string? _runId;
    private Task? _searchWatch;
    private Task? _runWatch;
    private int _probeSeq;

    /// <param name="agent">The Agent (started on first use: one UAC / pkexec prompt).</param>
    /// <param name="probe">(host, port, tls, local port) → the full-download probe from that local port.</param>
    public GenevaController(Func<CancellationToken, Task<IGenevaAgent>> agent, IGenevaStore store, Func<string, int, bool, int, CancellationToken, Task<ProbeResult>> probe)
    {
        _agent = agent;
        _store = store;
        _probe = probe;
        _state = GenevaState.Parse(store.Load());
    }

    /// <summary>Why geneva may not start now (zapret2's protection runs, the wizard tunes), or null.</summary>
    public Func<string?>? Busy { get; set; }

    /// <summary>Something the page or MCP shows changed.</summary>
    public event Action? Changed;

    public GenevaState State
    {
        get
        {
            lock (_lock)
                return _state;
        }
    }

    public GenevaSearchView Search
    {
        get
        {
            lock (_lock)
                return _search;
        }
    }

    public GenevaRunView Run
    {
        get
        {
            lock (_lock)
                return _run;
        }
    }

    public IReadOnlyList<GenevaTrial> Trials
    {
        get
        {
            lock (_lock)
                return [.. _trials];
        }
    }

    public IReadOnlyList<string> Log
    {
        get
        {
            lock (_lock)
                return [.. _log];
        }
    }

    public bool SearchRunning => Search.Running;

    public bool RunRunning => Run.Running;

    public BypassEngine Engine
    {
        get => State.Engine;
        set => Update(s => s with { Engine = value });
    }

    private void Update(Func<GenevaState, GenevaState> change)
    {
        string json;
        lock (_lock)
        {
            _state = change(_state);
            json = _state.Serialize();
        }
        _store.Save(json);
        Changed?.Invoke();
    }

    private void AddLog(string line)
    {
        lock (_lock)
        {
            _log.Add(DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture) + " " + line);
            if (_log.Count > MaxLog)
                _log.RemoveRange(0, _log.Count - MaxLog);
        }
    }

    // ---- the search

    /// <summary>
    /// Starts geneva's search for a blocked site. <paramref name="settings"/>.Resume continues the saved one. Returns
    /// when geneva started; the search goes on in the background. Throws <see cref="GenevaRefusedException"/>.
    /// </summary>
    public async Task StartSearchAsync(GenevaSearchSettings settings, CancellationToken ct)
    {
        if (settings.Problems() is { Count: > 0 } bad)
            throw new GenevaRefusedException(string.Join("; ", bad));
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (SearchRunning)
                throw new GenevaRefusedException("подбор geneva уже идёт / a geneva search is already running");
            if (Busy?.Invoke() is { } why)
                throw new GenevaRefusedException(why);
            var agent = await _agent(ct).ConfigureAwait(false);
            var req = new GenevaStartRequest
            {
                Mode = "evolve",
                Host = settings.Host,
                Port = settings.Port,
                Population = settings.Population,
                Generations = settings.Generations,
                Resume = settings.Resume,
                Tag = "geneva-search:" + settings.Host,
            };
            req.Seeds.AddRange(settings.Seeds);
            var reply = await agent.StartAsync(req, CancellationToken.None).ConfigureAwait(false);
            var prev = State.ProgressOf(settings.Host, settings.Port);
            var probeCts = new CancellationTokenSource();
            lock (_lock)
            {
                _searchId = reply.Id;
                _probeCts?.Dispose();
                _probeCts = probeCts;
                _trials.Clear();
                _search = new GenevaSearchView
                {
                    Running = true,
                    Host = settings.Host,
                    Port = settings.Port,
                    Population = settings.Population,
                    Generations = settings.Generations,
                    Started = DateTimeOffset.Now,
                    Resumed = settings.Resume,
                    Generation = settings.Resume && prev is not null ? prev.Generation : -1,
                    BestFitness = settings.Resume && prev is not null ? prev.BestFitness : 0,
                    Best = settings.Resume ? prev?.Best : null,
                };
            }
            AddLog(settings.Resume ? $"Продолжение подбора для {settings.Host}" : $"Подбор для {settings.Host}: популяция {settings.Population}, поколений {settings.Generations}");
            Update(s => s with { LastHost = settings.Host, LastPort = settings.Port, Population = settings.Population, Generations = settings.Generations });
            _searchWatch = Task.Run(() => WatchSearchAsync(agent, reply.Id, settings, probeCts.Token, _dispose.Token));
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task StopSearchAsync(CancellationToken ct = default)
    {
        string? id;
        CancellationTokenSource? probe;
        lock (_lock)
            (id, probe) = (_searchId, _probeCts);
        if (id is null)
            return;
        // the probe in flight is not waited for: geneva stops after its current step anyway
        await (probe?.CancelAsync() ?? Task.CompletedTask).ConfigureAwait(false);
        AddLog("Остановка подбора: geneva сохраняет прогресс…");
        Changed?.Invoke();
        var agent = await _agent(ct).ConfigureAwait(false);
        await agent.StopAsync(id, ct).ConfigureAwait(false);
        if (_searchWatch is { } w)
            await Task.WhenAny(w, Task.Delay(TimeSpan.FromSeconds(20), ct)).ConfigureAwait(false);
    }

    private async Task WatchSearchAsync(IGenevaAgent agent, string id, GenevaSearchSettings settings, CancellationToken probeCt, CancellationToken ct)
    {
        int exitCode = -1;
        string? reason = null;
        try
        {
            await foreach (var o in agent.WatchAsync(id, ct).ConfigureAwait(false))
            {
                if (o.Exited)
                {
                    exitCode = o.ExitCode;
                    break;
                }
                if (o.Log.Length > 0)
                {
                    AddLog(o.Log);
                    continue;
                }
                if (GenevaEvent.Parse(o.Event) is not { } e)
                    continue;
                if (e.Ev == "exit")
                    reason = e.Str("reason");
                await OnSearchEventAsync(agent, id, settings, e, probeCt, ct).ConfigureAwait(false);
                Changed?.Invoke();
            }
        }
        catch (Exception e) when (e is Grpc.Core.RpcException or OperationCanceledException or IOException)
        {
            AddLog("Связь с Agent потеряна / the Agent connection was lost: " + e.Message);
        }
        var ended = GenevaText.Exit(exitCode, reason);
        lock (_lock)
        {
            if (_searchId == id)
                _searchId = null;
            _search = _search with { Running = false, Ended = ended };
        }
        var view = Search;
        Update(s => s.WithProgress(new GenevaSearchProgress
        {
            Host = view.Host,
            Port = view.Port,
            Population = view.Population,
            Generation = view.Generation,
            Generations = view.Generations,
            BestFitness = view.BestFitness,
            Best = view.Best,
            Updated = DateTimeOffset.Now,
            Finished = exitCode == 0 && reason == "done",
        }));
        AddLog(ended.Ru);
        Changed?.Invoke();
    }

    private async Task OnSearchEventAsync(IGenevaAgent agent, string id, GenevaSearchSettings settings, GenevaEvent e, CancellationToken probeCt, CancellationToken ct)
    {
        switch (e.Ev)
        {
            case "start":
                if (e.Long("proto") != GenevaEvent.Proto)
                {
                    AddLog($"geneva говорит на протоколе {e.Long("proto")}, нужен {GenevaEvent.Proto}: останавливаю");
                    await agent.StopAsync(id, CancellationToken.None).ConfigureAwait(false);
                }
                break;
            case "eval_request":
                await AnswerAsync(agent, id, settings, e, probeCt, ct).ConfigureAwait(false);
                break;
            case "baseline":
                lock (_lock)
                    _search = _search with { Blocked = e.Bool("blocked"), BaselineOutcome = e.Str("outcome") };
                AddLog(e.Bool("blocked") ? $"Без обхода: {GenevaText.Outcome(e.Str("outcome")).Ru} — сайт заблокирован, ищем" : "Без обхода сайт открывается: подбирать нечего");
                break;
            case "eval":
            {
                var strategy = e.Str("strategy") ?? "";
                if (strategy.Length == 0)
                    break; // the baseline's own eval
                var t = new GenevaTrial(e.Time, strategy, e.Num("fitness"), e.Str("outcome") ?? "", e.Str("detail") ?? "");
                lock (_lock)
                {
                    _trials.Insert(0, t);
                    if (_trials.Count > MaxTrials)
                        _trials.RemoveAt(_trials.Count - 1);
                    _search = _search with
                    {
                        Evaluated = _search.Evaluated + 1,
                        EvaluatedInGeneration = Math.Min(_search.Population, _search.EvaluatedInGeneration + 1),
                        Succeeded = _search.Succeeded + (t.Fitness > 0 ? 1 : 0),
                    };
                }
                if (t.Fitness > 0)
                {
                    // saved at once: a crash or a power cut does not lose what loaded the site
                    Update(s => s.WithFound([new GenevaFoundStrategy { Host = settings.Host, Port = settings.Port, Strategy = strategy, Fitness = t.Fitness, Runs = (int)Math.Max(1, e.Long("runs")), Found = DateTimeOffset.Now }]));
                }
                break;
            }
            case "generation":
            {
                GenevaSearchView view;
                lock (_lock)
                {
                    _search = _search with
                    {
                        Generation = (int)e.Long("gen"),
                        EvaluatedInGeneration = 0,
                        BestFitness = e.Num("best_fitness"),
                        AvgFitness = e.Num("avg_fitness"),
                        Best = e.Str("best"),
                        BestByGeneration = [.. _search.BestByGeneration.TakeLast(MaxHistory - 1), e.Num("best_fitness")],
                        AvgByGeneration = [.. _search.AvgByGeneration.TakeLast(MaxHistory - 1), e.Num("avg_fitness")],
                    };
                    view = _search;
                }
                AddLog($"Поколение {view.Generation + 1}/{view.Generations}: лучший фитнес {view.BestFitness:0}, средний {view.AvgFitness:0}");
                Update(s => s.WithProgress(new GenevaSearchProgress
                {
                    Host = view.Host,
                    Port = view.Port,
                    Population = view.Population,
                    Generation = view.Generation,
                    Generations = view.Generations,
                    BestFitness = view.BestFitness,
                    Best = view.Best,
                    Updated = DateTimeOffset.Now,
                }));
                break;
            }
            case "result":
            {
                var found = new List<GenevaFoundStrategy>();
                if (e.Data["best"] is System.Text.Json.Nodes.JsonArray best)
                {
                    foreach (var b in best.OfType<System.Text.Json.Nodes.JsonObject>())
                    {
                        var s = (string?)b["strategy"];
                        var f = (double?)b["avg_fitness"] ?? 0;
                        if (s is { Length: > 0 } && f > 0)
                            found.Add(new GenevaFoundStrategy { Host = settings.Host, Port = settings.Port, Strategy = s, Fitness = f, Runs = (int?)b["runs"] ?? 1, Found = DateTimeOffset.Now });
                    }
                }
                if (found.Count > 0)
                    Update(s => s.WithFound(found));
                AddLog(found.Count > 0 ? $"Найдено рабочих стратегий: {found.Count}" : "Рабочая стратегия не найдена");
                break;
            }
            case "error":
                AddLog($"Ошибка geneva ({e.Str("where")}): {e.Str("message")}");
                break;
        }
    }

    /// <summary>
    /// One strategy's verdict: the page downloaded from a local port of geneva's block, so the strategy applies to it.
    /// A port still busy from the previous probe is skipped (the block has 64).
    /// </summary>
    private async Task AnswerAsync(IGenevaAgent agent, string id, GenevaSearchSettings settings, GenevaEvent e, CancellationToken probeCt, CancellationToken ct)
    {
        if (probeCt.IsCancellationRequested)
            return;
        long reqId = e.Long("id");
        var lports = e.Str("lports") ?? "";
        int fitness;
        string detail;
        try
        {
            ProbeResult? r = null;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                int port = GenevaArgv.LocalPort(lports, Interlocked.Increment(ref _probeSeq));
                using var both = CancellationTokenSource.CreateLinkedTokenSource(probeCt, ct);
                r = await _probe(settings.Host, settings.Port, settings.Tls, port, both.Token).ConfigureAwait(false);
                if (!(r.Error == ProbeError.Other && r.ErrorDetail is { } d && d.Contains("in use", StringComparison.OrdinalIgnoreCase)))
                    break;
            }
            (fitness, var outcome) = GenevaFitness.FromProbe(r!);
            detail = outcome + ": " + r;
        }
        catch (OperationCanceledException) when (probeCt.IsCancellationRequested)
        {
            return; // stopped: geneva gets no answer and ends with its stdin
        }
        catch (FormatException)
        {
            (fitness, detail) = (-400, "bad lports " + lports);
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or IOException)
        {
            (fitness, detail) = (-400, "failed: " + ex.Message);
        }
        try
        {
            await agent.AnswerAsync(id, reqId, fitness, detail, ct).ConfigureAwait(false);
        }
        catch (GenevaRefusedException)
        {
            // the search was stopped while the probe ran
        }
    }

    // ---- the bypass

    /// <summary>Turns the bypass with geneva on. <paramref name="autoStart"/>: start it again with the program.</summary>
    public async Task StartRunAsync(string strategy, string ports, bool autoStart, CancellationToken ct)
    {
        var settings = new GenevaRunSettings { Strategy = strategy.Trim(), Ports = ports };
        if (settings.Problems() is { Count: > 0 } bad)
            throw new GenevaRefusedException(string.Join("; ", bad));
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (RunRunning)
                throw new GenevaRefusedException("обход geneva уже включён: сначала выключите / the geneva bypass is already on");
            if (Busy?.Invoke() is { } why)
                throw new GenevaRefusedException(why);
            var agent = await _agent(ct).ConfigureAwait(false);
            var reply = await agent.StartAsync(new GenevaStartRequest { Mode = "run", Strategy = settings.Strategy, Ports = settings.Ports, Tag = "geneva-run" }, CancellationToken.None).ConfigureAwait(false);
            lock (_lock)
            {
                _runId = reply.Id;
                _run = new GenevaRunView { Running = true, Strategy = reply.Strategy, Ports = GenevaArgv.NormalizePorts(settings.Ports), Started = DateTimeOffset.Now };
            }
            AddLog($"Обход geneva включён на портах {settings.Ports}: {reply.Strategy}");
            Update(s => s with { Engine = BypassEngine.Geneva, Active = new GenevaActiveRun { Strategy = reply.Strategy, Ports = settings.Ports, AutoStart = autoStart } });
            _runWatch = Task.Run(() => WatchRunAsync(agent, reply.Id, _dispose.Token));
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Turns the bypass off. <paramref name="forget"/>: it does not come back with the next start of the program.</summary>
    public async Task StopRunAsync(bool forget, CancellationToken ct = default)
    {
        string? id;
        lock (_lock)
            id = _runId;
        if (forget)
            Update(s => s.Active is null ? s : s with { Active = s.Active with { AutoStart = false } });
        if (id is null)
            return;
        var agent = await _agent(ct).ConfigureAwait(false);
        await agent.StopAsync(id, ct).ConfigureAwait(false);
        if (_runWatch is { } w)
            await Task.WhenAny(w, Task.Delay(TimeSpan.FromSeconds(10), ct)).ConfigureAwait(false);
    }

    /// <summary>Whether the bypass comes back with the next start of the program.</summary>
    public void SetAutoStart(bool on) => Update(s => s.Active is null || s.Active.AutoStart == on ? s : s with { Active = s.Active with { AutoStart = on } });

    /// <summary>Pauses (packets pass unchanged, the rules stay) or resumes the running bypass.</summary>
    public async Task PauseRunAsync(bool pause, CancellationToken ct)
    {
        string? id;
        lock (_lock)
            id = _runId;
        if (id is null)
            throw new GenevaRefusedException("обход geneva не включён / the geneva bypass is off");
        var agent = await _agent(ct).ConfigureAwait(false);
        var r = await agent.ControlAsync(id, pause ? "pause" : "resume", null, ct).ConfigureAwait(false);
        if (!r.Ok)
            throw new GenevaRefusedException(r.Json);
        lock (_lock)
            _run = _run with { Stats = _run.Stats is { } st ? st with { Paused = pause } : null };
        AddLog(pause ? "Обход на паузе" : "Обход продолжен");
        Changed?.Invoke();
    }

    /// <summary>Brings back the bypass the user left on (Settings: "Включать при запуске"); null when there is nothing to start.</summary>
    public async Task<bool> RestoreAsync(CancellationToken ct)
    {
        if (State is not { Engine: BypassEngine.Geneva, Active: { AutoStart: true } a } || RunRunning)
            return false;
        await StartRunAsync(a.Strategy, a.Ports, autoStart: true, ct).ConfigureAwait(false);
        return true;
    }

    private async Task WatchRunAsync(IGenevaAgent agent, string id, CancellationToken ct)
    {
        int exitCode = -1;
        string? reason = null;
        GenevaStats? prev = null;
        try
        {
            await foreach (var o in agent.WatchAsync(id, ct).ConfigureAwait(false))
            {
                if (o.Exited)
                {
                    exitCode = o.ExitCode;
                    break;
                }
                if (o.Log.Length > 0)
                {
                    AddLog(o.Log);
                    continue;
                }
                if (GenevaEvent.Parse(o.Event) is not { } e)
                    continue;
                switch (e.Ev)
                {
                    case "ready":
                        lock (_lock)
                            _run = _run with { Ready = true, Firewall = e.Str("firewall") };
                        AddLog($"Перехват работает ({e.Str("backend")}, {e.Str("firewall")})");
                        break;
                    case "stats":
                    {
                        var st = GenevaStats.From(e);
                        lock (_lock)
                        {
                            double secs = prev is null ? 0 : Math.Max(0.001, (st.UptimeMs - prev.UptimeMs) / 1000.0);
                            _run = _run with
                            {
                                Stats = st,
                                RateOut = prev is null ? 0 : Math.Max(0, st.PktsOut - prev.PktsOut) / secs,
                                RateIn = prev is null ? 0 : Math.Max(0, st.PktsIn - prev.PktsIn) / secs,
                                TriggeredHistory = [.. _run.TriggeredHistory.TakeLast(MaxHistory - 1), Math.Max(0, st.Triggered - (prev?.Triggered ?? 0))],
                            };
                        }
                        prev = st;
                        break;
                    }
                    case "state":
                        AddLog(e.Str("state") == "paused" ? "geneva: пауза" : "geneva: работает");
                        break;
                    case "strategy":
                        lock (_lock)
                            _run = _run with { Strategy = e.Str("strategy") ?? _run.Strategy };
                        break;
                    case "error":
                        AddLog($"Ошибка geneva ({e.Str("where")}): {e.Str("message")}");
                        break;
                    case "exit":
                        reason = e.Str("reason");
                        break;
                }
                Changed?.Invoke();
            }
        }
        catch (Exception e) when (e is Grpc.Core.RpcException or OperationCanceledException or IOException)
        {
            AddLog("Связь с Agent потеряна / the Agent connection was lost: " + e.Message);
        }
        var ended = GenevaText.Exit(exitCode, reason);
        lock (_lock)
        {
            if (_runId == id)
                _runId = null;
            _run = _run with { Running = false, Ready = false, Ended = ended };
        }
        AddLog("Обход geneva выключен: " + ended.Ru);
        Changed?.Invoke();
    }

    // ---- what the Agent keeps

    /// <summary>The Agent's view: version, saved searches, the database's best strategies.</summary>
    public async Task<GenevaInfoReply> InfoAsync(CancellationToken ct) => await (await _agent(ct).ConfigureAwait(false)).InfoAsync(ct).ConfigureAwait(false);

    public async ValueTask DisposeAsync()
    {
        // the Agent stops geneva on its own when the UI goes; this only ends the watchers
        await _dispose.CancelAsync().ConfigureAwait(false);
        _dispose.Dispose();
        _probeCts?.Dispose();
        _gate.Dispose();
    }

    /// <summary>The address the probe connects to: the first one the system resolver gives (IPv4 first).</summary>
    public static async Task<IPAddress> ResolveAsync(string host, CancellationToken ct)
    {
        var all = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        return all.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) ?? all.FirstOrDefault()
            ?? throw new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.HostNotFound);
    }
}
