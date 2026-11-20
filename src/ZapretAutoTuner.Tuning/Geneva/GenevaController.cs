using System.Globalization;
using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Probes.Http;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning.Geneva;

/// <summary>One strategy geneva's search tried, as the page's feed shows it.</summary>
public sealed record GenevaTrial(DateTimeOffset Time, string Strategy, double Fitness, string Outcome, string Detail);

/// <summary>A probe's verdict on one strategy of a search: the fitness for geneva, or that the local port was unusable.</summary>
public sealed record GenevaJudgement(int Fitness, string Detail, bool PortUnavailable = false);

/// <summary>
/// Judges one strategy of a search from a local port of geneva's block (the "Авто" mode's probes for protocols without
/// a page: a replay of the program's first packets). The default is the page's full download.
/// </summary>
public delegate Task<GenevaJudgement> GenevaJudge(int localPort, CancellationToken ct);

/// <summary>The search as the page and MCP see it.</summary>
public sealed record GenevaSearchView
{
    public bool Running { get; init; }

    /// <summary>The Agent's id of the search; empty before the first.</summary>
    public string Id { get; init; } = "";

    /// <summary>Started by the "Авто" mode (which may run several at once), not by the user.</summary>
    public bool Auto { get; init; }

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

    /// <summary>The layers geneva may change (<c>--protos</c>): a resumed search must keep them.</summary>
    public string Protos { get; init; } = "TCP";

    /// <summary>Strategies judged at once (geneva's workers) as asked; the Agent may run fewer.</summary>
    public int Workers { get; init; } = 1;

    /// <summary>Why the last search ended, in Russian and English; null while it runs or before the first.</summary>
    public (string Ru, string En)? Ended { get; init; }

    /// <summary>geneva's search is over and the strategies it found are being opened in the program's browser.</summary>
    public bool BrowserChecking { get; init; }

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
    private readonly Func<string, int, bool, int, ProbeCriteria, CancellationToken, Task<ProbeResult>> _probe;
    private readonly Lock _lock = new();
    private readonly List<GenevaTrial> _trials = [];

    /// <summary>The running searches by id: the user's one, or up to <see cref="GenevaArgv.MaxSearches"/> of the "Авто" mode.</summary>
    private readonly Dictionary<string, SearchSlot> _searches = new(StringComparer.Ordinal);
    private readonly List<string> _log = [];
    private readonly CancellationTokenSource _dispose = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private GenevaState _state;
    private GenevaSearchView _search = new();
    private GenevaRunView _run = new();
    private string? _runId;
    private bool _browserChecking;
    private Task? _runWatch;
    private int _probeSeq;

    /// <param name="agent">The Agent (started on first use: one UAC / pkexec prompt).</param>
    /// <param name="probe">(host, port, tls, local port, criterion) → the full-download probe from that local port.</param>
    public GenevaController(Func<CancellationToken, Task<IGenevaAgent>> agent, IGenevaStore store, Func<string, int, bool, int, ProbeCriteria, CancellationToken, Task<ProbeResult>> probe)
    {
        _agent = agent;
        _store = store;
        _probe = probe;
        _state = GenevaState.Parse(store.Load());
    }

    /// <summary>Why geneva may not start now (zapret2's protection runs, the wizard tunes), or null.</summary>
    public Func<string?>? Busy { get; set; }

    /// <summary>The "Авто" mode runs: it applies its own strategies, so the single-strategy bypass waits.</summary>
    public Func<bool>? AutoRunning { get; set; }

    /// <summary>The program's own browser for the final check (<see cref="GenevaBrowserCheck"/>); null: there is none.</summary>
    public GenevaBrowser? Browser { get; set; }

    /// <summary>"Итоговая проверка в браузере" (manual search and "Авто"): saved with the rest.</summary>
    public bool BrowserCheck
    {
        get => State.BrowserCheck;
        set => Update(s => s with { BrowserCheck = value });
    }

    /// <summary>The browser to check with now: the switch is on and the program has one.</summary>
    internal GenevaBrowser? BrowserNow => BrowserCheck && Browser is { } b && b.Available() ? b : null;

    /// <summary>Something the page or MCP shows changed.</summary>
    public event Action? Changed;

    /// <summary>A search ended (done, stopped, failed): its last view.</summary>
    public event Action<GenevaSearchView>? SearchEnded;

    public GenevaState State
    {
        get
        {
            lock (_lock)
                return _state;
        }
    }

    /// <summary>One running search: what it judges by and how it goes.</summary>
    private sealed class SearchSlot(string id, GenevaSearchSettings settings, GenevaJudge? judge, GenevaSearchView view)
    {
        public string Id { get; } = id;

        public GenevaSearchSettings Settings { get; } = settings;

        public GenevaJudge? Judge { get; } = judge;

        public ProbeCriteria Criteria { get; set; } = settings.Criteria;

        public CancellationTokenSource ProbeCts { get; } = new();

        public bool StopRequested { get; set; }

        public (string Ru, string En)? PortsUnavailable { get; set; }

        public GenevaSearchView View { get; set; } = view;

        public Task? Watch { get; set; }

        /// <summary>What geneva's <c>result</c> named, best first: the final check opens them in the browser.</summary>
        public List<GenevaFoundStrategy> Result { get; } = [];
    }

    /// <summary>The search the page shows: the latest running one, or the last that ended.</summary>
    public GenevaSearchView Search
    {
        get
        {
            lock (_lock)
                return _searches.Count == 0 ? _search : _searches.Values.MaxBy(x => x.View.Started)!.View;
        }
    }

    /// <summary>Every running search (the "Авто" mode may run several).</summary>
    public IReadOnlyList<GenevaSearchView> Searches
    {
        get
        {
            lock (_lock)
                return [.. _searches.Values.Select(x => x.View).OrderBy(x => x.Started)];
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

    public bool SearchRunning
    {
        get
        {
            lock (_lock)
                return _searches.Count > 0;
        }
    }

    /// <summary>A search the user started (the page, MCP) runs: the "Авто" mode waits for it.</summary>
    public bool UserSearchRunning
    {
        get
        {
            lock (_lock)
                return _searches.Values.Any(x => !x.View.Auto);
        }
    }

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
    /// <param name="judge">How each strategy is judged; null: the page's full download (<see cref="GenevaSearchSettings.Tls"/>).</param>
    /// <param name="auto">
    /// The "Авто" mode's search: it may run beside its other ones (up to <see cref="GenevaArgv.MaxSearches"/>, each
    /// target once); the user's search runs alone.
    /// </param>
    /// <returns>The search's id (<see cref="StopSearchAsync(string, CancellationToken)"/>).</returns>
    public async Task<string> StartSearchAsync(GenevaSearchSettings settings, CancellationToken ct, GenevaJudge? judge = null, bool auto = false)
    {
        if (settings.Resume && State.ProgressOf(settings.Host, settings.Port) is { Population: > 0 } saved)
        {
            // geneva refuses to resume a search whose population changed; more generations are fine
            // nor one whose layers changed: Auto's wider round saves "TCP,IP" under the same key a manual resume uses
            settings = settings with
            {
                Population = saved.Population,
                Generations = Math.Max(settings.Generations, saved.Generations),
                Protos = saved.Protos is { Length: > 0 } p ? p : settings.Protos,
            };
        }
        if (settings.Problems() is { Count: > 0 } bad)
            throw new GenevaRefusedException(string.Join("; ", bad));
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            lock (_lock)
            {
                if (_searches.Count > 0 && (!auto || _searches.Values.Any(x => !x.View.Auto)))
                    throw new GenevaRefusedException("подбор geneva уже идёт / a geneva search is already running");
                if (_searches.Count >= GenevaArgv.MaxSearches)
                    throw new GenevaRefusedException($"уже идут {GenevaArgv.MaxSearches} подбора geneva / {GenevaArgv.MaxSearches} geneva searches already run");
                if (_searches.Values.Any(x => string.Equals(x.Settings.Host, settings.Host, StringComparison.OrdinalIgnoreCase) && x.Settings.Port == settings.Port))
                    throw new GenevaRefusedException("подбор этой цели уже идёт / this target is already being searched");
            }
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
                Protos = settings.Protos,
                Probe = settings.Probe,
                Workers = settings.Workers,
            };
            req.Seeds.AddRange(settings.Seeds);
            var reply = await agent.StartAsync(req, CancellationToken.None).ConfigureAwait(false);
            var prev = State.ProgressOf(settings.Host, settings.Port);
            SearchSlot slot;
            lock (_lock)
            {
                // the feed belongs to the searches running now
                if (_searches.Count == 0)
                    _trials.Clear();
                slot = new SearchSlot(reply.Id, settings, judge, new GenevaSearchView
                {
                    Running = true,
                    Id = reply.Id,
                    Auto = auto,
                    Host = settings.Host,
                    Port = settings.Port,
                    Population = settings.Population,
                    Generations = settings.Generations,
                    Started = DateTimeOffset.Now,
                    Resumed = settings.Resume,
                    Protos = settings.Protos,
                    Workers = settings.Workers,
                    Generation = settings.Resume && prev is not null ? prev.Generation : -1,
                    BestFitness = settings.Resume && prev is not null ? prev.BestFitness : 0,
                    Best = settings.Resume ? prev?.Best : null,
                });
                _searches[reply.Id] = slot;
            }
            AddLog(settings.Resume ? $"Продолжение подбора для {settings.Host}" : $"Подбор для {settings.Host}: популяция {settings.Population}, поколений {settings.Generations}");
            Update(s => auto ? s : s with { LastHost = settings.Host, LastPort = settings.Port, Population = settings.Population, Generations = settings.Generations });
            slot.Watch = Task.Run(() => WatchSearchAsync(agent, slot, _dispose.Token));
            return reply.Id;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Stops every running search (the page's Stop, MCP, the program's "turn everything off").</summary>
    public async Task StopSearchAsync(CancellationToken ct = default)
    {
        List<string> ids;
        lock (_lock)
            ids = [.. _searches.Keys];
        await Task.WhenAll(ids.Select(id => StopSearchAsync(id, ct))).ConfigureAwait(false);
    }

    /// <summary>Stops one search; geneva saves its checkpoint. Nothing happens when it already ended.</summary>
    public async Task StopSearchAsync(string id, CancellationToken ct)
    {
        SearchSlot? slot;
        lock (_lock)
        {
            if (!_searches.TryGetValue(id, out slot))
                return;
            slot.StopRequested = true;
        }
        // the probe in flight is not waited for: geneva stops after its current step anyway
        try
        {
            await slot.ProbeCts.CancelAsync().ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            return; // it ended meanwhile
        }
        AddLog($"Остановка подбора для {slot.Settings.Host}: geneva сохраняет прогресс… / stopping the search for {slot.Settings.Host}: geneva saves its progress…");
        Changed?.Invoke();
        var agent = await _agent(ct).ConfigureAwait(false);
        await agent.StopAsync(id, ct).ConfigureAwait(false);
        if (slot.Watch is { } w)
            await Task.WhenAny(w, Task.Delay(TimeSpan.FromSeconds(20), ct)).ConfigureAwait(false);
    }

    private async Task WatchSearchAsync(IGenevaAgent agent, SearchSlot slot, CancellationToken ct)
    {
        var id = slot.Id;
        var settings = slot.Settings;
        var probeCt = slot.ProbeCts.Token;
        int exitCode = -1;
        string? reason = null;
        var inflight = new List<Task>();
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
                if (e.Ev == "eval_request" && settings.Workers > 1)
                {
                    // several workers ask at once, each from its own ports: their probes run side by side, and geneva
                    // takes the answers by id in any order. One worker keeps the old order: one probe at a time.
                    var pending = Task.Run(() => AnswerAsync(agent, slot, e, probeCt, ct), CancellationToken.None);
                    inflight.Add(pending);
                    inflight.RemoveAll(t => t.IsCompleted);
                    continue;
                }
                await OnSearchEventAsync(agent, slot, e, probeCt, ct).ConfigureAwait(false);
                Changed?.Invoke();
            }
        }
        catch (Exception e) when (e is Grpc.Core.RpcException or OperationCanceledException or IOException)
        {
            AddLog("Связь с Agent потеряна / the Agent connection was lost: " + e.Message);
        }
        catch (Exception e)
        {
            // anything else must not leave the search shown as running with geneva waiting for an answer
            AddLog("Ошибка подбора / search error: " + e.Message);
            await agent.StopAsync(id, CancellationToken.None).ContinueWith(_ => { }, TaskScheduler.Default).ConfigureAwait(false);
        }
        // the probes still running answer nobody now (geneva is gone); they end with the probe's own timeout
        await Task.WhenAny(Task.WhenAll(inflight), Task.Delay(TimeSpan.FromSeconds(15), CancellationToken.None)).ConfigureAwait(false);
        // the user's search found something: the final check in the browser before the search counts as over (the
        // "Авто" mode checks on the service's own traffic itself)
        if (!slot.View.Auto && exitCode == 0 && !_dispose.IsCancellationRequested && !slot.ProbeCts.IsCancellationRequested)
        {
            try
            {
                await CheckInBrowserAsync(agent, slot, ct).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                // the search must still end below: a slot left behind would refuse every later search
                AddLog("Итоговая проверка в браузере прервана / the final check in the browser stopped: " + e.Message);
            }
            finally
            {
                Volatile.Write(ref _browserChecking, false);
            }
        }
        bool stopped;
        (string Ru, string En)? ports;
        lock (_lock)
            (stopped, ports) = (slot.StopRequested, slot.PortsUnavailable);
        // the Agent stops a search by closing its input, which geneva reports as a failed evaluation (code 1): the
        // user pressed Stop, the checkpoint is saved
        var ended = ports ?? (stopped && reason != "done" ? GenevaText.Exit(0, "signal") : GenevaText.Exit(exitCode, reason));
        GenevaSearchView view;
        lock (_lock)
        {
            view = slot.View with { Running = false, Ended = ended };
            _searches.Remove(id);
            _search = view;
        }
        slot.ProbeCts.Dispose();
        Update(s => s.WithProgress(new GenevaSearchProgress
        {
            Host = view.Host,
            Port = view.Port,
            Population = view.Population,
            Generation = view.Generation,
            Generations = view.Generations,
            BestFitness = view.BestFitness,
            Best = view.Best,
            Protos = view.Protos,
            Updated = DateTimeOffset.Now,
            Finished = exitCode == 0 && reason == "done",
        }));
        if (_dispose.IsCancellationRequested)
            return;
        AddLog(ended.Ru);
        Changed?.Invoke();
        SearchEnded?.Invoke(view);
    }

    private async Task OnSearchEventAsync(IGenevaAgent agent, SearchSlot slot, GenevaEvent e, CancellationToken probeCt, CancellationToken ct)
    {
        var id = slot.Id;
        var settings = slot.Settings;
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
                await AnswerAsync(agent, slot, e, probeCt, ct).ConfigureAwait(false);
                break;
            case "baseline":
                lock (_lock)
                    slot.View = slot.View with { Blocked = e.Bool("blocked"), BaselineOutcome = e.Str("outcome") };
                AddLog(e.Bool("blocked")
                    ? $"{settings.Host} без обхода: {GenevaText.Outcome(e.Str("outcome")).Ru} — сайт заблокирован, ищем / without a bypass: {GenevaText.Outcome(e.Str("outcome")).En}, blocked, searching"
                    : $"{settings.Host} без обхода открывается: подбирать нечего / opens without a bypass: nothing to search");
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
                    var v = slot.View;
                    slot.View = v with
                    {
                        Evaluated = v.Evaluated + 1,
                        EvaluatedInGeneration = Math.Min(v.Population, v.EvaluatedInGeneration + 1),
                        Succeeded = v.Succeeded + (t.Fitness > 0 ? 1 : 0),
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
                    var v = slot.View;
                    slot.View = v with
                    {
                        Generation = (int)e.Long("gen"),
                        EvaluatedInGeneration = 0,
                        BestFitness = e.Num("best_fitness"),
                        AvgFitness = e.Num("avg_fitness"),
                        Best = e.Str("best"),
                        BestByGeneration = [.. v.BestByGeneration.TakeLast(MaxHistory - 1), e.Num("best_fitness")],
                        AvgByGeneration = [.. v.AvgByGeneration.TakeLast(MaxHistory - 1), e.Num("avg_fitness")],
                    };
                    view = slot.View;
                }
                AddLog($"{view.Host}: поколение {view.Generation + 1}/{view.Generations}: лучший фитнес {view.BestFitness:0}, средний {view.AvgFitness:0} / generation {view.Generation + 1}/{view.Generations}: best fitness {view.BestFitness:0}, average {view.AvgFitness:0}");
                Update(s => s.WithProgress(new GenevaSearchProgress
                {
                    Host = view.Host,
                    Port = view.Port,
                    Population = view.Population,
                    Generation = view.Generation,
                    Generations = view.Generations,
                    BestFitness = view.BestFitness,
                    Best = view.Best,
                    Protos = view.Protos,
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
                lock (_lock)
                {
                    slot.Result.Clear();
                    slot.Result.AddRange(found.OrderByDescending(f => f.Fitness).ThenByDescending(f => f.Runs));
                }
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
    private async Task AnswerAsync(IGenevaAgent agent, SearchSlot slot, GenevaEvent e, CancellationToken probeCt, CancellationToken ct)
    {
        var id = slot.Id;
        if (probeCt.IsCancellationRequested)
            return;
        long reqId = e.Long("id");
        var lports = e.Str("lports") ?? "";
        int fitness;
        string detail;
        try
        {
            GenevaJudge judge = slot.Judge ?? ((port, c) => PageJudgeAsync(slot, port, lports, e.Str("strategy") ?? "", c));
            GenevaJudgement? j = null;
            for (int attempt = 0; attempt < MaxPortAttempts; attempt++)
            {
                int port = GenevaArgv.LocalPort(lports, Interlocked.Increment(ref _probeSeq));
                using var both = CancellationTokenSource.CreateLinkedTokenSource(probeCt, ct);
                j = await judge(port, both.Token).ConfigureAwait(false);
                if (!j.PortUnavailable)
                    break;
            }
            if (j!.PortUnavailable)
            {
                // every port of the block is taken or reserved (Windows excludes ranges for Hyper-V): no strategy can
                // be judged, and a made-up failure would mislead the search
                AddLog($"Локальные порты {lports} заняты или зарезервированы системой: подбор остановлен ({j.Detail})");
                lock (_lock)
                    slot.PortsUnavailable = ($"локальные порты {lports} заняты или зарезервированы системой", $"local ports {lports} are busy or reserved by the system");
                await agent.StopAsync(id, CancellationToken.None).ConfigureAwait(false);
                return;
            }
            (fitness, detail) = (j.Fitness, j.Detail);
        }
        catch (OperationCanceledException) when (probeCt.IsCancellationRequested)
        {
            return; // stopped: geneva gets no answer and ends with its stdin
        }
        catch (FormatException)
        {
            (fitness, detail) = (-400, "bad lports " + lports);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // geneva waits for every answer: a probe that throws still gets one
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

    /// <summary>
    /// The default judge: the page's full download (L2) from the local port under the target's criterion. The baseline
    /// (geneva's first request, without a strategy) also checks for a shaper and for the 16 KB cut-off behind a small
    /// page (<see cref="PageCheck"/>): a page that only seems to open is blocked, and every strategy after it must pass
    /// the tighter criterion (the speed, the padded 128 KB). geneva repeats the baseline when a search continues.
    /// </summary>
    private async Task<GenevaJudgement> PageJudgeAsync(SearchSlot slot, int port, string lports, string strategy, CancellationToken ct)
    {
        var settings = slot.Settings;
        ProbeCriteria c;
        lock (_lock)
            c = slot.Criteria;
        bool baseline = GenevaStrategyText.IsEmpty(strategy);
        int n = 0;
        var check = await PageCheck.RunAsync(c, baseline, LinkCapacity.Shared,
            // the baseline's padded second download gets a port of its own: the first one's may still be in TIME_WAIT
            (k, t) => _probe(settings.Host, settings.Port, settings.Tls, n++ == 0 ? port : GenevaArgv.LocalPort(lports, Interlocked.Increment(ref _probeSeq)), k, t), ct).ConfigureAwait(false);
        var r = check.Probe;
        if (LocalPortUnavailable(r))
            return new GenevaJudgement(0, r.ErrorDetail ?? "", PortUnavailable: true);
        if (check.Finding is { } found)
        {
            lock (_lock)
                slot.Criteria = check.Criteria;
            AddLog($"{settings.Host}: без обхода страница открывается, но: {found}. Стратегия должна дать {check.Criteria} / without a bypass the page opens, but not as it should; a strategy must give {check.Criteria}");
        }
        var (fitness, outcome) = GenevaFitness.FromProbe(r, ProbeLevel.L2Body, check.Criteria.MinBytes);
        return new GenevaJudgement(fitness, outcome + ": " + r);
    }

    /// <summary>
    /// The final check of a manual search (<see cref="GenevaBrowserCheck"/>): each of the best strategies found runs as
    /// the bypass on the target's port for a moment, and the program's browser opens the site through it. The verdict is
    /// kept with the found strategy. Skipped when the switch is off, there is no browser, or another geneva bypass holds
    /// the port (the single-strategy bypass, "Авто").
    /// </summary>
    private async Task CheckInBrowserAsync(IGenevaAgent agent, SearchSlot slot, CancellationToken ct)
    {
        List<GenevaFoundStrategy> found;
        lock (_lock)
            found = [.. slot.Result.Take(GenevaBrowserCheck.MaxManual)];
        if (found.Count == 0 || !BrowserCheck)
            return;
        var settings = slot.Settings;
        if (BrowserNow is not { } browser)
        {
            AddLog("Итоговая проверка в браузере пропущена: встроенного браузера программы нет / the final check in the browser is skipped: the program has no browser of its own");
            return;
        }
        if (RunRunning || AutoRunning?.Invoke() == true || Busy?.Invoke() is not null)
        {
            AddLog("Итоговая проверка в браузере пропущена: работает обход geneva («Авто» или одна стратегия) / the final check in the browser is skipped: a geneva bypass runs (\"Auto\" or a single strategy)");
            return;
        }
        lock (_lock)
            slot.View = slot.View with { BrowserChecking = true };
        Volatile.Write(ref _browserChecking, true);
        Changed?.Invoke();
        using var both = CancellationTokenSource.CreateLinkedTokenSource(slot.ProbeCts.Token, ct);
        var excluded = new AutoNameList(State.Lists.Excluded);
        var family = GenevaBrowserCheck.SiteAndFamily(settings.Host);
        int passed = 0, checkedCount = 0;
        foreach (var f in found)
        {
            string? id = null;
            try
            {
                var req = new GenevaStartRequest
                {
                    Mode = "run",
                    Strategy = f.Strategy,
                    Ports = settings.Port.ToString(CultureInfo.InvariantCulture),
                    Tag = "geneva-check:" + settings.Host,
                };
                req.ExcludeSubnets.AddRange(excluded.Subnets);
                req.ExcludeDomains.AddRange(excluded.Domains);
                id = (await agent.StartAsync(req, both.Token).ConfigureAwait(false)).Id;
                if (await WaitReadyAsync(agent, id, both.Token).ConfigureAwait(false) is { } why)
                {
                    AddLog($"Итоговая проверка: geneva со стратегией не запустилась ({why}): {f.Strategy} / the final check: geneva did not start with the strategy");
                    continue;
                }
                // the bypass takes the whole port: on 443 the site's other names and its family (YouTube's googlevideo.com
                // and ytimg.com) go through the strategy and must load, except what the user's "не трогать" keeps out.
                // Other domains of the page may fail for reasons of their own (blocked by address, down): only logged
                var verdict = await GenevaBrowserCheck.RunAsync(browser.Open, settings.Host, settings.Port, null, both.Token,
                    h => settings.Port == 443 && !excluded.MatchesName(h) && family.Any(d => GenevaBrowserCheck.Under(h, d))).ConfigureAwait(false);
                if (verdict is null)
                {
                    AddLog("Итоговая проверка в браузере пропущена: встроенного браузера программы нет / the final check in the browser is skipped: the program has no browser of its own");
                    break;
                }
                if (verdict.Ok is not { } ok)
                {
                    AddLog($"Итоговая проверка: браузер не знает корневой сертификат сайта ({verdict.Detail}), по стратегии судить нельзя / the browser does not know the site's root certificate, no verdict: {f.Strategy}");
                    continue;
                }
                checkedCount++;
                passed += ok ? 1 : 0;
                Update(s => s.WithBrowser(settings.Host, settings.Port, f.Strategy, ok));
                var related = verdict.RelatedOk.Count == 0 ? "" : $" (и связанные: {string.Join(", ", verdict.RelatedOk)} / and related ones)";
                AddLog(ok
                    ? $"{settings.Host} открылся во встроенном браузере{related}: {f.Strategy} / opened in the program's browser"
                    : verdict.SiteOpened
                    ? $"{settings.Host} открылся во встроенном браузере, но не загрузились связанные ресурсы ({verdict.Detail}): {f.Strategy} / opened in the program's browser, but its related resources did not load"
                    : $"{settings.Host} не открылся во встроенном браузере ({verdict.Detail}): {f.Strategy} / did not open in the program's browser");
                if (verdict.NotCovered.Count > 0)
                    AddLog($"{settings.Host}: на странице не грузятся и другие ресурсы, их стратегия сайта не касается: {string.Join(", ", verdict.NotCovered)} / other resources of the page fail too, not the site's strategy's business");
            }
            catch (OperationCanceledException)
            {
                break; // stopped: what was checked stays
            }
            catch (GenevaRefusedException e)
            {
                AddLog($"Итоговая проверка в браузере прервана: {e.Message} / the final check in the browser stopped");
                break;
            }
            catch (Exception e) when (e is Grpc.Core.RpcException or IOException or InvalidOperationException)
            {
                AddLog($"Итоговая проверка в браузере прервана: {e.Message} / the final check in the browser stopped");
                break;
            }
            finally
            {
                if (id is not null)
                    await agent.StopAsync(id, CancellationToken.None).ContinueWith(_ => { }, TaskScheduler.Default).ConfigureAwait(false);
            }
        }
        if (checkedCount > 0)
        {
            AddLog(passed > 0
                ? $"Итоговая проверка в браузере: открыли сайт {passed} из {checkedCount} / the final check in the browser: {passed} of {checkedCount} opened the site"
                : $"Итоговая проверка в браузере: ни одна из {checkedCount} стратегий не открыла сайт в браузере — подбор можно продолжить / the final check in the browser: none of {checkedCount} opened the site, the search can go on");
        }
        lock (_lock)
            slot.View = slot.View with { BrowserChecking = false };
    }

    /// <summary>Waits for a bypass's <c>ready</c> (its rules are in): null, or why it did not come.</summary>
    private static async Task<string?> WaitReadyAsync(IGenevaAgent agent, string id, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(ReadyTimeout);
        string? error = null;
        try
        {
            await foreach (var o in agent.WatchAsync(id, limit.Token).ConfigureAwait(false))
            {
                if (o.Exited)
                    return error ?? $"exit {o.ExitCode}";
                if (GenevaEvent.Parse(o.Event) is not { } e)
                    continue;
                if (e.Ev == "ready")
                    return null;
                if (e.Ev == "error")
                    error = e.Str("message");
            }
        }
        catch (Exception e) when (!ct.IsCancellationRequested && (e is OperationCanceledException || e is Grpc.Core.RpcException { StatusCode: Grpc.Core.StatusCode.Cancelled or Grpc.Core.StatusCode.DeadlineExceeded }))
        {
            return error ?? "timeout";
        }
        ct.ThrowIfCancellationRequested();
        return error ?? "ended";
    }

    /// <summary>How long a bypass of the final check may take to put its rules in.</summary>
    internal static TimeSpan ReadyTimeout { get; set; } = TimeSpan.FromSeconds(20);

    /// <summary>Ports of the block the probe tries for one strategy before it gives up on the block.</summary>
    public const int MaxPortAttempts = 8;

    private static bool LocalPortUnavailable(ProbeResult r) =>
        r.Error == ProbeError.Other && r.ErrorDetail?.StartsWith(ProbeDetail.LocalPortPrefix, StringComparison.Ordinal) == true;

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
            if (Volatile.Read(ref _browserChecking))
                throw new GenevaRefusedException("идёт итоговая проверка найденного в браузере: дождитесь её конца / the final check of what was found runs in the browser, wait for it to end");
            if (AutoRunning?.Invoke() == true)
                throw new GenevaRefusedException("включён режим «Авто»: сначала выключите его / the \"Auto\" mode is on: turn it off first");
            if (Busy?.Invoke() is { } why)
                throw new GenevaRefusedException(why);
            var agent = await _agent(ct).ConfigureAwait(false);
            // the user's "не трогать" list (a VPN or proxy server) stays out of the bypass (geneva_c 2.0)
            var excluded = new AutoNameList(State.Lists.Excluded);
            var req = new GenevaStartRequest { Mode = "run", Strategy = settings.Strategy, Ports = settings.Ports, Tag = "geneva-run" };
            req.ExcludeSubnets.AddRange(excluded.Subnets);
            req.ExcludeDomains.AddRange(excluded.Domains);
            var reply = await agent.StartAsync(req, CancellationToken.None).ConfigureAwait(false);
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
        if (State is not { Engine: BypassEngine.Geneva, Active: { AutoStart: true } a } || RunRunning || AutoRunning?.Invoke() == true)
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
                    case "start" when e.Long("proto") != GenevaEvent.Proto:
                        AddLog($"geneva говорит на протоколе {e.Long("proto")}, нужен {GenevaEvent.Proto}: выключаю");
                        await agent.StopAsync(id, CancellationToken.None).ConfigureAwait(false);
                        break;
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
        catch (Exception e)
        {
            AddLog("Ошибка обхода / bypass error: " + e.Message);
            await agent.StopAsync(id, CancellationToken.None).ContinueWith(_ => { }, TaskScheduler.Default).ConfigureAwait(false);
        }
        var ended = GenevaText.Exit(exitCode, reason);
        lock (_lock)
        {
            if (_runId == id)
                _runId = null;
            _run = _run with { Running = false, Ready = false, Ended = ended };
        }
        if (_dispose.IsCancellationRequested)
            return;
        AddLog("Обход geneva выключен: " + ended.Ru);
        Changed?.Invoke();
    }

    // ---- what the Agent keeps

    /// <summary>Saves the "Авто" mode's state with the rest (one settings key).</summary>
    public void SaveAuto(GenevaAutoState auto) => Update(s => s with { Auto = auto });

    /// <summary>
    /// The user's lists (important, unimportant, never touched); a change reaches the "Авто" mode at once, and a new
    /// "never touch" list restarts the single-strategy bypass with it (its exclusions are fixed at start).
    /// </summary>
    public AutoLists Lists
    {
        get => State.Lists;
        set
        {
            bool exclusions = !State.Lists.Excluded.SequenceEqual(value.Excluded, StringComparer.Ordinal);
            Update(s => s with { Lists = value });
            ListsChanged?.Invoke();
            if (exclusions && RunRunning)
                ListsRestart = RestartRunAsync();
        }
    }

    /// <summary>The last restart of the bypass for a new "never touch" list (tests wait for it).</summary>
    public Task? ListsRestart { get; private set; }

    private readonly SemaphoreSlim _restartGate = new(1, 1);

    /// <summary>
    /// Restarts the running bypass with the current "never touch" list. One restart at a time: a second edit waits and
    /// restarts with its list. A restart that cannot start again says so in the log and on the page.
    /// </summary>
    private async Task RestartRunAsync()
    {
        try
        {
            await _restartGate.WaitAsync(_dispose.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException)
        {
            return;
        }
        try
        {
            if (!RunRunning || State.Active is not { } a)
                return;
            await StopRunAsync(forget: false).ConfigureAwait(false);
            // the watch sees the exit: only then is the bypass off for StartRunAsync
            for (int i = 0; i < 100 && RunRunning && !_dispose.IsCancellationRequested; i++)
                await Task.Delay(100, _dispose.Token).ConfigureAwait(false);
            await StartRunAsync(a.Strategy, a.Ports, a.AutoStart, _dispose.Token).ConfigureAwait(false);
            AddLog("Список «Не трогать» изменился: обход geneva перезапущен с ним / the \"never touch\" list changed: the bypass restarted with it");
        }
        catch (Exception e) when (e is GenevaRefusedException or AgentStartException or InvalidOperationException or Grpc.Core.RpcException or IOException)
        {
            AddLog("Обход geneva выключен: с новым списком «Не трогать» он не запустился, включите его снова / the bypass is off, it did not start with the new list: " + e.Message);
        }
        catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException)
        {
        }
        finally
        {
            _restartGate.Release();
        }
        Changed?.Invoke();
    }

    /// <summary>The "Авто" mode applies site strategies by name too (geneva_c 2.0).</summary>
    public bool ByName
    {
        get => State.ByName;
        set
        {
            Update(s => s with { ByName = value });
            ListsChanged?.Invoke();
        }
    }

    /// <summary>The lists or the by-name switch changed.</summary>
    public event Action? ListsChanged;

    /// <summary>Strategies a search judges at once, 1 to <see cref="GenevaSearchSettings.WorkersRange"/>'s maximum.</summary>
    public int Workers
    {
        get => Math.Clamp(State.Workers, GenevaSearchSettings.WorkersRange.Min, GenevaSearchSettings.WorkersRange.Max);
        set => Update(s => s with { Workers = Math.Clamp(value, GenevaSearchSettings.WorkersRange.Min, GenevaSearchSettings.WorkersRange.Max) });
    }

    /// <summary>The "Авто" mode searches several services at once, the workers split between them.</summary>
    public bool AutoSplit
    {
        get => State.AutoSplit;
        set => Update(s => s with { AutoSplit = value });
    }

    /// <summary>Searches the "Авто" mode runs side by side now: 1, or with <see cref="AutoSplit"/> one per worker, at most <see cref="GenevaArgv.MaxSearches"/>.</summary>
    public int AutoSearches => AutoSplit ? Math.Clamp(Workers, 1, GenevaArgv.MaxSearches) : 1;

    /// <summary>
    /// The workers of each of the "Авто" mode's searches: all of them, or an equal share per slot. Fixed per slot, so
    /// the searches together never run more than the user set, whenever each of them starts.
    /// </summary>
    public int AutoWorkers => Math.Max(1, Workers / AutoSearches);

    /// <summary>
    /// Adds strategies from another user's file (already checked by <c>geneva check</c>): next to the working ones,
    /// nothing replaced. Returns how many were new. The "Авто" mode tries them on a service's traffic before use.
    /// </summary>
    public int Import(IEnumerable<GenevaSharedStrategy> rows)
    {
        int added = 0;
        Update(s =>
        {
            var (next, n) = s.WithImported(rows, DateTimeOffset.Now);
            added = n;
            return next;
        });
        AddLog($"Импортировано новых стратегий: {added}");
        return added;
    }

    /// <summary>Forgets one imported strategy (the user's list); what is applied is not touched.</summary>
    public void RemoveImported(string strategy) => Update(s => s with { Imported = [.. s.Imported.Where(x => x.Strategy != strategy)] });

    /// <summary>The Agent's view: version, saved searches, the database's best strategies.</summary>
    public async Task<GenevaInfoReply> InfoAsync(CancellationToken ct) => await (await _agent(ct).ConfigureAwait(false)).InfoAsync(ct).ConfigureAwait(false);

    public async ValueTask DisposeAsync()
    {
        // the Agent stops geneva on its own when the UI goes; this only ends the watchers, and waits for them so none
        // writes the state after the program closed its store
        await _dispose.CancelAsync().ConfigureAwait(false);
        List<Task?> watches;
        lock (_lock)
            watches = [.. _searches.Values.Select(x => x.Watch), _runWatch];
        foreach (var w in watches)
        {
            if (w is not null)
                await Task.WhenAny(w, Task.Delay(TimeSpan.FromSeconds(3))).ConfigureAwait(false);
        }
        _dispose.Dispose();
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
