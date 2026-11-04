using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning.Geneva;

/// <summary>One running strategy of the "Авто" mode, with the services it serves and its live counters.</summary>
public sealed record AutoGroupView
{
    public string Strategy { get; init; } = "";

    public string Id { get; init; } = "";

    public int Queue { get; init; }

    public IReadOnlyList<string> Services { get; init; } = [];

    public GenevaStats? Stats { get; init; }

    /// <summary>Packets per second through the strategy since the previous poll.</summary>
    public double Rate { get; init; }
}

/// <summary>The "Авто" mode as the page and MCP see it.</summary>
public sealed record GenevaAutoView
{
    public bool Enabled { get; init; }

    /// <summary>The observation loop is alive (it may be between slices).</summary>
    public bool Running { get; init; }

    /// <summary>What the mode is doing now, in Russian and English.</summary>
    public (string Ru, string En) Phase { get; init; } = ("выключен", "off");

    public int Slices { get; init; }

    public DateTimeOffset? LastSlice { get; init; }

    /// <summary>Flows of the last slice: the observation sees traffic at all.</summary>
    public int Flows { get; init; }

    public IReadOnlyList<AutoService> Services { get; init; } = [];

    public IReadOnlyList<AutoGroupView> Groups { get; init; } = [];

    /// <summary>The service a strategy is being found for now, and the strategy being tried.</summary>
    public string? Current { get; init; }

    public string? Trying { get; init; }

    public IReadOnlyList<string> Problems { get; init; } = [];

    /// <summary>Windows with a geneva_c that cannot filter by address: found strategies are not applied.</summary>
    public bool Limited { get; init; }

    public int Count(AutoStatus s) => Services.Count(x => x.Status == s);
}

/// <summary>
/// The "Авто" mode (skill <c>geneva</c>, §9): the user turns it on and nothing else. The Agent captures the whole PC's
/// traffic in slices; flows become samples (<see cref="AutoObserver"/>) and services (<see cref="AutoBook"/>). A
/// service that fails like DPI makes it fail is probed without a bypass (the baseline, AGENTS.md rule 5); a blocked one
/// gets known strategies tried on its traffic alone, then geneva's search. A working strategy is applied only to the
/// service's addresses and ports (or a peer-to-peer program's local port), one <c>geneva run</c> per strategy; the
/// rest of the traffic never reaches geneva. Applied services stay watched: one that fails again is checked with its
/// bypass on and searched again, continuing the saved search with more generations. Everything is saved as it changes
/// and comes back after a restart.
/// </summary>
public sealed class GenevaAuto : IAsyncDisposable
{
    public const int MaxLog = 300;

    private readonly GenevaController _controller;
    private readonly Func<CancellationToken, Task<IGenevaAgent>> _agent;
    private readonly IProgramMonitor _capture;
    private readonly IAutoProbes _probes;
    private readonly Func<DateTime> _now;
    private readonly Lock _lock = new();
    private readonly SemaphoreSlim _applyGate = new(1, 1);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<string> _log = [];
    private readonly AutoBook _book;
    private CancellationTokenSource? _loopCts;
    private Task? _loop;
    private Task? _work;
    private (string Key, string Strategy)? _trial;
    private string? _current;
    private List<AutoGroupView> _groups = [];
    private List<string> _problems = [];
    private bool _limited;
    private string _applied = "";
    private DateTime _appliedAt;
    private (string Ru, string En) _phase = ("выключен", "off");
    private int _slices;
    private int _flows;
    private DateTimeOffset? _lastSlice;
    private DateTime _savedAt;
    private Dictionary<string, (long Packets, long Uptime)> _prevStats = [];

    /// <param name="capture">The Agent's capture of the whole PC (AGENTS.md rule 6).</param>
    /// <param name="clock">UTC now; tests pass their own.</param>
    public GenevaAuto(GenevaController controller, Func<CancellationToken, Task<IGenevaAgent>> agent, IProgramMonitor capture, IAutoProbes probes, Func<DateTime>? clock = null)
    {
        _controller = controller;
        _agent = agent;
        _capture = capture;
        _probes = probes;
        _now = clock ?? (() => DateTime.UtcNow);
        _book = new AutoBook(controller.State.Auto.Services);
        controller.AutoRunning = () => Running;
    }

    /// <summary>One capture slice: short enough that a trial sees the program's retries soon, long enough to hold flows.</summary>
    public TimeSpan Slice { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>How long a strategy tried on a service without a probe (WireGuard, DHT) waits for its own traffic.</summary>
    public TimeSpan PassiveTrial { get; init; } = TimeSpan.FromSeconds(50);

    /// <summary>The running groups are applied again this often (new addresses join their sets).</summary>
    public TimeSpan Refresh { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Geneva's library for the wider round (client-side strategies, best first); null: the round goes without it.
    /// The App reads it from the bundle without rights.
    /// </summary>
    public Func<CancellationToken, Task<IReadOnlyList<string>>>? Library { get; init; }

    /// <summary>Why the mode may not start now (zapret2's protection runs, the wizard tunes, MCP experiments), or null.</summary>
    public Func<string?>? Busy { get; set; }

    public event Action? Changed;

    public bool Enabled => _controller.State.Auto.Enabled;

    /// <summary>The loop runs: zapret2 and the single-strategy bypass wait (both would queue the same packets).</summary>
    public bool Running
    {
        get
        {
            lock (_lock)
                return _loop is { IsCompleted: false };
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

    public GenevaAutoView View
    {
        get
        {
            lock (_lock)
            {
                return new GenevaAutoView
                {
                    Enabled = Enabled,
                    Running = _loop is { IsCompleted: false },
                    Phase = _phase,
                    Slices = _slices,
                    LastSlice = _lastSlice,
                    Flows = _flows,
                    Services = _book.Snapshot(),
                    Groups = [.. _groups],
                    Current = _current,
                    Trying = _trial?.Strategy,
                    Problems = [.. _problems],
                    Limited = _limited,
                };
            }
        }
    }

    private void AddLog(string line)
    {
        if (line.Length == 0)
            return;
        lock (_lock)
        {
            _log.Add(DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture) + " " + line);
            if (_log.Count > MaxLog)
                _log.RemoveRange(0, _log.Count - MaxLog);
        }
    }

    private void Phase(string ru, string en)
    {
        lock (_lock)
            _phase = (ru, en);
        Changed?.Invoke();
    }

    // ---- on and off

    /// <summary>Turns the mode on: the choice is saved, and it comes back with the program. Throws <see cref="GenevaRefusedException"/>.</summary>
    public async Task EnableAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (Running)
                return;
            if (Busy?.Invoke() is { } why)
                throw new GenevaRefusedException(why);
            if (_controller.RunRunning)
                throw new GenevaRefusedException("включён обход geneva с одной стратегией: сначала выключите его / the single-strategy geneva bypass is on");
            if (_controller.SearchRunning)
                throw new GenevaRefusedException("идёт подбор geneva: дождитесь конца или остановите его / a geneva search is running");
            // the Agent first: its prompt belongs to the click, not to the first slice
            await _agent(ct).ConfigureAwait(false);
            Save(enabled: true, force: true);
            StartLoop();
            AddLog("Режим «Авто» включён: слежу за трафиком");
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Turns the mode off: the search stops (its progress stays), every group stops and its rules go.</summary>
    public async Task DisableAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Save(enabled: false, force: true);
            await StopLoopAsync().ConfigureAwait(false);
            try
            {
                var agent = await _agent(ct).ConfigureAwait(false);
                await agent.AutoApplyAsync(new GenevaAutoApplyRequest(), ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is GenevaRefusedException or Grpc.Core.RpcException or IOException or InvalidOperationException)
            {
                AddLog("Не удалось остановить группы / could not stop the groups: " + e.Message);
            }
            lock (_lock)
            {
                _groups = [];
                _applied = "";
                _trial = null;
                _current = null;
            }
            Phase("выключен", "off");
            AddLog("Режим «Авто» выключен");
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Brings the mode back after a restart when it was on; false when there is nothing to do.</summary>
    public async Task<bool> RestoreAsync(CancellationToken ct)
    {
        if (!Enabled || Running)
            return false;
        if (Busy?.Invoke() is not null || _controller.RunRunning)
            return false;
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (Running)
                return false;
            StartLoop();
            AddLog("Режим «Авто» восстановлен после запуска");
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Forgets what is known about one service: back to watching, its strategy is no longer applied.</summary>
    public async Task ResetServiceAsync(string key, CancellationToken ct)
    {
        lock (_lock)
            _book.Reset(key, _now());
        Save(force: true);
        if (Running)
            await ApplyAsync(ct, force: true).ConfigureAwait(false);
        Changed?.Invoke();
    }

    private void StartLoop()
    {
        var cts = new CancellationTokenSource();
        lock (_lock)
        {
            _loopCts = cts;
            _loop = Task.Run(() => LoopAsync(cts.Token));
        }
        Changed?.Invoke();
    }

    private async Task StopLoopAsync()
    {
        CancellationTokenSource? cts;
        Task? loop, work;
        lock (_lock)
            (cts, loop, work) = (_loopCts, _loop, _work);
        if (cts is null)
            return;
        await cts.CancelAsync().ConfigureAwait(false);
        foreach (var t in new[] { work, loop })
        {
            if (t is not null)
                await Task.WhenAny(t, Task.Delay(TimeSpan.FromSeconds(30))).ConfigureAwait(false);
        }
        lock (_lock)
        {
            foreach (var s in _book.Services.Where(s => s.Status == AutoStatus.Searching).ToList())
                _book.Interrupted(s.Key, _now());
            _loopCts = null;
            _loop = null;
            _work = null;
        }
        cts.Dispose();
        Save(force: true);
    }

    // ---- the loop

    private async Task LoopAsync(CancellationToken ct)
    {
        int failures = 0;
        try
        {
            // the strategies found before work from the first second
            await ApplyAsync(ct, force: true).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            AddLog("Группы не применились / groups not applied: " + e.Message);
        }
        while (!ct.IsCancellationRequested)
        {
            try
            {
                Phase(_current is null ? "наблюдаю за трафиком" : $"подбираю обход: {_current}", _current is null ? "watching the traffic" : $"searching: {_current}");
                await SliceAsync(ct).ConfigureAwait(false);
                await ConfirmAsync(ct).ConfigureAwait(false);
                StartSearchIfDue(ct);
                await ApplyAsync(ct).ConfigureAwait(false);
                await PollStatsAsync(ct).ConfigureAwait(false);
                Save();
                failures = 0;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception e)
            {
                failures++;
                AddLog($"Ошибка наблюдения / observation error ({failures}): {e.Message}");
                Phase("ошибка, повторяю", "error, retrying");
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(Math.Min(300, 5 * Math.Pow(2, Math.Min(failures - 1, 6)))), ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
            Changed?.Invoke();
        }
    }

    /// <summary>One slice of the whole PC's traffic into the book.</summary>
    private async Task SliceAsync(CancellationToken ct)
    {
        var id = await _capture.StartCaptureAsync(ct).ConfigureAwait(false);
        byte[] pcap;
        try
        {
            await Task.Delay(Slice, ct).ConfigureAwait(false);
        }
        finally
        {
            (pcap, _) = await _capture.StopCaptureAsync(id, CancellationToken.None).ConfigureAwait(false);
        }
        var packets = PcapReader.Read(pcap);
        var flows = FlowAnalyzer.Analyze(packets);
        var end = _now();
        var samples = AutoObserver.Observe(flows, end, ProgramEndpoints.DnsNames(packets));
        List<string> log;
        lock (_lock)
        {
            _book.Feed(samples, end);
            log = _book.Evaluate(end);
            _slices++;
            _flows = flows.Count;
            _lastSlice = DateTimeOffset.Now;
        }
        foreach (var l in log)
            AddLog(l);
    }

    /// <summary>The probe of one suspected (without a bypass) or degraded (with it) service.</summary>
    private async Task ConfirmAsync(CancellationToken ct)
    {
        AutoService? s;
        lock (_lock)
            s = _book.NextToConfirm(_now())?.Clone();
        if (s is null)
            return;
        var result = s.Probeable ? await _probes.CheckAsync(s, ct).ConfigureAwait(false) : AutoConfirm.Unknown;
        string line;
        lock (_lock)
            line = _book.Confirmed(s.Key, result, _now());
        AddLog(line);
        if (s.Status == AutoStatus.Degraded && result != AutoConfirm.NotBlocked)
            await ApplyAsync(ct, force: true).ConfigureAwait(false);
        Save(force: true);
    }

    private void StartSearchIfDue(CancellationToken ct)
    {
        AutoService? s;
        lock (_lock)
        {
            if (_work is { IsCompleted: false })
                return;
            s = _book.NextToSearch(_now());
            if (s is null)
                return;
            // the user's own search on the page has the search slot: wait for it
            if (_controller.SearchRunning)
                return;
            _book.Searching(s.Key, _now());
            _current = s.Name;
            s = s.Clone();
            _work = Task.Run(() => SearchAsync(s, ct));
        }
    }

    // ---- finding a strategy for one service

    private async Task SearchAsync(AutoService s, CancellationToken ct)
    {
        try
        {
            await FindAsync(s, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        catch (Exception e)
        {
            AddLog($"{s.Name}: ошибка подбора / search error: {e.Message}");
            lock (_lock)
                _book.Interrupted(s.Key, _now());
        }
        finally
        {
            lock (_lock)
            {
                _trial = null;
                _current = null;
            }
            // the mode going off (or the program closing) stops the groups itself: applying them here could start them
            // again after it did
            if (!ct.IsCancellationRequested)
            {
                try
                {
                    await ApplyAsync(ct, force: true).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                }
                catch (Exception e) when (e is GenevaRefusedException or Grpc.Core.RpcException or IOException or InvalidOperationException)
                {
                    AddLog("Группы не применились / groups not applied: " + e.Message);
                }
            }
            Save(force: true);
            Changed?.Invoke();
        }
    }

    private async Task FindAsync(AutoService s, CancellationToken ct)
    {
        // nothing found twice: the wider round tries every known strategy and Geneva's library, then a bigger search
        bool wide = s.Attempts >= AutoRules.WideAfter;
        IReadOnlyList<string> library = [];
        if (wide && Library is { } lib)
        {
            try
            {
                library = await lib(ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is InvalidOperationException or IOException or FormatException or System.ComponentModel.Win32Exception)
            {
                AddLog($"{s.Name}: библиотека Geneva недоступна / Geneva's library is unavailable: {e.Message}");
            }
        }
        List<string> candidates;
        lock (_lock)
        {
            var state = _controller.State;
            var running = _groups.Select(g => g.Strategy).ToList();
            var found = state.Found.Where(f => f.Fitness > 0).Select(f => f.Strategy)
                .Concat(_book.Services.Where(x => x.Strategy is not null).Select(x => x.Strategy!));
            candidates = AutoCandidates.For(s, running, found, state.Shared(), library, wide ? AutoRules.MaxWideCandidates : AutoRules.MaxQuickCandidates);
        }
        AddLog(wide
            ? $"{s.Name}: обычный подбор не помог {s.Attempts} раза — расширенный круг: {candidates.Count} стратегий, затем подбор шире"
            : $"{s.Name}: пробую известные стратегии ({candidates.Count})");
        foreach (var c in candidates)
        {
            ct.ThrowIfCancellationRequested();
            if (await TrialAsync(s, c, ct).ConfigureAwait(false))
            {
                Applied(s, c, 400, "известная стратегия");
                return;
            }
        }
        lock (_lock)
            _trial = null;
        await ApplyAsync(ct, force: true).ConfigureAwait(false);

        if (!s.Probeable)
        {
            // WireGuard, DHT: no probe can stand in for the program, and a search would need hundreds of its retries
            lock (_lock)
                _book.NotFound(s.Key, _now());
            AddLog($"{s.Name}: известные стратегии не помогли; повторю позже");
            return;
        }
        await EvolveAsync(s, candidates, wide, ct).ConfigureAwait(false);
    }

    /// <summary>geneva's search for the service, continued from its checkpoint when there is one.</summary>
    private async Task EvolveAsync(AutoService s, List<string> seeds, bool wide, CancellationToken ct)
    {
        bool web = s.Kind == AutoKind.Web;
        var host = web ? (s.Host.Length > 0 ? s.Host : s.Name) : s.Address?.ToString() ?? "";
        var saved = _controller.State.ProgressOf(host, s.Port);
        // the wider search starts over once, bigger and with more layers; later it is continued like any other
        bool restartWide = wide && saved is { Finished: true } && saved.Population < AutoRules.WidePopulation;
        var settings = restartWide
            ? new GenevaSearchSettings
            {
                Host = host,
                Port = s.Port,
                Tls = s.Port != 80,
                Probe = web ? GenevaArgv.WebProbe : GenevaArgv.ReplayProbe,
                Protos = AutoCandidates.Protos(s, wide: true),
                Population = AutoRules.WidePopulation,
                Generations = AutoRules.WideGenerations,
                Resume = false,
                Seeds = [.. seeds.Take(GenevaArgv.MaxSeeds)],
                Workers = _controller.Workers,
            }
            : new GenevaSearchSettings
            {
                Host = host,
                Port = s.Port,
                Tls = s.Port != 80,
                Probe = web ? GenevaArgv.WebProbe : GenevaArgv.ReplayProbe,
                // a resumed search keeps its layers: geneva refuses to continue with others
                Protos = saved is { Protos.Length: > 0 } ? saved.Protos : AutoCandidates.Protos(s),
                Population = saved?.Population > 0 ? saved.Population : AutoRules.Population,
                Generations = saved is null ? AutoRules.Generations : saved.Finished ? saved.Generations + AutoRules.MoreGenerations : saved.Generations,
                Resume = saved is not null,
                Seeds = saved is null ? [.. seeds.Take(GenevaArgv.MaxSeeds)] : [],
                Workers = _controller.Workers,
            };
        if (settings.Problems() is { Count: > 0 } bad)
        {
            AddLog($"{s.Name}: подбор невозможен: {string.Join("; ", bad)}");
            lock (_lock)
                _book.NotFound(s.Key, _now());
            return;
        }
        var ended = new TaskCompletionSource<GenevaSearchView>(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnEnded(GenevaSearchView v) => ended.TrySetResult(v);
        _controller.SearchEnded += OnEnded;
        try
        {
            AddLog(settings.Resume ? $"{s.Name}: продолжаю подбор geneva, поколений {settings.Generations}"
                : restartWide ? $"{s.Name}: подбор geneva шире: популяция {settings.Population}, слои {settings.Protos}"
                : $"{s.Name}: подбор geneva");
            await _controller.StartSearchAsync(settings, ct, _probes.Judge(s)).ConfigureAwait(false);
            GenevaSearchView view;
            try
            {
                view = await ended.Task.WaitAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await _controller.StopSearchAsync(CancellationToken.None).ConfigureAwait(false);
                throw;
            }
            if (view.Blocked == false)
            {
                string line;
                lock (_lock)
                {
                    _book.Searching(s.Key, _now());
                    line = _book.Confirmed(s.Key, AutoConfirm.NotBlocked, _now());
                }
                AddLog(line);
                return;
            }
            var best = _controller.State.Found
                .Where(f => string.Equals(f.Host, host, StringComparison.OrdinalIgnoreCase) && f.Port == s.Port && f.Fitness > 0)
                .OrderByDescending(f => f.Fitness).ThenByDescending(f => f.Runs)
                .Take(3).ToList();
            foreach (var b in best)
            {
                // what passed the search's probe from geneva's ports must pass on the service's own traffic too
                if (await TrialAsync(s, b.Strategy, ct).ConfigureAwait(false))
                {
                    Applied(s, b.Strategy, b.Fitness, "подбор geneva");
                    return;
                }
            }
            lock (_lock)
                _book.NotFound(s.Key, _now());
            AddLog($"{s.Name}: подбор не нашёл обход; продолжу позже с новыми поколениями");
        }
        finally
        {
            _controller.SearchEnded -= OnEnded;
        }
    }

    private void Applied(AutoService s, string strategy, double fitness, string how)
    {
        lock (_lock)
        {
            _book.Applied(s.Key, strategy, fitness, _now());
            _trial = null;
        }
        AddLog($"{s.Name}: обход найден ({how}) и применён только к этому трафику: {strategy}");
        Save(force: true);
    }

    /// <summary>
    /// One strategy on the service's own traffic: applied to it alone, then the probe (or, without one, the program's
    /// next flows in the coming slices).
    /// </summary>
    private async Task<bool> TrialAsync(AutoService s, string strategy, CancellationToken ct)
    {
        lock (_lock)
            _trial = (s.Key, strategy);
        Changed?.Invoke();
        var reply = await ApplyAsync(ct, force: true).ConfigureAwait(false);
        // the tried strategy itself must run: a probe while only the other groups started would judge no bypass at all
        if (reply is null || reply.Limited || !reply.Groups.Any(g => g.Requested.Contains(strategy)))
            return false;
        // the rules are in; let the next connection meet them
        await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
        AutoService current;
        lock (_lock)
            current = (_book.Find(s.Key) ?? s).Clone();
        if (current.Probeable)
            return await _probes.CheckAsync(current, ct).ConfigureAwait(false) == AutoConfirm.NotBlocked;

        var start = _now();
        var until = start + PassiveTrial;
        while (_now() < until)
        {
            await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
            lock (_lock)
            {
                var x = _book.Find(s.Key);
                if (x is null)
                    return false;
                if (x.Oks.Any(t => t >= start))
                    return true;
            }
        }
        return false;
    }

    // ---- applying

    /// <summary>
    /// Sends the groups to the Agent when they changed (or <paramref name="force"/>, or every <see cref="Refresh"/>).
    /// Returns the Agent's reply, or null when nothing was sent.
    /// </summary>
    private async Task<GenevaAutoApplyReply?> ApplyAsync(CancellationToken ct, bool force = false)
    {
        await _applyGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            List<AutoGroup> groups;
            lock (_lock)
            {
                (AutoService, string)? trial = _trial is { } t && _book.Find(t.Key) is { } ts ? (ts, t.Strategy) : null;
                groups = AutoPlan.Groups(_book.Services, trial);
            }
            var req = new GenevaAutoApplyRequest();
            foreach (var g in groups)
            {
                var pg = new GenevaAutoGroup { Strategy = g.Strategy };
                foreach (var t in g.Targets)
                {
                    var pt = new GenevaAutoTarget { TcpPorts = t.TcpPorts, UdpPorts = t.UdpPorts, ByLocalPort = t.ByLocalPort };
                    pt.Addresses.AddRange(t.Addresses.Select(a => a.ToString()));
                    pg.Targets.Add(pt);
                }
                req.Groups.Add(pg);
            }
            var json = req.ToString();
            if (!force && json == _applied && _now() - _appliedAt < Refresh)
                return null;
            var agent = await _agent(ct).ConfigureAwait(false);
            var reply = await agent.AutoApplyAsync(req, ct).ConfigureAwait(false);
            lock (_lock)
            {
                _applied = json;
                _appliedAt = _now();
                _problems = [.. reply.Problems];
                _limited = reply.Limited;
                _groups = [.. reply.Groups.Select(rg =>
                {
                    // the Agent names a group by its canonical form and lists the texts it serves
                    var names = groups.Where(x => rg.Requested.Contains(x.Strategy) || x.Strategy == rg.Strategy)
                        .SelectMany(x => x.Services).Distinct(StringComparer.Ordinal)
                        .Select(k => _book.Find(k)?.Name ?? k).ToList();
                    var old = _groups.FirstOrDefault(x => x.Id == rg.Id);
                    return new AutoGroupView { Strategy = rg.Strategy, Id = rg.Id, Queue = rg.Queue, Services = names, Stats = old?.Stats, Rate = old?.Rate ?? 0 };
                })];
            }
            foreach (var p in reply.Problems)
                AddLog(p);
            Changed?.Invoke();
            return reply;
        }
        finally
        {
            _applyGate.Release();
        }
    }

    /// <summary>The groups' counters (geneva's <c>stats</c>): the page's telemetry.</summary>
    private async Task PollStatsAsync(CancellationToken ct)
    {
        List<AutoGroupView> groups;
        lock (_lock)
            groups = [.. _groups];
        if (groups.Count == 0)
            return;
        var agent = await _agent(ct).ConfigureAwait(false);
        var updated = new List<AutoGroupView>();
        foreach (var g in groups)
        {
            try
            {
                var r = await agent.ControlAsync(g.Id, "stats", null, ct).ConfigureAwait(false);
                if (!r.Ok || JsonNode.Parse(r.Json) is not JsonObject o)
                {
                    updated.Add(g);
                    continue;
                }
                var st = GenevaStats.From(new GenevaEvent("stats", 0, o));
                double rate = 0;
                if (_prevStats.TryGetValue(g.Id, out var prev) && st.UptimeMs > prev.Uptime)
                    rate = Math.Max(0, st.PktsOut + st.PktsIn - prev.Packets) * 1000.0 / (st.UptimeMs - prev.Uptime);
                _prevStats[g.Id] = (st.PktsOut + st.PktsIn, st.UptimeMs);
                updated.Add(g with { Stats = st, Rate = rate });
            }
            catch (Exception e) when (e is GenevaRefusedException or Grpc.Core.RpcException or JsonException)
            {
                updated.Add(g);
            }
        }
        lock (_lock)
        {
            // a group replaced meanwhile keeps its new form
            _groups = [.. _groups.Select(g => updated.FirstOrDefault(u => u.Id == g.Id) ?? g)];
        }
    }

    // ---- saving

    /// <summary>Saves the book: at once with <paramref name="force"/>, else at most once a minute.</summary>
    private void Save(bool? enabled = null, bool force = false)
    {
        GenevaAutoState state;
        lock (_lock)
        {
            if (!force && _now() - _savedAt < TimeSpan.FromMinutes(1))
                return;
            state = new GenevaAutoState { Enabled = enabled ?? Enabled, Services = GenevaAutoState.Trimmed(_book.Services) };
            _savedAt = _now();
        }
        _controller.SaveAuto(state);
    }

    public async ValueTask DisposeAsync()
    {
        // the Agent stops the groups when the UI goes; this only ends the loop and saves where it was
        CancellationTokenSource? cts;
        Task? loop, work;
        lock (_lock)
            (cts, loop, work) = (_loopCts, _loop, _work);
        if (cts is not null)
        {
            await cts.CancelAsync().ConfigureAwait(false);
            foreach (var t in new[] { work, loop })
            {
                if (t is not null)
                    await Task.WhenAny(t, Task.Delay(TimeSpan.FromSeconds(3))).ConfigureAwait(false);
            }
            lock (_lock)
            {
                foreach (var s in _book.Services.Where(s => s.Status == AutoStatus.Searching).ToList())
                    _book.Interrupted(s.Key, _now());
            }
            Save(force: true);
            cts.Dispose();
        }
        _gate.Dispose();
        _applyGate.Dispose();
    }
}
