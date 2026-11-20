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

    /// <summary>The name-based process (geneva_c 2.0): its strategies, one per line, apply to the sites by name.</summary>
    public bool ByName { get; init; }

    /// <summary>Only a strategy being tried on one service: not a working one yet, the page does not list it.</summary>
    public bool Trial { get; init; }
}

/// <summary>One service the "Авто" mode searches now, and the strategy it tries on the service's traffic.</summary>
public sealed record AutoSearchView(string Key, string Name, string? Trying);

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

    /// <summary>The service a strategy is being found for now, and the strategy being tried (the first of <see cref="Searches"/>).</summary>
    public string? Current { get; init; }

    public string? Trying { get; init; }

    /// <summary>Every service being searched now (several when the workers are split between services).</summary>
    public IReadOnlyList<AutoSearchView> Searches { get; init; } = [];

    public IReadOnlyList<string> Problems { get; init; } = [];

    /// <summary>Site strategies are applied by name too (geneva_c 2.0 runs the name-based process).</summary>
    public bool ByName { get; init; }

    /// <summary>geneva_c knows x-actions: zapret2's methods are tried.</summary>
    public bool Ext { get; init; }

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

    /// <summary>The services searched (or tried with the user's strategy) now, by key: one, or several side by side.</summary>
    private readonly Dictionary<string, SearchWork> _works = new(StringComparer.Ordinal);
    private bool _byName;
    private bool _ext;
    private bool _hostUp;

    /// <summary>The trials whose family went to the name-based process with the last apply: service key → domains.</summary>
    private Dictionary<string, IReadOnlyList<string>> _relatedSent = new(StringComparer.Ordinal);
    private string? _observerId;
    private IReadOnlyList<string> _blobs = [];
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

    /// <summary>One service's search: its task, how to interrupt it, and the strategy tried on its traffic now.</summary>
    private sealed class SearchWork(string key, string name, CancellationTokenSource? cts)
    {
        public string Key { get; } = key;

        public string Name { get; } = name;

        /// <summary>Interrupts the search (a more important service, the lists); null: the user's own trial, never interrupted.</summary>
        public CancellationTokenSource? Cts { get; } = cts;

        public Task Task { get; set; } = Task.CompletedTask;

        public string? Trying { get; set; }

        /// <summary>The browser checks <see cref="Trying"/>: it also goes by name to the site's family (<see cref="AutoPlan.TrialFamilies"/>).</summary>
        public bool Related { get; set; }
    }

    private void SetTrying(string key, string? strategy)
    {
        lock (_lock)
        {
            if (_works.TryGetValue(key, out var w))
                w.Trying = strategy;
        }
    }

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
        _book.SetLists(controller.State.Lists);
        controller.AutoRunning = () => Running;
        controller.ListsChanged += OnListsChanged;
    }

    /// <summary>The user changed the lists: priorities again, excluded services leave, the groups follow.</summary>
    private void OnListsChanged()
    {
        List<string> gone, skipped;
        List<CancellationTokenSource> stops;
        lock (_lock)
        {
            gone = _book.SetLists(_controller.State.Lists, out skipped);
            // a service searched now is no longer wanted: its search stops (geneva keeps its progress)
            stops = [.. _works.Values.Where(w => w.Cts is not null && (_book.Find(w.Key) is not { } cur || _book.NotSearched(cur))).Select(w => w.Cts!)];
        }
        foreach (var name in gone)
            AddLog($"{name}: в списке «не трогать», обход к нему больше не применяется / on the \"do not touch\" list, no bypass for it any more");
        foreach (var name in skipped)
            AddLog($"{name}: в списке «не подбирать», убран из списка проблем / on the \"do not search\" list, removed from the problems");
        foreach (var stop in stops)
        {
            try
            {
                stop.Cancel();
            }
            catch (ObjectDisposedException)
            {
            }
        }
        Save(force: true);
        CancellationToken loop;
        lock (_lock)
            loop = _loopCts?.Token ?? new CancellationToken(canceled: true);
        // with the loop's token: a mode turned off meanwhile is not brought back by this apply
        if (Running && !loop.IsCancellationRequested)
            _ = Task.Run(async () =>
            {
                try
                {
                    await ApplyAsync(loop, force: true).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
                catch (Exception e) when (e is GenevaRefusedException or Grpc.Core.RpcException or IOException or InvalidOperationException)
                {
                    AddLog("Группы не применились / groups not applied: " + e.Message);
                }
            }, CancellationToken.None);
        Changed?.Invoke();
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

    /// <summary>
    /// zapret2's blockcheck2 grid as geneva strategies (geneva_c 2.0): a spread slice of the test's grid (<c>tls12</c>,
    /// <c>http</c> or <c>http3</c>); the round number moves the slice, so each wider round tries lines the earlier ones
    /// did not. The wider round tries it after Geneva's library. Null: without it.
    /// </summary>
    public Func<string, int, CancellationToken, Task<IReadOnlyList<string>>>? Grid { get; init; }


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

    /// <summary>What the loop is doing now, in Russian and English: the cheap part of <see cref="View"/> (the tray).</summary>
    public (string Ru, string En) CurrentPhase
    {
        get
        {
            lock (_lock)
                return _phase;
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
                    Current = _works.Values.FirstOrDefault()?.Name,
                    Trying = _works.Values.FirstOrDefault()?.Trying,
                    Searches = [.. _works.Values.Select(w => new AutoSearchView(w.Key, w.Name, w.Trying))],
                    Problems = [.. _problems],
                    Limited = _limited,
                    ByName = _byName && _controller.ByName,
                    Ext = _ext,
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
            if (_controller.UserSearchRunning)
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
            // under the apply gate: an apply already on its way finishes first, one still waiting sees the loop's
            // cancelled token, so nothing starts the groups again after this
            await _applyGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var agent = await _agent(ct).ConfigureAwait(false);
                await agent.AutoApplyAsync(new GenevaAutoApplyRequest(), ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is GenevaRefusedException or Grpc.Core.RpcException or IOException or InvalidOperationException)
            {
                AddLog("Не удалось остановить группы / could not stop the groups: " + e.Message);
            }
            finally
            {
                _applyGate.Release();
            }
            lock (_lock)
            {
                _groups = [];
                _applied = "";
                _works.Clear();
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

    /// <summary>The user's "Проверить сейчас": the probe (or, for an applied service, the check with its bypass) at once.</summary>
    public void CheckNow(string key)
    {
        string line;
        lock (_lock)
            line = _book.CheckNow(key, _now());
        AddLog(line);
        Save(force: true);
        Changed?.Invoke();
    }

    /// <summary>Pins or unpins the applied strategy of a service; false when it has none.</summary>
    public bool Pin(string key, bool pinned)
    {
        bool ok;
        string name;
        lock (_lock)
        {
            ok = _book.Pin(key, pinned);
            name = _book.Find(key)?.Name ?? key;
        }
        if (ok)
            AddLog(pinned ? $"{name}: стратегия закреплена" : $"{name}: закрепление снято");
        Save(force: true);
        Changed?.Invoke();
        return ok;
    }

    /// <summary>The user's word about a service's importance.</summary>
    public bool SetPriority(string key, AutoUserPriority p)
    {
        bool ok;
        lock (_lock)
            ok = _book.SetUserPriority(key, p);
        Save(force: true);
        Changed?.Invoke();
        return ok;
    }

    /// <summary>
    /// Tries the user's own strategy on a service's traffic now (the same trial as a found one: applied to it alone,
    /// the probe twice and the browser's handshakes). Works: applied and pinned. Throws <see cref="GenevaRefusedException"/>
    /// while a search runs, when the mode is off or the text is no strategy.
    /// </summary>
    public async Task<bool> TryStrategyAsync(string key, string strategy, CancellationToken ct)
    {
        strategy = strategy.Trim();
        if (GenevaStrategyText.Problem(strategy) is { } bad)
            throw new GenevaRefusedException(bad);
        if (!Running)
            throw new GenevaRefusedException("режим «Авто» выключен / the \"Auto\" mode is off");
        AutoService s;
        TaskCompletionSource<bool> done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_lock)
        {
            if (_works.ContainsKey(key) || _works.Count >= SearchSlots())
                throw new GenevaRefusedException("идёт подбор: попробуйте после него / a search is running, try after it");
            if (_book.Find(key) is not { } found)
                throw new GenevaRefusedException("нет такого сервиса / no such service");
            // a service sharing an address with one searched now would meet its trials' groups
            if (_works.Keys.Select(_book.Find).Any(b => b is not null && AutoBook.Overlap(found, b)))
                throw new GenevaRefusedException("идёт подбор для сервиса на тех же адресах: попробуйте после него / a service on the same addresses is being searched, try after it");
            if (!AutoCandidates.Fits(found, strategy))
                throw new GenevaRefusedException("стратегия не для этого транспорта (TCP/UDP) / the strategy does not fit the transport");
            // only where the probe without a bypass saw the block (AGENTS.md rule 5): a service that opens anyway would
            // pass any strategy, and the pin would keep it there for good
            if (found.Status is not (AutoStatus.Blocked or AutoStatus.NotFound or AutoStatus.Degraded or AutoStatus.Applied))
                throw new GenevaRefusedException("блокировка не подтверждена: сначала «Проверить сейчас» / the block is not confirmed: use \"Check now\" first");
            s = found.Clone();
            var work = new SearchWork(s.Key, s.Name, null);
            _works[s.Key] = work;
            var token = _loopCts?.Token ?? ct;
            work.Task = Task.Run(async () =>
            {
                bool ok = false;
                try
                {
                    AddLog($"{s.Name}: пробую стратегию пользователя: {strategy}");
                    ok = await TrialAsync(s, strategy, token).ConfigureAwait(false);
                    if (ok)
                    {
                        Applied(s, strategy, 400, "стратегия пользователя");
                        lock (_lock)
                            _book.Pin(s.Key, true);
                    }
                    else
                    {
                        AddLog($"{s.Name}: стратегия пользователя не прошла проверку");
                    }
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    AddLog($"{s.Name}: ошибка проверки / check error: {e.Message}");
                }
                catch (OperationCanceledException)
                {
                }
                finally
                {
                    lock (_lock)
                    {
                        if (_works.GetValueOrDefault(s.Key) == work)
                            _works.Remove(s.Key);
                    }
                    if (!token.IsCancellationRequested)
                    {
                        try
                        {
                            await ApplyAsync(token, force: true).ConfigureAwait(false);
                        }
                        catch (Exception e) when (e is OperationCanceledException or GenevaRefusedException or Grpc.Core.RpcException or IOException or InvalidOperationException)
                        {
                        }
                    }
                    Save(force: true);
                    Changed?.Invoke();
                    done.TrySetResult(ok);
                }
            }, CancellationToken.None);
        }
        return await done.Task.WaitAsync(ct).ConfigureAwait(false);
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
        Task? loop;
        List<Task> works;
        lock (_lock)
            (cts, loop, works) = (_loopCts, _loop, [.. _works.Values.Select(w => w.Task)]);
        if (cts is null)
            return;
        await cts.CancelAsync().ConfigureAwait(false);
        // the searches side by side stop together
        await Task.WhenAny(Task.WhenAll(works), Task.Delay(TimeSpan.FromSeconds(30))).ConfigureAwait(false);
        if (loop is not null)
            await Task.WhenAny(loop, Task.Delay(TimeSpan.FromSeconds(30))).ConfigureAwait(false);
        lock (_lock)
        {
            foreach (var s in _book.Services.Where(s => s.Status == AutoStatus.Searching).ToList())
                _book.Interrupted(s.Key, _now());
            _loopCts = null;
            _loop = null;
            _works.Clear();
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
                string? names;
                lock (_lock)
                    names = _works.Count == 0 ? null : string.Join(", ", _works.Values.Select(w => w.Name));
                Phase(names is null ? "наблюдаю за трафиком" : $"подбираю обход: {names}", names is null ? "watching the traffic" : $"searching: {names}");
                await SliceAsync(ct).ConfigureAwait(false);
                await ConfirmAsync(ct).ConfigureAwait(false);
                PreemptIfNeeded();
                StartSearchIfDue(ct);
                await ApplyAsync(ct).ConfigureAwait(false);
                await PollStatsAsync(ct).ConfigureAwait(false);
                await PollDetectorAsync(ct).ConfigureAwait(false);
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
        // with the bypass on, the browser's own handshakes must get through as well: the page load alone passed while
        // the browser kept failing (issue 28)
        if (s.Status == AutoStatus.Degraded && result == AutoConfirm.NotBlocked && !await _probes.HandshakesAsync(s, ct).ConfigureAwait(false))
            result = AutoConfirm.Blocked;
        string line;
        string? tightened = null;
        lock (_lock)
        {
            // the probe learned what the page must show (a shaper, the 16 KB cut-off): the search judges by it
            if (s.Criteria is { } learned && _book.Find(s.Key) is { } kept && kept.Criteria != learned)
            {
                kept.Criteria = learned;
                if (learned != Core.Diagnostics.ProbeCriteria.Default)
                    tightened = $"{s.Name}: страница открывается не вся или медленно (шейпер, обрыв 16 КБ) — успех теперь: {learned}";
            }
            line = _book.Confirmed(s.Key, result, _now());
        }
        if (tightened is not null)
            AddLog(tightened);
        AddLog(line);
        if (s.Status == AutoStatus.Degraded && result != AutoConfirm.NotBlocked)
            await ApplyAsync(ct, force: true).ConfigureAwait(false);
        Save(force: true);
    }

    /// <summary>
    /// A more important service became blocked while a less important one is searched (issue 28): that search stops
    /// and goes back to the queue; geneva's checkpoint keeps its progress, and it continues later.
    /// </summary>
    private void PreemptIfNeeded()
    {
        List<CancellationTokenSource> stop;
        string line;
        lock (_lock)
        {
            var now = _now();
            if (_book.NextToSearch(now) is not { } next || next.Priority == AutoPriority.Background)
                return;
            var rank = AutoPriorities.Effective(next, now);
            var running = _works.Values.Select(w => (Work: w, Service: _book.Find(w.Key)!)).Where(x => x.Service is not null).ToList();
            // the searches on its addresses keep it from starting even in a free slot: they give way if all are less
            // important (the user's own trial never does)
            var blockers = running.Where(x => AutoBook.Overlap(next, x.Service)).ToList();
            List<(SearchWork Work, AutoService Service)> victims;
            if (blockers.Count > 0)
            {
                if (blockers.Any(x => x.Work.Cts is null || AutoPriorities.Effective(x.Service, now) <= rank))
                    return;
                victims = blockers;
            }
            else
            {
                // a free slot takes it without stopping anything; else the least important search gives way
                if (_works.Count < SearchSlots())
                    return;
                var least = running.Where(x => x.Work.Cts is not null).OrderByDescending(x => AutoPriorities.Effective(x.Service, now)).FirstOrDefault();
                if (least.Work is null || AutoPriorities.Effective(least.Service, now) <= rank)
                    return;
                victims = [least];
            }
            stop = [.. victims.Select(x => x.Work.Cts!)];
            var names = string.Join(", ", victims.Select(x => x.Work.Name));
            line = $"Прерываю подбор для {names} ради более важного: {next.Name} (продолжу позже) / pausing the search for {names} for a more important {next.Name} (to go on later)";
        }
        AddLog(line);
        foreach (var cts in stop)
        {
            try
            {
                cts.Cancel();
            }
            catch (ObjectDisposedException)
            {
            }
        }
    }

    /// <summary>
    /// Searches side by side now (under the lock): the setting's, but each needs a group of its own for its trials,
    /// and the working strategies keep theirs (<see cref="AutoRules.MaxGroups"/>).
    /// </summary>
    private int SearchSlots()
    {
        int applied = _groups.Count(g => !g.Trial && !g.ByName);
        return Math.Max(1, Math.Min(_controller.AutoSearches, AutoRules.MaxGroups - applied));
    }

    /// <summary>
    /// Starts the searches due while there are free slots (<see cref="GenevaController.AutoSearches"/>): the most
    /// important blocked services first, never two that share an address (<see cref="AutoBook.Overlap"/>).
    /// </summary>
    private void StartSearchIfDue(CancellationToken ct)
    {
        lock (_lock)
        {
            int slots = SearchSlots();
            while (_works.Count < slots)
            {
                // the user's own search on the page goes alone: wait for it
                if (_controller.UserSearchRunning)
                    return;
                var busy = _works.Keys.Select(k => _book.Find(k)).Where(x => x is not null).Select(x => x!).ToList();
                var s = _book.NextToSearch(_now(), x => !busy.Any(b => AutoBook.Overlap(x, b)));
                if (s is null)
                    return;
                bool fresh = s.BaselineAt is { } b && _now() - b < BaselineFresh;
                _book.Searching(s.Key, _now());
                s = s.Clone();
                var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var work = new SearchWork(s.Key, s.Name, cts);
                _works[s.Key] = work;
                work.Task = Task.Run(() => SearchAsync(s, work, ct, fresh));
            }
        }
    }

    // ---- finding a strategy for one service

    private async Task SearchAsync(AutoService s, SearchWork work, CancellationToken loop, bool fresh = true)
    {
        var search = work.Cts!;
        var ct = search.Token;
        try
        {
            if (!fresh && await OpensNowAsync(s, ct).ConfigureAwait(false))
                return;
            await FindAsync(s, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // interrupted for a more important service (the loop itself goes on): back to the queue
            if (!loop.IsCancellationRequested)
            {
                lock (_lock)
                    _book.Interrupted(s.Key, _now());
            }
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
                if (_works.GetValueOrDefault(s.Key) == work)
                    _works.Remove(s.Key);
            }
            search.Dispose();
            // the mode going off (or the program closing) stops the groups itself: applying them here could start them
            // again after it did
            if (!loop.IsCancellationRequested)
            {
                try
                {
                    await ApplyAsync(loop, force: true).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (loop.IsCancellationRequested)
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

    /// <summary>
    /// The probe without a bypass before a search whose block was seen long ago (a retry after hours, a search
    /// continued after a restart, a bypass that stopped working): a service that opens now is not searched, and one
    /// blocked by address is left to a tunnel. True when the search is not needed.
    /// </summary>
    private async Task<bool> OpensNowAsync(AutoService s, CancellationToken ct)
    {
        if (!s.Probeable)
            return false;
        var probe = s.Clone();
        probe.Status = AutoStatus.Suspected;
        var result = await _probes.CheckAsync(probe, ct).ConfigureAwait(false);
        // no probe could judge it (no address yet): the search goes on as before, without a new baseline mark
        if (result == AutoConfirm.Unknown)
            return false;
        if (result == AutoConfirm.Blocked)
        {
            s.Criteria = probe.Criteria;
            lock (_lock)
            {
                if (_book.Find(s.Key) is { } kept)
                {
                    kept.BaselineAt = _now();
                    kept.Criteria = probe.Criteria;
                }
            }
            return false;
        }
        string line;
        lock (_lock)
            line = _book.Confirmed(s.Key, result, _now());
        AddLog(line);
        return true;
    }

    /// <summary>How long a "blocked" from the probe without a bypass holds before a search looks again.</summary>
    public TimeSpan BaselineFresh { get; init; } = TimeSpan.FromMinutes(5);

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
        bool ext;
        lock (_lock)
            ext = _ext;
        // zapret2's whole method grid (geneva_c 2.0) for sites and QUIC after everything else: a slice of it each round,
        // tried on the service but not a seed of the search (the search has the methods themselves among its seeds)
        IReadOnlyList<string> gridSlice = [];
        if (wide && ext && Grid is { } grid && (s.Kind is AutoKind.Web or AutoKind.Quic))
        {
            try
            {
                // a site seen only on port 80 is plain HTTP (tls13's grid is a part of tls12's); the round moves the
                // slice over the whole grid
                var test = s.Kind == AutoKind.Quic ? "http3" : s.Ports.Count > 0 && !s.Ports.Contains(443) && s.Ports.Contains(80) ? "http" : "tls12";
                gridSlice = await grid(test, s.Attempts - AutoRules.WideAfter, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is InvalidOperationException or IOException or FormatException or System.ComponentModel.Win32Exception)
            {
                AddLog($"{s.Name}: сетка blockcheck недоступна / the blockcheck grid is unavailable: {e.Message}");
            }
        }
        List<string> candidates, seeds;
        lock (_lock)
        {
            var state = _controller.State;
            var running = _groups.Select(g => g.Strategy).ToList();
            var found = state.Found.Where(f => f.Fitness > 0).Select(f => f.Strategy)
                .Concat(_book.Services.Where(x => x.Strategy is not null).Select(x => x.Strategy!));
            var family = _book.FamilyStrategy(s);
            candidates = AutoCandidates.For(s, running, found, state.Shared(), library, wide ? AutoRules.MaxWideCandidates : AutoRules.MaxQuickCandidates, family, ext, wide, _blobs, s.Attempts - AutoRules.WideAfter);
            seeds = [.. candidates];
            // the grid's lines pass the same checks as every other candidate (rule 4)
            candidates = [.. candidates, .. gridSlice.Where(g => AutoCandidates.Fits(s, g) && GenevaStrategyText.Problem(g) is null && !candidates.Contains(g, StringComparer.Ordinal))];
            if (family is not null)
                AddLog($"{s.Name}: сначала стратегия того же сервиса ({AutoFamilies.Of(s)})");
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
        SetTrying(s.Key, null);
        await ApplyAsync(ct, force: true).ConfigureAwait(false);

        if (!s.Probeable)
        {
            // WireGuard, DHT: no probe can stand in for the program, and a search would need hundreds of its retries
            lock (_lock)
                _book.NotFound(s.Key, _now());
            AddLog($"{s.Name}: известные стратегии не помогли; повторю позже");
            return;
        }
        await EvolveAsync(s, [.. seeds.Where(c => ext || !GenevaStrategyText.NeedsExt(c))], wide, ct).ConfigureAwait(false);
    }

    /// <summary>geneva's search for the service, continued from its checkpoint when there is one.</summary>
    private async Task EvolveAsync(AutoService s, List<string> seeds, bool wide, CancellationToken ct)
    {
        bool web = s.Kind == AutoKind.Web;
        var host = web ? (s.Host.Length > 0 ? s.Host : s.Name) : s.Address?.ToString() ?? "";
        var saved = _controller.State.ProgressOf(host, s.Port);
        int workers = _controller.AutoWorkers;
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
                Workers = workers,
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
                Workers = workers,
                Criteria = s.Criteria ?? Core.Diagnostics.ProbeCriteria.Default,
            };
        if (settings.Problems() is { Count: > 0 } bad)
        {
            AddLog($"{s.Name}: подбор невозможен: {string.Join("; ", bad)}");
            lock (_lock)
                _book.NotFound(s.Key, _now());
            return;
        }
        var ended = new TaskCompletionSource<GenevaSearchView>(TaskCreationOptions.RunContinuationsAsynchronously);
        var since = DateTimeOffset.Now;
        void OnEnded(GenevaSearchView v)
        {
            // only this search's end: another one (a manual search just finishing) may end after this subscribed
            if (string.Equals(v.Host, host, StringComparison.OrdinalIgnoreCase) && v.Port == s.Port && v.Started >= since)
                ended.TrySetResult(v);
        }
        _controller.SearchEnded += OnEnded;
        try
        {
            AddLog(settings.Resume ? $"{s.Name}: продолжаю подбор geneva, поколений {settings.Generations}"
                : restartWide ? $"{s.Name}: подбор geneva шире: популяция {settings.Population}, слои {settings.Protos}"
                : $"{s.Name}: подбор geneva");
            var id = await _controller.StartSearchAsync(settings, ct, _probes.Judge(s), auto: true).ConfigureAwait(false);
            GenevaSearchView view;
            try
            {
                view = await ended.Task.WaitAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // only this service's search: the others side by side go on
                await _controller.StopSearchAsync(id, CancellationToken.None).ConfigureAwait(false);
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
            if (view.Stopped)
            {
                // stopped from outside (the program closing, the Agent): not searched through, so not "nothing found"
                lock (_lock)
                    _book.Interrupted(s.Key, _now());
                AddLog($"{s.Name}: подбор остановлен; продолжу позже с того же места / the search was stopped; it continues later from the same point");
                return;
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
            if (_works.TryGetValue(s.Key, out var w))
                w.Trying = null;
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
        SetTrying(s.Key, strategy);
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
            return await _probes.WorksAsync(current, ct).ConfigureAwait(false) && await OpensInBrowserAsync(current, strategy, ct).ConfigureAwait(false);

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

    /// <summary>
    /// "Итоговая проверка в браузере" for a site: with the tried strategy applied to the service's addresses, the
    /// program's own browser opens the page at the address the service was seen at (the name pinned to it, HTTP/3 off:
    /// the strategy is for TCP). True when it opened, the switch is off, there is no browser or the service is not a
    /// site.
    /// </summary>
    private async Task<bool> OpensInBrowserAsync(AutoService s, string strategy, CancellationToken ct)
    {
        if (s.Kind != AutoKind.Web || s.Address is not { } address || s.Port is not (80 or 443) || _controller.BrowserNow is not { } browser)
            return true;
        var host = s.Host.Length > 0 ? s.Host : s.Name;
        // the page's related resources (YouTube's googlevideo.com, ytimg.com) go through the tried strategy by name for
        // the check, as they will once it is applied; without the name-based process only the site itself is judged
        IReadOnlyList<string> related = [];
        bool marked = false;
        lock (_lock)
        {
            if (_controller.ByName && _byName && _works.TryGetValue(s.Key, out var w))
                marked = w.Related = true;
        }
        try
        {
            if (marked)
            {
                await ApplyAsync(ct, force: true).ConfigureAwait(false);
                lock (_lock)
                    related = _relatedSent.TryGetValue(s.Key, out var d) ? d : [];
                // a new strategy restarts the name-based process: let it take the next connections first
                if (related.Count > 0)
                    await Task.Delay(RelatedSettle, ct).ConfigureAwait(false);
            }
            var verdict = await GenevaBrowserCheck.RunAsync(browser.Open, host, s.Port, s.Port == 443, address, ct,
                h => related.Any(d => GenevaBrowserCheck.Under(h, d))).ConfigureAwait(false);
            // no browser any more, or a root it does not know: the probes' verdict stands, as without the switch
            if (verdict is not { Ok: { } ok } v)
                return true;
            if (!ok)
            {
                AddLog(v.SiteOpened
                    ? $"{s.Name}: сайт открылся во встроенном браузере, но не загрузились связанные ресурсы ({v.Detail}) — пробую дальше / the site opened in the program's browser, but its related resources did not load, trying on: {strategy}"
                    : $"{s.Name}: стратегия прошла проверки, но сайт не открылся во встроенном браузере ({v.Detail}) — пробую дальше / the strategy passed the probes, but the site did not open in the program's browser, trying on: {strategy}");
            }
            else if (v.RelatedOk.Count > 0)
                AddLog($"{s.Name}: во встроенном браузере открылись сайт и связанные ресурсы: {string.Join(", ", v.RelatedOk)} / the site and its related resources opened in the program's browser");
            if (v.NotCovered.Count > 0)
                AddLog($"{s.Name}: на странице не грузятся и другие ресурсы, у них своя блокировка: {string.Join(", ", v.NotCovered)} / other resources of the page fail too, a block of their own");
            return ok;
        }
        finally
        {
            if (marked)
            {
                lock (_lock)
                {
                    if (_works.TryGetValue(s.Key, out var w))
                        w.Related = false;
                }
            }
        }
    }

    /// <summary>The pause after the family went to the name-based process (it restarts) before the browser opens the page.</summary>
    public TimeSpan RelatedSettle { get; init; } = TimeSpan.FromSeconds(2);

    // ---- applying

    /// <summary>
    /// Sends the groups to the Agent when they changed (or <paramref name="force"/>, or every <see cref="Refresh"/>).
    /// Returns the Agent's reply, or null when nothing was sent.
    /// </summary>
    private async Task<GenevaAutoApplyReply?> ApplyAsync(CancellationToken ct, bool force = false)
    {
        var (reply, again) = await ApplyOnceAsync(ct, force).ConfigureAwait(false);
        // the first answer told what this geneva_c can do (by name, x-actions): the plan differs, it goes again
        return again ? (await ApplyOnceAsync(ct, force: true).ConfigureAwait(false)).Reply : reply;
    }

    private async Task<(GenevaAutoApplyReply? Reply, bool Again)> ApplyOnceAsync(CancellationToken ct, bool force)
    {
        bool again = false;
        await _applyGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ct.ThrowIfCancellationRequested();
            List<AutoGroup> groups;
            List<AutoHostProfile> hosts;
            AutoNameList excluded;
            HashSet<string> trialKeys;
            Dictionary<string, IReadOnlyList<string>> relatedNow;
            bool byName = _controller.ByName;
            lock (_lock)
            {
                List<(AutoService, string)> trials = [.. _works.Values
                    .Where(w => w.Trying is not null && _book.Find(w.Key) is not null)
                    .Select(w => (_book.Find(w.Key)!, w.Trying!))];
                trialKeys = [.. trials.Select(t => t.Item1.Key)];
                // asked for while geneva may still say it cannot (the first apply learns it): the Agent then ignores them
                hosts = byName ? AutoPlan.HostProfiles(_book.Services, trialKeys, quic: true) : [];
                // a trial the browser checks: its family by name too, unless that would push an applied profile out
                var related = byName ? AutoPlan.TrialFamilies(_book.Services,
                    trials.Where(t => _works.TryGetValue(t.Item1.Key, out var w) && w.Related), hosts) : [];
                if (hosts.Count + related.Count > AutoRules.MaxHostProfiles)
                    related = [];
                relatedNow = related.ToDictionary(r => r.Key, r => r.Profile.Domains, StringComparer.Ordinal);
                // after the applied ones: a name both match stays with the applied profile (the first match wins)
                hosts = [.. hosts, .. related.Select(r => r.Profile)];
                // shared addresses go to the names only once the name-based process runs: until then (or if it failed)
                // the address groups keep every site's traffic
                var covered = byName && _byName && _hostUp ? AutoPlan.ByNameCovers(_book.Services, hosts) : null;
                groups = AutoPlan.Groups(_book.Services, trials, covered);
                excluded = _book.Excluded;
            }
            // geneva's detector beside the groups (geneva_c 2.0, ext_auto): a shaper and a freeze the slices miss
            var req = new GenevaAutoApplyRequest { Observe = true };
            foreach (var h in hosts)
            {
                var ph = new GenevaAutoHost { Strategy = h.Strategy, Udp = h.Udp };
                ph.Domains.AddRange(h.Domains);
                req.Hosts.Add(ph);
            }
            req.ExcludeSubnets.AddRange(excluded.Subnets);
            req.ExcludeDomains.AddRange(excluded.Domains);
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
                return (null, false);
            var agent = await _agent(ct).ConfigureAwait(false);
            var reply = await agent.AutoApplyAsync(req, ct).ConfigureAwait(false);
            bool learned;
            lock (_lock)
            {
                // the first answer tells what this geneva_c can do: a change means the plan differs, so it goes again
                learned = _byName != reply.ByName || _ext != reply.Ext || _hostUp != (reply.Host is not null);
                _hostUp = reply.Host is not null;
                _relatedSent = _hostUp ? relatedNow : new(StringComparer.Ordinal);
                _book.ByName = _hostUp ? AutoPlan.ByNameCovers(_book.Services, hosts) : new HashSet<string>();
                _observerId = reply.Observer?.Id;
                _byName = reply.ByName;
                _ext = reply.Ext;
                // the fakes the Agent really loads: a candidate never names one geneva does not have
                _blobs = [.. reply.Blobs];
                _applied = json;
                _appliedAt = _now();
                _problems = [.. reply.Problems];
                _limited = reply.Limited;
                _groups = [.. reply.Groups.Select(rg =>
                {
                    // the Agent names a group by its canonical form and lists the texts it serves
                    var keys = groups.Where(x => rg.Requested.Contains(x.Strategy) || x.Strategy == rg.Strategy)
                        .SelectMany(x => x.Services).Distinct(StringComparer.Ordinal).ToList();
                    // a service on trial is not served yet: its strategy is only being checked
                    var names = keys.Where(k => !trialKeys.Contains(k)).Select(k => _book.Find(k)?.Name ?? k).ToList();
                    var old = _groups.FirstOrDefault(x => x.Id == rg.Id);
                    return new AutoGroupView
                    {
                        Strategy = rg.Strategy, Id = rg.Id, Queue = rg.Queue, Services = names, Stats = old?.Stats, Rate = old?.Rate ?? 0,
                        Trial = keys.Any(trialKeys.Contains) && names.Count == 0,
                    };
                })];
                if (reply.Host is { } rh)
                {
                    var names = hosts.SelectMany(h => h.Services).Distinct(StringComparer.Ordinal).Select(k => _book.Find(k)?.Name ?? k)
                        .Concat(hosts.SelectMany(h => h.Domains).Where(d => _book.Services.All(x => AutoFamilies.SiteOf(x) != d)).Select(d => d + " (семейство)"))
                        .ToList();
                    var old = _groups.FirstOrDefault(x => x.Id == rh.Id);
                    _groups.Add(new AutoGroupView
                    {
                        Strategy = string.Join("\n", hosts.Select(h => h.Strategy).Distinct(StringComparer.Ordinal)),
                        Id = rh.Id,
                        Queue = rh.Queue,
                        Services = names,
                        ByName = true,
                        Stats = old?.Stats,
                        Rate = old?.Rate ?? 0,
                    });
                }
            }
            if (learned && (_byName || hosts.Count > 0))
                again = true;
            foreach (var p in reply.Problems)
                AddLog(p);
            Changed?.Invoke();
            return (reply, again);
        }
        finally
        {
            _applyGate.Release();
        }
    }

    /// <summary>
    /// geneva's detector (<c>ext_status</c>): names and addresses it holds impaired with a shaper or a freeze become
    /// suspicions (the probe without a bypass decides, <see cref="AutoBook.Detect"/>), and its link capacity feeds the
    /// shaper check of every probe (<see cref="LinkCapacity"/>).
    /// </summary>
    private async Task PollDetectorAsync(CancellationToken ct)
    {
        string? id;
        lock (_lock)
            id = _observerId;
        if (id is null)
            return;
        JsonObject? o;
        try
        {
            var agent = await _agent(ct).ConfigureAwait(false);
            var r = await agent.ControlAsync(id, "ext_status", null, ct).ConfigureAwait(false);
            o = r.Ok ? JsonNode.Parse(r.Json) as JsonObject : null;
        }
        catch (Exception e) when (e is GenevaRefusedException or Grpc.Core.RpcException or JsonException)
        {
            return;
        }
        if (o is null)
            return;
        foreach (var line in Detected(o, _book, _lock, _now()))
            AddLog(line);
    }

    /// <summary>Feeds an <c>ext_status</c> answer into the book; returns the log lines.</summary>
    internal static List<string> Detected(JsonObject status, AutoBook book, Lock gate, DateTime now)
    {
        var log = new List<string>();
        if (status["capacity"] is JsonValue cv && cv.TryGetValue(out double capacity) && capacity > 0)
            Core.Diagnostics.LinkCapacity.Shared.Observe(capacity);
        if (status["impaired"] is not JsonArray impaired)
            return log;
        lock (gate)
        {
            foreach (var k in impaired.OfType<JsonObject>())
            {
                if ((bool?)k["impaired"] == false)
                    continue;
                if ((string?)k["class"] == "DNS_POISON" && (string?)k["level"] == "host")
                {
                    if (book.DnsPoisoned((string?)k["key"] ?? "", now))
                        log.Add($"Детектор geneva: DNS подменяет ответ для {(string?)k["key"]} — стратегия тут не поможет, включите DoH (DNS через HTTPS) в браузере или системе / geneva's detector: DNS answers for {(string?)k["key"]} are forged — no strategy helps, turn on DoH (DNS over HTTPS) in the browser or the system");
                    continue;
                }
                var hit = book.Detect((string?)k["level"] ?? "", (string?)k["key"] ?? "", (string?)k["class"] ?? "", now);
                if (hit.Count > 0)
                    log.Add($"Детектор geneva: {(string?)k["key"]} — {(string?)k["class"]}: проверяю {string.Join(", ", hit)} / geneva's detector: {(string?)k["key"]} — {(string?)k["class"]}: checking {string.Join(", ", hit)}");
            }
        }
        return log;
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
        _controller.ListsChanged -= OnListsChanged;
        // the Agent stops the groups when the UI goes; this only ends the loop and saves where it was
        CancellationTokenSource? cts;
        Task? loop;
        List<Task> works;
        lock (_lock)
            (cts, loop, works) = (_loopCts, _loop, [.. _works.Values.Select(w => w.Task)]);
        if (cts is not null)
        {
            await cts.CancelAsync().ConfigureAwait(false);
            await Task.WhenAny(Task.WhenAll(works), Task.Delay(TimeSpan.FromSeconds(3))).ConfigureAwait(false);
            if (loop is not null)
                await Task.WhenAny(loop, Task.Delay(TimeSpan.FromSeconds(3))).ConfigureAwait(false);
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
