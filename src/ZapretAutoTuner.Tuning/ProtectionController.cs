using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Monitor;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning;

/// <summary>
/// "Защита активна" with its repairs (PLAN 7.1–7.5), apart from the UI: owns the running solution, the engine instance
/// and its queue, and serialises every change of them. A repair takes the domain out of the protection (so the probes
/// see the bare block), runs <see cref="RepairRunner"/>, and puts the domain back unless a fix was applied; whatever
/// fails on the way, the domain does not stay without bypass. Every edit is made on the latest applied solution.
/// </summary>
public sealed class ProtectionController
{
    private readonly IEngineControl _engine;
    private readonly Func<Solution, int, (List<string> Argv, QueueRule? Queue)> _launch;
    private readonly Func<ApplyPolicy> _policy;
    private readonly RepairCoordinator _coordinator;
    private readonly SemaphoreSlim _swapGate = new(1, 1);
    private readonly SemaphoreSlim _repairGate = new(1, 1);
    private readonly HashSet<string> _queued = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _cts = new();
    private volatile bool _stopping;
    private string? _engineId;
    private int _queue = Protection.QueueNum;
    private Solution? _solution;

    /// <param name="launch">The argv and queue rule of a solution on a queue (<see cref="Protection.Launch"/>).</param>
    /// <param name="policy">Read at the moment a fix is found: the settings are the one source of truth.</param>
    public ProtectionController(IEngineControl engine, IRepairSteps steps, Func<Solution, int, (List<string> Argv, QueueRule? Queue)> launch, Func<ApplyPolicy> policy)
    {
        _engine = engine;
        _launch = launch;
        _policy = policy;
        _coordinator = new RepairCoordinator(steps, d => _solution is { } s ? Protection.CurrentOf(s, d) : null, ApplyPolicy.Ask);
        _coordinator.Journal += (d, kind, ru, en) => Journal?.Invoke(d, kind, ru, en);
    }

    /// <summary>The solution the engine runs now.</summary>
    public Solution? Solution => _solution;

    public string? EngineId => _engineId;

    /// <summary>The queue of the running instance (Linux).</summary>
    public int Queue => _queue;

    public bool Running => _engineId is not null && !_stopping;

    /// <summary>(domain, kind, reason in Russian, reason in English) for the change journal.</summary>
    public event Action<string, string, string, string>? Journal;

    /// <summary>A repair of the domain started: its probes run now.</summary>
    public event Action<string>? Repairing;

    /// <summary>A repair ended without being applied: the UI offers a Replaced or BlockLifted result to the user.</summary>
    public event Action<RepairResult>? Finished;

    /// <summary>A result was applied (by the user or by the auto policy); the solution is the new running one.</summary>
    public event Action<RepairResult, Solution>? Applied;

    /// <summary>Something failed (the Agent, the engine, a probe); the text is for the status line.</summary>
    public event Action<string?, string>? Problem;

    /// <summary>Starts the protection with the solution.</summary>
    public async Task StartAsync(Solution solution)
    {
        await _swapGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_stopping || _engineId is not null)
                throw new InvalidOperationException("protection is already started or stopped");
            var (argv, queue) = _launch(solution, Protection.QueueNum);
            // not cancellable: the Agent may start the engine after the client gave up, and then nobody would stop it
            _engineId = await _engine.StartAsync(argv, queue, "protection", CancellationToken.None).ConfigureAwait(false);
            _queue = Protection.QueueNum;
            _solution = solution;
        }
        finally
        {
            _swapGate.Release();
        }
    }

    /// <summary>
    /// A detector event or the user's report. Never throws: failures go to <see cref="Problem"/>. Repairs run one at
    /// a time (they share the repair queue); a domain already waiting or under repair is not queued twice.
    /// </summary>
    public async Task<RepairResult?> HandleAsync(HealthEvent e, (string Ru, string En)? why = null)
    {
        var ct = _cts.Token;
        try
        {
            if (_stopping)
                return null;
            if (e.Change == HealthChange.Recovered)
            {
                await _coordinator.OnEventAsync(e, ct).ConfigureAwait(false);
                return null;
            }
            lock (_queued)
            {
                if (!_queued.Add(e.Domain))
                    return null;
            }
            try
            {
                await _repairGate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    return await RepairAsync(e, why, ct).ConfigureAwait(false);
                }
                finally
                {
                    _repairGate.Release();
                }
            }
            finally
            {
                lock (_queued)
                    _queued.Remove(e.Domain);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception ex)
        {
            Problem?.Invoke(e.Domain, ex.Message);
            return null;
        }
    }

    private async Task<RepairResult?> RepairAsync(HealthEvent e, (string Ru, string En)? why, CancellationToken ct)
    {
        // the strategy is taken before the domain leaves the solution: afterwards nothing serves it
        if (_solution is not { } before || Protection.CurrentOf(before, e.Domain) is not { } current)
            return null;
        Repairing?.Invoke(e.Domain);
        Solution? isolated = null;
        bool applied = false;
        try
        {
            // the protection must not touch the domain while the repair probes it
            isolated = await SwapAsync(s => Protection.ReplaceDomain(s, e.Domain, null)).ConfigureAwait(false);
            if (isolated is null)
                return null;
            var r = await _coordinator.OnEventAsync(e, ct, why, current).ConfigureAwait(false);
            if (r is null)
                return null;
            if (r.Verdict == RepairVerdict.Replaced && _policy() == ApplyPolicy.Auto)
            {
                applied = await ApplyCoreAsync(r).ConfigureAwait(false);
                if (applied)
                    return r;
            }
            Finished?.Invoke(r);
            return r;
        }
        finally
        {
            if (isolated is not null && !applied)
                await RestoreAsync(e.Domain, before, isolated, current).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The domain back under its strategy: the original solution when nothing else changed meanwhile, otherwise the
    /// latest one with the domain under its old strategy.
    /// </summary>
    private async Task RestoreAsync(string domain, Solution before, Solution isolated, StrategyCandidate current)
    {
        try
        {
            await SwapAsync(s => ReferenceEquals(s, isolated) ? before : Protection.ReplaceDomain(s, domain, current)).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Problem?.Invoke(domain, ex.Message);
        }
    }

    /// <summary>The user's yes to a pending result. False when the protection is stopped or the swap failed.</summary>
    public async Task<bool> ApplyAsync(RepairResult r)
    {
        try
        {
            return await ApplyCoreAsync(r).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Problem?.Invoke(r.Domain, ex.Message);
            return false;
        }
    }

    private async Task<bool> ApplyCoreAsync(RepairResult r)
    {
        var strategy = r.Verdict == RepairVerdict.Replaced ? r.Strategy : null;
        if (r.Verdict == RepairVerdict.Replaced && strategy is null)
            return false;
        var next = await SwapAsync(s => Protection.ReplaceDomain(s, r.Domain, strategy)).ConfigureAwait(false);
        if (next is null)
            return false;
        Applied?.Invoke(r, next);
        return true;
    }

    /// <summary>
    /// One hot swap, under the gate every change of the engine takes: the edit is made on the solution running now,
    /// the new instance takes the other queue and starts before the old one stops. Null when the protection stopped.
    /// </summary>
    private async Task<Solution?> SwapAsync(Func<Solution, Solution> edit)
    {
        await _swapGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_stopping || _engineId is not { } oldId || _solution is not { } current)
                return null;
            var next = edit(current);
            var queueNum = Protection.NextQueue(_queue);
            var (argv, queue) = _launch(next, queueNum);
            var id = await _engine.StartAsync(argv, queue, "protection", CancellationToken.None).ConfigureAwait(false);
            (_engineId, _queue, _solution) = (id, queueNum, next);
            try
            {
                await _engine.StopAsync(oldId, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // the new instance runs; the old one is the Agent's to reap (it stops every engine on exit)
                Problem?.Invoke(null, ex.Message);
            }
            return next;
        }
        finally
        {
            _swapGate.Release();
        }
    }

    /// <summary>
    /// Stops the protection: a running repair is cancelled, a swap in flight is waited for (so it cannot leave a new
    /// instance behind), then the engine stops. Safe to call more than once and off the UI thread.
    /// </summary>
    public async Task StopAsync()
    {
        _stopping = true;
        await _cts.CancelAsync().ConfigureAwait(false);
        await _swapGate.WaitAsync().ConfigureAwait(false);
        string? id;
        try
        {
            id = _engineId;
            _engineId = null;
        }
        finally
        {
            _swapGate.Release();
        }
        if (id is not null)
            await _engine.StopAsync(id, CancellationToken.None).ConfigureAwait(false);
    }
}
