using System.Collections.ObjectModel;
using System.Net;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Monitor;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>One protected domain: the last window's numbers and what is happening to it.</summary>
public sealed partial class DomainHealthViewModel(string domain) : ObservableObject
{
    public string Domain { get; } = domain;

    [ObservableProperty]
    private string _state = Loc.Loc.I["monitor.state_ok"];

    [ObservableProperty]
    private string _window = "";

    [ObservableProperty]
    private string _brush = "#2E9E5B";
}

/// <summary>A repair result that waits for the user's yes (ApplyPolicy.Ask, AGENTS.md rule 7 spirit on the PC too).</summary>
public sealed record PendingRepair(RepairResult Result, string Text);

/// <summary>
/// "Монитор" (PLAN 7.1–7.5): runs the final solution as protection, watches its domains passively, repairs a
/// degraded one and either asks (default) or applies the fix by itself, as the user chose in the settings.
/// </summary>
public sealed partial class MonitorViewModel : PageViewModel
{
    private readonly AppHost _host;
    private readonly SemaphoreSlim _repairGate = new(1, 1);
    private CancellationTokenSource? _cts;
    private IEngineControl? _engine;
    private string? _engineId;
    private Solution? _solution;
    private RepairCoordinator? _coordinator;

    public MonitorViewModel(AppHost host)
    {
        _host = host;
        AutoApply = host.Settings.ApplyPolicy == "auto";
        LoadJournal();
    }

    public override string TitleKey => "nav.monitor";

    public ObservableCollection<DomainHealthViewModel> Domains { get; } = [];

    public ObservableCollection<string> Journal { get; } = [];

    public ObservableCollection<PendingRepair> Pending { get; } = [];

    [ObservableProperty]
    private bool _active;

    [ObservableProperty]
    private string _status = "";

    [ObservableProperty]
    private bool _autoApply;

    partial void OnAutoApplyChanged(bool value)
    {
        _host.Settings.ApplyPolicy = value ? "auto" : "ask";
        if (_coordinator is not null)
            _coordinator.Policy = value ? ApplyPolicy.Auto : ApplyPolicy.Ask;
    }

    [RelayCommand]
    private async Task ToggleAsync()
    {
        if (Active)
        {
            await StopAsync();
            return;
        }
        if (SessionState.I.Last?.Solution is not { } solution)
        {
            Status = L["monitor.no_solution"];
            return;
        }
        _cts = new CancellationTokenSource();
        try
        {
            var agent = await _host.AgentAsync(_cts.Token);
            _engine = new AgentEngineControl(agent.Client);
            _solution = solution;
            var (argv, queue) = Protection.Launch(solution, _host.Bundle.LuaDir);
            _engineId = await _engine.StartAsync(argv, queue, "protection", _cts.Token);
            Active = true;
            Domains.Clear();
            foreach (var d in Protection.Domains(solution))
                Domains.Add(new DomainHealthViewModel(d));
            Status = L.F("monitor.active", Domains.Count);

            var monitor = new LiveMonitor(new AgentProgramMonitor(agent.Client), new LiveMonitorOptions { Domains = [.. Protection.Domains(solution)] });
            monitor.WindowClosed += w => Dispatcher.UIThread.Post(() => OnWindow(w));
            monitor.Changed += e => _ = HandleAsync(e, null);
            _coordinator = new RepairCoordinator(RepairSteps(), d => _solution is null ? null : Protection.CurrentOf(_solution, d), AutoApply ? ApplyPolicy.Auto : ApplyPolicy.Ask);
            _coordinator.Journal += (d, kind, reason) => Dispatcher.UIThread.Post(() =>
            {
                _host.Kb.AddChange(d, kind, reason);
                LoadJournal();
            });
            _ = Task.Run(() => monitor.RunAsync(_cts.Token));
        }
        catch (OperationCanceledException)
        {
            Status = L["common.stopped"];
        }
        catch (Exception e) when (e is EngineRefusedException or InvalidOperationException or IOException or Grpc.Core.RpcException)
        {
            Status = e.Message;
            await StopAsync();
        }
    }

    /// <summary>"Не работает сейчас": the user's word starts the repair at once (PLAN 7.5).</summary>
    [RelayCommand]
    private void ReportBroken(DomainHealthViewModel? row)
    {
        if (row is not null && Active)
            _ = HandleAsync(new HealthEvent(row.Domain, HealthChange.Degraded, DateTime.UtcNow, []), "пользователь сообщил, что не работает / the user reported it broken");
    }

    [RelayCommand]
    private async Task ApplyAsync(PendingRepair? p)
    {
        if (p is null || _solution is null)
            return;
        Pending.Remove(p);
        var next = Protection.ReplaceDomain(_solution, p.Result.Domain, p.Result.Verdict == RepairVerdict.Replaced ? p.Result.Strategy : null);
        await SwapAsync(next, applied: true, p.Result);
    }

    [RelayCommand]
    private void Dismiss(PendingRepair? p)
    {
        if (p is null)
            return;
        Pending.Remove(p);
        _host.Kb.AddChange(p.Result.Domain, "dismissed", "пользователь отказался / the user declined");
        LoadJournal();
    }

    private async Task HandleAsync(HealthEvent e, string? why)
    {
        if (_coordinator is null || _solution is null || _cts is null)
            return;
        if (e.Change == HealthChange.Recovered)
        {
            await _coordinator.OnEventAsync(e, _cts.Token);
            Dispatcher.UIThread.Post(() => SetState(e.Domain, "monitor.state_ok", "#2E9E5B"));
            return;
        }
        if (_coordinator.IsRunning(e.Domain) || !await _repairGate.WaitAsync(0))
            return;
        var original = _solution;
        try
        {
            Dispatcher.UIThread.Post(() => SetState(e.Domain, "monitor.state_repairing", "#D9A21B"));
            // the protection must not touch the domain while the repair probes it
            await SwapAsync(Protection.ReplaceDomain(original, e.Domain, null), applied: false, null);
            var r = await _coordinator.OnEventAsync(e, _cts.Token, why);
            if (r is { Verdict: RepairVerdict.Replaced } && AutoApply)
            {
                await SwapAsync(Protection.ReplaceDomain(original, e.Domain, r.Strategy), applied: true, r);
                return;
            }
            await SwapAsync(original, applied: false, null);
            if (r is null)
                return;
            Dispatcher.UIThread.Post(() =>
            {
                if (r.Verdict is RepairVerdict.Replaced or RepairVerdict.BlockLifted)
                    Pending.Add(new PendingRepair(r, $"{r.Domain}: {L.Pick(r.ReasonRu, r.ReasonEn)}{(r.Strategy is { } s ? "\n" + s.Strategy : "")}"));
                SetState(e.Domain, r.Verdict == RepairVerdict.NotFound ? "monitor.state_broken" : "monitor.state_ok", r.Verdict == RepairVerdict.NotFound ? "#D0443E" : "#2E9E5B");
            });
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex) when (ex is EngineRefusedException or InvalidOperationException or IOException or Grpc.Core.RpcException)
        {
            Dispatcher.UIThread.Post(() => Status = ex.Message);
        }
        finally
        {
            _repairGate.Release();
        }
    }

    /// <summary>The new instance starts before the old one stops (PLAN 7.3.4).</summary>
    private async Task SwapAsync(Solution next, bool applied, RepairResult? r)
    {
        if (_engine is null)
            return;
        var (argv, queue) = Protection.Launch(next, _host.Bundle.LuaDir);
        _engineId = await HotSwap.ReplaceAsync(_engine, _engineId, argv, queue, "protection", CancellationToken.None);
        _solution = next;
        if (!applied || r is null)
            return;
        if (SessionState.I.Last is { } last)
            SessionState.I.Last = last with { Solution = next };
        Dispatcher.UIThread.Post(() =>
        {
            _host.Kb.AddChange(r.Domain, r.Verdict == RepairVerdict.BlockLifted ? "removed" : "applied", r.ReasonRu, null, r.Strategy?.Strategy.ToString(), applied: true);
            LoadJournal();
            if (r.Verdict == RepairVerdict.BlockLifted)
                Domains.Remove(Domains.FirstOrDefault(d => d.Domain == r.Domain)!);
            else
                SetState(r.Domain, "monitor.state_ok", "#2E9E5B");
        });
    }

    private SearchRepairSteps RepairSteps()
    {
        var mode = Enum.TryParse<SearchMode>(_host.Settings.SearchMode, out var m) ? m : SearchMode.Standard;
        var options = new AgentTrialOptions { LuaDir = _host.Bundle.LuaDir };
        async Task<AgentTrialExecutor> For(string domain, CancellationToken ct)
        {
            var addresses = await Dns.GetHostAddressesAsync(domain, ct);
            return new AgentTrialExecutor(_engine!, new TrialTarget { Host = domain, Addresses = addresses }, options);
        }
        return new SearchRepairSteps(
            async (d, ct) => await For(d, ct),
            async (d, ct) =>
            {
                var series = await (await For(d, ct)).ProbeSeriesAsync(3, o => o.Any(x => !x.Ok), ct);
                return series.Count > 0 && series.All(o => o.Ok);
            },
            new SearchOptions { Generator = new GeneratorOptions { Mode = mode }, Learning = SearchContext.For(_host).Learning });
    }

    private void OnWindow(WindowStats w)
    {
        _host.Kb.AddMonitorWindow(w.Domain, w.Start, w.Sessions, w.Ok, w.Reset, w.Stalled16k, w.Stalled, w.NoReply, w.Retransmissions);
        var row = Domains.FirstOrDefault(d => string.Equals(d.Domain, w.Domain, StringComparison.OrdinalIgnoreCase));
        if (row is not null)
            row.Window = L.F("monitor.window", w.Ok, w.Sessions, w.Failures > 0 ? L["outcome." + w.MainFailure.ToString().ToLowerInvariant()] : "—");
    }

    private void SetState(string domain, string key, string brush)
    {
        var row = Domains.FirstOrDefault(d => string.Equals(d.Domain, domain, StringComparison.OrdinalIgnoreCase));
        if (row is null)
            return;
        row.State = L[key];
        row.Brush = brush;
    }

    private void LoadJournal()
    {
        Journal.Clear();
        foreach (var c in _host.Kb.Changes(200))
            Journal.Add($"{c.Time.ToLocalTime():dd.MM HH:mm} {c.Domain} · {L["journal." + c.Kind]} · {c.Reason}{(c.NewArgs is null ? "" : " → " + c.NewArgs)}");
    }

    public async Task StopAsync()
    {
        await ShutdownAsync();
        _coordinator = null;
        Active = false;
        Status = L["monitor.stopped"];
    }

    /// <summary>Stops the protection engine; safe off the UI thread (on exit).</summary>
    public async Task ShutdownAsync()
    {
        _cts?.Cancel();
        var (engine, id) = (_engine, _engineId);
        _engineId = null;
        if (engine is null || id is null)
            return;
        try
        {
            await engine.StopAsync(id, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or Grpc.Core.RpcException)
        {
        }
    }
}
