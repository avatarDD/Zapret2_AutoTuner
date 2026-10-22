using System.Collections.ObjectModel;
using System.Net;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Monitor;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Storage;
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
/// degraded one and either asks (default) or applies the fix by itself, as the user chose in the settings. The
/// protection itself (engine, queues, swaps, the repair flow) is <see cref="ProtectionController"/>; this only shows it.
/// </summary>
public sealed partial class MonitorViewModel : PageViewModel
{
    private readonly AppHost _host;
    private readonly Dictionary<string, (DateTime At, IReadOnlyList<IPAddress> Addresses)> _addresses = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _cts;
    private IEngineControl? _engine;
    private ProtectionController? _protection;

    public MonitorViewModel(AppHost host)
    {
        _host = host;
        _autoApply = host.Settings.ApplyPolicy == "auto";
        // one source of truth: the settings page and this switch both write the setting, and both follow it
        host.Settings.ApplyPolicyChanged += () => Dispatcher.UIThread.Post(() => AutoApply = host.Settings.ApplyPolicy == "auto");
        // the journal keeps both languages; the page shows the current one
        Loc.Loc.I.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(Loc.Loc.English))
                LoadJournal();
        };
        // the router's commits and feedback write to the same journal (PLAN 7.6.5)
        host.Router.JournalChanged += () => Dispatcher.UIThread.Post(LoadJournal);
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

    /// <summary>Set by the window: the "Сообщить о проблеме" dialog (PLAN 4a.6).</summary>
    public Func<BugReportInput, Task>? ReportProblem { get; set; }

    /// <summary>The protection could not start or a repair failed: shows the report button.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasProblem))]
    private BugReportInput? _problem;

    public bool HasProblem => Problem is not null;

    [RelayCommand]
    private async Task ReportProblemAsync()
    {
        if (ReportProblem is not null)
            await ReportProblem(Problem ?? BugReports.From(null, BugKind.AppError, Status));
    }

    partial void OnAutoApplyChanged(bool value) => _host.Settings.ApplyPolicy = value ? "auto" : "ask";

    private ApplyPolicy Policy() => _host.Settings.ApplyPolicy == "auto" ? ApplyPolicy.Auto : ApplyPolicy.Ask;

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
        await StartAsync(solution);
    }

    /// <summary>A solution the user accepted elsewhere (an MCP experiment's commit) becomes the protection.</summary>
    public async Task ApplySolutionAsync(Solution solution)
    {
        if (Active)
            await StopAsync();
        SessionState.I.Last = SessionState.I.Last is { } last ? last with { Solution = solution } : new PipelineResult([], null, solution);
        await StartAsync(solution);
    }

    private async Task StartAsync(Solution solution)
    {
        _cts = new CancellationTokenSource();
        try
        {
            // the chart needs a week at most; older windows only grow the file
            _host.Kb.PruneMonitorWindows(DateTimeOffset.UtcNow.AddDays(-7));
            var agent = await _host.AgentAsync(_cts.Token);
            _engine = new AgentEngineControl(agent.Client);
            Problem = null;
            // the approved user Lua the solution calls is loaded with it (PLAN 4a.5)
            var userLua = _host.Resources.ApprovedLuaPaths();
            var protection = new ProtectionController(_engine, RepairSteps(), (s, q) => Protection.Launch(s, _host.Bundle.LuaDir, q, userLua), Policy);
            Wire(protection);
            await protection.StartAsync(solution);
            _protection = protection;
            Active = true;
            Domains.Clear();
            Pending.Clear();
            foreach (var d in Protection.Domains(solution))
                Domains.Add(new DomainHealthViewModel(d));
            Status = L.F("monitor.active", Domains.Count);

            var monitor = new LiveMonitor(new AgentProgramMonitor(agent.Client), new LiveMonitorOptions { Domains = [.. Protection.Domains(solution)] });
            monitor.WindowClosed += w => Dispatcher.UIThread.Post(() => OnWindow(w));
            monitor.Changed += e => _ = Task.Run(() => protection.HandleAsync(e));
            monitor.Failed += (e, n) => Dispatcher.UIThread.Post(() => Status = L.F("monitor.capture_failed", e.Message, n));
            var ct = _cts.Token;
            _ = Task.Run(() => monitor.RunAsync(ct));
        }
        catch (OperationCanceledException)
        {
            Status = L["common.stopped"];
            await ShutdownAsync();
        }
        catch (Exception e)
        {
            // a declined UAC / pkexec prompt, a refused engine, a dropped Agent: said, not crashed
            await ShutdownAsync();
            Active = false;
            Status = e.Message;
            Problem = BugReports.From(e);
        }
    }

    private void Wire(ProtectionController p)
    {
        p.Journal += (d, kind, ru, en) => Dispatcher.UIThread.Post(() =>
        {
            _host.Kb.AddChange(d, kind, JournalReason.Encode(ru, en));
            LoadJournal();
        });
        p.Repairing += d => Dispatcher.UIThread.Post(() => SetState(d, "monitor.state_repairing", "#D9A21B"));
        p.Finished += r => Dispatcher.UIThread.Post(() =>
        {
            if (r.Verdict is RepairVerdict.Replaced or RepairVerdict.BlockLifted)
                Pending.Add(new PendingRepair(r, $"{r.Domain}: {L.Pick(r.ReasonRu, r.ReasonEn)}{(r.Strategy is { } s ? "\n" + s.Strategy : "")}"));
            SetState(r.Domain, r.Verdict == RepairVerdict.NotFound ? "monitor.state_broken" : "monitor.state_ok", r.Verdict == RepairVerdict.NotFound ? "#D0443E" : "#2E9E5B");
        });
        p.Applied += (r, next) => Dispatcher.UIThread.Post(() => OnApplied(r, next));
        p.Problem += (d, message) => Dispatcher.UIThread.Post(() =>
        {
            Status = d is null ? message : L.F("monitor.repair_failed", d, message);
            Problem = BugReports.From(null, BugKind.AppError, Status);
            if (d is not null)
                SetState(d, "monitor.state_broken", "#D0443E");
        });
    }

    /// <summary>"Не работает сейчас": the user's word starts the repair at once (PLAN 7.5).</summary>
    [RelayCommand]
    private void ReportBroken(DomainHealthViewModel? row)
    {
        if (row is not null && Active && _protection is { } p)
            _ = Task.Run(() => p.HandleAsync(new HealthEvent(row.Domain, HealthChange.Degraded, DateTime.UtcNow, []), RepairCoordinator.UserReport));
    }

    [RelayCommand]
    private async Task ApplyAsync(PendingRepair? p)
    {
        if (p is null || _protection is not { } protection)
            return;
        Pending.Remove(p);
        try
        {
            // the controller builds the edit on the solution running now, through the same gate as the repairs
            await protection.ApplyAsync(p.Result);
        }
        catch (Exception e)
        {
            Status = e.Message;
        }
    }

    [RelayCommand]
    private void Dismiss(PendingRepair? p)
    {
        if (p is null)
            return;
        Pending.Remove(p);
        _host.Kb.AddChange(p.Result.Domain, "dismissed", JournalReason.Encode("пользователь отказался", "the user declined"));
        LoadJournal();
    }

    private void OnApplied(RepairResult r, Solution next)
    {
        if (SessionState.I.Last is { } last)
            SessionState.I.Last = last with { Solution = next };
        _host.Kb.AddChange(r.Domain, r.Verdict == RepairVerdict.BlockLifted ? "removed" : "applied", JournalReason.Encode(r.ReasonRu, r.ReasonEn), null,
            r.Strategy?.Strategy.ToString(), applied: true);
        LoadJournal();
        foreach (var stale in Pending.Where(x => string.Equals(x.Result.Domain, r.Domain, StringComparison.OrdinalIgnoreCase)).ToList())
            Pending.Remove(stale);
        if (r.Verdict == RepairVerdict.BlockLifted)
        {
            if (Domains.FirstOrDefault(d => string.Equals(d.Domain, r.Domain, StringComparison.OrdinalIgnoreCase)) is { } row)
                Domains.Remove(row);
        }
        else
        {
            SetState(r.Domain, "monitor.state_ok", "#2E9E5B");
        }
    }

    /// <summary>The domain's live addresses (as the classifier picks them), kept a few minutes: every repair step asks.</summary>
    private async Task<IReadOnlyList<IPAddress>> AddressesAsync(string domain, CancellationToken ct)
    {
        lock (_addresses)
        {
            if (_addresses.TryGetValue(domain, out var c) && DateTime.UtcNow - c.At < TimeSpan.FromMinutes(5))
                return c.Addresses;
        }
        var live = await LiveAddresses.ResolveAsync(domain, ct);
        lock (_addresses)
            _addresses[domain] = (DateTime.UtcNow, live);
        return live;
    }

    private SearchRepairSteps RepairSteps()
    {
        var mode = Enum.TryParse<SearchMode>(_host.Settings.SearchMode, out var m) ? m : SearchMode.Standard;
        var engine = _engine!;
        // its own queue: a wizard run may hold the trials' 300 at the same time
        var options = new AgentTrialOptions { LuaDir = _host.Bundle.LuaDir, QueueNum = Protection.RepairQueueNum };
        async Task<AgentTrialExecutor> For(string domain, CancellationToken ct)
        {
            var addresses = await AddressesAsync(domain, ct);
            return new AgentTrialExecutor(engine, new TrialTarget { Host = domain, Addresses = addresses }, options);
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
        {
            var (ru, en) = JournalReason.Decode(c.Reason);
            Journal.Add($"{c.Time.ToLocalTime():dd.MM HH:mm} {c.Domain} · {L["journal." + c.Kind]} · {L.Pick(ru, en)}{(c.NewArgs is null ? "" : " → " + c.NewArgs)}");
        }
    }

    public async Task StopAsync()
    {
        await ShutdownAsync();
        Active = false;
        Pending.Clear();
        Status = L["monitor.stopped"];
    }

    /// <summary>
    /// Stops the protection: a repair in flight is cancelled and a swap in flight is waited for, so no instance it
    /// starts is left behind. Safe off the UI thread (on exit).
    /// </summary>
    public async Task ShutdownAsync()
    {
        _cts?.Cancel();
        var protection = _protection;
        _protection = null;
        _engine = null;
        if (protection is null)
            return;
        try
        {
            await protection.StopAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
            // the Agent stops every engine when it exits anyway
        }
    }
}
