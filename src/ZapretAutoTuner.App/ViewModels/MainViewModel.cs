using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;

namespace ZapretAutoTuner.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    public MainViewModel(AppHost host)
    {
        Home = new HomeViewModel(this);
        Wizard = new WizardViewModel(host);
        Monitor = new MonitorViewModel(host);
        Reports = new ReportsViewModel();
        Expert = new ExpertViewModel { Resources = host.Resources };
        Resources = new ResourcesViewModel(host.Resources, host.RouterResources);
        Mcp = new McpService(host, Monitor, Wizard);
        // the wizard and the model never tune at the same time (review M6)
        Wizard.McpBusy = () => Mcp.Session.Busy;
        Wizard.McpRouterBusy = () => Mcp.Session.RouterBusy;
        Reports.McpAudit = Mcp.AuditLines;
        Settings = new SettingsViewModel(host, Mcp);
        Advisor = new AdvisorViewModel(host, Mcp.Tools);
        Mcp.Stopped += Advisor.Cancel;
        Engine = new EngineViewModel(host);
        Auto = new AutoViewModel(host);
        // one engine bypasses at a time: geneva waits for zapret2's protection, the wizard and the model's runs
        host.Geneva.Busy = () =>
            Monitor.Active ? Loc.Loc.I["engine.busy_protection"]
            : Wizard.LocalTuningRunning ? Loc.Loc.I["engine.busy_wizard"]
            : Mcp.Session.Busy ? Loc.Loc.I["engine.busy_mcp"]
            : null;
        // and zapret2 waits for geneva: its bypass, and its search (the probe's packets would pass both engines)
        host.GenevaAuto.Busy = host.Geneva.Busy;
        Monitor.GenevaRunning = () => host.Geneva.RunRunning || host.Geneva.SearchRunning || host.GenevaAuto.Running;
        Wizard.GenevaBusy = () => host.Geneva.RunRunning || host.Geneva.SearchRunning || host.GenevaAuto.Running;
        // "Включить на этом компьютере": the monitor runs the solution as protection
        Wizard.ProtectHere = async () =>
        {
            Current = Monitor;
            if (SessionState.I.Last?.Solution is { } s)
                await Monitor.ApplySolutionAsync(s);
        };
        // the menu by what the user does: the automatic mode first (the main one), then manual work by engine, then
        // the service pages
        EnvironmentPage = new EnvironmentViewModel(host, () => AgentStatus) { Navigate = Navigate };
        Pages = [Auto, Engine, Home, Wizard, Monitor, Expert, Resources, Reports, Advisor, EnvironmentPage, Settings];
        // the two engines side by side, told apart by a badge (UX audit P0: "Подбор для сайта" did not say it is geneva)
        foreach (var p in new PageViewModel[] { Auto, Engine })
            p.Engine = "geneva";
        foreach (var p in new PageViewModel[] { Home, Wizard, Monitor, Expert, Resources })
            p.Engine = "zapret2";
        _current = Auto;
        _host = host;
        host.AgentLost += m => AgentStatus = Loc.Loc.I.F("agent.lost", m);
        Wizard.Finish = () => Current = Monitor.Active ? Monitor : Home;
        Expert.ProtectHere = Wizard.ProtectHere;
        Expert.OpenExport = OpenExport;
        Monitor.Navigate = Navigate;
        Loc.Loc.I.PropertyChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(WindowTitle));
            RefreshStatus();
        };
        // what runs is read from the engines a few times a second: they change state on their own (an Agent that
        // dropped, a search that finished, the model's runs), and a missed event must not leave a stale "вкл"
        _statusTimer = new Avalonia.Threading.DispatcherTimer(TimeSpan.FromSeconds(1), Avalonia.Threading.DispatcherPriority.Background, (_, _) => RefreshStatus());
        _statusTimer.Start();
        RefreshStatus();
        // the environment is checked at start: a missing bundle is said now, not after "Начать"
        Avalonia.Threading.Dispatcher.UIThread.Post(() => _ = EnvironmentPage.CheckAsync(), Avalonia.Threading.DispatcherPriority.Background);
        // the geneva bypass the user left on with "Включать при запуске" comes back (one elevation prompt)
        Avalonia.Threading.Dispatcher.UIThread.Post(() => _ = RestoreGenevaAsync(host), Avalonia.Threading.DispatcherPriority.Background);
    }

    private async Task RestoreGenevaAsync(AppHost host)
    {
        try
        {
            if (await host.Geneva.RestoreAsync(CancellationToken.None))
                Engine.Status = Loc.Loc.I["engine.restored"];
            // the "Авто" mode the user left on comes back by itself
            else if (await host.GenevaAuto.RestoreAsync(CancellationToken.None))
                Auto.Status = Loc.Loc.I["engine.auto_restored"];
        }
        catch (Exception e) when (e is Tuning.Geneva.GenevaRefusedException or Protocol.AgentStartException or InvalidOperationException or Grpc.Core.RpcException)
        {
            Auto.Status = Loc.Loc.I.F("engine.failed", e.Message);
        }
    }

    private readonly AppHost _host;
    private readonly Avalonia.Threading.DispatcherTimer _statusTimer;

    public HomeViewModel Home { get; }

    /// <summary>"Состояние": the tools and the environment (bundles, browser, Agent, nft, router, data folder).</summary>
    public EnvironmentViewModel EnvironmentPage { get; }

    public WizardViewModel Wizard { get; }

    public MonitorViewModel Monitor { get; }

    public ReportsViewModel Reports { get; }

    public ExpertViewModel Expert { get; }

    public ResourcesViewModel Resources { get; }

    public SettingsViewModel Settings { get; }

    public AdvisorViewModel Advisor { get; }

    /// <summary>"Ручной подбор geneva": geneva's search for one site, the found strategies and the one-strategy bypass.</summary>
    public EngineViewModel Engine { get; }

    /// <summary>"Авто": the main page, geneva finds and bypasses whatever is blocked by itself.</summary>
    public AutoViewModel Auto { get; }

    public McpService Mcp { get; }

    public ObservableCollection<PageViewModel> Pages { get; }

    [ObservableProperty]
    private PageViewModel _current;

    partial void OnCurrentChanged(PageViewModel value)
    {
        value.OnShown();
        OnPropertyChanged(nameof(WindowTitle));
    }

    /// <summary>The window's title names the page, so the taskbar and a screen reader say where the user is.</summary>
    public string WindowTitle => $"{Current.Title} — Zapret2 AutoTuner";

    /// <summary>Ctrl+1…9: the n-th page of the menu.</summary>
    [RelayCommand]
    private void GoTo(string? n)
    {
        if (int.TryParse(n, out var i) && i >= 1 && i <= Pages.Count)
            Current = Pages[i - 1];
    }

    /// <summary>Goes to a page by name, for links between pages ("settings_router": the router tab of Settings).</summary>
    public void Navigate(string where)
    {
        switch (where)
        {
            case "settings_router":
                Settings.TabIndex = SettingsViewModel.RouterTab;
                Current = Settings;
                break;
            case "environment":
                Current = EnvironmentPage;
                break;
            case "wizard":
                StartWizard([]);
                break;
            case "expert":
                Current = Expert;
                break;
            case "auto":
                Current = Auto;
                break;
            case "engine":
                Current = Engine;
                break;
        }
    }

    // ---- the status bar (UX audit P0): what runs now, whatever page is open, and one button that stops it all

    /// <summary>What runs now, one item each; empty: nothing intercepts traffic.</summary>
    public ObservableCollection<StatusItem> Running { get; } = [];

    [ObservableProperty]
    private bool _anythingRunning;

    /// <summary>The environment's worst problem ("zapret2 не найден"), shown in the bar as a link to "Состояние".</summary>
    [ObservableProperty]
    private string _environmentProblem = "";

    [ObservableProperty]
    private string _agentText = "";

    [ObservableProperty]
    private bool _stopping;

    /// <summary>Reads what runs from the engines and the pages; called by a timer and after every stop.</summary>
    public void RefreshStatus()
    {
        var items = new List<StatusItem>();
        var auto = _host.GenevaAuto.Running;
        var genevaRun = _host.Geneva.RunRunning;
        var genevaSearch = _host.Geneva.SearchRunning;
        if (auto)
            items.Add(new StatusItem(L["status.auto"], Auto));
        if (genevaRun)
            items.Add(new StatusItem(L["status.geneva_run"], Engine));
        if (genevaSearch)
            items.Add(new StatusItem(L["status.geneva_search"], Engine));
        if (Monitor.Active)
            items.Add(new StatusItem(L["status.protection"], Monitor));
        if (Wizard.Running)
            items.Add(new StatusItem(Wizard.Paused ? L["status.wizard_paused"] : L.F("status.wizard", Wizard.Percent.ToString("0")), Wizard));
        if (Home.Running)
            items.Add(new StatusItem(L["status.checker"], Home));
        if (Mcp.Session.Busy)
            items.Add(new StatusItem(L["status.mcp"], Settings));
        if (!items.Select(i => i.Text).SequenceEqual(Running.Select(i => i.Text)))
        {
            Running.Clear();
            foreach (var i in items)
                Running.Add(i);
        }
        AnythingRunning = items.Count > 0;
        Auto.Busy = auto;
        Engine.Busy = genevaRun || genevaSearch;
        Monitor.Busy = Monitor.Active;
        Wizard.Busy = Wizard.Running;
        Home.Busy = Home.Running;
        AgentText = AgentStatus.Length > 0 ? L["status.agent_lost"] : _host.AgentRunning ? L["status.agent_on"] : L["status.agent_off"];
        EnvironmentProblem = EnvironmentPage.Problem is { } p ? L.F("status.env_problem", p) : "";
    }

    private static Loc.Loc L => Loc.Loc.I;

    /// <summary>The window's yes/no dialog; set by the window.</summary>
    public Func<string, string, Task<bool>>? Confirm { get; set; }

    [RelayCommand]
    private void OpenStatus(StatusItem? item)
    {
        if (item is not null)
            Current = item.Page;
    }

    [RelayCommand]
    private void OpenEnvironment() => Current = EnvironmentPage;

    /// <summary>
    /// "Остановить всё": every search, bypass and protection of both engines stops and the Agent removes its rules,
    /// after a yes that lists what stops. The geneva bypass and "Авто" are switched off as by their own buttons, so they
    /// do not come back at the next start.
    /// </summary>
    [RelayCommand]
    private async Task StopAllAsync()
    {
        RefreshStatus();
        if (Running.Count == 0 || Stopping)
            return;
        if (Confirm is not null && !await Confirm(L["status.stop_all_title"], L.F("status.stop_all_text", string.Join("\n", Running.Select(r => "• " + r.Text)))))
            return;
        await StopEverythingAsync();
    }

    /// <summary>Stops everything without asking (the tray's and tests' entry); each step's failure does not stop the next.</summary>
    public async Task StopEverythingAsync()
    {
        Stopping = true;
        var failures = new List<string>();
        async Task Step(bool needed, Func<Task> stop)
        {
            if (!needed)
                return;
            try
            {
                await stop();
            }
            catch (Exception e) when (e is Tuning.Geneva.GenevaRefusedException or Grpc.Core.RpcException or InvalidOperationException
                or IOException or OperationCanceledException or Protocol.AgentStartException)
            {
                failures.Add(e.Message);
            }
        }
        try
        {
            // the searches first: a search may hold the bypass paused
            if (Wizard.Running)
                Wizard.StopCommand.Execute(null);
            if (Home.Running)
                Home.CheckCommand.Execute(null);
            await Step(Mcp.Session.Busy, Mcp.StopAsync);
            await Step(_host.Geneva.SearchRunning, () => _host.Geneva.StopSearchAsync());
            await Step(_host.GenevaAuto.Running, () => _host.GenevaAuto.DisableAsync());
            await Step(_host.Geneva.RunRunning, () => _host.Geneva.StopRunAsync(forget: true));
            await Step(Monitor.Active, Monitor.StopAsync);
        }
        finally
        {
            Stopping = false;
            RefreshStatus();
        }
        StopResult = failures.Count == 0 ? L["status.stopped_all"] : L.F("status.stop_failed", string.Join("; ", failures));
    }

    [ObservableProperty]
    private string _stopResult = "";

    [ObservableProperty]
    private string _agentStatus = "";

    public string Version => $"{Core.AppInfo.Version} · zapret2 {Core.AppInfo.Zapret2Version}";

    /// <summary>The wizard's last step for the current solution: where to turn it on or install it.</summary>
    public void OpenExport()
    {
        Wizard.Step = 5;
        Current = Wizard;
    }

    /// <summary>From the checker: start the wizard on the blocked resources.</summary>
    public void StartWizard(IEnumerable<string> hosts)
    {
        Wizard.InputText = string.Join(Environment.NewLine, hosts);
        Wizard.Step = 1;
        Current = Wizard;
    }
}

/// <summary>One thing that runs now, in the status bar; a click opens its page.</summary>
public sealed record StatusItem(string Text, PageViewModel Page);
