using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
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
        Pages = [Auto, Engine, Home, Wizard, Monitor, Expert, Resources, Reports, Advisor, Settings];
        _current = Auto;
        host.AgentLost += m => AgentStatus = Loc.Loc.I.F("agent.lost", m);
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

    public HomeViewModel Home { get; }

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

    partial void OnCurrentChanged(PageViewModel value) => value.OnShown();

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
