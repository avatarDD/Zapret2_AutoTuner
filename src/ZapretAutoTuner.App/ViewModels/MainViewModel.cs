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
        Engine = new EngineViewModel(host)
        {
            Navigate = page => Current = page == "monitor" ? Monitor : Wizard,
        };
        // one engine bypasses at a time: geneva waits for zapret2's protection, the wizard and the model's runs
        host.Geneva.Busy = () =>
            Monitor.Active ? Loc.Loc.I["engine.busy_protection"]
            : Wizard.LocalTuningRunning ? Loc.Loc.I["engine.busy_wizard"]
            : Mcp.Session.Busy ? Loc.Loc.I["engine.busy_mcp"]
            : null;
        Monitor.GenevaRunning = () => host.Geneva.RunRunning;
        Pages = [Home, Wizard, Monitor, Engine, Reports, Expert, Resources, Advisor, Settings];
        _current = Home;
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
        }
        catch (Exception e) when (e is Tuning.Geneva.GenevaRefusedException or Protocol.AgentStartException or InvalidOperationException or Grpc.Core.RpcException)
        {
            Engine.Status = Loc.Loc.I.F("engine.failed", e.Message);
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

    /// <summary>"Движок обхода": nfqws2 or geneva, and geneva's search and bypass.</summary>
    public EngineViewModel Engine { get; }

    public McpService Mcp { get; }

    public ObservableCollection<PageViewModel> Pages { get; }

    [ObservableProperty]
    private PageViewModel _current;

    partial void OnCurrentChanged(PageViewModel value) => value.OnShown();

    [ObservableProperty]
    private string _agentStatus = "";

    public string Version => $"{Core.AppInfo.Version} · zapret2 {Core.AppInfo.Zapret2Version}";

    /// <summary>From the checker: start the wizard on the blocked resources.</summary>
    public void StartWizard(IEnumerable<string> hosts)
    {
        Wizard.InputText = string.Join(Environment.NewLine, hosts);
        Wizard.Step = 1;
        Current = Wizard;
    }
}
