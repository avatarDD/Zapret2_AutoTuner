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
        Expert = new ExpertViewModel();
        Settings = new SettingsViewModel(host);
        Pages = [Home, Wizard, Monitor, Reports, Expert, Settings];
        _current = Home;
        host.AgentLost += m => AgentStatus = Loc.Loc.I.F("agent.lost", m);
    }

    public HomeViewModel Home { get; }

    public WizardViewModel Wizard { get; }

    public MonitorViewModel Monitor { get; }

    public ReportsViewModel Reports { get; }

    public ExpertViewModel Expert { get; }

    public SettingsViewModel Settings { get; }

    public ObservableCollection<PageViewModel> Pages { get; }

    [ObservableProperty]
    private PageViewModel _current;

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
