using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.Probes.Diagnostics;

namespace ZapretAutoTuner.App.ViewModels;

public sealed partial class CheckerRowViewModel(CheckerRow row) : ObservableObject
{
    public CheckerRow Row { get; } = row;

    public string Name => Loc.Loc.I.Pick(Row.Resource.NameRu, Row.Resource.NameEn);

    public string Summary => Loc.Loc.I.Pick(Row.SummaryRu, Row.SummaryEn);

    public TrafficLight Light => Row.Light;

    public string LightBrush => Row.Light switch
    {
        TrafficLight.Green => "#2E9E5B",
        TrafficLight.Yellow => "#D9A21B",
        TrafficLight.Red => "#D0443E",
        _ => "#8A8A8A",
    };

    public IEnumerable<string> Hosts => Row.Targets.Select(t => t.Target.Host);
}

/// <summary>The main screen: the big "Проверить блокировки" button (the checker, PLAN 2.5b) and "Подобрать стратегию".</summary>
public sealed partial class HomeViewModel(MainViewModel main) : PageViewModel
{
    private CancellationTokenSource? _cts;

    public override string TitleKey => "nav.home";

    public ObservableCollection<CheckerRowViewModel> Rows { get; } = [];

    [ObservableProperty]
    private bool _running;

    [ObservableProperty]
    private string _status = "";


    [RelayCommand]
    private async Task CheckAsync()
    {
        if (Running)
        {
            _cts?.Cancel();
            return;
        }
        Running = true;
        Rows.Clear();
        Status = L["home.checking"];
        _cts = new CancellationTokenSource();
        try
        {
            var resources = CheckerData.Default.Resources;
            var report = await Checker.RunAsync(resources, new CheckerOptions(), new Progress<ClassifierStep>(st => Status = L.Pick(st.MessageRu, st.MessageEn)), _cts.Token);
            foreach (var r in report.Rows)
                Rows.Add(new CheckerRowViewModel(r));
            Status = report.NetworkProblem ? L["home.network_problem"] : L.F("home.done", report.Rows.Count(r => r.Light == TrafficLight.Red), report.Duration.TotalSeconds.ToString("0"));
            Services.AppHost.Current?.Kb.AddCheckerRun(report.Started, report.Duration, report.NetworkProblem,
                System.Text.Json.JsonSerializer.Serialize(report.Rows.Select(r => new { r.Resource.Id, Label = r.Primary.ToString(), Light = r.Light.ToString() })));
        }
        catch (OperationCanceledException)
        {
            Status = L["common.stopped"];
        }
        finally
        {
            Running = false;
        }
    }

    [RelayCommand]
    private void TuneBlocked() =>
        main.StartWizard(Rows.Where(r => r.Light is TrafficLight.Red or TrafficLight.Yellow).SelectMany(r => r.Hosts).Distinct());

    [RelayCommand]
    private void Tune(CheckerRowViewModel? row)
    {
        if (row is not null)
            main.StartWizard(row.Hosts);
    }

    [RelayCommand]
    private void OpenWizard() => main.StartWizard([]);
}
