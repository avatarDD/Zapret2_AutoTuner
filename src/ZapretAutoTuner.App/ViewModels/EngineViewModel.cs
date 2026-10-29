using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Tools;
using ZapretAutoTuner.Tuning.Geneva;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>A strategy the search found, with its buttons.</summary>
public sealed record FoundRow(string Host, string Strategy, string Score, string When);

/// <summary>A strategy of the search's feed.</summary>
public sealed record TrialRow(string Time, string Fitness, string Outcome, string Strategy, string Brush);

/// <summary>A strategy of Geneva's library.</summary>
public sealed record LibraryRow(string Strategy, string Rate, string Where, string Description);

/// <summary>A counter tile of the bypass's telemetry.</summary>
public sealed record StatTile(string Label, string Value);

/// <summary>
/// "Движок обхода": which engine bypasses on this PC (nfqws2 or geneva) and, for geneva, the whole cycle on one page:
/// 1) find a strategy for a blocked site (geneva's genetic search, each strategy judged by the full download),
/// 2) the strategies found (kept between runs), 3) the bypass with live telemetry. Everything privileged is the Agent's.
/// </summary>
public sealed partial class EngineViewModel : PageViewModel
{
    private readonly AppHost _host;
    private readonly DispatcherTimer _timer;
    private volatile bool _dirty = true;

    public EngineViewModel(AppHost host)
    {
        _host = host;
        var s = host.Geneva.State;
        _isGeneva = s.Engine == BypassEngine.Geneva;
        _searchHost = s.LastHost;
        _port = s.LastPort.ToString(CultureInfo.InvariantCulture);
        _population = s.Population;
        _generations = s.Generations;
        _runStrategy = s.Active?.Strategy ?? s.Found.FirstOrDefault()?.Strategy ?? "";
        _runPorts = s.Active?.Ports ?? "80,443";
        _autoStart = s.Active?.AutoStart ?? false;
        host.Geneva.Changed += () => _dirty = true;
        Loc.Loc.I.PropertyChanged += (_, _) => _dirty = true;
        _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(500), DispatcherPriority.Background, (_, _) => Refresh());
        _timer.Start();
    }

    public override string TitleKey => "nav.engine";

    public override void OnShown()
    {
        _dirty = true;
        Targets.Clear();
        foreach (var t in _host.Settings.Targets)
            Targets.Add(t);
        _ = CheckBundleAsync();
    }

    /// <summary>The user's targets, offered for the search.</summary>
    public ObservableCollection<string> Targets { get; } = [];

    // ---- engine choice

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsNfqws2))]
    private bool _isGeneva;

    public bool IsNfqws2
    {
        get => !IsGeneva;
        set => IsGeneva = !value;
    }

    partial void OnIsGenevaChanged(bool value)
    {
        _host.Geneva.Engine = value ? BypassEngine.Geneva : BypassEngine.Nfqws2;
        if (!value && _host.Geneva.RunRunning)
            Status = L["engine.switch_running"];
    }

    /// <summary>Set by the main view model: opens the wizard or the monitor (the nfqws2 side).</summary>
    public Action<string>? Navigate { get; set; }

    [RelayCommand]
    private void OpenWizard() => Navigate?.Invoke("wizard");

    [RelayCommand]
    private void OpenMonitor() => Navigate?.Invoke("monitor");

    [ObservableProperty]
    private string _bundleStatus = "";

    [ObservableProperty]
    private bool _bundleOk;

    private async Task CheckBundleAsync()
    {
        var b = _host.GenevaBundle;
        try
        {
            if (!b.Exists)
            {
                (BundleOk, BundleStatus) = (false, L["engine.bundle_missing"]);
                return;
            }
            var check = await Task.Run(b.Verify);
            if (!check.Ok)
            {
                (BundleOk, BundleStatus) = (false, L.F("engine.bundle_bad", string.Join("; ", check.Problems)));
                return;
            }
            var v = await b.GetVersionAsync();
            (BundleOk, BundleStatus) = v.Proto == GenevaEvent.Proto
                ? (true, L.F("engine.bundle_ok", v.Version, v.Arch, string.Join(", ", v.Features)))
                : (false, L.F("engine.bundle_proto", v.Proto, GenevaEvent.Proto));
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or FormatException or System.ComponentModel.Win32Exception)
        {
            (BundleOk, BundleStatus) = (false, L.F("engine.bundle_bad", e.Message));
        }
    }

    [ObservableProperty]
    private string _status = "";

    // ---- 1. search

    [ObservableProperty]
    private string _searchHost;

    [ObservableProperty]
    private string _port;

    [ObservableProperty]
    private decimal? _population;

    [ObservableProperty]
    private decimal? _generations;

    [ObservableProperty]
    private bool _seedLibrary = true;

    [ObservableProperty]
    private bool _searching;

    [ObservableProperty]
    private bool _canResume;

    [ObservableProperty]
    private string _resumeText = "";

    [ObservableProperty]
    private double _searchPercent;

    [ObservableProperty]
    private string _searchProgress = "";

    [ObservableProperty]
    private string _searchBaseline = "";

    [ObservableProperty]
    private string _searchBest = "";

    [ObservableProperty]
    private string _searchEnded = "";

    [ObservableProperty]
    private IList<Point> _bestChart = [];

    [ObservableProperty]
    private IList<Point> _avgChart = [];

    public ObservableCollection<TrialRow> Feed { get; } = [];

    public ObservableCollection<FoundRow> Found { get; } = [];

    public ObservableCollection<string> Log { get; } = [];

    partial void OnSearchHostChanged(string value) => _dirty = true;

    private (string Host, int Port)? Target()
    {
        var host = (SearchHost ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        if (host.StartsWith("https://", StringComparison.Ordinal))
            host = host[8..].Split('/')[0];
        if (!Core.Model.Target.IsValidHostName(host))
        {
            Status = L.F("engine.bad_host", SearchHost);
            return null;
        }
        if (!int.TryParse(Port, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
        {
            Status = L.F("engine.bad_port", Port);
            return null;
        }
        return (host, port);
    }

    [RelayCommand]
    private Task SearchAsync() => StartSearchAsync(resume: false);

    [RelayCommand]
    private Task ResumeAsync() => StartSearchAsync(resume: true);

    private async Task StartSearchAsync(bool resume)
    {
        if (Target() is not { } t)
            return;
        var seeds = new List<string>();
        if (SeedLibrary && !resume)
        {
            // the found strategies of this site first, then the library's best: geneva starts from them
            seeds.AddRange(_host.Geneva.State.Found.Where(f => string.Equals(f.Host, t.Host, StringComparison.OrdinalIgnoreCase)).Select(f => f.Strategy).Take(20));
            try
            {
                seeds.AddRange((await _host.GenevaBundle.LibraryAsync()).Where(l => !l.ServerSide && l.Rate > 0).OrderByDescending(l => l.Rate).Select(l => l.Strategy).Take(GenevaArgv.MaxSeeds - seeds.Count));
            }
            catch (Exception e) when (e is InvalidOperationException or IOException or FormatException or System.ComponentModel.Win32Exception)
            {
            }
        }
        var settings = new GenevaSearchSettings
        {
            Host = t.Host,
            Port = t.Port,
            Tls = t.Port != 80,
            Population = (int)(Population ?? 30),
            Generations = (int)(Generations ?? 15),
            Resume = resume,
            Seeds = [.. seeds.Distinct().Where(s => GenevaStrategyText.Problem(s) is null).Take(GenevaArgv.MaxSeeds)],
        };
        try
        {
            Status = L["engine.starting"];
            await _host.Geneva.StartSearchAsync(settings, CancellationToken.None);
            _host.Settings.AddTargets([t.Host]);
            Status = "";
        }
        catch (Exception e) when (e is GenevaRefusedException or Protocol.AgentStartException or InvalidOperationException or Grpc.Core.RpcException)
        {
            Status = L.F("engine.failed", e.Message);
        }
        _dirty = true;
    }

    [RelayCommand]
    private async Task StopSearchAsync()
    {
        try
        {
            await _host.Geneva.StopSearchAsync();
        }
        catch (Exception e) when (e is GenevaRefusedException or Grpc.Core.RpcException or InvalidOperationException)
        {
            Status = L.F("engine.failed", e.Message);
        }
    }

    [RelayCommand]
    private void UseFound(FoundRow row)
    {
        RunStrategy = row.Strategy;
        Status = L["engine.taken"];
    }

    [RelayCommand]
    private async Task CopyAsync(string text)
    {
        if (Avalonia.Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime { MainWindow.Clipboard: { } cb })
            await cb.SetTextAsync(text);
    }

    // ---- 3. bypass

    [ObservableProperty]
    private string _runStrategy;

    [ObservableProperty]
    private string _runPorts;

    [ObservableProperty]
    private bool _autoStart;

    partial void OnAutoStartChanged(bool value) => _host.Geneva.SetAutoStart(value);

    [ObservableProperty]
    private bool _running;

    [ObservableProperty]
    private bool _paused;

    [ObservableProperty]
    private string _runStatus = "";

    [ObservableProperty]
    private string _runIdle = "";

    [ObservableProperty]
    private IList<Point> _triggeredChart = [];

    public ObservableCollection<StatTile> Tiles { get; } = [];

    public ObservableCollection<string> TreeLines { get; } = [];

    [RelayCommand]
    private async Task StartRunAsync()
    {
        try
        {
            Status = L["engine.starting"];
            await _host.Geneva.StartRunAsync(RunStrategy, RunPorts, AutoStart, CancellationToken.None);
            Status = "";
        }
        catch (Exception e) when (e is GenevaRefusedException or Protocol.AgentStartException or InvalidOperationException or Grpc.Core.RpcException)
        {
            Status = L.F("engine.failed", e.Message);
        }
        _dirty = true;
    }

    [RelayCommand]
    private async Task StopRunAsync()
    {
        try
        {
            await _host.Geneva.StopRunAsync(forget: true);
        }
        catch (Exception e) when (e is GenevaRefusedException or Grpc.Core.RpcException or InvalidOperationException)
        {
            Status = L.F("engine.failed", e.Message);
        }
    }

    [RelayCommand]
    private async Task PauseAsync()
    {
        try
        {
            await _host.Geneva.PauseRunAsync(!Paused, CancellationToken.None);
        }
        catch (Exception e) when (e is GenevaRefusedException or Grpc.Core.RpcException or InvalidOperationException)
        {
            Status = L.F("engine.failed", e.Message);
        }
    }

    // ---- library

    public ObservableCollection<LibraryRow> Library { get; } = [];

    [ObservableProperty]
    private string _libraryStatus = "";

    [RelayCommand]
    private async Task LoadLibraryAsync()
    {
        try
        {
            var all = await _host.GenevaBundle.LibraryAsync();
            Library.Clear();
            foreach (var l in all.Where(l => !l.ServerSide).OrderByDescending(l => l.Rate))
                Library.Add(new LibraryRow(l.Strategy, l.Rate.ToString(CultureInfo.InvariantCulture) + "%", $"{l.Country} / {l.Test}", l.Description));
            LibraryStatus = L.F("engine.library_loaded", Library.Count);
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or FormatException or System.ComponentModel.Win32Exception)
        {
            LibraryStatus = L.F("engine.failed", e.Message);
        }
    }

    [RelayCommand]
    private void UseLibrary(LibraryRow row)
    {
        RunStrategy = row.Strategy;
        Status = L["engine.taken"];
    }

    // ---- refresh from the controller

    private void Refresh()
    {
        if (!_dirty)
            return;
        _dirty = false;
        var g = _host.Geneva;
        var search = g.Search;
        var state = g.State;
        bool en = Loc.Loc.I.English;
        // MCP's engine_select and a started bypass change the choice too
        if ((state.Engine == BypassEngine.Geneva) != IsGeneva)
            IsGeneva = state.Engine == BypassEngine.Geneva;

        Searching = search.Running;
        SearchPercent = search.Percent * 100;
        SearchProgress = search.Running || search.Generation >= 0
            ? L.F("engine.progress", Math.Max(0, search.Generation + 1), search.Generations, search.Evaluated, search.Succeeded, search.Host)
            : "";
        SearchBaseline = search.Blocked switch
        {
            true => L.F("engine.baseline_blocked", Pick(GenevaText.Outcome(search.BaselineOutcome), en)),
            false => L["engine.baseline_open"],
            _ => search.Running ? L["engine.baseline_wait"] : "",
        };
        SearchBest = search.Best is { } best ? L.F("engine.best", search.BestFitness.ToString("0", CultureInfo.InvariantCulture), best) : "";
        SearchEnded = !search.Running && search.Ended is { } ended ? Pick(ended, en) : "";
        BestChart = Chart(search.BestByGeneration, -500, 400);
        AvgChart = Chart(search.AvgByGeneration, -500, 400);

        var target = Target2();
        var progress = target is { } t ? state.ProgressOf(t.Host, t.Port) : null;
        CanResume = !search.Running && progress is { Finished: false, Generation: >= 0 };
        ResumeText = progress is null ? "" : L.F("engine.saved", progress.Generation + 1, progress.Generations, progress.BestFitness.ToString("0", CultureInfo.InvariantCulture),
            progress.Updated.ToLocalTime().ToString("g", CultureInfo.CurrentCulture));

        Sync(Feed, g.Trials.Take(60).Select(x => new TrialRow(x.Time.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture),
            x.Fitness.ToString("0", CultureInfo.InvariantCulture), Pick(GenevaText.Outcome(x.Outcome), en), x.Strategy, x.Fitness > 0 ? "#2E9E5B" : "#D0443E")).ToList());
        Sync(Found, state.Found.Take(50).Select(f => new FoundRow(f.Host, f.Strategy,
            L.F("engine.score", f.Fitness.ToString("0", CultureInfo.InvariantCulture), f.Runs), f.Found.ToLocalTime().ToString("g", CultureInfo.CurrentCulture))).ToList());
        Sync(Log, g.Log.TakeLast(150).Reverse().ToList());

        var run = g.Run;
        Running = run.Running;
        Paused = run.Stats?.Paused ?? false;
        RunStatus = run.Running
            ? (run.Ready ? L.F("engine.run_ready", run.Ports, run.Firewall ?? "", Uptime(run.Stats?.UptimeMs ?? 0)) : L["engine.run_starting"])
            : run.Ended is { } e ? L.F("engine.run_ended", Pick(e, en)) : L["engine.run_off"];
        RunIdle = run.Running && run.Stats is { Idle: true } ? L["engine.idle"] : "";
        TriggeredChart = Chart(run.TriggeredHistory, 0, Math.Max(1, run.TriggeredHistory.DefaultIfEmpty(0).Max()));
        var st = run.Stats;
        Sync(Tiles, st is null ? [] : new List<StatTile>
        {
            new(L["engine.t_out"], $"{st.PktsOut:N0} ({run.RateOut:0}/s)"),
            new(L["engine.t_in"], $"{st.PktsIn:N0} ({run.RateIn:0}/s)"),
            new(L["engine.t_triggered"], st.Triggered.ToString("N0", CultureInfo.CurrentCulture)),
            new(L["engine.t_modified"], st.Modified.ToString("N0", CultureInfo.CurrentCulture)),
            new(L["engine.t_injected"], st.Injected.ToString("N0", CultureInfo.CurrentCulture)),
            new(L["engine.t_dropped"], st.Dropped.ToString("N0", CultureInfo.CurrentCulture)),
            new(L["engine.t_errors"], (st.Errors + st.Overruns).ToString("N0", CultureInfo.CurrentCulture)),
        });
        Sync(TreeLines, st is null ? [] : st.Trees.Select(t => L.F("engine.tree", t.Fired, t.Tree)).ToList());
    }

    private (string Host, int Port)? Target2()
    {
        var host = (SearchHost ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        return Core.Model.Target.IsValidHostName(host) && int.TryParse(Port, NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? (host, p) : null;
    }

    private static string Pick((string Ru, string En) t, bool en) => en ? t.En : t.Ru;

    private static string Uptime(long ms)
    {
        var t = TimeSpan.FromMilliseconds(ms);
        return t.TotalHours >= 1 ? $"{(int)t.TotalHours}:{t.Minutes:00}:{t.Seconds:00}" : $"{t.Minutes}:{t.Seconds:00}";
    }

    public const double ChartWidth = 360;
    public const double ChartHeight = 60;

    /// <summary>The values as a polyline in a <see cref="ChartWidth"/>×<see cref="ChartHeight"/> box.</summary>
    internal static List<Point> Chart(IReadOnlyList<double> values, double min, double max)
    {
        if (values.Count == 0)
            return [];
        if (values.Count == 1)
            values = [values[0], values[0]];
        double range = Math.Max(1e-9, max - min);
        return [.. values.Select((v, i) => new Point(i * ChartWidth / (values.Count - 1), ChartHeight - (Math.Clamp(v, min, max) - min) / range * ChartHeight))];
    }

    private static void Sync<T>(ObservableCollection<T> target, IReadOnlyList<T> items)
    {
        if (target.SequenceEqual(items))
            return;
        target.Clear();
        foreach (var i in items)
            target.Add(i);
    }
}
