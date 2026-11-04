using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Tools;
using ZapretAutoTuner.Tuning.Geneva;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>A service of the "Авто" mode: what it is, where it stands, the strategy applied to it.</summary>
public sealed record AutoRow(string Key, string Name, string Status, string Detail, string Strategy, string Brush, bool CanReset);

/// <summary>
/// One working strategy and every service it bypasses: one strategy for many addresses is one group (one
/// <c>geneva run</c>), and the page shows it that way.
/// </summary>
public sealed record AutoGroupRow(string Strategy, string Services, string Counters, int Count);

/// <summary>An imported strategy with the services it came for.</summary>
public sealed record ImportedRow(string Strategy, string Services, string When);

/// <summary>
/// "Авто" (the program's main page): one switch, and geneva finds and bypasses whatever is blocked on this PC by itself
/// (skill <c>geneva</c>, §9). The page shows what it found, which strategy serves which services, the search's
/// threads, and the exchange of found strategies with other users in zapret-gui's format.
/// </summary>
public sealed partial class AutoViewModel : PageViewModel
{
    private readonly AppHost _host;
    private readonly DispatcherTimer _timer;
    private volatile bool _dirty = true;
    private bool _workersSupported;

    public AutoViewModel(AppHost host)
    {
        _host = host;
        _workers = host.Geneva.Workers;
        host.Geneva.Changed += () => _dirty = true;
        host.GenevaAuto.Changed += () => _dirty = true;
        Loc.Loc.I.PropertyChanged += (_, _) => _dirty = true;
        _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(500), DispatcherPriority.Background, (_, _) => Refresh());
        _timer.Start();
    }

    public override string TitleKey => "nav.auto";

    public override string? SectionKey => "nav.section_auto";

    public override void OnShown()
    {
        _dirty = true;
        _ = CheckFeaturesAsync();
    }

    /// <summary>Set by the window: save and open files (export, import).</summary>
    public Func<string, byte[], Task>? SaveFile { get; set; }

    public Func<Task<(string Name, byte[] Bytes)?>>? OpenFile { get; set; }

    public Func<string, Task>? CopyText { get; set; }

    [ObservableProperty]
    private string _status = "";

    [ObservableProperty]
    private bool _autoOn;

    [ObservableProperty]
    private bool _autoBusy;

    [ObservableProperty]
    private string _autoPhase = "";

    [ObservableProperty]
    private string _autoSummary = "";

    [ObservableProperty]
    private string _autoNotice = "";

    [ObservableProperty]
    private bool _autoShowAll;

    /// <summary>Nothing found or watched yet: the page explains what the switch does and what to expect.</summary>
    [ObservableProperty]
    private bool _firstRun = true;

    public ObservableCollection<AutoRow> AutoServices { get; } = [];

    public ObservableCollection<AutoGroupRow> AutoGroups { get; } = [];

    public ObservableCollection<ImportedRow> Imported { get; } = [];

    public ObservableCollection<string> AutoLog { get; } = [];

    /// <summary>How many strategies come with the program (the starting set).</summary>
    public string PresetText => L.F("auto.preset", GenevaShare.Preset.Count, GenevaShare.Preset.Sum(p => p.Services.Count));

    partial void OnAutoShowAllChanged(bool value) => _dirty = true;

    // ---- threads

    [ObservableProperty]
    private decimal? _workers;

    [ObservableProperty]
    private string _workersNote = "";

    partial void OnWorkersChanged(decimal? value)
    {
        if (value is { } v)
            _host.Geneva.Workers = (int)v;
        WorkersNote = WorkersText();
    }

    private string WorkersText() => (Workers ?? 1) > 1 && !_workersSupported ? L["auto.workers_old"] : "";

    private async Task CheckFeaturesAsync()
    {
        try
        {
            if (_host.GenevaBundle.Exists)
                _workersSupported = (await _host.GenevaBundle.GetVersionAsync()).Features.Contains(GenevaBundle.ExternalWorkersFeature);
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or FormatException or System.ComponentModel.Win32Exception)
        {
            _workersSupported = false;
        }
        WorkersNote = WorkersText();
    }

    // ---- the switch

    /// <summary>The one switch of the mode: everything else it decides itself.</summary>
    [RelayCommand]
    private async Task ToggleAutoAsync()
    {
        AutoBusy = true;
        try
        {
            if (_host.GenevaAuto.Running)
                await _host.GenevaAuto.DisableAsync();
            else
            {
                Status = L["engine.starting"];
                await _host.GenevaAuto.EnableAsync(CancellationToken.None);
                Status = "";
            }
        }
        catch (Exception e) when (e is GenevaRefusedException or Protocol.AgentStartException or InvalidOperationException or Grpc.Core.RpcException)
        {
            Status = L.F("engine.failed", e.Message);
        }
        finally
        {
            AutoBusy = false;
            _dirty = true;
        }
    }

    [RelayCommand]
    private async Task ResetAutoServiceAsync(AutoRow row)
    {
        try
        {
            await _host.GenevaAuto.ResetServiceAsync(row.Key, CancellationToken.None);
        }
        catch (Exception e) when (e is GenevaRefusedException or Grpc.Core.RpcException or InvalidOperationException)
        {
            Status = L.F("engine.failed", e.Message);
        }
    }

    [RelayCommand]
    private async Task CopyAsync(string text)
    {
        if (CopyText is { } copy)
            await copy(text);
    }

    // ---- exchange

    /// <summary>What goes into the export file: each working strategy with the names of the services it serves.</summary>
    internal static List<GenevaSharedStrategy> ExportItems(GenevaState state, IEnumerable<AutoService> services)
    {
        var items = new List<GenevaSharedStrategy>();
        foreach (var s in services.Where(s => s.IsActive))
            items.Add(new GenevaSharedStrategy { Strategy = s.Strategy!, Services = ExportName(s) is { Length: > 0 } n ? [n] : [], Fitness = s.Fitness > 0 ? s.Fitness : null });
        foreach (var f in state.Found.Where(f => f.Fitness > 0))
            items.Add(new GenevaSharedStrategy { Strategy = f.Strategy, Services = IsAddress(f.Host) ? [] : [f.Host], Fitness = f.Fitness });
        return items;
    }

    /// <summary>A service's name for another user: the domain or the protocol, never an address of this network.</summary>
    internal static string ExportName(AutoService s) => s.Kind switch
    {
        AutoKind.Web => s.Name,
        AutoKind.Quic => s.Name.Replace(" (QUIC)", "", StringComparison.Ordinal),
        AutoKind.Dns => "DNS",
        _ when s.Host.Length > 0 && !IsAddress(s.Host) => s.Host,
        _ => s.App,
    };

    private static bool IsAddress(string host) => System.Net.IPAddress.TryParse(host.Trim('[', ']'), out _);

    [RelayCommand]
    private async Task ExportAsync()
    {
        var items = ExportItems(_host.Geneva.State, _host.GenevaAuto.View.Services);
        if (items.Count == 0)
        {
            Status = L["auto.export_empty"];
            return;
        }
        var json = GenevaShare.Build(items, DateTimeOffset.Now);
        if (SaveFile is { } save)
        {
            await save($"geneva-strategies-{DateTime.Now:yyyyMMdd}.json", Encoding.UTF8.GetBytes(json));
            Status = L.F("auto.exported", items.Select(i => i.Strategy).Distinct().Count());
        }
    }

    [RelayCommand]
    private async Task ImportAsync()
    {
        if (OpenFile is not { } open || await open() is not { } file)
            return;
        await ImportTextAsync(Encoding.UTF8.GetString(file.Bytes));
    }

    /// <summary>Checks every strategy with <c>geneva check</c> (no rights) and adds the good ones next to the working ones.</summary>
    internal async Task ImportTextAsync(string text)
    {
        var (rows, errors) = GenevaShare.Parse(text);
        if (rows.Count > 0 && _host.GenevaBundle.Exists)
        {
            try
            {
                var checks = await _host.GenevaBundle.CheckAsync([.. rows.Select(r => r.Strategy)]);
                var good = new List<GenevaSharedStrategy>();
                for (int i = 0; i < rows.Count; i++)
                {
                    if (i < checks.Count && checks[i] is { Ok: true, Strategy: { } canonical })
                        good.Add(rows[i] with { Strategy = canonical });
                    else
                        errors.Add($"{rows[i].Strategy}: {(i < checks.Count ? checks[i].Error : "?")}");
                }
                rows = good;
            }
            catch (Exception e) when (e is InvalidOperationException or IOException or FormatException or System.ComponentModel.Win32Exception)
            {
                Status = L.F("engine.failed", e.Message);
                return;
            }
        }
        else if (rows.Count > 0)
        {
            // without geneva nothing can be checked (AGENTS.md rule 4): nothing is taken
            Status = L["engine.bundle_missing"];
            return;
        }
        int added = rows.Count > 0 ? _host.Geneva.Import(rows) : 0;
        Status = L.F("auto.imported", added, rows.Count - added) + (errors.Count > 0 ? "\n" + string.Join("\n", errors.Take(5)) : "");
        _dirty = true;
    }

    [RelayCommand]
    private void RemoveImported(ImportedRow row)
    {
        _host.Geneva.RemoveImported(row.Strategy);
        _dirty = true;
    }

    // ---- refresh

    private void Refresh()
    {
        if (!_dirty)
            return;
        _dirty = false;
        bool en = Loc.Loc.I.English;
        var a = _host.GenevaAuto.View;
        AutoOn = a.Running;
        FirstRun = !a.Running && a.Services.Count == 0;
        AutoPhase = a.Running ? (en ? a.Phase.En : a.Phase.Ru) : a.Enabled ? L["engine.auto_waiting"] : L["engine.auto_off"];
        AutoSummary = a.Services.Count == 0 ? "" : L.F("engine.auto_summary", a.Services.Count, a.Count(AutoStatus.Applied),
            a.Count(AutoStatus.Searching) + a.Count(AutoStatus.Blocked) + a.Count(AutoStatus.Suspected) + a.Count(AutoStatus.Degraded),
            a.Count(AutoStatus.NotFound) + a.Count(AutoStatus.IpBlocked), a.Flows);
        AutoNotice = a.Limited ? L["engine.auto_limited"] : string.Join("\n", a.Problems);
        var rows = a.Services
            .Where(x => AutoShowAll || x.Status is not (AutoStatus.Watching or AutoStatus.NotBlocked))
            .Take(200)
            .Select(x =>
            {
                var (status, brush) = AutoStatusText(x.Status);
                var detail = x.Status == AutoStatus.Searching && x.Name == a.Current && a.Trying is { } t
                    ? L.F("engine.auto_trying", t)
                    : x.Why;
                return new AutoRow(x.Key, x.Name, status, detail, x.Strategy ?? "", brush, x.Status != AutoStatus.Watching);
            }).ToList();
        Sync(AutoServices, rows);
        Sync(AutoGroups, Groups(a));
        var state = _host.Geneva.State;
        Sync(Imported, [.. state.Imported.AsEnumerable().Reverse().Select(i => new ImportedRow(i.Strategy, string.Join(", ", i.Services),
            i.Imported.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)))]);
        Sync(AutoLog, [.. _host.GenevaAuto.Log.TakeLast(150).Reverse()]);
    }

    /// <summary>
    /// The working strategies with the services each serves: the running groups, or (mode off) the applied services
    /// by strategy, so the user sees the same grouping before turning it on.
    /// </summary>
    private List<AutoGroupRow> Groups(GenevaAutoView a)
    {
        if (a.Groups.Count > 0)
        {
            return [.. a.Groups.Select(g => new AutoGroupRow(g.Strategy, string.Join(", ", g.Services),
                g.Stats is { } st ? L.F("engine.auto_counters", st.PktsOut + st.PktsIn, g.Rate.ToString("0", CultureInfo.InvariantCulture), st.Triggered, Uptime(st.UptimeMs)) : "",
                g.Services.Count))];
        }
        return [.. a.Services.Where(s => s.IsActive).GroupBy(s => s.Strategy!, StringComparer.Ordinal)
            .OrderByDescending(g => g.Count())
            .Select(g => new AutoGroupRow(g.Key, string.Join(", ", g.Select(s => s.Name)), "", g.Count()))];
    }

    private (string Text, string Brush) AutoStatusText(AutoStatus s) => s switch
    {
        AutoStatus.Watching => (L["engine.as_watching"], "#8A8A8A"),
        AutoStatus.Suspected => (L["engine.as_suspected"], "#C98A12"),
        AutoStatus.Blocked => (L["engine.as_blocked"], "#D0443E"),
        AutoStatus.NotBlocked => (L["engine.as_notblocked"], "#8A8A8A"),
        AutoStatus.IpBlocked => (L["engine.as_ipblocked"], "#D0443E"),
        AutoStatus.Fallback => (L["engine.as_fallback"], "#8A8A8A"),
        AutoStatus.Searching => (L["engine.as_searching"], "#2F7FD0"),
        AutoStatus.Applied => (L["engine.as_applied"], "#2E9E5B"),
        AutoStatus.Degraded => (L["engine.as_degraded"], "#C98A12"),
        _ => (L["engine.as_notfound"], "#D0443E"),
    };

    private static string Uptime(long ms)
    {
        var t = TimeSpan.FromMilliseconds(ms);
        return t.TotalHours >= 1 ? $"{(int)t.TotalHours}:{t.Minutes:00}:{t.Seconds:00}" : $"{t.Minutes}:{t.Seconds:00}";
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
