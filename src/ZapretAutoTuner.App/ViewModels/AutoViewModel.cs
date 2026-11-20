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

/// <summary>What a service row shows, computed on each refresh.</summary>
internal sealed record AutoRowData(string Key, string Name, string Status, string Detail, string Strategy, string Brush, bool CanReset,
    string Tags, bool CanPin, bool Pinned, string PinText);

/// <summary>
/// A service of the "Авто" mode: what it is, where it stands, the strategy applied to it. One object per service for
/// as long as it is listed: a refresh changes its texts in place, so its row, its "⋯" button and an open menu stay
/// where they are while the search moves on.
/// </summary>
public sealed partial class AutoRow : ObservableObject
{
    public AutoRow(AutoViewModel owner, string key)
    {
        Owner = owner;
        Key = key;
    }

    /// <summary>The page: the menu's commands are bound through it (a menu is a popup, outside the list's tree).</summary>
    public AutoViewModel Owner { get; }

    public string Key { get; }

    [ObservableProperty]
    private string _name = "";

    [ObservableProperty]
    private string _status = "";

    [ObservableProperty]
    private string _detail = "";

    [ObservableProperty]
    private string _strategy = "";

    [ObservableProperty]
    private string _brush = "";

    [ObservableProperty]
    private bool _canReset;

    /// <summary>Importance and pin as words: "важно · закреплена".</summary>
    [ObservableProperty]
    private string _tags = "";

    [ObservableProperty]
    private bool _canPin;

    [ObservableProperty]
    private bool _pinned;

    [ObservableProperty]
    private string _pinText = "";

    internal void Set(AutoRowData d)
    {
        Name = d.Name;
        Status = d.Status;
        Detail = d.Detail;
        Strategy = d.Strategy;
        Brush = d.Brush;
        CanReset = d.CanReset;
        Tags = d.Tags;
        CanPin = d.CanPin;
        Pinned = d.Pinned;
        PinText = d.PinText;
    }
}

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
        _splitIndex = host.Geneva.AutoSplit ? 1 : 0;
        host.Geneva.Changed += () => _dirty = true;
        host.GenevaAuto.Changed += () => _dirty = true;
        // lists changed elsewhere (MCP geneva_auto_lists): the boxes show them, so a later "Сохранить" does not undo them
        host.Geneva.ListsChanged += () =>
        {
            _listsLoaded = false;
            _dirty = true;
        };
        Loc.Loc.I.PropertyChanged += (_, _) => _dirty = true;
        _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(500), DispatcherPriority.Background, (_, _) => Refresh());
        _timer.Start();
    }

    public override string TitleKey => "nav.auto";

    public override string? SectionKey => "nav.section_auto";

    public override void OnShown()
    {
        _resort = true;
        _dirty = true;
        OnPropertyChanged(nameof(BrowserCheck)); // the manual page shares the switch
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

    partial void OnAutoShowAllChanged(bool value)
    {
        _resort = true;
        _dirty = true;
    }

    /// <summary>Only the services whose name, address or protocol has this text (the list is long).</summary>
    [ObservableProperty]
    private string _serviceFilter = "";

    partial void OnServiceFilterChanged(string value)
    {
        _resort = true;
        _dirty = true;
    }

    /// <summary>Services shown out of those the filter and "show all" leave: "12 из 340".</summary>
    [ObservableProperty]
    private string _filterCount = "";

    /// <summary>The list is put in order again (opening the page, a new filter); else rows keep their places.</summary>
    private bool _resort = true;

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

    /// <summary>"Итоговая проверка в браузере": a site's strategy opens the site in the program's browser before it is applied.</summary>
    public bool BrowserCheck
    {
        get => _host.Geneva.BrowserCheck;
        set
        {
            if (value != _host.Geneva.BrowserCheck)
            {
                _host.Geneva.BrowserCheck = value;
                OnPropertyChanged();
            }
        }
    }

    /// <summary>0: all threads search one service; 1: they are split between several services searched at once.</summary>
    [ObservableProperty]
    private int _splitIndex;

    partial void OnSplitIndexChanged(int value)
    {
        if (_host.Geneva.AutoSplit != (value == 1))
            _host.Geneva.AutoSplit = value == 1;
        WorkersNote = WorkersText();
    }

    private string WorkersText()
    {
        var notes = new List<string>();
        if (SplitIndex == 1)
        {
            var g = _host.Geneva;
            notes.Add(g.AutoSearches > 1 ? L.F("auto.split_note", g.AutoSearches, g.AutoWorkers) : L["auto.split_note_one"]);
            // the working strategies hold the groups the searches need for their trials: fewer run side by side
            if (_host.GenevaAuto.View is { Running: true, SearchSlots: var now } && now < g.AutoSearches)
                notes.Add(L.F("auto.split_limited", now, AutoRules.MaxGroups));
        }
        if ((Workers ?? 1) > 1 && !_workersSupported)
            notes.Add(L["auto.workers_old"]);
        return string.Join(" ", notes);
    }

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

    // ---- one service: the user's word

    [RelayCommand]
    private void CheckNow(AutoRow row)
    {
        _host.GenevaAuto.CheckNow(row.Key);
        Status = L.F("auto.checking", row.Name);
    }

    [RelayCommand]
    private void MarkImportant(AutoRow row) => _host.GenevaAuto.SetPriority(row.Key, AutoUserPriority.Important);

    [RelayCommand]
    private void MarkUnimportant(AutoRow row) => _host.GenevaAuto.SetPriority(row.Key, AutoUserPriority.Unimportant);

    [RelayCommand]
    private void MarkAuto(AutoRow row) => _host.GenevaAuto.SetPriority(row.Key, AutoUserPriority.None);

    /// <summary>"Не подбирать": the service's site (or name, or address) joins the list, and it leaves the problems.</summary>
    [RelayCommand]
    private void NoSearch(AutoRow row)
    {
        if (_host.GenevaAuto.View.Services.FirstOrDefault(x => x.Key == row.Key) is not { } s || NoSearchEntry(s) is not { } entry)
            return;
        var lists = _host.Geneva.Lists;
        if (!lists.NoSearch.Contains(entry, StringComparer.OrdinalIgnoreCase))
            _host.Geneva.Lists = lists with { NoSearch = [.. lists.NoSearch, entry] };
        Status = L.F("auto.no_search_done", entry);
    }

    /// <summary>What "Не подбирать" adds for a service: the site, the server's name, or its address.</summary>
    internal static string? NoSearchEntry(AutoService s) => s.Kind switch
    {
        AutoKind.Web or AutoKind.Quic => AutoFamilies.SiteOf(s),
        _ when s.Host.Length > 0 && AutoNameList.Problem(s.Host) is null && !IsAddress(s.Host) => s.Host,
        _ => s.Address?.ToString(),
    };

    [RelayCommand]
    private void TogglePin(AutoRow row) => _host.GenevaAuto.Pin(row.Key, !row.Pinned);

    /// <summary>The service whose own strategy the user is about to try (the small form above the list).</summary>
    [ObservableProperty]
    private AutoRow? _tryRow;

    [ObservableProperty]
    private string _tryStrategy = "";

    [ObservableProperty]
    private string _tryTitle = "";

    partial void OnTryRowChanged(AutoRow? value) => TryTitle = value is null ? "" : L.F("auto.try_title", value.Name);

    [ObservableProperty]
    private bool _tryBusy;

    [RelayCommand]
    private void BeginTry(AutoRow row)
    {
        TryRow = row;
        TryStrategy = row.Strategy;
    }

    [RelayCommand]
    private void CancelTry() => TryRow = null;

    [RelayCommand]
    private async Task TryAsync()
    {
        if (TryRow is not { } row)
            return;
        TryBusy = true;
        Status = L.F("auto.try_running", row.Name);
        try
        {
            bool ok = await _host.GenevaAuto.TryStrategyAsync(row.Key, TryStrategy, CancellationToken.None);
            Status = ok ? L.F("auto.try_ok", row.Name) : L.F("auto.try_failed", row.Name);
            if (ok)
                TryRow = null;
        }
        catch (Exception e) when (e is GenevaRefusedException or Grpc.Core.RpcException or InvalidOperationException)
        {
            Status = L.F("engine.failed", e.Message);
        }
        finally
        {
            TryBusy = false;
        }
    }

    // ---- the lists

    [ObservableProperty]
    private string _importantText = "";

    [ObservableProperty]
    private string _unimportantText = "";

    [ObservableProperty]
    private string _excludedText = "";

    [ObservableProperty]
    private string _noSearchText = "";

    [ObservableProperty]
    private bool _listsBusy;

    [ObservableProperty]
    private bool _knownImportant = true;

    [ObservableProperty]
    private bool _byName = true;

    [ObservableProperty]
    private string _listsStatus = "";

    private volatile bool _listsLoaded;

    private void LoadLists()
    {
        var l = _host.Geneva.Lists;
        ImportantText = string.Join("\n", l.Important);
        UnimportantText = string.Join("\n", l.Unimportant);
        ExcludedText = string.Join("\n", l.Excluded);
        NoSearchText = string.Join("\n", l.NoSearch);
        KnownImportant = l.KnownImportant;
        ByName = _host.Geneva.ByName;
        _listsLoaded = true;
    }

    private static List<string> Lines(string text) =>
        [.. text.Split(['\n', '\r', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase)];

    /// <summary>Reads a URL as text (RIPEstat for the AS networks); tests pass their own.</summary>
    internal Func<string, CancellationToken, Task<string>> Get { get; set; } = AsnPrefixes.DefaultGet;

    private DateTime _asnCheckedAt;
    private int _asnRefreshing;

    /// <summary>
    /// The AS networks of the lists fetched again when they are a week old, without the user saving the lists: checked
    /// at start and every few hours. Only the networks change; the lists stay as they are now.
    /// </summary>
    private async Task RefreshStaleAsnAsync()
    {
        if (Interlocked.Exchange(ref _asnRefreshing, 1) == 1)
            return;
        try
        {
            var lists = _host.Geneva.Lists;
            if (!AsnPrefixes.Stale(lists, DateTime.UtcNow))
                return;
            var (fresh, _) = await AsnPrefixes.RefreshAsync(lists, Get, DateTime.UtcNow, CancellationToken.None);
            _host.Geneva.Lists = _host.Geneva.Lists with { AsnPrefixes = fresh.AsnPrefixes, AsnFetched = fresh.AsnFetched };
        }
        finally
        {
            Volatile.Write(ref _asnRefreshing, 0);
        }
    }

    [RelayCommand]
    private async Task SaveListsAsync()
    {
        var important = Lines(ImportantText);
        var unimportant = Lines(UnimportantText);
        var excluded = Lines(ExcludedText);
        var noSearch = Lines(NoSearchText);
        // "не трогать" goes to geneva and the firewall as it is: names and networks only; the others take masks and AS
        if (excluded.Select(AutoNameList.Problem).Concat(important.Concat(unimportant).Concat(noSearch).Select(AutoNameList.MaskProblem))
            .FirstOrDefault(p => p is not null) is { } bad)
        {
            ListsStatus = bad;
            return;
        }
        var before = _host.Geneva.Lists;
        var lists = before with { Important = important, Unimportant = unimportant, Excluded = excluded, NoSearch = noSearch, KnownImportant = KnownImportant };
        // the networks of the AS numbers named (fetched only when missing or a week old; those no longer named go)
        bool fetch = AsnPrefixes.Stale(lists, DateTime.UtcNow);
        ListsBusy = fetch;
        if (fetch)
            ListsStatus = L["auto.asn_loading"];
        List<string> problems;
        try
        {
            (lists, problems) = await AsnPrefixes.RefreshAsync(lists, Get, DateTime.UtcNow, CancellationToken.None);
        }
        finally
        {
            ListsBusy = false;
        }
        // the fetch takes a while: what was added meanwhile elsewhere (a row's "Не подбирать", MCP) is kept
        _host.Geneva.Lists = AsnPrefixes.Merge(lists, before, _host.Geneva.Lists);
        if (_host.Geneva.ByName != ByName)
            _host.Geneva.ByName = ByName;
        ListsStatus = problems.Count == 0 ? L["auto.lists_saved"] : L["auto.lists_saved"] + "\n" + string.Join("\n", problems);
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
        if (!_listsLoaded)
            LoadLists();
        if (DateTime.UtcNow - _asnCheckedAt > TimeSpan.FromHours(6))
        {
            _asnCheckedAt = DateTime.UtcNow;
            _ = RefreshStaleAsnAsync();
        }
        // the split changed elsewhere (MCP geneva_auto_lists): the box follows, without writing it back
        int split = _host.Geneva.AutoSplit ? 1 : 0;
        if (split != SplitIndex)
            SplitIndex = split;
        bool en = Loc.Loc.I.English;
        var a = _host.GenevaAuto.View;
        var searches = _host.Geneva.Searches;
        AutoOn = a.Running;
        FirstRun = !a.Running && a.Services.Count == 0;
        AutoPhase = a.Running ? (en ? a.Phase.En : a.Phase.Ru) : a.Enabled ? L["engine.auto_waiting"] : L["engine.auto_off"];
        AutoSummary = a.Services.Count == 0 ? "" : L.F("engine.auto_summary", a.Services.Count, a.Count(AutoStatus.Applied),
            a.Count(AutoStatus.Searching) + a.Count(AutoStatus.Blocked) + a.Count(AutoStatus.Suspected) + a.Count(AutoStatus.Degraded),
            a.Count(AutoStatus.NotFound) + a.Count(AutoStatus.IpBlocked), a.Flows);
        AutoNotice = a.Limited ? L["engine.auto_limited"] : string.Join("\n", a.Problems);
        var filter = ServiceFilter.Trim();
        var shown = a.Services
            .Where(x => AutoShowAll || x.Status is not (AutoStatus.Watching or AutoStatus.NotBlocked))
            .ToList();
        var matching = filter.Length == 0 ? shown : shown.Where(x => Matches(x, filter)).ToList();
        FilterCount = filter.Length == 0 ? "" : L.F("auto.filter_count", Math.Min(matching.Count, MaxRows), shown.Count);
        var rows = matching
            .Take(MaxRows)
            .Select(x =>
            {
                var (status, brush) = AutoStatusText(x.Status);
                var work = x.Status == AutoStatus.Searching ? a.Searches.FirstOrDefault(w => w.Key == x.Key) : null;
                var evolve = work?.SearchId is { } sid ? searches.FirstOrDefault(v => v.Id == sid) : null;
                var detail = work?.Trying is { } t ? L.F("engine.auto_trying", t)
                    : evolve is not null ? L.F("auto.evolving", Math.Max(0, evolve.Generation + 1), evolve.Generations, evolve.Probing, evolve.Workers, evolve.Evaluated)
                    : x.Why;
                var tags = new List<string>();
                if (x.Priority == AutoPriority.Important)
                    tags.Add(L["auto.tag_important"]);
                else if (x.Priority == AutoPriority.Background)
                    tags.Add(L["auto.tag_background"]);
                if (x.Pinned)
                    tags.Add(L["auto.tag_pinned"]);
                return new AutoRowData(x.Key, x.Name, status, detail, x.Strategy ?? "", brush, x.Status != AutoStatus.Watching,
                    string.Join(" · ", tags), x.Strategy is not null, x.Pinned, x.Pinned ? L["auto.unpin"] : L["auto.pin"]);
            }).ToList();
        SyncRows(rows, _resort);
        _resort = false;
        WorkersNote = WorkersText();
        Sync(AutoGroups, Groups(a));
        var state = _host.Geneva.State;
        Sync(Imported, [.. state.Imported.AsEnumerable().Reverse().Select(i => new ImportedRow(i.Strategy, string.Join(", ", i.Services),
            i.Imported.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)))]);
        Sync(AutoLog, [.. _host.GenevaAuto.Log.TakeLast(150).Reverse()]);
    }

    /// <summary>The most services listed at once.</summary>
    public const int MaxRows = 200;

    private static bool Matches(AutoService x, string filter) =>
        x.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)
        || x.Host.Contains(filter, StringComparison.OrdinalIgnoreCase)
        || x.App.Contains(filter, StringComparison.OrdinalIgnoreCase)
        || x.Addresses.Any(a => a.Ip.Contains(filter, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The rows in place: a listed service keeps its row object and (unless <paramref name="resort"/>) its place, and
    /// only its texts change; one that left goes, a new one joins at the end. The search changing what it tries no
    /// longer moves the list under the user's mouse, and an open "⋯" menu stays open.
    /// </summary>
    internal void SyncRows(IReadOnlyList<AutoRowData> rows, bool resort)
    {
        var wanted = rows.ToDictionary(r => r.Key, StringComparer.Ordinal);
        for (int i = AutoServices.Count - 1; i >= 0; i--)
        {
            if (!wanted.ContainsKey(AutoServices[i].Key))
                AutoServices.RemoveAt(i);
        }
        var have = AutoServices.ToDictionary(r => r.Key, StringComparer.Ordinal);
        if (resort)
        {
            for (int i = 0; i < rows.Count; i++)
            {
                if (!have.TryGetValue(rows[i].Key, out var row))
                {
                    row = new AutoRow(this, rows[i].Key);
                    AutoServices.Insert(i, row);
                }
                else
                {
                    int at = AutoServices.IndexOf(row);
                    if (at != i)
                        AutoServices.Move(at, i);
                }
                row.Set(rows[i]);
            }
            return;
        }
        foreach (var d in rows)
        {
            if (!have.TryGetValue(d.Key, out var row))
            {
                row = new AutoRow(this, d.Key);
                AutoServices.Add(row);
            }
            row.Set(d);
        }
    }

    /// <summary>
    /// The working strategies with the services each serves: the running groups, or (mode off) the applied services
    /// by strategy, so the user sees the same grouping before turning it on.
    /// </summary>
    private List<AutoGroupRow> Groups(GenevaAutoView a)
    {
        if (a.Groups.Count > 0)
        {
            // a strategy only being tried is not a working one: it is not listed (the service's row says what is tried)
            return [.. a.Groups.Where(g => !g.Trial).Select(g => new AutoGroupRow(g.Strategy, (g.ByName ? L["auto.by_name"] + ": " : "") + string.Join(", ", g.Services),
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
        if (target.Count == items.Count)
        {
            // the counters change every few seconds: only the rows that differ are replaced, the card keeps its size
            for (int i = 0; i < items.Count; i++)
            {
                if (!EqualityComparer<T>.Default.Equals(target[i], items[i]))
                    target[i] = items[i];
            }
            return;
        }
        target.Clear();
        foreach (var i in items)
            target.Add(i);
    }
}
