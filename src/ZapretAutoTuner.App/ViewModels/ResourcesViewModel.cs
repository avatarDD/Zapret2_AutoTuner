using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.Core.Resources;
using ZapretAutoTuner.Delivery;
using ZapretAutoTuner.Storage;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>One resource in the list: name, version, size, approval and who uses it.</summary>
public sealed class ResourceRowViewModel(ResourceInfo info)
{
    public ResourceInfo Info { get; } = info;

    public string Name => Info.Name;

    public string Details
    {
        get
        {
            var L = Loc.Loc.I;
            var size = Info.Kind is ResourceKind.Hostlist or ResourceKind.Ipset ? L.F("resources.items", Info.Size) : L.F("resources.bytes", Info.Size);
            var parts = new List<string> { L.F("resources.version", Info.Version), size };
            if (Info.Kind == ResourceKind.LuaScript)
                parts.Add(ResourcesViewModel.ApprovalText(Info));
            if (Info.Owners.Count > 0)
                parts.Add(L.F("resources.used_by", Info.Owners.Count));
            return string.Join(" · ", parts);
        }
    }
}

/// <summary>What the Lua approval dialog shows: the whole text, the diff with the version in effect, the check's findings.</summary>
public sealed record LuaApprovalRequest(string Name, int Version, int? ApprovedVersion, string Source, LineDiff Diff, IReadOnlyList<ResourceProblem> Problems);

/// <summary>
/// "Ресурсы" (PLAN 4a.5): hostlists, ipsets, blobs and Lua scripts as named objects of the program. Create, edit
/// and delete them (a used one refuses, naming who uses it); approve a Lua script after seeing its whole text and the
/// diff (the only place that can); send one to the configured router or remove it there after a yes that shows exactly
/// what is written or deleted (AGENTS.md rule 7).
/// </summary>
public sealed partial class ResourcesViewModel : PageViewModel
{
    private static readonly ResourceKind[] KindOrder = [ResourceKind.Hostlist, ResourceKind.Ipset, ResourceKind.Blob, ResourceKind.LuaScript];

    private readonly ResourceStore _store;
    private readonly IRouterResourceProvider? _router;

    public ResourcesViewModel(ResourceStore store, IRouterResourceProvider? router = null)
    {
        _store = store;
        _router = router;
        Loc.Loc.I.PropertyChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(KindTitles));
            OnPropertyChanged(nameof(ContentHint));
            OnPropertyChanged(nameof(RouterText));
            // the rows' texts in the new language, from what is loaded (no database read)
            var keep = Selected?.Info;
            var infos = Items.Select(i => i.Info).ToList();
            Items.Clear();
            foreach (var i in infos)
                Items.Add(new ResourceRowViewModel(i));
            if (keep is not null)
            {
                // a hostlist and an ipset may share a name: the kind tells them apart
                _selected = Items.FirstOrDefault(r => r.Info.Kind == keep.Kind && r.Name == keep.Name);
                OnPropertyChanged(nameof(Selected));
                Approval = keep.Kind == ResourceKind.LuaScript ? ApprovalText(keep) : "";
            }
        };
        Reload();
    }

    public override string TitleKey => "nav.resources";

    /// <summary>The yes/no dialog of the window (rule 7).</summary>
    public Func<string, string, Task<bool>>? Confirm { get; set; }

    /// <summary>The Lua approval dialog: true only when the user pressed "Подтвердить" in it.</summary>
    public Func<LuaApprovalRequest, Task<bool>>? ApproveDialog { get; set; }

    /// <summary>Opens the "Сообщить о проблеме" dialog; set by the window.</summary>
    public Func<BugReportInput, Task>? ReportProblem { get; set; }

    public IReadOnlyList<string> KindTitles => [L["resources.kind_hostlist"], L["resources.kind_ipset"], L["resources.kind_blob"], L["resources.kind_lua"]];

    public IReadOnlyList<string> BlobEncodings => ["auto", "hex", "base64"];

    public ObservableCollection<ResourceRowViewModel> Items { get; } = [];

    public ObservableCollection<string> Problems { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Kind), nameof(IsLua), nameof(IsBlob), nameof(IsList), nameof(ContentHint), nameof(ContentStats), nameof(HasDuplicates))]
    private int _kindIndex;

    public ResourceKind Kind => KindOrder[Math.Clamp(KindIndex, 0, KindOrder.Length - 1)];

    public bool IsLua => Kind == ResourceKind.LuaScript;

    public bool IsBlob => Kind == ResourceKind.Blob;

    public string ContentHint => L["resources.hint_" + ResourceNames.Key(Kind)];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    private ResourceRowViewModel? _selected;

    public bool HasSelection => Selected is not null;

    [ObservableProperty]
    private string _name = "";

    [ObservableProperty]
    private bool _isNew = true;

    [ObservableProperty]
    private string _content = "";

    [ObservableProperty]
    private int _blobEncodingIndex;

    [ObservableProperty]
    private string _approval = "";

    [ObservableProperty]
    private string _status = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasProblem))]
    private BugReportInput? _problem;

    public bool HasProblem => Problem is not null;

    public string RouterText => _router?.Describe() is { } r ? L.F("resources.router", r) : L["resources.no_router"];

    public bool RouterIsGui => _router?.Describe()?.StartsWith(RouterResources.ZapretGui, StringComparison.Ordinal) == true;

    public string RouterPassword
    {
        get => RouterIsGui ? RouterCredentials.GuiPassword : RouterCredentials.RouterPassword;
        set
        {
            if (RouterIsGui)
                RouterCredentials.GuiPassword = value;
            else
                RouterCredentials.RouterPassword = value;
            OnPropertyChanged();
        }
    }

    partial void OnKindIndexChanged(int value)
    {
        Reload();
        New();
    }

    partial void OnSelectedChanged(ResourceRowViewModel? value)
    {
        if (value is not null)
            Load(value.Info);
    }

    /// <summary>Lua approval state in words.</summary>
    public static string ApprovalText(ResourceInfo i) => Loc.Loc.I[i.Approval switch
    {
        LuaApproval.Approved => "resources.approved",
        LuaApproval.ApprovedWithNewDraft => "resources.approved_new_draft",
        _ => "resources.draft",
    }];

    /// <summary>Re-reads the list (after a change here or over MCP) and keeps the selection by name.</summary>
    [RelayCommand]
    public void Reload()
    {
        var keep = Selected?.Info;
        Items.Clear();
        var filter = Filter.Trim();
        var all = _store.List(Kind);
        foreach (var i in all.Where(i => filter.Length == 0 || i.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)))
            Items.Add(new ResourceRowViewModel(i));
        Total = all.Count;
        OnPropertyChanged(nameof(Shown));
        OnPropertyChanged(nameof(NothingFound));
        OnPropertyChanged(nameof(RouterText));
        OnPropertyChanged(nameof(RouterPassword));
        if (keep is not null && Items.FirstOrDefault(r => r.Info.Kind == keep.Kind && r.Name == keep.Name) is { } row)
            Selected = row;
    }

    private void Load(ResourceInfo info)
    {
        if (_store.Get(info.Kind, info.Name) is not { } r)
            return;
        Name = info.Name;
        IsNew = false;
        Content = Text(r.Data);
        BlobEncodingIndex = 1;
        Approval = info.Kind == ResourceKind.LuaScript ? ApprovalText(r.Info) : "";
        Problems.Clear();
        Status = "";
    }

    /// <summary>The editor text of a stored resource: one item per line, hex in rows of 16 bytes, the source.</summary>
    public static string Text(ResourceData d) => d.Kind switch
    {
        ResourceKind.Blob => string.Join("\n", d.Bytes.Chunk(16).Select(c => Convert.ToHexString(c).ToLowerInvariant())),
        ResourceKind.LuaScript => d.Source,
        _ => string.Join("\n", d.Items),
    };

    // ---- the manager's tools (UX audit: only a master-detail editor before): search, import, export, copy, the content's numbers

    /// <summary>Shows only the names with this text in them.</summary>
    [ObservableProperty]
    private string _filter = "";

    partial void OnFilterChanged(string value) => Reload();

    /// <summary>How many of the kind there are, whatever the filter.</summary>
    [ObservableProperty]
    private int _total;

    public string Shown => Filter.Trim().Length == 0 ? "" : L.F("resources.shown", Items.Count, Total);

    public bool NothingFound => Items.Count == 0 && Total > 0;

    /// <summary>Picks files to import (several at once); set by the window.</summary>
    public Func<Task<IReadOnlyList<(string Name, byte[] Bytes)>>>? OpenFiles { get; set; }

    /// <summary>Saves a file the user picks; set by the window.</summary>
    public Func<string, byte[], Task>? SaveFile { get; set; }

    /// <summary>
    /// Files become resources of the current kind, named by the file ("YouTube.txt" → "youtube"). A name that exists gets
    /// a new version (the old ones are kept); a Lua script always lands as a draft that still needs "Подтвердить".
    /// </summary>
    [RelayCommand]
    private async Task ImportAsync()
    {
        if (OpenFiles is null)
            return;
        var files = await OpenFiles();
        if (files.Count == 0)
            return;
        var problems = new List<string>();
        int created = 0, updated = 0, failed = 0;
        string? last = null;
        foreach (var (file, bytes) in files)
        {
            var name = ResourceNames.Normalize(file);
            var input = ImportInput(Kind, name, bytes);
            try
            {
                var exists = _store.Get(Kind, name) is not null;
                var r = exists ? _store.Update(input, "import") : _store.Create(input, "import");
                if (exists)
                    updated++;
                else
                    created++;
                last = r.Info.Name;
                foreach (var w in r.Warnings)
                    problems.Add($"⚠ {file}: {w.Message(!L.English)}");
            }
            catch (ResourceException e)
            {
                failed++;
                problems.Add($"✖ {file}: {L.Pick(e.Ru, e.En)}");
                foreach (var p in e.Problems.Take(5))
                    problems.Add("   " + p.Message(!L.English));
            }
        }
        Selected = null;
        Reload();
        if (last is not null)
            Selected = Items.FirstOrDefault(i => i.Name == last);
        // after the selection: loading the selected one clears the list
        Problems.Clear();
        foreach (var p in problems)
            Problems.Add(p);
        Status = L.F("resources.imported", created, updated, failed);
    }

    /// <summary>A file's bytes as the input of a kind: text by lines for lists, the bytes themselves for a blob.</summary>
    internal static ResourceInput ImportInput(ResourceKind kind, string name, byte[] bytes)
    {
        string Text() => System.Text.Encoding.UTF8.GetString(bytes).TrimStart('\uFEFF');
        return kind switch
        {
            ResourceKind.Hostlist => ResourceInput.Hostlist(name, Text().ReplaceLineEndings("\n").Split('\n')),
            ResourceKind.Ipset => ResourceInput.Ipset(name, Text().ReplaceLineEndings("\n").Split('\n')),
            ResourceKind.Blob => ResourceInput.Blob(name, bytes),
            _ => ResourceInput.Lua(name, Text()),
        };
    }

    /// <summary>The file a resource is exported as: the same name and form zapret2 uses on disk.</summary>
    internal static (string File, byte[] Bytes) ExportFile(StoredResource r) => r.Data.Kind switch
    {
        ResourceKind.Blob => (r.Info.Name + ".bin", r.Data.Bytes),
        ResourceKind.LuaScript => (r.Info.Name + ".lua", System.Text.Encoding.UTF8.GetBytes(r.Data.Source)),
        _ => (r.Info.Name + ".txt", System.Text.Encoding.UTF8.GetBytes(string.Join("\n", r.Data.Items) + "\n")),
    };

    [RelayCommand]
    private async Task ExportAsync()
    {
        if (Selected is not { } row || SaveFile is null || _store.Get(row.Info.Kind, row.Name) is not { } r)
            return;
        var (file, bytes) = ExportFile(r);
        await SaveFile(file, bytes);
    }

    /// <summary>A copy under a new name, not saved yet: with "Удалить" on the old one it is a rename.</summary>
    [RelayCommand]
    private void Duplicate()
    {
        if (Selected is not { } row)
            return;
        var content = Content;
        var encoding = BlobEncodingIndex;
        var name = row.Name + "-2";
        for (int n = 3; _store.Get(Kind, name) is not null; n++)
            name = $"{row.Name}-{n}";
        New();
        Name = name;
        Content = content;
        BlobEncodingIndex = encoding;
        Status = L["resources.duplicated"];
    }

    /// <summary>Lines of a list: entries, repeats, comments — counted as the user types.</summary>
    public string ContentStats
    {
        get
        {
            if (Kind is not (ResourceKind.Hostlist or ResourceKind.Ipset))
                return "";
            var (entries, unique, comments) = Count(Content);
            return L.F("resources.stats", entries, entries - unique, comments);
        }
    }

    public bool HasDuplicates => Kind is ResourceKind.Hostlist or ResourceKind.Ipset && Count(Content) is var (e, u, _) && e > u;

    internal static (int Entries, int Unique, int Comments) Count(string text)
    {
        int entries = 0, comments = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in text.ReplaceLineEndings("\n").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0)
                continue;
            if (line.StartsWith('#'))
            {
                comments++;
                continue;
            }
            entries++;
            seen.Add(line);
        }
        return (entries, seen.Count, comments);
    }

    /// <summary>Removes repeated entries and empty lines, keeps the order and the comments.</summary>
    internal static string Dedupe(string text)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var lines = new List<string>();
        foreach (var raw in text.ReplaceLineEndings("\n").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || (!line.StartsWith('#') && !seen.Add(line)))
                continue;
            lines.Add(line);
        }
        return string.Join("\n", lines);
    }

    [RelayCommand]
    private void RemoveDuplicates() => Content = Dedupe(Content);

    partial void OnContentChanged(string value)
    {
        OnPropertyChanged(nameof(ContentStats));
        OnPropertyChanged(nameof(HasDuplicates));
    }

    public bool IsList => Kind is ResourceKind.Hostlist or ResourceKind.Ipset;

    [RelayCommand]
    private void New()
    {
        Selected = null;
        Name = "";
        IsNew = true;
        Content = "";
        BlobEncodingIndex = 0;
        Approval = "";
        Problems.Clear();
        Status = "";
    }

    private ResourceInput Input()
    {
        // "youtube.txt" or "lists/YouTube.txt" is the list "youtube": the file gets its extension when it is written
        var name = ResourceNames.Normalize(Name);
        var lines = Content.ReplaceLineEndings("\n").Split('\n');
        return Kind switch
        {
            ResourceKind.Hostlist => ResourceInput.Hostlist(name, lines),
            ResourceKind.Ipset => ResourceInput.Ipset(name, lines),
            ResourceKind.Blob => ResourceInput.Blob(name, Content, (BlobEncoding)Math.Clamp(BlobEncodingIndex, 0, 2)),
            _ => ResourceInput.Lua(name, Content),
        };
    }

    [RelayCommand]
    private void Save()
    {
        Problems.Clear();
        try
        {
            var r = IsNew ? _store.Create(Input(), "ui") : _store.Update(Input(), "ui");
            Selected = null;
            Reload();
            Selected = Items.FirstOrDefault(i => i.Name == r.Info.Name);
            foreach (var w in r.Warnings)
                Problems.Add("⚠ " + w.Message(!L.English));
            Status = !r.Changed ? L["resources.unchanged"]
                : r.Info.Kind == ResourceKind.LuaScript ? L["resources.saved_draft"]
                : L["resources.saved"];
        }
        catch (ResourceException e)
        {
            Status = L.Pick(e.Ru, e.En);
            foreach (var p in e.Problems)
                Problems.Add((p.IsError ? "✖ " : "⚠ ") + p.Message(!L.English));
        }
    }

    /// <summary>Deletes the selected resource after a yes; one a solution uses is refused with the names of its users.</summary>
    [RelayCommand]
    private async Task DeleteAsync()
    {
        if (Selected is not { } row)
            return;
        try
        {
            if (row.Info.Owners.Count == 0)
            {
                if (Confirm is null || !await Confirm(L["resources.delete_title"], L.F("resources.delete_text", KindName(row.Info.Kind), row.Name, row.Info.Version)))
                    return;
            }
            // with users the store refuses and names them; nothing is asked first
            _store.Delete(row.Info.Kind, row.Name);
            New();
            Reload();
            Status = L.F("resources.deleted", row.Name);
        }
        catch (ResourceException e)
        {
            Status = L.Pick(e.Ru, e.En);
        }
    }

    /// <summary>
    /// The only way a Lua script gets approved: the dialog shows the whole text, the diff with the version in effect
    /// and the check's warnings; "Подтвердить" approves exactly the version shown.
    /// </summary>
    [RelayCommand]
    private async Task ApproveAsync()
    {
        if (Selected is not { Info.Kind: ResourceKind.LuaScript } row || _store.Get(ResourceKind.LuaScript, row.Name) is not { } current)
            return;
        Problems.Clear();
        if (current.Data.Source != Content.ReplaceLineEndings("\n") && !IsNew)
        {
            Status = L["resources.save_first"];
            return;
        }
        if (current.Info.Approval == LuaApproval.Approved)
        {
            Status = L["resources.approved"];
            return;
        }
        var check = LuaScriptCheck.Check(current.Data.Source);
        if (!check.Ok)
        {
            Status = L["resources.check_failed"];
            foreach (var p in check.Problems)
                Problems.Add((p.IsError ? "✖ " : "⚠ ") + p.Message(!L.English));
            return;
        }
        var request = new LuaApprovalRequest(row.Name, current.Version, current.Info.ApprovedVersion, current.Data.Source, _store.Diff(row.Name), check.Problems);
        if (ApproveDialog is null || !await ApproveDialog(request))
            return;
        try
        {
            _store.Approve(row.Name, request.Version, confirmedByUser: true);
            Reload();
            Status = L.F("resources.approved_done", row.Name, request.Version);
        }
        catch (ResourceException e)
        {
            Status = L.Pick(e.Ru, e.En);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // the script file could not be written: the version stays a draft
            Status = e.Message;
        }
    }

    [RelayCommand]
    private Task PushAsync() => RouterAsync(RouterResourceAction.Put);

    [RelayCommand]
    private Task RouterDeleteAsync() => RouterAsync(RouterResourceAction.Delete);

    /// <summary>On the router only after the user saw what is written or deleted and said yes (rule 7).</summary>
    private async Task RouterAsync(RouterResourceAction action)
    {
        if (Selected is not { } row)
            return;
        if (_router?.Describe() is null)
        {
            Status = L["resources.no_router"];
            return;
        }
        Problem = null;
        try
        {
            Status = L["resources.router_preparing"];
            var op = await _router.PrepareAsync(action, row.Info.Kind, row.Name, CancellationToken.None);
            var title = L.F(action == RouterResourceAction.Put ? "resources.push_title" : "resources.router_delete_title", KindName(row.Info.Kind), row.Name, op.Router);
            if (Confirm is null || !await Confirm(title, op.Text(!L.English)))
            {
                Status = "";
                return;
            }
            var r = await op.RunConfirmedAsync(CancellationToken.None);
            Status = r.Ok ? L.F("resources.router_done", op.Router) : L.F("resources.router_failed", r.Error);
            if (!r.Ok)
                Problem = BugReports.From(null, op.Router == RouterResources.ZapretGui ? BugKind.ZapretGuiError : BugKind.AppError, r.Error);
        }
        catch (ResourceException e)
        {
            Status = L.Pick(e.Ru, e.En);
        }
        catch (Exception e)
        {
            // a wrong address, a refused connection, the router said no: shown and offered as a report, never a crash
            Status = L.F("resources.router_failed", e.Message);
            Problem = BugReports.From(e);
        }
    }

    [RelayCommand]
    private async Task ReportProblemAsync()
    {
        if (ReportProblem is not null)
            await ReportProblem(Problem ?? BugReports.From(null, BugKind.AppError, Status));
    }

    private string KindName(ResourceKind k) => L.Pick(ResourceNames.KindNameRu(k), ResourceNames.KindNameEn(k));
}
