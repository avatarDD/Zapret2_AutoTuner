using System.Text;
using ZapretAutoTuner.Core.Catalog;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Resources;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Storage;

/// <summary>Where a Lua script stands: a draft nobody approved, approved, or approved with a newer draft pending.</summary>
public enum LuaApproval
{
    /// <summary>Not a Lua script.</summary>
    None,

    /// <summary>No version is approved: nothing of it runs or leaves the PC.</summary>
    Draft,

    /// <summary>The current version is the approved one.</summary>
    Approved,

    /// <summary>An older version is approved and stays in effect; the current one is a draft waiting for approval.</summary>
    ApprovedWithNewDraft,
}

/// <summary>What the lists show about a resource.</summary>
/// <param name="Size">Entries for a hostlist or ipset, bytes for a blob or a script.</param>
/// <param name="Owners">Saved or current solutions that use it; a used resource cannot be deleted.</param>
public sealed record ResourceInfo(
    ResourceKind Kind,
    string Name,
    int Version,
    int? ApprovedVersion,
    LuaApproval Approval,
    DateTimeOffset Created,
    DateTimeOffset Updated,
    int Size,
    IReadOnlyList<string> Owners);

public sealed record ResourceVersionInfo(int Version, string Origin, DateTimeOffset Created, bool InEffect, long Size);

/// <summary>A resource with the content of one version.</summary>
public sealed record StoredResource(ResourceInfo Info, int Version, ResourceData Data);

/// <summary>The result of a create or update: the resource now, the warnings of the checks, and whether a version was added.</summary>
public sealed record ResourceSaveResult(ResourceInfo Info, IReadOnlyList<ResourceProblem> Warnings, bool Changed);

/// <summary>An approved Lua script as the engine loads it: the file the program wrote and the functions it defines.</summary>
public sealed record UserLuaScript(string Name, int Version, string FileName, string Path, IReadOnlyList<string> Functions);

/// <summary>
/// Strategy resources (PLAN 4a.5) in the local knowledge base: hostlists, ipsets, blobs and Lua scripts as named
/// objects with every version kept. Callers pass names and content, never paths: the program keeps the files it needs
/// (approved Lua for <c>--lua-init=@…</c>) in its own data folder. A resource a saved or the current solution uses
/// cannot be deleted. A Lua script runs with the engine's rights, so a created or edited script is a draft; only
/// <see cref="Approve"/> with the user's confirmation (the UI shows the whole text and the diff first) puts a version
/// in effect, and editing an approved script leaves the approved version in effect until the new one is approved.
/// </summary>
public sealed class ResourceStore
{
    public const string CurrentSolutionOwner = "solution:current";

    private static readonly string[] Origins = ["ui", "mcp", "import"];

    private readonly KnowledgeBase _kb;
    private readonly LuaCatalog _catalog;
    private readonly Lock _files = new();

    /// <summary>The store next to the knowledge base: files go to <c>resources/</c> in the same data folder.</summary>
    public ResourceStore(KnowledgeBase kb, LuaCatalog? catalog = null)
        : this(kb, DefaultRoot(kb), catalog)
    {
    }

    internal ResourceStore(KnowledgeBase kb, string root, LuaCatalog? catalog = null)
    {
        _kb = kb;
        _catalog = catalog ?? LuaCatalog.Default;
        Root = root;
    }

    /// <summary>The program's own folder for resource files (read-only information for the UI).</summary>
    public string Root { get; }

    private string LuaDir => Path.Combine(Root, "lua");

    private static string DefaultRoot(KnowledgeBase kb) =>
        kb.Path == ":memory:"
            ? Path.Combine(Path.GetTempPath(), "ZapretAutoTuner-" + Guid.NewGuid().ToString("N"), "resources")
            : Path.Combine(Path.GetDirectoryName(Path.GetFullPath(kb.Path)) ?? ".", "resources");

    // ---- read ----

    public IReadOnlyList<ResourceInfo> List(ResourceKind? kind = null) =>
        [.. _kb.ResourceRows(kind is null ? null : ResourceNames.Key(kind.Value)).Select(Info)];

    /// <summary>The resource with the content of <paramref name="version"/> (the current one by default), or null.</summary>
    public StoredResource? Get(ResourceKind kind, string name, int? version = null)
    {
        if (Row(kind, name) is not { } row)
            return null;
        var v = version ?? row.Current;
        if (_kb.ResourceContent(row.Id, v) is not { } bytes)
            return null;
        return new StoredResource(Info(row), v, ResourceData.FromBytes(kind, name, bytes));
    }

    public IReadOnlyList<ResourceVersionInfo> Versions(ResourceKind kind, string name)
    {
        var row = Require(kind, name);
        bool lua = kind == ResourceKind.LuaScript;
        return [.. _kb.ResourceVersions(row.Id).Select(v => new ResourceVersionInfo(v.Version, v.Origin, v.Created, lua ? v.Version == row.Approved : v.Version == row.Current, v.Size))];
    }

    // ---- create, update, delete ----

    /// <summary>Creates a resource; refused if one of that kind and name exists or the content fails the checks.</summary>
    /// <param name="origin">Who asked: ui, mcp or import (kept with the version for the journal).</param>
    public ResourceSaveResult Create(ResourceInput input, string origin = "ui") => Save(input, origin, create: true);

    /// <summary>
    /// Replaces the content of an existing resource with a new version (none if the content is the same). For a Lua
    /// script the new version is a draft; an approved version stays in effect until the new one is approved.
    /// </summary>
    public ResourceSaveResult Update(ResourceInput input, string origin = "ui") => Save(input, origin, create: false);

    private ResourceSaveResult Save(ResourceInput input, string origin, bool create)
    {
        if (!Origins.Contains(origin))
            throw new ArgumentException("origin: ui, mcp or import", nameof(origin));
        var (data, warnings) = ResourceRules.Prepare(input, _catalog);
        var key = ResourceNames.Key(data.Kind);
        var existing = _kb.ResourceRow(key, data.Name);
        if (create && existing is not null)
            throw new ResourceException($"{Ru(data.Kind)} «{data.Name}» уже есть: измените его или выберите другое имя",
                $"{En(data.Kind)} '{data.Name}' already exists: update it or choose another name");
        if (!create && existing is null)
            throw NotFound(data.Kind, data.Name);
        if (data.Kind == ResourceKind.LuaScript)
            CheckFunctionsUnique(data);
        var bytes = data.ToBytes();
        if (existing is not null && _kb.ResourceContent(existing.Id, existing.Current) is { } current && current.AsSpan().SequenceEqual(bytes))
            return new ResourceSaveResult(Info(existing), warnings, false);
        if (_kb.AddResourceVersion(key, data.Name, bytes, origin, create) is null)
            throw create
                ? new ResourceException($"{Ru(data.Kind)} «{data.Name}» уже есть", $"{En(data.Kind)} '{data.Name}' already exists")
                : NotFound(data.Kind, data.Name);
        return new ResourceSaveResult(Info(Require(data.Kind, data.Name)), warnings, true);
    }

    /// <summary>Two scripts must not define the same desync function: the engine would keep whichever loads last.</summary>
    private void CheckFunctionsUnique(ResourceData data)
    {
        foreach (var other in _kb.ResourceRows("lua").Where(r => r.Name != data.Name))
        {
            var versions = new[] { other.Current, other.Approved ?? other.Current }.Distinct();
            foreach (var v in versions)
            {
                if (_kb.ResourceContent(other.Id, v) is not { } bytes)
                    continue;
                var clash = LuaScriptCheck.FindDesyncFunctions(Encoding.UTF8.GetString(bytes)).Intersect(data.Functions, StringComparer.Ordinal).FirstOrDefault();
                if (clash is not null)
                    throw new ResourceException($"функция {clash} уже определена в скрипте «{other.Name}»: выберите другое имя",
                        $"function {clash} is already defined in the script '{other.Name}': choose another name");
            }
        }
    }

    /// <summary>Deletes a resource with all its versions; refused while a saved or the current solution uses it.</summary>
    public void Delete(ResourceKind kind, string name)
    {
        var row = Require(kind, name);
        var owners = _kb.ResourceOwners(ResourceNames.Key(kind), name);
        if (owners.Count > 0)
            throw new ResourceException(
                $"{Ru(kind)} «{name}» нельзя удалить: его использует {string.Join(", ", owners.Select(OwnerRu))}. Сначала уберите его из стратегии.",
                $"{En(kind)} '{name}' cannot be deleted: {string.Join(", ", owners.Select(OwnerEn))} uses it. Remove it from the strategy first.");
        _kb.DeleteResource(row.Id);
        if (kind == ResourceKind.LuaScript)
        {
            lock (_files)
            {
                var file = Path.Combine(LuaDir, ResourceNames.LuaFile(name));
                if (File.Exists(file))
                    File.Delete(file);
            }
        }
    }

    // ---- Lua approval ----

    /// <summary>
    /// The line diff the approval dialog shows: from <paramref name="fromVersion"/> (by default the version in effect,
    /// or nothing for a script never approved) to <paramref name="toVersion"/> (by default the current one).
    /// </summary>
    public LineDiff Diff(string luaName, int? fromVersion = null, int? toVersion = null)
    {
        var row = Require(ResourceKind.LuaScript, luaName);
        var from = fromVersion ?? row.Approved;
        var oldText = from is { } f ? Source(row, f) : "";
        return LineDiff.Compute(oldText, Source(row, toVersion ?? row.Current));
    }

    /// <summary>
    /// Puts <paramref name="version"/> of a script in effect. Called by the UI only, after it showed the whole text and
    /// the diff; <paramref name="version"/> must be the current one (what the user saw), so an edit made meanwhile
    /// (for example over MCP) is never approved unseen.
    /// </summary>
    /// <param name="confirmedByUser">Set by the approval dialog only; without it nothing changes.</param>
    public ResourceInfo Approve(string luaName, int version, bool confirmedByUser)
    {
        if (!confirmedByUser)
            throw new InvalidOperationException("подтвердить Lua-скрипт может только пользователь в окне AutoTuner / only the user can approve a Lua script, in the AutoTuner window");
        var row = Require(ResourceKind.LuaScript, luaName);
        if (version != row.Current)
            throw new ResourceException($"скрипт «{luaName}» изменился (сейчас версия {row.Current}, показана {version}): откройте его заново",
                $"the script '{luaName}' changed (now version {row.Current}, shown {version}): open it again");
        var source = Source(row, version);
        var check = LuaScriptCheck.Check(source, _catalog);
        if (!check.Ok)
            throw ResourceException.From([.. check.Problems]);
        // the file first: if it cannot be written, the database does not claim an approved version that has no file
        WriteLua(luaName, source);
        if (row.Approved != version)
            _kb.ApproveResource(row.Id, version);
        return Info(Require(ResourceKind.LuaScript, luaName));
    }

    /// <summary>
    /// The approved scripts with the files the engine loads (<c>--lua-init=@Path</c>), rewritten from the database when
    /// missing or changed on disk: what runs is always the approved text. A script that cannot be read or written is
    /// left out and named in <see cref="ScriptProblems"/> (and in <paramref name="problems"/>); the others still load.
    /// </summary>
    public IReadOnlyList<UserLuaScript> ApprovedScripts(List<string>? problems = null)
    {
        var list = new List<UserLuaScript>();
        var bad = new List<string>();
        foreach (var row in _kb.ResourceRows("lua").Where(r => r.Approved is not null))
        {
            try
            {
                var source = Source(row, row.Approved!.Value);
                var path = WriteLua(row.Name, source);
                list.Add(new UserLuaScript(row.Name, row.Approved.Value, ResourceNames.LuaFile(row.Name), path, LuaScriptCheck.FindDesyncFunctions(source)));
            }
            catch (Exception e) when (e is ResourceException or IOException or UnauthorizedAccessException or ArgumentException)
            {
                bad.Add($"Lua-скрипт «{row.Name}» пропущен / the Lua script '{row.Name}' is skipped: {e.Message}");
            }
        }
        ScriptProblems = bad;
        problems?.AddRange(bad);
        return list;
    }

    /// <summary>The scripts the last <see cref="ApprovedScripts"/> had to leave out, with the reason; empty when none.</summary>
    public IReadOnlyList<string> ScriptProblems { get; private set; } = [];

    /// <summary>Approved function → script file path, for the launch (<see cref="ResourceRefs.LuaPathsFor"/>).</summary>
    public IReadOnlyDictionary<string, string> ApprovedLuaPaths()
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var s in ApprovedScripts())
        {
            foreach (var f in s.Functions)
                map.TryAdd(f, s.Path);
        }
        return map;
    }

    /// <summary>
    /// The validator context with the user's Lua: approved functions are accepted, functions that exist only in a
    /// draft are refused with "approve the script first".
    /// </summary>
    public ValidationContext ApplyTo(ValidationContext ctx)
    {
        var approved = new Dictionary<string, string>(StringComparer.Ordinal);
        var drafts = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var row in _kb.ResourceRows("lua"))
        {
            if (row.Approved is { } a)
            {
                foreach (var f in LuaScriptCheck.FindDesyncFunctions(Source(row, a)))
                    approved[f] = ResourceNames.LuaFile(row.Name);
            }
            if (row.Current != row.Approved)
            {
                foreach (var f in LuaScriptCheck.FindDesyncFunctions(Source(row, row.Current)))
                    drafts.TryAdd(f, row.Name);
            }
        }
        foreach (var f in approved.Keys)
            drafts.Remove(f);
        return ctx.WithUserLua(approved, drafts);
    }

    // ---- solutions ----

    /// <summary>
    /// An imported strategy names its lists by file (<c>--hostlist=lists/youtube.txt</c>); when the file did not come
    /// with it, the store's list of that name (<see cref="ResourceNames.Normalize"/>) takes its place as a reference by
    /// name, which every exporter then carries. Returns the paths it replaced.
    /// </summary>
    public IReadOnlyList<string> ResolveListPaths(Solution s)
    {
        var replaced = new List<string>();
        ListRef Resolve(ListRef r, ResourceKind kind)
        {
            if (r.Path is null)
                return r;
            var name = ResourceNames.Normalize(r.Path);
            if (!ResourceNames.IsValid(name) || Get(kind, name) is null)
                return r;
            replaced.Add(r.Path);
            return new ListRef(name);
        }
        foreach (var p in s.Profiles)
        {
            p.Hostlists = [.. p.Hostlists.Select(r => Resolve(r, ResourceKind.Hostlist))];
            p.HostlistExcludes = [.. p.HostlistExcludes.Select(r => Resolve(r, ResourceKind.Hostlist))];
            p.Ipsets = [.. p.Ipsets.Select(r => Resolve(r, ResourceKind.Ipset))];
            p.IpsetExcludes = [.. p.IpsetExcludes.Select(r => Resolve(r, ResourceKind.Ipset))];
        }
        return [.. replaced.Distinct(StringComparer.Ordinal)];
    }

    /// <summary>
    /// Fills a solution with the store's resources it uses and does not carry yet: lists by name, blobs it names, and
    /// the approved scripts whose functions it calls (as <c>LuaFiles</c>), so every exporter and delivery takes them
    /// along. Refused when it calls a function that exists only in an unapproved draft.
    /// </summary>
    public IReadOnlyList<ResourceRef> AttachTo(Solution s)
    {
        var ctx = ApplyTo(new ValidationContext { Catalog = _catalog });
        var used = ResourceRefs.FunctionsUsed(s.Profiles.Select(p => p.Strategy), _catalog).ToList();
        foreach (var f in used)
        {
            if (ctx.DraftFunctions.TryGetValue(f, out var draft))
                throw new ResourceException($"стратегия вызывает {f} из Lua-скрипта «{draft}», который не подтверждён: подтвердите его в AutoTuner",
                    $"the strategy calls {f} from the Lua script '{draft}', which is not approved: approve it in AutoTuner");
        }
        var added = new List<ResourceRef>();
        foreach (var r in ResourceRefs.Of(s, null, _catalog))
        {
            bool carried = r.Kind switch
            {
                ResourceKind.Hostlist => s.Hostlists.ContainsKey(r.Name),
                ResourceKind.Ipset => s.Ipsets.ContainsKey(r.Name),
                ResourceKind.Blob => s.Blobs.ContainsKey(r.Name),
                _ => s.LuaFiles.ContainsKey(ResourceNames.LuaFile(r.Name)),
            };
            if (carried || Get(r.Kind, r.Name) is not { } stored || r.Kind == ResourceKind.LuaScript)
                continue;
            stored.Data.ApplyTo(s);
            added.Add(r);
        }
        foreach (var f in used)
        {
            if (!ctx.UserFunctions.TryGetValue(f, out var file) || s.LuaFiles.ContainsKey(file))
                continue;
            var name = ResourceNames.LuaNameOf(file)!;
            var row = Require(ResourceKind.LuaScript, name);
            new ResourceData { Kind = ResourceKind.LuaScript, Name = name, Source = Source(row, row.Approved!.Value) }.ApplyTo(s);
            added.Add(new ResourceRef(ResourceKind.LuaScript, name));
        }
        return added;
    }

    /// <summary>
    /// The content that may leave the PC (export, router): the current version, and for a Lua script the approved
    /// one only.
    /// </summary>
    public ResourceData ForDelivery(ResourceKind kind, string name)
    {
        var row = Require(kind, name);
        if (kind != ResourceKind.LuaScript)
            return Get(kind, name)!.Data;
        if (row.Approved is not { } a)
            throw new ResourceException($"Lua-скрипт «{name}» не подтверждён: на роутер и в экспорт он не уходит, пока вы не подтвердите его в AutoTuner",
                $"the Lua script '{name}' is not approved: it does not go to the router or into an export until you approve it in AutoTuner");
        return Get(kind, name, a)!.Data;
    }

    /// <summary>Records which store resources <paramref name="s"/> uses, under <paramref name="owner"/> (replacing the old list).</summary>
    public IReadOnlyList<ResourceRef> SetReferences(string owner, Solution s)
    {
        var scriptOf = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var row in _kb.ResourceRows("lua"))
        {
            foreach (var v in new[] { row.Current, row.Approved ?? row.Current }.Distinct())
            {
                foreach (var f in LuaScriptCheck.FindDesyncFunctions(Source(row, v)))
                    scriptOf.TryAdd(f, row.Name);
            }
        }
        var refs = ResourceRefs.Of(s, scriptOf, _catalog).Where(r => Row(r.Kind, r.Name) is not null).ToList();
        SetReferences(owner, refs);
        return refs;
    }

    public void SetReferences(string owner, IEnumerable<ResourceRef> refs)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(owner);
        _kb.SetResourceRefs(owner, refs.Select(r => (ResourceNames.Key(r.Kind), r.Name)));
    }

    public void ClearReferences(string owner) => _kb.SetResourceRefs(owner, []);

    public IReadOnlyList<string> Owners(ResourceKind kind, string name) => _kb.ResourceOwners(ResourceNames.Key(kind), name);

    public IReadOnlyList<ResourceRef> ReferencesOf(string owner) =>
        [.. _kb.ResourceRefsOf(owner).Select(r => new ResourceRef(ResourceNames.ParseKey(r.Kind), r.Name))];

    // ---- plumbing ----

    private ResourceRow? Row(ResourceKind kind, string name) => _kb.ResourceRow(ResourceNames.Key(kind), name);

    private ResourceRow Require(ResourceKind kind, string name) => Row(kind, name) ?? throw NotFound(kind, name);

    private static ResourceException NotFound(ResourceKind kind, string name) =>
        new($"{Ru(kind)} «{name}» не найден", $"{En(kind)} '{name}' not found");

    private string Source(ResourceRow row, int version) =>
        Encoding.UTF8.GetString(_kb.ResourceContent(row.Id, version) ?? throw new ResourceException($"нет версии {version} скрипта «{row.Name}»", $"no version {version} of the script '{row.Name}'"));

    private string WriteLua(string name, string source)
    {
        lock (_files)
        {
            Directory.CreateDirectory(LuaDir);
            var path = Path.Combine(LuaDir, ResourceNames.LuaFile(name));
            var bytes = new UTF8Encoding(false).GetBytes(source);
            if (!File.Exists(path) || !File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes))
            {
                var tmp = path + ".tmp";
                File.WriteAllBytes(tmp, bytes);
                File.Move(tmp, path, overwrite: true);
            }
            return path;
        }
    }

    private ResourceInfo Info(ResourceRow row)
    {
        var kind = ResourceNames.ParseKey(row.Kind);
        var approval = kind != ResourceKind.LuaScript ? LuaApproval.None
            : row.Approved is null ? LuaApproval.Draft
            : row.Approved == row.Current ? LuaApproval.Approved
            : LuaApproval.ApprovedWithNewDraft;
        var content = _kb.ResourceContent(row.Id, row.Current) ?? [];
        int size = kind is ResourceKind.Hostlist or ResourceKind.Ipset
            ? (content.Length == 0 ? 0 : content.Count((byte)'\n') + 1)
            : content.Length;
        return new ResourceInfo(kind, row.Name, row.Current, row.Approved, approval, row.Created, row.Updated, size, _kb.ResourceOwners(row.Kind, row.Name));
    }

    private static string Ru(ResourceKind k)
    {
        var s = ResourceNames.KindNameRu(k);
        return char.ToUpperInvariant(s[0]) + s[1..];
    }

    private static string En(ResourceKind k)
    {
        var s = ResourceNames.KindNameEn(k);
        return char.ToUpperInvariant(s[0]) + s[1..];
    }

    private static string OwnerRu(string owner) =>
        owner == CurrentSolutionOwner ? "текущее решение" : owner.StartsWith("solution:", StringComparison.Ordinal) ? $"сохранённое решение «{owner[9..]}»" : owner;

    private static string OwnerEn(string owner) =>
        owner == CurrentSolutionOwner ? "the current solution" : owner.StartsWith("solution:", StringComparison.Ordinal) ? $"the saved solution '{owner[9..]}'" : owner;
}
