using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Resources;
using ZapretAutoTuner.Delivery;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// Strategy resources over MCP (PLAN 4a.5): hostlists, ipsets, blobs and Lua scripts as named objects of the program.
/// The model passes a name and the content as typed data (<c>domains</c>, <c>entries</c>, <c>hex</c>,
/// <c>lua_source</c>), never a path; every change asks the user in the AutoTuner window. A Lua script created or
/// edited here is a draft: approving it (so it runs or leaves the PC) is a button in the window, which this layer has
/// no way to press.
/// </summary>
public sealed class ResourceTools(McpSession session)
{
    public const string NamePattern = "^[a-z0-9_-]{1,48}$";
    public const int MaxListItems = 10_000;
    public const int MaxHexChars = 40_000;

    /// <summary>A Lua source or a diff longer than this is cut in an answer (and says so).</summary>
    public const int MaxTextChars = 20_000;

    private static readonly string[] Kinds = ["hostlist", "ipset", "blob", "lua"];

    private static JsonObject Kind(string what = "Resource kind") => S.Str(what, values: Kinds);

    private static JsonObject Name() => S.Str("Resource name: lower-case letters, digits, _ and - (a blob name must also be a Lua identifier: no -)", 48, NamePattern);

    private static IEnumerable<(string, JsonObject)> Content() =>
    [
        ("domains", S.Arr("hostlist: the domains, one per item (normalised: lower case, IDN to punycode, ^domain for no subdomains)", S.Str("A domain", 260), MaxListItems)),
        ("entries", S.Arr("ipset: IP addresses and CIDRs, one per item", S.Str("An address or CIDR", 64), MaxListItems)),
        ("hex", S.Str("blob: the bytes in hex (spaces and : allowed), 1 to 16384 bytes", MaxHexChars)),
        ("lua_source", S.Str("lua: the script source; desync functions are function name(ctx, desync) and must not reuse zapret2's names", ResourceRules.MaxLuaBytes)),
    ];

    public static IReadOnlyList<McpToolDefinition> Definitions { get; } =
    [
        new("resource_list", McpScope.Resources,
            "The user's strategy resources (hostlists, ipsets, blobs, Lua scripts) with version, size, the solutions that use them and, for Lua, whether a version is approved.",
            S.Obj([("kind", Kind("Only this kind"))])),
        new("resource_get", McpScope.Resources,
            "One resource with its content (domains, entries, hex or lua_source) and its versions. Addresses in answers are masked as in the report.",
            S.Obj([("kind", Kind()), ("name", Name()), ("version", S.Int("A version (default: the current one)", 1, 1_000_000))], "kind", "name")),
        new("resource_diff", McpScope.Resources,
            "Line diff between two versions of a resource. For a Lua script the default is from the approved version to the current draft (what the user will be shown before approving).",
            S.Obj([("kind", Kind()), ("name", Name()), ("from_version", S.Int("Old version (default: approved for Lua, else the previous one)", 1, 1_000_000)), ("to_version", S.Int("New version (default: the current one)", 1, 1_000_000))], "kind", "name")),
        new("resource_create", McpScope.Resources,
            "Creates a resource from typed content: domains for a hostlist, entries for an ipset, hex for a blob, lua_source for a Lua script. Checked first; then the user decides in the AutoTuner window (pending until then, call again with the same arguments). A Lua script is created as a draft: you cannot approve it, only the user can, in the AutoTuner window after seeing the whole text and the diff.",
            S.Obj([("kind", Kind()), ("name", Name()), .. Content()], "kind", "name"), Confirms: true),
        new("resource_update", McpScope.Resources,
            "Replaces the content of a resource with a new version (same fields as resource_create); the user decides in the AutoTuner window. Editing a Lua script makes a new draft: the approved version stays in effect until the user approves the new one in the window; you cannot approve it.",
            S.Obj([("kind", Kind()), ("name", Name()), .. Content()], "kind", "name"), Confirms: true),
        new("resource_delete", McpScope.Resources,
            "Deletes a resource with all its versions after the user's yes. Refused while a saved or the current solution uses it (the answer names them).",
            S.Obj([("kind", Kind()), ("name", Name())], "kind", "name"), Confirms: true),
        new("router_resource_push", McpScope.Resources,
            "Writes a resource to the router the user configured (zapret-gui or nfqws2-keenetic) after the user's yes in the AutoTuner window, which shows exactly what is written. Also needs the export permission. A Lua script goes only in its approved version; a draft is refused.",
            S.Obj([("kind", Kind()), ("name", Name())], "kind", "name"), Confirms: true),
        new("router_resource_delete", McpScope.Resources,
            "Removes one of AutoTuner's resources from the configured router after the user's yes (zapret-gui: refused while a GUI strategy uses it; keenetic: kept as .bak, refused while nfqws2.conf refers to it). Also needs the export permission.",
            S.Obj([("kind", Kind()), ("name", Name())], "kind", "name"), Confirms: true),
    ];

    public IEnumerable<KeyValuePair<string, Func<JsonObject, CancellationToken, Task<JsonObject>>>> Handlers() =>
    [
        new("resource_list", (a, ct) => Run(() => List((string?)a["kind"]))),
        new("resource_get", (a, ct) => Run(() => Get(a))),
        new("resource_diff", (a, ct) => Run(() => Diff(a))),
        new("resource_create", (a, ct) => Run(() => Save(a, create: true))),
        new("resource_update", (a, ct) => Run(() => Save(a, create: false))),
        new("resource_delete", (a, ct) => Run(() => Delete(a))),
        new("router_resource_push", (a, ct) => RouterAsync(RouterResourceAction.Put, a, ct)),
        new("router_resource_delete", (a, ct) => RouterAsync(RouterResourceAction.Delete, a, ct)),
    ];

    private ResourceStore Store => session.Host.Resources ?? throw new ResourceException("ресурсы недоступны в этой программе", "resources are not available in this program");

    private static Task<JsonObject> Run(Func<JsonObject> f)
    {
        try
        {
            return Task.FromResult(f());
        }
        catch (ResourceException e)
        {
            return Task.FromResult(Refusal(e));
        }
    }

    private static JsonObject Refusal(ResourceException e) => new()
    {
        ["ok"] = false,
        ["error"] = e.En + " / " + e.Ru,
        ["problems"] = Problems(e.Problems.Where(p => p.IsError)),
        ["warnings"] = Problems(e.Problems.Where(p => !p.IsError)),
    };

    private static JsonArray? Problems(IEnumerable<ResourceProblem> problems)
    {
        var list = problems.Take(20).ToList();
        return list.Count == 0 ? null : new JsonArray([.. list.Select(p => (JsonNode)new JsonObject { ["code"] = p.Code, ["item"] = p.Item, ["en"] = p.En, ["ru"] = p.Ru })]);
    }

    private static ResourceKind KindOf(JsonObject a) => ResourceNames.ParseKey((string)a["kind"]!);

    internal static JsonObject Info(ResourceInfo i) => new()
    {
        ["kind"] = ResourceNames.Key(i.Kind),
        ["name"] = i.Name,
        ["version"] = i.Version,
        ["size"] = i.Size,
        ["size_unit"] = i.Kind is ResourceKind.Hostlist or ResourceKind.Ipset ? "items" : "bytes",
        ["approval"] = i.Approval switch
        {
            LuaApproval.Draft => "draft",
            LuaApproval.Approved => "approved",
            LuaApproval.ApprovedWithNewDraft => "approved_with_new_draft",
            _ => null,
        },
        ["approved_version"] = i.ApprovedVersion,
        ["used_by"] = new JsonArray([.. i.Owners.Select(o => (JsonNode)JsonValue.Create(o))]),
        ["updated"] = i.Updated.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture),
    };

    private JsonObject List(string? kind)
    {
        var list = Store.List(kind is null ? null : ResourceNames.ParseKey(kind));
        return new JsonObject
        {
            ["ok"] = true,
            ["resources"] = new JsonArray([.. list.Select(i => (JsonNode)Info(i))]),
            ["hint"] = "Lua drafts run nowhere until the user approves them in the AutoTuner window (Resources page); you cannot approve them",
        };
    }

    private JsonObject Get(JsonObject a)
    {
        var kind = KindOf(a);
        var name = (string)a["name"]!;
        var r = Store.Get(kind, name, (int?)a["version"]) ?? throw NotFound(kind, name, (int?)a["version"]);
        var o = Info(r.Info);
        o["ok"] = true;
        o["shown_version"] = r.Version;
        switch (kind)
        {
            case ResourceKind.Hostlist:
                o["domains"] = new JsonArray([.. r.Data.Items.Select(d => (JsonNode)JsonValue.Create(d))]);
                break;
            case ResourceKind.Ipset:
                o["entries"] = new JsonArray([.. r.Data.Items.Select(d => (JsonNode)JsonValue.Create(d))]);
                break;
            case ResourceKind.Blob:
                o["hex"] = Convert.ToHexString(r.Data.Bytes).ToLowerInvariant();
                break;
            default:
                o["lua_source"] = Cut(r.Data.Source, out var cut);
                o["source_truncated"] = cut ? true : null;
                o["functions"] = new JsonArray([.. r.Data.Functions.Select(f => (JsonNode)JsonValue.Create(f))]);
                break;
        }
        o["versions"] = new JsonArray([.. Store.Versions(kind, name).TakeLast(20).Select(v => (JsonNode)new JsonObject
        {
            ["version"] = v.Version,
            ["origin"] = v.Origin,
            ["in_effect"] = v.InEffect,
            ["created"] = v.Created.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture),
        })]);
        return o;
    }

    private JsonObject Diff(JsonObject a)
    {
        var kind = KindOf(a);
        var name = (string)a["name"]!;
        var current = Store.Get(kind, name) ?? throw NotFound(kind, name, null);
        int to = (int?)a["to_version"] ?? current.Version;
        int? from = (int?)a["from_version"] ?? (kind == ResourceKind.LuaScript ? current.Info.ApprovedVersion : to > 1 ? to - 1 : null);
        string Text(int? v) => v is null ? "" : AsText(Store.Get(kind, name, v) ?? throw NotFound(kind, name, v));
        var diff = LineDiff.Compute(Text(from), Text(to));
        return new JsonObject
        {
            ["ok"] = true,
            ["kind"] = ResourceNames.Key(kind),
            ["name"] = name,
            ["from_version"] = from,
            ["to_version"] = to,
            ["added"] = diff.Added,
            ["removed"] = diff.Removed,
            ["diff"] = Cut(diff.ToUnified(), out var cut),
            ["diff_truncated"] = cut ? true : null,
        };
    }

    /// <summary>A version as lines: list items, the blob in 16-byte hex rows, the Lua source.</summary>
    private static string AsText(StoredResource r) => r.Data.Kind switch
    {
        ResourceKind.Blob => string.Join("\n", r.Data.Bytes.Chunk(16).Select(c => Convert.ToHexString(c).ToLowerInvariant())),
        ResourceKind.LuaScript => r.Data.Source,
        _ => string.Join("\n", r.Data.Items),
    };

    private JsonObject Save(JsonObject a, bool create)
    {
        var kind = KindOf(a);
        var name = (string)a["name"]!;
        var input = Input(kind, name, a);
        var (data, warnings) = ResourceRules.Prepare(input);
        var bytes = data.ToBytes();
        var key = $"{(create ? "resource_create" : "resource_update")}:{ResourceNames.Key(kind)}:{name}:{Hash(bytes)}";
        if (session.Confirmations.Report(key) is { } known)
            return known;
        var existing = Store.Get(kind, name);
        if (create && existing is not null)
            return McpErrors.Error($"{ResourceNames.KindNameEn(kind)} '{name}' already exists: use resource_update / уже есть: используйте resource_update");
        if (!create && existing is null)
            return McpErrors.Error($"{ResourceNames.KindNameEn(kind)} '{name}' not found: use resource_create / не найден: используйте resource_create");
        if (existing is not null && existing.Data.ToBytes().AsSpan().SequenceEqual(bytes))
            return new JsonObject { ["ok"] = true, ["status"] = "unchanged", ["resource"] = Info(existing.Info) };
        var (ru, en) = RouterResources.Preview(data);
        bool lua = kind == ResourceKind.LuaScript;
        var warnRu = warnings.Count == 0 ? "" : "\n\nПредупреждения:\n" + string.Join("\n", warnings.Take(10).Select(w => "⚠ " + w.Message(true)));
        var warnEn = warnings.Count == 0 ? "" : "\n\nWarnings:\n" + string.Join("\n", warnings.Take(10).Select(w => "⚠ " + w.Message(false)));
        var draftRu = lua ? "\n\nЭто черновик: скрипт не запустится и не уйдёт на роутер, пока вы сами не подтвердите его на странице «Ресурсы»." : "";
        var draftEn = lua ? "\n\nThis is a draft: the script does not run or go to the router until you approve it yourself on the Resources page." : "";
        if (lua)
        {
            ru = "Lua-скрипт:\n" + data.Source;
            en = "Lua script:\n" + data.Source;
        }
        var request = new ConfirmRequest(create ? "resource_create" : "resource_update",
            create ? $"Внешний агент создаёт {ResourceNames.KindNameRu(kind)} «{name}»" : $"Внешний агент изменяет {ResourceNames.KindNameRu(kind)} «{name}»",
            create ? $"An external agent creates the {ResourceNames.KindNameEn(kind)} '{name}'" : $"An external agent changes the {ResourceNames.KindNameEn(kind)} '{name}'",
            ru + warnRu + draftRu, en + warnEn + draftEn);
        return session.Confirmations.Request(key, request, _ =>
        {
            var r = create ? Store.Create(input, "mcp") : Store.Update(input, "mcp");
            return Task.FromResult(new JsonObject
            {
                ["ok"] = true,
                ["status"] = r.Changed ? (create ? "created" : "updated") : "unchanged",
                ["resource"] = Info(r.Info),
                ["warnings"] = Problems(r.Warnings),
                ["note"] = lua ? "the script is a draft; only the user can approve it in the AutoTuner window / черновик: подтвердить может только пользователь в окне AutoTuner" : null,
            });
        });
    }

    private static ResourceInput Input(ResourceKind kind, string name, JsonObject a)
    {
        var field = kind switch
        {
            ResourceKind.Hostlist => "domains",
            ResourceKind.Ipset => "entries",
            ResourceKind.Blob => "hex",
            _ => "lua_source",
        };
        var given = new[] { "domains", "entries", "hex", "lua_source" }.Where(a.ContainsKey).ToList();
        if (given.Count != 1 || given[0] != field)
            throw new ResourceException($"для вида {ResourceNames.Key(kind)} нужно ровно одно поле {field}", $"a {ResourceNames.Key(kind)} takes exactly one content field: {field}");
        static IEnumerable<string> Items(JsonNode? n) => n!.AsArray().Select(x => (string?)x ?? "");
        return kind switch
        {
            ResourceKind.Hostlist => ResourceInput.Hostlist(name, Items(a["domains"])),
            ResourceKind.Ipset => ResourceInput.Ipset(name, Items(a["entries"])),
            ResourceKind.Blob => ResourceInput.Blob(name, (string)a["hex"]!, BlobEncoding.Hex),
            _ => ResourceInput.Lua(name, (string)a["lua_source"]!),
        };
    }

    private JsonObject Delete(JsonObject a)
    {
        var kind = KindOf(a);
        var name = (string)a["name"]!;
        var key = $"resource_delete:{ResourceNames.Key(kind)}:{name}";
        if (session.Confirmations.Report(key) is { } known)
            return known;
        var existing = Store.Get(kind, name) ?? throw NotFound(kind, name, null);
        if (existing.Info.Owners.Count > 0)
        {
            return new JsonObject
            {
                ["ok"] = false,
                ["error"] = $"{ResourceNames.KindNameEn(kind)} '{name}' cannot be deleted: used by {string.Join(", ", existing.Info.Owners)} / нельзя удалить: используется в {string.Join(", ", existing.Info.Owners)}",
                ["used_by"] = new JsonArray([.. existing.Info.Owners.Select(o => (JsonNode)JsonValue.Create(o))]),
                ["hint"] = "remove it from the strategy first",
            };
        }
        var request = new ConfirmRequest("resource_delete",
            $"Внешний агент удаляет {ResourceNames.KindNameRu(kind)} «{name}»", $"An external agent deletes the {ResourceNames.KindNameEn(kind)} '{name}'",
            $"Удалить {ResourceNames.KindNameRu(kind)} «{name}» со всеми {existing.Info.Version} версиями? Это нельзя отменить.",
            $"Delete the {ResourceNames.KindNameEn(kind)} '{name}' with all its {existing.Info.Version} versions? This cannot be undone.");
        return session.Confirmations.Request(key, request, _ =>
        {
            Store.Delete(kind, name);
            return Task.FromResult(new JsonObject { ["ok"] = true, ["status"] = "deleted", ["kind"] = ResourceNames.Key(kind), ["name"] = name });
        });
    }

    private async Task<JsonObject> RouterAsync(RouterResourceAction action, JsonObject a, CancellationToken ct)
    {
        // a router write is an export of the user's data: it needs that switch as well as resources
        var perms = session.Permissions();
        if (!perms.Granted(McpScope.Export))
            return perms.Denial(McpScope.Export);
        var kind = KindOf(a);
        var name = (string)a["name"]!;
        var put = action == RouterResourceAction.Put;
        RouterResourceOperation op;
        string key;
        try
        {
            // the content that may leave the PC: for a Lua script the approved version, a draft is refused here
            var version = put ? Hash(Store.ForDelivery(kind, name).ToBytes()) : "";
            key = $"{(put ? "router_resource_push" : "router_resource_delete")}:{ResourceNames.Key(kind)}:{name}:{version}";
            if (session.Confirmations.Report(key) is { } known)
                return known;
            op = await session.Host.PrepareRouterResourceAsync(action, kind, name, ct).ConfigureAwait(false);
        }
        catch (ResourceException e)
        {
            return Refusal(e);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return McpErrors.Error(e.Message);
        }
        var request = new ConfirmRequest(put ? "router_resource_push" : "router_resource_delete",
            put ? $"Внешний агент отправляет {ResourceNames.KindNameRu(kind)} «{name}» на роутер ({op.Router})" : $"Внешний агент удаляет {ResourceNames.KindNameRu(kind)} «{name}» с роутера ({op.Router})",
            put ? $"An external agent sends the {ResourceNames.KindNameEn(kind)} '{name}' to the router ({op.Router})" : $"An external agent removes the {ResourceNames.KindNameEn(kind)} '{name}' from the router ({op.Router})",
            op.Text(true), op.Text(false));
        return session.Confirmations.Request(key, request, async c =>
        {
            var r = await op.RunConfirmedAsync(c).ConfigureAwait(false);
            return new JsonObject
            {
                ["ok"] = r.Ok,
                ["status"] = r.Ok ? (put ? "written" : "deleted") : "failed",
                ["router"] = op.Router,
                ["log"] = new JsonArray([.. r.Log.Select(l => (JsonNode)JsonValue.Create(l))]),
                ["error"] = r.Error,
            };
        });
    }

    private static ResourceException NotFound(ResourceKind kind, string name, int? version) =>
        version is { } v
            ? new($"нет версии {v} ресурса «{name}»", $"no version {v} of the {ResourceNames.KindNameEn(kind)} '{name}'")
            : new($"{ResourceNames.KindNameRu(kind)} «{name}» не найден", $"{ResourceNames.KindNameEn(kind)} '{name}' not found");

    private static string Cut(string s, out bool cut)
    {
        cut = s.Length > MaxTextChars;
        return cut ? s[..MaxTextChars] : s;
    }

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes))[..12].ToLowerInvariant();
}
