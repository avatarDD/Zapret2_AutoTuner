using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Resources;

namespace ZapretAutoTuner.Delivery;

/// <summary>What saving into zapret-gui will do: the strategy id it gets (never an existing one) and the steps.</summary>
public sealed record GuiSavePlan(string Id, IReadOnlyList<DeliveryStep> Steps);

/// <summary>
/// Delivery into zapret-gui over its REST API (PLAN 5.3, strategy-export §3.2): create the lists, ipsets and blobs,
/// save the strategy under a new id. Applying it is a separate call behind a second button (AGENTS.md rule 7). Saving
/// never replaces a strategy, but it does replace our <c>zt-*</c> lists, and nfqws2 re-reads a changed list at once:
/// the plan says so for every list the active strategy uses.
/// </summary>
public sealed class ZapretGuiClient
{
    private readonly HttpClient _http;

    /// <param name="http">With <c>BaseAddress</c> set to the GUI, e.g. <c>http://192.168.1.1:8080/</c>.</param>
    public ZapretGuiClient(HttpClient http, string? user = null, string? password = null)
    {
        _http = http;
        if (password is not null)
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user ?? "admin"}:{password}")));
    }

    /// <summary>
    /// The GUI's base address from what the user typed: <c>192.168.1.1:8080</c> becomes <c>http://192.168.1.1:8080/</c>.
    /// Null for anything that is not an http(s) address of a host.
    /// </summary>
    public static Uri? BaseAddress(string? text)
    {
        var t = text?.Trim() ?? "";
        if (t.Length == 0)
            return null;
        if (!t.Contains("://", StringComparison.Ordinal))
            t = "http://" + t;
        if (!Uri.TryCreate(t.TrimEnd('/') + "/", UriKind.Absolute, out var u) || u.Scheme is not ("http" or "https") || u.Host.Length == 0
            || u.Query.Length > 0 || u.Fragment.Length > 0 || u.UserInfo.Length > 0)
            return null;
        return u;
    }

    /// <summary>Reads the GUI's strategies and says what <see cref="SaveAsync"/> will do, for the confirmation dialog.</summary>
    public async Task<GuiSavePlan> PlanAsync(Solution s, CancellationToken ct = default)
    {
        var list = await EnsureAsync(await _http.GetAsync("api/strategies", ct).ConfigureAwait(false), ct).ConfigureAwait(false);
        var strategies = list?["strategies"]?.AsArray().OfType<JsonObject>().ToList() ?? [];
        var taken = strategies.Select(x => (string?)x["id"]).OfType<string>().ToHashSet(StringComparer.Ordinal);
        var active = strategies.FirstOrDefault(x => (bool?)x["is_active"] == true);
        var activeArgs = string.Join(' ', active?["profiles"]?.AsArray().Select(p => (string?)p?["args"]) ?? []);

        var baseId = ZapretGuiExporter.StrategyId(s);
        var id = baseId;
        for (int n = 2; taken.Contains(id); n++)
            id = $"{baseId[..Math.Min(60, baseId.Length)]}_{n}";

        var steps = new List<DeliveryStep>();
        void List(string kind, string kindEn, string name)
        {
            var live = activeArgs.Contains($"lists/{name}.txt", StringComparison.Ordinal);
            steps.Add(live
                ? new($"Заменить {kind} {name}: его использует активная стратегия, nfqws2 подхватит изменения сразу", $"Replace {kindEn} {name}: the active strategy uses it, nfqws2 picks the change up at once")
                : new($"Создать или заменить {kind} {name}", $"Create or replace {kindEn} {name}"));
        }
        foreach (var name in s.Hostlists.Keys.Select(ZapretGuiExporter.GuiHostlist))
            List("список", "hostlist", name);
        foreach (var name in s.Ipsets.Keys.Select(ZapretGuiExporter.GuiIpset))
            List("ipset", "ipset", name);
        foreach (var name in s.Blobs.Keys)
            steps.Add(new($"Загрузить блоб {name} (существующий заменяется)", $"Upload blob {name} (an existing one is replaced)"));
        foreach (var file in s.LuaFiles.Keys)
        {
            var live = activeArgs.Contains($"@lua/{file}", StringComparison.Ordinal);
            steps.Add(live
                ? new($"Заменить Lua-скрипт {ZapretGuiExporter.GuiLua(file)}: его загружает активная стратегия", $"Replace Lua script {ZapretGuiExporter.GuiLua(file)}: the active strategy loads it")
                : new($"Создать или заменить Lua-скрипт {ZapretGuiExporter.GuiLua(file)}", $"Create or replace Lua script {ZapretGuiExporter.GuiLua(file)}"));
        }
        steps.Add(new($"Сохранить новую стратегию {id} (не применяя)", $"Save a new strategy {id} without applying it"));
        return new GuiSavePlan(id, steps);
    }

    /// <summary>Saves everything the strategy needs and the strategy itself under the plan's id; returns that id.</summary>
    /// <param name="confirmedByUser">Set by the confirmation dialog only.</param>
    public async Task<string> SaveAsync(Solution s, GuiSavePlan plan, bool confirmedByUser, CancellationToken ct = default)
    {
        if (!confirmedByUser)
            throw new InvalidOperationException("сохранение в zapret-gui без подтверждения запрещено / saving needs the user's confirmation");
        var strategy = ZapretGuiExporter.StrategyJson(s, plan.Id);
        foreach (var (name, domains) in s.Hostlists)
            await PutListAsync("hostlists", ZapretGuiExporter.GuiHostlist(name), "domains", domains, ct).ConfigureAwait(false);
        foreach (var (name, cidrs) in s.Ipsets)
            await PutListAsync("ipsets", ZapretGuiExporter.GuiIpset(name), "entries", cidrs, ct).ConfigureAwait(false);
        foreach (var (name, bytes) in s.Blobs)
            await UploadBlobAsync(name, bytes, ct).ConfigureAwait(false);
        foreach (var (file, text) in s.LuaFiles)
            await UploadLuaAsync(ZapretGuiExporter.GuiLua(file), text, ct).ConfigureAwait(false);
        await EnsureAsync(await SendAsync(HttpMethod.Post, "api/strategies", strategy, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
        return (string)strategy["id"]!;
    }

    /// <summary>The GUI's own check of the saved strategy.</summary>
    public async Task<JsonNode?> ValidateAsync(string id, CancellationToken ct = default) =>
        await EnsureAsync(await SendAsync(HttpMethod.Post, $"api/strategies/{Uri.EscapeDataString(id)}/validate", new JsonObject(), ct).ConfigureAwait(false), ct).ConfigureAwait(false);

    /// <summary>Applies the strategy (nfqws2 restarts with it). The second button, never part of saving.</summary>
    public async Task<JsonNode?> ApplyAsync(string id, bool confirmedByUser, CancellationToken ct = default)
    {
        if (!confirmedByUser)
            throw new InvalidOperationException("применение без подтверждения запрещено / applying needs the user's confirmation");
        return await EnsureAsync(await SendAsync(HttpMethod.Post, $"api/strategies/{Uri.EscapeDataString(id)}/apply", new JsonObject(), ct).ConfigureAwait(false), ct).ConfigureAwait(false);
    }

    // ---- single resources (PLAN 4a.5): each call changes the router, so each needs the user's confirmation ----

    /// <summary>Creates or replaces the GUI hostlist of an AutoTuner hostlist (<c>zt-&lt;name&gt;</c>).</summary>
    public Task PutHostlistAsync(string name, IEnumerable<string> domains, bool confirmedByUser, CancellationToken ct = default)
    {
        Confirm(confirmedByUser);
        return PutListAsync("hostlists", ZapretGuiExporter.GuiHostlist(Checked(name)), "domains", domains, ct);
    }

    /// <summary>Creates or replaces the GUI ipset of an AutoTuner ipset (<c>zt-&lt;name&gt;-ipset</c>).</summary>
    public Task PutIpsetAsync(string name, IEnumerable<string> entries, bool confirmedByUser, CancellationToken ct = default)
    {
        Confirm(confirmedByUser);
        return PutListAsync("ipsets", ZapretGuiExporter.GuiIpset(Checked(name)), "entries", entries, ct);
    }

    /// <summary>Uploads a blob under its own name (<c>POST /api/blobs</c>, <c>PUT</c> when it exists).</summary>
    public Task PutBlobAsync(string name, byte[] bytes, bool confirmedByUser, CancellationToken ct = default)
    {
        Confirm(confirmedByUser);
        if (!Identifiers.IsLuaIdentifier(name))
            throw new ArgumentException("blob name must be a Lua identifier", nameof(name));
        return UploadBlobAsync(name, bytes, ct);
    }

    /// <summary>
    /// Creates or replaces a Lua script as <c>zt-&lt;name&gt;.lua</c> (<c>POST /api/lua/create</c>, then
    /// <c>PUT /api/lua/&lt;name&gt;</c> when it exists). The caller hands in the approved text only
    /// (<c>ResourceStore.ForDelivery</c>).
    /// </summary>
    public Task PutLuaAsync(string name, string source, bool confirmedByUser, CancellationToken ct = default)
    {
        Confirm(confirmedByUser);
        return UploadLuaAsync(GuiName(ResourceKind.LuaScript, Checked(name)), source, ct);
    }

    /// <summary>Deletes a resource of ours from the GUI; refused while one of the GUI's strategies refers to it.</summary>
    public async Task DeleteAsync(ResourceKind kind, string name, bool confirmedByUser, CancellationToken ct = default)
    {
        Confirm(confirmedByUser);
        var users = await UsersOfAsync(kind, name, ct).ConfigureAwait(false);
        if (users.Count > 0)
            throw new ZapretGuiException($"{GuiName(kind, name)}: его используют стратегии zapret-gui {string.Join(", ", users)} / used by the zapret-gui strategies {string.Join(", ", users)}") { Code = "in_use" };
        var path = kind switch
        {
            ResourceKind.Hostlist => "api/hostlists/",
            ResourceKind.Ipset => "api/ipsets/",
            ResourceKind.Blob => "api/blobs/",
            _ => "api/lua/",
        } + Uri.EscapeDataString(GuiName(kind, name));
        await EnsureAsync(await _http.DeleteAsync(path, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
    }

    /// <summary>The ids of the GUI strategies whose profiles refer to the resource (list path, blob name or lua file).</summary>
    public async Task<IReadOnlyList<string>> UsersOfAsync(ResourceKind kind, string name, CancellationToken ct = default)
    {
        var gui = GuiName(kind, Checked(name));
        var list = await EnsureAsync(await _http.GetAsync("api/strategies", ct).ConfigureAwait(false), ct).ConfigureAwait(false);
        var re = kind switch
        {
            ResourceKind.Hostlist or ResourceKind.Ipset => new Regex($"lists/{Regex.Escape(gui)}\\.txt(?![A-Za-z0-9_.-])"),
            ResourceKind.Blob => new Regex($"(?:[=:]|[%#]){Regex.Escape(gui)}(?![A-Za-z0-9_])"),
            _ => new Regex($"@lua/{Regex.Escape(gui)}\\.lua(?![A-Za-z0-9_.-])"),
        };
        var users = new List<string>();
        foreach (var st in list?["strategies"]?.AsArray().OfType<JsonObject>() ?? [])
        {
            var args = string.Join(' ', st["profiles"]?.AsArray().Select(p => (string?)p?["args"]) ?? []);
            if (re.IsMatch(args))
                users.Add((string?)st["id"] ?? "?");
        }
        return users;
    }

    /// <summary>The names of the resources the GUI has of a kind (its own and ours); read-only.</summary>
    public async Task<IReadOnlyList<string>> ListAsync(ResourceKind kind, CancellationToken ct = default)
    {
        var (path, field) = kind switch
        {
            ResourceKind.Hostlist => ("api/hostlists", "files"),
            ResourceKind.Ipset => ("api/ipsets", "files"),
            ResourceKind.Blob => ("api/blobs", "blobs"),
            _ => ("api/lua", "files"),
        };
        var json = await EnsureAsync(await _http.GetAsync(path, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
        return [.. json?[field]?.AsArray().Select(x => x is JsonObject o ? (string?)o["name"] : null).OfType<string>() ?? []];
    }

    /// <summary>The GUI's own Lua syntax check (luac on the router when it has one); read-only, nothing is saved.</summary>
    public async Task<(bool Valid, IReadOnlyList<string> Errors)> CheckLuaAsync(string source, CancellationToken ct = default)
    {
        var json = await EnsureAsync(await SendAsync(HttpMethod.Post, "api/lua/check", new JsonObject { ["content"] = source }, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
        var errors = json?["errors"]?.AsArray().Select(e => e is JsonObject o ? (string?)o["message"] ?? o.ToJsonString() : e?.ToString()).OfType<string>().ToList() ?? [];
        return ((bool?)json?["valid"] ?? false, errors);
    }

    /// <summary>The name a resource of ours has in the GUI: <c>zt-x</c>, <c>zt-x-ipset</c>, the blob name, <c>zt-x</c> (zt-x.lua).</summary>
    public static string GuiName(ResourceKind kind, string name) => kind switch
    {
        ResourceKind.Hostlist => ZapretGuiExporter.GuiHostlist(name),
        ResourceKind.Ipset => ZapretGuiExporter.GuiIpset(name),
        ResourceKind.Blob => name,
        _ => ZapretGuiExporter.GuiLua(ResourceNames.LuaFile(name)),
    };

    private static void Confirm(bool confirmedByUser)
    {
        if (!confirmedByUser)
            throw new InvalidOperationException("изменение zapret-gui без подтверждения запрещено / changing zapret-gui needs the user's confirmation");
    }

    private static string Checked(string name) =>
        ResourceNames.IsValid(name) ? name : throw new ArgumentException("resource name must be [a-z0-9_-]{1,48}", nameof(name));

    private async Task UploadBlobAsync(string name, byte[] bytes, CancellationToken ct)
    {
        var hex = Convert.ToHexString(bytes).ToLowerInvariant();
        using var r = await SendAsync(HttpMethod.Post, "api/blobs", new JsonObject { ["name"] = name, ["hex"] = hex }, ct).ConfigureAwait(false);
        if (r.StatusCode == HttpStatusCode.Conflict)
            await EnsureAsync(await SendAsync(HttpMethod.Put, $"api/blobs/{name}", new JsonObject { ["hex"] = hex }, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
        else
            await EnsureAsync(r, ct).ConfigureAwait(false);
    }

    private async Task UploadLuaAsync(string guiName, string source, CancellationToken ct)
    {
        using (var created = await SendAsync(HttpMethod.Post, "api/lua/create", new JsonObject { ["name"] = guiName, ["content"] = source }, ct).ConfigureAwait(false))
        {
            if (created.IsSuccessStatusCode)
                return;
            // 400 "уже существует" means we replace its content below
            if (!(ErrorOf(await created.Content.ReadAsStringAsync(ct).ConfigureAwait(false)) ?? "").Contains("существует", StringComparison.Ordinal))
            {
                await EnsureAsync(created, ct).ConfigureAwait(false);
                return;
            }
        }
        await EnsureAsync(await SendAsync(HttpMethod.Put, $"api/lua/{Uri.EscapeDataString(guiName)}", new JsonObject { ["content"] = source }, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
    }

    private async Task PutListAsync(string kind, string name, string field, IEnumerable<string> items, CancellationToken ct)
    {
        using (var created = await SendAsync(HttpMethod.Post, $"api/{kind}/create", new JsonObject { ["name"] = name }, ct).ConfigureAwait(false))
        {
            // 400 "уже существует" means we replace its content below; Bottle sends the error as \u-escaped JSON
            if (!created.IsSuccessStatusCode && !(ErrorOf(await created.Content.ReadAsStringAsync(ct).ConfigureAwait(false)) ?? "").Contains("существует", StringComparison.Ordinal))
                await EnsureAsync(created, ct).ConfigureAwait(false);
        }
        await EnsureAsync(await SendAsync(HttpMethod.Put, $"api/{kind}/{name}", new JsonObject { [field] = new JsonArray([.. items.Select(i => (JsonNode)i!)]) }, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
    }

    private static string? ErrorOf(string body)
    {
        try
        {
            return (string?)JsonNode.Parse(body)?["error"];
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException)
        {
            return body;
        }
    }

    private Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, JsonNode body, CancellationToken ct) =>
        _http.SendAsync(new HttpRequestMessage(method, path) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") }, ct);

    private static async Task<JsonNode?> EnsureAsync(HttpResponseMessage r, CancellationToken ct)
    {
        using (r)
        {
            var text = await r.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            JsonNode? json = null;
            try
            {
                json = text.Length > 0 ? JsonNode.Parse(text) : null;
            }
            catch (System.Text.Json.JsonException)
            {
            }
            if (!r.IsSuccessStatusCode || (bool?)json?["ok"] == false)
                throw new ZapretGuiException($"{r.RequestMessage?.Method} {r.RequestMessage?.RequestUri?.AbsolutePath}: {(int)r.StatusCode} {(string?)json?["error"] ?? text}");
            return json;
        }
    }
}

public sealed class ZapretGuiException(string message) : Exception(message)
{
    /// <summary>The GUI's <c>error_code</c> (e.g. <c>busy</c>) or the JSON-RPC error code, when it gave one.</summary>
    public string? Code { get; init; }
}
