using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;

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
        {
            var body = new JsonObject { ["name"] = name, ["hex"] = Convert.ToHexString(bytes).ToLowerInvariant() };
            using var r = await SendAsync(HttpMethod.Post, "api/blobs", body, ct).ConfigureAwait(false);
            if (r.StatusCode == HttpStatusCode.Conflict)
                await EnsureAsync(await SendAsync(HttpMethod.Put, $"api/blobs/{name}", new JsonObject { ["hex"] = body["hex"]!.GetValue<string>() }, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
            else
                await EnsureAsync(r, ct).ConfigureAwait(false);
        }
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
