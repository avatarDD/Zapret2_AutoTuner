using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Delivery;

/// <summary>
/// Delivery into zapret-gui over its REST API (PLAN 5.3, strategy-export §3.2): create the lists, ipsets and blobs,
/// save the strategy. Applying it is a separate call behind a second button: saving changes nothing on the router's
/// traffic, applying restarts nfqws2 (AGENTS.md rule 7).
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

    /// <summary>What <see cref="SaveAsync"/> will do, for the confirmation dialog.</summary>
    public static List<DeliveryStep> Plan(Solution s, string? id = null)
    {
        var strategy = ZapretGuiExporter.StrategyJson(s, id);
        var steps = new List<DeliveryStep>();
        foreach (var name in s.Hostlists.Keys.Select(ZapretGuiExporter.GuiHostlist))
            steps.Add(new($"Создать или заменить список {name}", $"Create or replace hostlist {name}"));
        foreach (var name in s.Ipsets.Keys.Select(ZapretGuiExporter.GuiIpset))
            steps.Add(new($"Создать или заменить ipset {name}", $"Create or replace ipset {name}"));
        foreach (var name in s.Blobs.Keys)
            steps.Add(new($"Загрузить блоб {name} (существующий заменяется)", $"Upload blob {name} (an existing one is replaced)"));
        steps.Add(new($"Сохранить стратегию {(string?)strategy["id"]} (не применяя)", $"Save strategy {(string?)strategy["id"]} without applying it"));
        return steps;
    }

    /// <summary>Saves everything the strategy needs and the strategy itself; returns the strategy id.</summary>
    /// <param name="confirmedByUser">Set by the confirmation dialog only.</param>
    public async Task<string> SaveAsync(Solution s, bool confirmedByUser, string? id = null, CancellationToken ct = default)
    {
        if (!confirmedByUser)
            throw new InvalidOperationException("сохранение в zapret-gui без подтверждения запрещено / saving needs the user's confirmation");
        var strategy = ZapretGuiExporter.StrategyJson(s, id);
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
            // 400 "уже существует" means we replace its content below
            if (!created.IsSuccessStatusCode && !(await created.Content.ReadAsStringAsync(ct).ConfigureAwait(false)).Contains("существует", StringComparison.Ordinal))
                await EnsureAsync(created, ct).ConfigureAwait(false);
        }
        await EnsureAsync(await SendAsync(HttpMethod.Put, $"api/{kind}/{name}", new JsonObject { [field] = new JsonArray([.. items.Select(i => (JsonNode)i!)]) }, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
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

public sealed class ZapretGuiException(string message) : Exception(message);
