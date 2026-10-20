using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Delivery;

/// <summary>
/// A minimal MCP client for zapret-gui (<c>POST /api/mcp</c>, JSON-RPC 2.0, stateless HTTP transport, Bearer token):
/// <c>initialize</c> once, then <c>tools/call</c>. Tool results come back as <c>structuredContent</c>; a result with
/// <c>isError</c> or <c>ok: false</c> raises <see cref="ZapretGuiException"/>.
/// </summary>
public sealed class ZapretGuiMcp
{
    public const string ProtocolVersion = "2025-06-18";

    private readonly HttpClient _http;
    private string? _session;
    private string? _negotiated;
    private int _id;

    /// <param name="http">With <c>BaseAddress</c> set to the GUI, e.g. <c>http://192.168.1.1:8080/</c>.</param>
    public ZapretGuiMcp(HttpClient http, string token)
    {
        _http = http;
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        var result = await RpcAsync("initialize", new JsonObject
        {
            ["protocolVersion"] = ProtocolVersion,
            ["capabilities"] = new JsonObject(),
            ["clientInfo"] = new JsonObject { ["name"] = Core.AppInfo.Name, ["version"] = Core.AppInfo.Version },
        }, ct).ConfigureAwait(false);
        _negotiated = (string?)result?["protocolVersion"] ?? ProtocolVersion;
        await NotifyAsync("notifications/initialized", ct).ConfigureAwait(false);
    }

    /// <summary>Calls a tool and returns its structured result.</summary>
    public async Task<JsonObject> CallAsync(string tool, JsonObject arguments, CancellationToken ct = default)
    {
        if (_negotiated is null)
            await InitializeAsync(ct).ConfigureAwait(false);
        var result = await RpcAsync("tools/call", new JsonObject { ["name"] = tool, ["arguments"] = arguments }, ct).ConfigureAwait(false)
            ?? throw new ZapretGuiException($"{tool}: пустой ответ / empty result");
        var data = result["structuredContent"] as JsonObject ?? ParseText(result);
        if ((bool?)result["isError"] == true || (bool?)data["ok"] == false)
            throw new ZapretGuiException($"{tool}: {(string?)data["error"] ?? TextOf(result)}") { Code = (string?)data["error_code"] };
        return data;
    }

    /// <summary>The tools this token may call (the GUI hides tools whose permission is off).</summary>
    public async Task<HashSet<string>> ToolsAsync(CancellationToken ct = default)
    {
        if (_negotiated is null)
            await InitializeAsync(ct).ConfigureAwait(false);
        var result = await RpcAsync("tools/list", new JsonObject(), ct).ConfigureAwait(false);
        return (result?["tools"] as JsonArray ?? []).Select(t => (string?)t?["name"]).OfType<string>().ToHashSet(StringComparer.Ordinal);
    }

    private static JsonObject ParseText(JsonNode result)
    {
        try
        {
            return JsonNode.Parse(TextOf(result)) as JsonObject ?? new JsonObject();
        }
        catch (System.Text.Json.JsonException)
        {
            return new JsonObject { ["text"] = TextOf(result) };
        }
    }

    private static string TextOf(JsonNode result) =>
        string.Join("\n", (result["content"] as JsonArray ?? []).Select(c => (string?)c?["text"]).OfType<string>());

    private async Task<JsonNode?> RpcAsync(string method, JsonObject @params, CancellationToken ct)
    {
        var id = Interlocked.Increment(ref _id);
        using var r = await PostAsync(new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["method"] = method, ["params"] = @params }, ct).ConfigureAwait(false);
        if (r.Headers.TryGetValues("Mcp-Session-Id", out var s))
            _session = s.FirstOrDefault() ?? _session;
        var text = await r.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!r.IsSuccessStatusCode)
            throw new ZapretGuiException($"MCP {method}: {(int)r.StatusCode} {Short(text)}") { Code = r.StatusCode == System.Net.HttpStatusCode.Unauthorized ? "unauthorized" : null };
        JsonNode? json;
        try
        {
            json = JsonNode.Parse(text);
        }
        catch (System.Text.Json.JsonException)
        {
            throw new ZapretGuiException($"MCP {method}: не JSON / not JSON: {Short(text)}");
        }
        if (json?["error"] is JsonObject e)
            throw new ZapretGuiException($"MCP {method}: {(string?)e["message"]}") { Code = ((int?)e["code"])?.ToString(System.Globalization.CultureInfo.InvariantCulture) };
        return json?["result"];
    }

    private async Task NotifyAsync(string method, CancellationToken ct)
    {
        using var r = await PostAsync(new JsonObject { ["jsonrpc"] = "2.0", ["method"] = method }, ct).ConfigureAwait(false);
    }

    private Task<HttpResponseMessage> PostAsync(JsonObject body, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "api/mcp") { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };
        req.Headers.Accept.ParseAdd("application/json");
        if (_negotiated is not null)
            req.Headers.TryAddWithoutValidation("MCP-Protocol-Version", _negotiated);
        if (_session is not null)
            req.Headers.TryAddWithoutValidation("Mcp-Session-Id", _session);
        return _http.SendAsync(req, ct);
    }

    private static string Short(string s) => s.Length > 300 ? s[..300] + "…" : s;
}
