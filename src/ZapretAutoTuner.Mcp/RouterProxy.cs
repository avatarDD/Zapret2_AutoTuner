using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Delivery;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// The bridge to the router's own MCP server (PLAN 4a.7): with the <c>router_proxy</c> permission and zapret-gui set up in
/// AutoTuner, zapret-gui's tools are listed as <c>gui_*</c> next to ours and forwarded with the address and token the
/// user entered (the model never sees either). A tool zapret-gui does not mark <c>readOnlyHint=true</c> waits for the
/// user's yes in the AutoTuner window, showing the tool and its arguments (AGENTS.md rule 7). The answers go through
/// <see cref="AutoTunerTools.CallAsync"/> like ours: masked, bounded and audited; Stop cancels a forward in flight.
/// <para>
/// These tools are dynamic, so the golden test of <see cref="McpTools.All"/> does not pin them: what they accept is
/// zapret-gui's boundary (its token's permissions), and what they change is the user's yes here.
/// </para>
/// </summary>
public sealed partial class RouterProxy(McpSession session)
{
    public const string Prefix = "gui_";

    /// <summary>The router's tool list is fetched again after this long (or at once when the link changes).</summary>
    public static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(60);

    /// <summary>After a failed fetch, the next tools/list tries again this soon.</summary>
    public static readonly TimeSpan RetryAfter = TimeSpan.FromSeconds(10);

    public const int MaxTools = 200;
    public const int MaxArgumentChars = 16000;
    public const int MaxDescriptionChars = 2000;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private ZapretGuiMcp? _source;
    private DateTime _fetched;
    private bool _failed;
    private IReadOnlyList<JsonObject> _tools = [];

    /// <summary>Why the last fetch of the router's tool list failed, or null.</summary>
    public string? LastError { get; private set; }

    public static bool IsProxied(string name) => name.StartsWith(Prefix, StringComparison.Ordinal);

    [GeneratedRegex("^[A-Za-z0-9_.-]{1,64}$")]
    private static partial Regex ToolName();

    /// <summary>zapret-gui's definitions as it lists them (cached), or none without the permission or zapret-gui.</summary>
    public async Task<IReadOnlyList<JsonObject>> RawToolsAsync(bool refresh = false, CancellationToken ct = default)
    {
        if (!session.Permissions().Granted(McpScope.RouterProxy) || session.Host.RouterMcp() is not { } mcp)
            return [];
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = session.Time.GetUtcNow().UtcDateTime;
            if (!refresh && ReferenceEquals(_source, mcp) && now - _fetched < (_failed ? RetryAfter : CacheFor))
                return _tools;
            try
            {
                var list = await mcp.ToolDefinitionsAsync(ct, MaxTools).ConfigureAwait(false);
                _tools = [.. list.Where(t => (string?)t["name"] is { } n && ToolName().IsMatch(n)).DistinctBy(t => (string)t["name"]!)];
                _failed = false;
                LastError = null;
            }
            catch (Exception e) when (e is ZapretGuiException or HttpRequestException or IOException or JsonException
                                          || (e is OperationCanceledException && !ct.IsCancellationRequested))
            {
                _tools = [];
                _failed = true;
                LastError = e.Message;
            }
            _source = mcp;
            _fetched = now;
            return _tools;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>The router's tools as our tools/list shows them: prefixed, with zapret-gui's input schema and annotations.</summary>
    public async Task<IReadOnlyList<JsonObject>> ListAsync(CancellationToken ct = default) =>
        [.. (await RawToolsAsync(false, ct).ConfigureAwait(false)).Select(Relayed)];

    public static bool IsReadOnly(JsonObject tool) => tool["annotations"] is JsonObject a && a["readOnlyHint"] is JsonValue v && v.TryGetValue<bool>(out var b) && b;

    internal static JsonObject Relayed(JsonObject tool)
    {
        var name = (string)tool["name"]!;
        var description = (string?)tool["description"] ?? "";
        if (description.Length > MaxDescriptionChars)
            description = description[..MaxDescriptionChars] + "…";
        bool ro = IsReadOnly(tool);
        var schema = tool["inputSchema"] is JsonObject s && (string?)s["type"] == "object" ? (JsonObject)s.DeepClone() : new JsonObject { ["type"] = "object" };
        var relayed = new JsonObject
        {
            ["name"] = Prefix + name,
            ["description"] = $"[router, zapret-gui tool «{name}», relayed by AutoTuner] {description}"
                + (ro ? "" : " Needs the user's confirmation in the AutoTuner window."),
            ["inputSchema"] = schema,
        };
        if ((string?)tool["title"] is { } title)
            relayed["title"] = title;
        if (tool["annotations"] is JsonObject a)
            relayed["annotations"] = a.DeepClone();
        return relayed;
    }

    /// <summary>
    /// Forwards one call (the permission was checked by the caller). A read-only tool goes at once; any other returns
    /// "pending confirmation" and runs after the user's yes; the next call with the same arguments gets its result.
    /// </summary>
    public async Task<JsonObject> CallAsync(string name, JsonObject args, CancellationToken ct)
    {
        if (session.Host.RouterMcp() is not { } mcp)
            return McpErrors.Error("zapret-gui is not set up in AutoTuner (address and MCP token, Settings) / zapret-gui не настроен в AutoTuner");
        var raw = name[Prefix.Length..];
        var def = Find(await RawToolsAsync(false, ct).ConfigureAwait(false), raw)
            ?? Find(await RawToolsAsync(true, ct).ConfigureAwait(false), raw);
        if (def is null)
        {
            return LastError is { } why
                ? McpErrors.Error($"the router's tool list is not available: {why} / список инструментов роутера недоступен")
                : McpErrors.Error($"the router has no tool {raw} for this token: call tools/list again / у роутера нет инструмента {raw}");
        }
        var text = args.ToJsonString();
        if (text.Length > MaxArgumentChars)
            return McpErrors.Error($"arguments too large: {text.Length} characters, at most {MaxArgumentChars} / слишком большие аргументы");
        if (IsReadOnly(def))
            return Answer(await mcp.CallRawAsync(raw, (JsonObject)args.DeepClone(), ct).ConfigureAwait(false));
        if (Conflict() is { } busy)
            return session.Confirmations.Report(Key(raw, text)) ?? busy;
        var pretty = args.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        if (pretty.Length > 2000)
            pretty = pretty[..2000] + "\n…";
        var request = new ConfirmRequest(name,
            "Инструмент роутера: " + raw,
            "Router tool: " + raw,
            $"Модель просит выполнить на роутере (zapret-gui) инструмент «{raw}». Он не помечен как только читающий и может изменить настройки роутера.\n\nАргументы:\n{pretty}",
            $"The model asks to run the zapret-gui tool «{raw}» on the router. It is not marked read-only and may change the router's settings.\n\nArguments:\n{pretty}");
        var forwarded = (JsonObject)args.DeepClone();
        return session.Confirmations.Request(Key(raw, text), request, async yesCt =>
        {
            if (Conflict() is { } late)
                return late;
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(yesCt, session.StopToken);
            return Answer(await mcp.CallRawAsync(raw, forwarded, linked.Token).ConfigureAwait(false));
        });
    }

    private static string Key(string raw, string args) => "gui:" + raw + ":" + args;

    private static JsonObject? Find(IReadOnlyList<JsonObject> tools, string raw) => tools.FirstOrDefault(t => (string?)t["name"] == raw);

    /// <summary>One experiment on the router at a time: our own (wizard or router_experiment_*) holds it now.</summary>
    private JsonObject? Conflict() => session.Host.RouterTuningRunning || session.Router.Running
        ? McpErrors.Error("busy: AutoTuner runs an experiment on the router (the wizard or router_experiment_*); router tools that change something wait until it ends / занято: идёт эксперимент на роутере")
        : null;

    /// <summary>zapret-gui's tools/call result as our structured answer; only text content is kept.</summary>
    internal static JsonObject Answer(JsonObject result)
    {
        var blocks = result["content"] as JsonArray ?? [];
        var text = string.Join("\n", blocks.Where(b => (string?)b?["type"] is null or "text").Select(b => (string?)b?["text"]).OfType<string>());
        int dropped = blocks.Count(b => (string?)b?["type"] is { } t && t != "text");
        var data = result["structuredContent"] is JsonObject sc ? (JsonObject)sc.DeepClone() : new JsonObject { ["text"] = text };
        if ((bool?)result["isError"] == true)
        {
            data["ok"] = false;
            if (data["error"] is null)
                data["error"] = text.Length > 0 ? text : "the router's tool failed / инструмент роутера вернул ошибку";
        }
        if (dropped > 0)
            data["dropped_content_blocks"] = dropped;
        // one huge string is not cut by halving arrays: keep the start of it
        if (data.ToJsonString().Length > AutoTunerTools.MaxAnswerChars * 4)
        {
            var whole = data.ToJsonString();
            data = new JsonObject { ["ok"] = data["ok"]?.DeepClone(), ["text"] = whole[..AutoTunerTools.MaxAnswerChars], ["truncated"] = true };
        }
        if (data["text"] is JsonValue tv && tv.TryGetValue<string>(out var t2) && t2.Length > AutoTunerTools.MaxAnswerChars)
        {
            data["text"] = t2[..AutoTunerTools.MaxAnswerChars];
            data["truncated"] = true;
        }
        return data;
    }
}
