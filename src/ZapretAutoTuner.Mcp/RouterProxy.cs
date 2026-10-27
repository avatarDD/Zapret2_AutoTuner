using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core;
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

    /// <summary>After a failed fetch, the next one is tried this soon; each further failure doubles it up to <see cref="MaxRetryAfter"/>.</summary>
    public static readonly TimeSpan RetryAfter = TimeSpan.FromSeconds(10);

    public static readonly TimeSpan MaxRetryAfter = TimeSpan.FromMinutes(5);

    /// <summary>One fetch of the router's list gives up after this long (the link's HttpClient waits a minute for real calls).</summary>
    public static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(5);

    /// <summary>tools/list waits this long for a fetch in flight, then answers with what it has; the fetch goes on.</summary>
    public static readonly TimeSpan ListWait = TimeSpan.FromSeconds(3);

    /// <summary>A gui_ name the cached list does not have refetches the list at most this often.</summary>
    public static readonly TimeSpan ForcedRefreshEvery = TimeSpan.FromSeconds(15);

    public const int MaxTools = 200;
    public const int MaxArgumentChars = 16000;
    public const int MaxDescriptionChars = 2000;

    /// <summary>The arguments of a changing tool are shown in full in the confirmation; longer ones are refused, never cut.</summary>
    public const int MaxConfirmChars = 6000;

    private readonly Lock _lock = new();
    private ZapretGuiMcp? _source;
    private DateTime _fetched;
    private int _failures;
    private DateTime _forced = DateTime.MinValue;
    private IReadOnlyList<JsonObject> _tools = [];
    private Task<IReadOnlyList<JsonObject>>? _refresh;
    private ZapretGuiMcp? _refreshFor;

    /// <summary>Why the last fetch of the router's tool list failed, or null.</summary>
    public string? LastError { get; private set; }

    public static bool IsProxied(string name) => name.StartsWith(Prefix, StringComparison.Ordinal);

    /// <summary>zapret-gui's own name: with our prefix it stays within 64 characters, and nothing else than these.</summary>
    [GeneratedRegex("^[A-Za-z0-9_-]{1,60}$")]
    private static partial Regex ToolName();

    private TimeSpan FreshFor => _failures == 0
        ? CacheFor
        : TimeSpan.FromTicks(Math.Min(MaxRetryAfter.Ticks, RetryAfter.Ticks << Math.Min(_failures - 1, 16)));

    /// <summary>
    /// zapret-gui's definitions as it lists them (cached), or none without the permission or zapret-gui. A stale list is
    /// fetched in the background with its own short timeout: the caller waits at most <see cref="ListWait"/> and gets the
    /// cached list (empty after a failure) when the router is slow, so tools/list never hangs on an unreachable router.
    /// </summary>
    /// <param name="refresh">Fetch now even when the cache is fresh (an unknown gui_ name), at most once per <see cref="ForcedRefreshEvery"/>.</param>
    public async Task<IReadOnlyList<JsonObject>> RawToolsAsync(bool refresh = false, CancellationToken ct = default)
    {
        if (!session.Permissions().Granted(McpScope.RouterProxy) || session.Host.RouterMcp() is not { } mcp)
            return [];
        Task<IReadOnlyList<JsonObject>> task;
        IReadOnlyList<JsonObject> cached;
        lock (_lock)
        {
            var now = session.Time.GetUtcNow().UtcDateTime;
            bool same = ReferenceEquals(_source, mcp);
            cached = same ? _tools : [];
            bool inFlight = _refresh is { IsCompleted: false } && ReferenceEquals(_refreshFor, mcp);
            // a forced fetch is rate-limited, and never shortens the back-off after a failure
            if (refresh && same && !inFlight && (now - _forced < ForcedRefreshEvery || (_failures > 0 && now - _fetched < FreshFor)))
                return cached;
            if (!refresh && same && !inFlight && now - _fetched < FreshFor)
                return cached;
            if (refresh)
                _forced = now;
            task = inFlight ? _refresh! : StartFetch(mcp);
        }
        try
        {
            return await task.WaitAsync(ListWait, ct).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            return cached;
        }
    }

    private Task<IReadOnlyList<JsonObject>> StartFetch(ZapretGuiMcp mcp)
    {
        _refreshFor = mcp;
        return _refresh = Task.Run(() => FetchAsync(mcp));
    }

    private async Task<IReadOnlyList<JsonObject>> FetchAsync(ZapretGuiMcp mcp)
    {
        IReadOnlyList<JsonObject> tools;
        string? error = null;
        try
        {
            using var timeout = new CancellationTokenSource(FetchTimeout);
            tools = Usable(await mcp.ToolDefinitionsAsync(timeout.Token, MaxTools).ConfigureAwait(false));
        }
        catch (Exception e)
        {
            // nobody awaits a background fetch for sure: every failure is the list's state, never an unobserved fault
            tools = [];
            error = e is OperationCanceledException ? $"the router did not answer within {FetchTimeout.TotalSeconds:0} s / роутер не ответил" : e.Message;
        }
        lock (_lock)
        {
            _source = mcp;
            _fetched = session.Time.GetUtcNow().UtcDateTime;
            _tools = tools;
            _failures = error is null ? 0 : _failures + 1;
            LastError = error;
        }
        return tools;
    }

    /// <summary>
    /// The router's definitions we can relay: a name of ours, and a definition that builds both our relayed form and the
    /// SDK's tool. One malformed definition (a number for a description, a bad schema) drops that tool, not the list.
    /// </summary>
    internal static IReadOnlyList<JsonObject> Usable(IEnumerable<JsonObject> list)
    {
        var tools = new List<JsonObject>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var t in list)
        {
            if (t["name"] is not JsonValue nv || !nv.TryGetValue<string>(out var n) || !ToolName().IsMatch(n) || names.Contains(n))
                continue;
            try
            {
                McpServerSetup.ToRelayedTool(Relayed(t));
            }
            catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException or ArgumentException or NotSupportedException)
            {
                continue;
            }
            names.Add(n);
            tools.Add(t);
        }
        return tools;
    }

    /// <summary>The router's tools as our tools/list shows them: prefixed, with zapret-gui's input schema and annotations.</summary>
    public async Task<IReadOnlyList<JsonObject>> ListAsync(CancellationToken ct = default) =>
        [.. (await RawToolsAsync(false, ct).ConfigureAwait(false)).Select(Relayed)];

    public static bool IsReadOnly(JsonObject tool) => tool["annotations"] is JsonObject a && a["readOnlyHint"] is JsonValue v && v.TryGetValue<bool>(out var b) && b;

    private static string? Str(JsonNode? node) => node is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    private static readonly string[] HintNames = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"];

    internal static JsonObject Relayed(JsonObject tool)
    {
        var name = Str(tool["name"]) ?? throw new InvalidOperationException("a router tool without a name");
        var description = Str(tool["description"]) ?? "";
        if (description.Length > MaxDescriptionChars)
            description = description[..MaxDescriptionChars] + "…";
        bool ro = IsReadOnly(tool);
        var schema = tool["inputSchema"] is JsonObject s && Str(s["type"]) == "object" ? (JsonObject)s.DeepClone() : new JsonObject { ["type"] = "object" };
        var relayed = new JsonObject
        {
            ["name"] = Prefix + name,
            ["description"] = $"[router, zapret-gui tool «{name}», relayed by AutoTuner] {description}"
                + (ro ? "" : " Needs the user's confirmation in the AutoTuner window."),
            ["inputSchema"] = schema,
        };
        if (Str(tool["title"]) is { } title)
            relayed["title"] = title;
        // only the hints of the spec, as booleans: anything else of zapret-gui's would only break the client's list
        if (tool["annotations"] is JsonObject a)
        {
            var hints = new JsonObject();
            if (Str(a["title"]) is { } at)
                hints["title"] = at;
            foreach (var h in HintNames)
                if (a[h] is JsonValue hv && hv.TryGetValue<bool>(out var b))
                    hints[h] = b;
            relayed["annotations"] = hints;
        }
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
        // rules 1 and 4: engine options in the arguments go to nfqws2 on the router as they are
        if (GuiArgumentPolicy.Check(args) is { } refused)
            return refused;
        if (IsReadOnly(def))
            return Answer(await mcp.CallRawAsync(raw, (JsonObject)args.DeepClone(), ct).ConfigureAwait(false));
        if (Conflict() is { } busy)
            return session.Confirmations.Report(Key(raw, text)) ?? busy;
        var pretty = SafeText.ForDisplay(args.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
        // the user approves what is forwarded: all of it is shown, so what cannot be shown is not forwarded
        if (pretty.Length > MaxConfirmChars)
            return McpErrors.Error($"the arguments are too long to show for confirmation: {pretty.Length} characters, at most {MaxConfirmChars} for a tool that changes something / аргументы слишком длинные, чтобы показать их для подтверждения");
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
    private JsonObject? Conflict() => session.Host.RouterTuningRunning || session.RouterBusy
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
