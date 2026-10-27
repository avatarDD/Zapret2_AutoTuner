using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Delivery;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>
/// zapret-gui's experiments over MCP in memory: <c>strategy_experiment_start</c> remembers the variants, the result
/// probes each target with a rule over the candidate profile's args (as core/strategy_experiment.py reports it).
/// </summary>
internal sealed class RouterGui : HttpMessageHandler
{
    public List<(string Tool, JsonObject Args)> Calls { get; } = [];

    /// <summary>(candidate args, target) → (ok, code, ok_count of 3).</summary>
    public Func<string, string, (bool Ok, string Code, int OkCount)> Probe { get; set; } = (_, _) => (false, "tls_rst", 0);

    public List<string> OpenWithoutBypass { get; set; } = [];

    /// <summary>When set, a result page holds at most this many variants (the GUI pages by offset/limit).</summary>
    public int? PageSize { get; set; }

    /// <summary>When set, the n-th start (1-based) is refused by the GUI with this error.</summary>
    public (int Start, string Error)? RefuseStart { get; set; }

    /// <summary>Awaited before a start is answered (after it is recorded): a slow router, to cancel a start in flight.</summary>
    public Func<CancellationToken, Task>? BeforeStart { get; set; }

    /// <summary>Status answers in turn; the last one repeats.</summary>
    public List<string> States { get; set; } = ["finished"];

    /// <summary>The tools the token may call (tools/list).</summary>
    public List<string> Tools { get; set; } = [.. ZapretGuiExperiments.RequiredTools, "strategy_experiment_commit", "strategy_get", "logs_tail"];

    /// <summary>Full tool definitions for tools/list (schemas, annotations); when null, <see cref="Tools"/> by name.</summary>
    public List<JsonObject>? ToolDefinitions { get; set; }

    /// <summary>When set, tools/list pages by this many tools (nextCursor).</summary>
    public int? ToolsPageSize { get; set; }

    public int ToolLists { get; private set; }

    /// <summary>A whole tools/call result for a tool (content, structuredContent, isError); null falls through to the built-in answers.</summary>
    public Func<string, JsonObject, CancellationToken, Task<JsonObject?>>? OnTool { get; set; }

    /// <summary>The strategy the router runs now (strategy_get): its enabled profiles.</summary>
    public (string Id, List<(string Name, string Args, bool Enabled)> Profiles) Active { get; set; } = ("", []);

    /// <summary>The token lacks strategies_write: a commit with save_as is refused.</summary>
    public bool DenySave { get; set; }

    /// <summary>Lines logs_tail returns.</summary>
    public List<string> LogLines { get; set; } = [];

    private bool _keepBest;
    private JsonArray _variants = [];
    private List<string> _targets = [];
    private int _status;

    public int Starts => Calls.Count(c => c.Tool == "strategy_experiment_start");

    public List<JsonObject> StartArgs => Calls.Where(c => c.Tool == "strategy_experiment_start").Select(c => c.Args).ToList();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = (JsonObject)JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!;
        if (body["id"] is null)
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        var method = (string)body["method"]!;
        JsonObject result;
        if (method == "initialize")
        {
            result = new JsonObject { ["protocolVersion"] = ZapretGuiMcp.ProtocolVersion, ["capabilities"] = new JsonObject() };
        }
        else if (method == "tools/list")
        {
            ToolLists++;
            var all = ToolDefinitions?.Select(t => (JsonNode)t.DeepClone()).ToList() ?? [.. Tools.Select(t => (JsonNode)new JsonObject { ["name"] = t })];
            int from = int.TryParse((string?)body["params"]?["cursor"], out var c) ? c : 0;
            int size = ToolsPageSize ?? all.Count;
            result = new JsonObject { ["tools"] = new JsonArray([.. all.Skip(from).Take(size)]) };
            if (from + size < all.Count)
                result["nextCursor"] = (from + size).ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        else
        {
            var name = (string)body["params"]!["name"]!;
            var args = (JsonObject)body["params"]!["arguments"]!;
            Calls.Add((name, args));
            if (name == "strategy_experiment_start" && BeforeStart is { } wait)
                await wait(ct);
            if (OnTool is { } custom && await custom(name, args, ct) is { } whole)
            {
                var reply = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = body["id"]!.DeepClone(), ["result"] = whole };
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(reply.ToJsonString(), Encoding.UTF8, "application/json") };
            }
            var payload = name switch
            {
                "strategy_experiment_start" when RefuseStart is { } refuse && refuse.Start == Starts =>
                    new JsonObject { ["ok"] = false, ["error"] = refuse.Error, ["error_code"] = "busy", ["__isError"] = true },
                "strategy_experiment_start" => Start(args),
                "strategy_experiment_status" => new JsonObject { ["ok"] = true, ["state"] = States[Math.Min(_status++, States.Count - 1)], ["phase"] = "variant", ["awaiting_commit"] = false },
                "strategy_experiment_result" => Result(args),
                "strategy_get" => Active.Id.Length == 0
                    ? new JsonObject { ["ok"] = true, ["available"] = false }
                    : new JsonObject
                    {
                        ["ok"] = true,
                        ["item"] = new JsonObject
                        {
                            ["id"] = Active.Id,
                            ["profiles"] = new JsonArray([.. Active.Profiles.Select(p => (JsonNode)new JsonObject { ["name"] = p.Name, ["args"] = p.Args, ["enabled"] = p.Enabled })]),
                        },
                    },
                "strategy_experiment_commit" when DenySave && args["save_as"] is not null =>
                    new JsonObject { ["ok"] = false, ["error"] = "нужно разрешение strategies_write", ["permission"] = "strategies_write" },
                "logs_tail" => new JsonObject { ["ok"] = true, ["items"] = new JsonArray([.. LogLines.Select(l => (JsonNode)new JsonObject { ["message"] = l })]) },
                _ => new JsonObject { ["ok"] = true },
            };
            bool isError = payload.Remove("__isError");
            result = new JsonObject
            {
                ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = payload.ToJsonString() }),
                ["structuredContent"] = payload,
                ["isError"] = isError,
            };
        }
        var json = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = body["id"]!.DeepClone(), ["result"] = result };
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json.ToJsonString(), Encoding.UTF8, "application/json") };
    }

    private JsonObject Start(JsonObject args)
    {
        _variants = (JsonArray)args["variants"]!.DeepClone();
        _targets = ((JsonArray)args["targets"]!).Select(t => (string)t!).ToList();
        _keepBest = (bool?)args["keep_best"] ?? false;
        _status = 0;
        return new JsonObject { ["ok"] = true, ["run_id"] = "exp-" + Starts, ["ttl_sec"] = args["ttl_sec"]!.DeepClone() };
    }

    private JsonObject Result(JsonObject args)
    {
        var items = new JsonArray();
        string best = "";
        int offset = (int?)args["offset"] ?? 0;
        int limit = Math.Min((int?)args["limit"] ?? 8, PageSize ?? int.MaxValue);
        var window = _variants.Skip(offset).Take(limit).ToList();
        foreach (var v in window)
        {
            var candidate = (string)v!["profiles"]![0]!["args"]!;
            var rows = new JsonArray();
            foreach (var t in _targets)
            {
                var (ok, code, okCount) = OpenWithoutBypass.Contains(t) ? (true, "ok", 3) : Probe(candidate, t);
                rows.Add((JsonNode)new JsonObject
                {
                    ["target"] = t, ["ok"] = ok, ["code"] = code, ["code_desc"] = code, ["latency_ms"] = 200.0, ["latency_stat"] = "median",
                    ["bytes_read"] = ok ? 65536 : 0, ["kbps"] = 0.0, ["attempts"] = 3, ["ok_count"] = okCount,
                });
            }
            // a winner must open every target that was blocked without bypass
            if (best.Length == 0 && rows.All(r => (bool)r!["ok"]!) && rows.Any(r => !OpenWithoutBypass.Contains((string)r!["target"]!)))
                best = (string)v["label"]!;
            items.Add((JsonNode)new JsonObject
            {
                ["label"] = v["label"]!.DeepClone(), ["source"] = "profiles", ["args"] = new JsonArray(),
                ["validation"] = new JsonObject { ["available"] = true, ["ok"] = true, ["returncode"] = 0, ["output"] = "" },
                ["started_nfqws"] = true, ["skipped"] = false, ["skip_reason"] = "", ["per_target"] = rows,
                ["success_rate"] = 0.0, ["score"] = 0.0, ["hints"] = new JsonArray(), ["nfqws_log"] = new JsonArray(),
            });
        }
        bool truncated = offset + window.Count < _variants.Count;
        return new JsonObject
        {
            ["ok"] = true, ["items"] = items, ["total"] = _variants.Count, ["offset"] = offset, ["truncated"] = truncated,
            ["next_offset"] = truncated ? offset + window.Count : null,
            ["run_id"] = "exp-" + Starts, ["state"] = "finished",
            ["baseline"] = new JsonObject { ["measured"] = true, ["open_without_bypass"] = new JsonArray([.. OpenWithoutBypass.Select(t => (JsonNode)t)]) },
            ["best"] = best, ["awaiting_commit"] = _keepBest && best.Length > 0, ["committed"] = false, ["restored"] = true, ["error"] = "",
        };
    }

    public ZapretGuiExperiments Experiments() => new(Mcp());

    public ZapretGuiMcp Mcp() => new(new HttpClient(this, disposeHandler: false) { BaseAddress = new Uri("http://192.168.1.1:8080/") }, "tok");
}
