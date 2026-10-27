using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ZapretAutoTuner.Mcp.Tests;

/// <summary>
/// The boundary of the server (MCP design, "Тест на эту границу"): the tools and their full schemas are pinned in a
/// golden file, and no schema may name a path, a command, arguments, a URL or a script anywhere.
/// </summary>
public sealed partial class SchemaTests
{
    private static string GoldenPath([CallerFilePath] string here = "") => Path.Combine(Path.GetDirectoryName(here)!, "golden", "tools.json");

    /// <summary>What a client sees in tools/list for every tool, plus the permission group and the confirmation flag.</summary>
    internal static string Snapshot()
    {
        var arr = new JsonArray();
        foreach (var d in McpTools.All)
        {
            var tool = McpServerSetup.ToTool(d);
            arr.Add((JsonNode)new JsonObject
            {
                ["name"] = tool.Name,
                ["scope"] = McpPermissions.Name(d.Scope),
                ["confirms"] = d.Confirms,
                ["description"] = tool.Description,
                ["inputSchema"] = JsonNode.Parse(tool.InputSchema.GetRawText()),
            });
        }
        return arr.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }).ReplaceLineEndings("\n") + "\n";
    }

    /// <summary>Review L1: a pattern's final $ is the end of the input, as in ECMA-262; "name\n" does not pass.</summary>
    [Fact]
    public void PatternDollarIsTheEndOfTheInput()
    {
        var schema = new JsonObject { ["type"] = "string", ["pattern"] = ResourceTools.NamePattern };
        Assert.Null(S.Check(schema, JsonValue.Create("yt")));
        Assert.NotNull(S.Check(schema, JsonValue.Create("yt\n")));
        Assert.Equal("^a\\$", S.NetPattern("^a\\$"));
    }

    /// <summary>
    /// Pins our own tools (<see cref="McpTools.All"/>) only. The router's zapret-gui tools relayed as gui_* with the
    /// router_proxy permission (PLAN 4a.7) are dynamic, zapret-gui's own schemas: they are not in the golden file, and
    /// BridgeTests checks that no tool of ours takes their prefix or scope.
    /// </summary>
    [Fact]
    public void TheToolListMatchesTheGoldenFile()
    {
        var actual = Snapshot();
        var path = GoldenPath();
        if (Environment.GetEnvironmentVariable("ZT_UPDATE_GOLDEN") == "1")
            File.WriteAllText(path, actual);
        Assert.True(File.Exists(path), "golden/tools.json is missing: run the tests with ZT_UPDATE_GOLDEN=1 once and review it");
        Assert.Equal(File.ReadAllText(path).ReplaceLineEndings("\n"), actual);
    }

    [GeneratedRegex("^(path|paths|file|files|filename|filepath|dir|directory|folder|command|commands|cmd|cmdline|args|arg|argv|url|urls|uri|uris|exec|execute|script|scripts|shell|lua|code|program|binary)$|path|file|command|cmd|args|argv|url|uri|exec|script|shell|lua", RegexOptions.IgnoreCase)]
    private static partial Regex Forbidden();

    private static IEnumerable<string> PropertyNames(JsonNode? n)
    {
        if (n is JsonObject o)
        {
            if (o["properties"] is JsonObject props)
            {
                foreach (var (k, v) in props)
                {
                    yield return k;
                    foreach (var inner in PropertyNames(v))
                        yield return inner;
                }
            }
            foreach (var (k, v) in o)
            {
                if (k == "properties")
                    continue;
                foreach (var inner in PropertyNames(v))
                    yield return inner;
            }
        }
        else if (n is JsonArray a)
        {
            foreach (var x in a)
                foreach (var inner in PropertyNames(x))
                    yield return inner;
        }
    }

    /// <summary>Our own tools only; the relayed gui_* tools carry zapret-gui's schemas, behind its token and the user's yes.</summary>
    [Fact]
    public void NoSchemaNamesAPathCommandArgsUrlOrScript()
    {
        var bad = McpTools.All.SelectMany(t => PropertyNames(t.InputSchema).Where(p => Forbidden().IsMatch(p) && !Allowed(t, p)).Select(p => $"{t.Name}.{p}")).ToList();
        Assert.Equal([], bad);
    }

    /// <summary>
    /// PLAN 4a.5: the one exception is the typed Lua draft of resource_create and resource_update; it is data the
    /// program checks and stores as a draft, and only the user can approve it in the window.
    /// </summary>
    private static bool Allowed(McpToolDefinition t, string property) =>
        property == "lua_source" && t.Name is "resource_create" or "resource_update";

    [Fact]
    public void OnlyTheResourceToolsTakeLuaSource()
    {
        Assert.Equal(["resource_create", "resource_update"],
            McpTools.All.Where(t => PropertyNames(t.InputSchema).Contains("lua_source")).Select(t => t.Name));
        Assert.All(McpTools.All.Where(t => PropertyNames(t.InputSchema).Contains("lua_source")), t => Assert.True(t.Confirms));
    }

    [Fact]
    public void TheForbiddenCheckWouldCatchOne()
    {
        var schema = S.Obj([("outer", S.Obj([("target_File", S.Str("x"))]))]);
        Assert.Contains("target_File", PropertyNames(schema).Where(p => Forbidden().IsMatch(p)));
        Assert.Contains("Args", new[] { "Args" }.Where(p => Forbidden().IsMatch(p)));
    }

    [Fact]
    public void EverySchemaIsClosed()
    {
        static IEnumerable<JsonObject> Objects(JsonNode? n) => n switch
        {
            JsonObject o => (((string?)o["type"]) == "object" ? [o] : Enumerable.Empty<JsonObject>()).Concat(o.SelectMany(kv => Objects(kv.Value))),
            JsonArray a => a.SelectMany(Objects),
            _ => [],
        };
        foreach (var t in McpTools.All)
            Assert.All(Objects(t.InputSchema), o => Assert.False((bool)o["additionalProperties"]!));
    }

    [Fact]
    public void TheToolsAreTheDesignTable()
    {
        Assert.Equal(
            ["targets_list", "diagnose", "trials_history", "catalog_functions", "strategy_validate", "kb_query", "bug_report_draft"],
            McpTools.All.Where(t => t.Scope == McpScope.Read).Select(t => t.Name));
        Assert.Equal(["target_add", "trial_run"], McpTools.All.Where(t => t.Scope == McpScope.Probes).Select(t => t.Name));
        Assert.Equal(["search_start", "search_status", "search_pause", "search_stop", "search_enqueue", "search_prune_family"], McpTools.All.Where(t => t.Scope == McpScope.Control).Select(t => t.Name));
        Assert.Equal(["strategy_experiment_start", "strategy_experiment_status", "strategy_experiment_result", "strategy_experiment_commit", "strategy_experiment_rollback"],
            McpTools.All.Where(t => t.Scope == McpScope.Experiments).Select(t => t.Name));
        Assert.Equal(["export_preview"], McpTools.All.Where(t => t.Scope == McpScope.Export).Select(t => t.Name));
        Assert.Equal(["router_experiment_start", "router_experiment_status", "router_experiment_result", "router_experiment_commit", "router_experiment_rollback"],
            McpTools.All.Where(t => t.Scope == McpScope.Router).Select(t => t.Name));
        // the router's start and commit change the router: both wait for the user's yes (AGENTS.md rule 7)
        Assert.Equal(["router_experiment_start", "router_experiment_commit"], McpTools.All.Where(t => t.Scope == McpScope.Router && t.Confirms).Select(t => t.Name));
        Assert.Equal(["resource_list", "resource_get", "resource_diff", "resource_create", "resource_update", "resource_delete", "router_resource_push", "router_resource_delete"],
            McpTools.All.Where(t => t.Scope == McpScope.Resources).Select(t => t.Name));
    }

    [Fact]
    public void UnknownArgumentsAreRefused()
    {
        var schema = McpTools.Find("diagnose")!.InputSchema;
        Assert.Null(S.Check(schema, JsonNode.Parse("""{"target":"a.example"}""")));
        Assert.Contains("unknown argument", S.Check(schema, JsonNode.Parse("""{"target":"a.example","path":"/etc/passwd"}""")));
        Assert.Contains("required", S.Check(schema, JsonNode.Parse("{}")));
        Assert.Contains("does not match", S.Check(schema, JsonNode.Parse("""{"target":"https://a.example/x"}""")));
    }
}
