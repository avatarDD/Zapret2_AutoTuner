using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using ModelContextProtocol.Client;
using ZapretAutoTuner.Tuning.Tests;

namespace ZapretAutoTuner.Mcp.Tests;

/// <summary>
/// PLAN 4a.7: the router's zapret-gui tools relayed as gui_* (router_proxy), and the HTTP transport opened to browser
/// extensions the user allowed (CORS, legacy SSE), the token still required.
/// </summary>
public sealed class BridgeTests
{
    private static readonly McpPermissions Proxy = new(RouterProxy: true);

    private static JsonObject Def(string name, bool? readOnly, JsonObject? schema = null) => new()
    {
        ["name"] = name,
        ["description"] = "zapret-gui " + name,
        ["inputSchema"] = schema ?? new JsonObject { ["type"] = "object", ["properties"] = new JsonObject { ["id"] = new JsonObject { ["type"] = "string" } } },
        ["annotations"] = readOnly is null ? null : new JsonObject { ["readOnlyHint"] = readOnly },
    };

    private static JsonObject Structured(JsonObject payload, bool isError = false) => new()
    {
        ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = payload.ToJsonString() }),
        ["structuredContent"] = payload,
        ["isError"] = isError,
    };

    private static (Rig Rig, RouterGui Gui) Setup(McpPermissions? permissions = null, TimeProvider? time = null)
    {
        var gui = new RouterGui
        {
            ToolDefinitions = [Def("status_get", true), Def("strategy_apply", null), Def("logs_tail", true), Def("service_restart", false), Def("bad name!", true)],
        };
        var rig = new Rig(permissions ?? Proxy, time: time);
        rig.Host.RouterLink = gui.Mcp();
        return (rig, gui);
    }

    [Fact]
    public void OurOwnToolsNeverUseTheRouterPrefixOrScope()
    {
        // the golden file pins McpTools.All only: the relayed gui_* tools are dynamic and deliberately not in it
        Assert.DoesNotContain(McpTools.All, t => RouterProxy.IsProxied(t.Name));
        Assert.DoesNotContain(McpTools.All, t => t.Scope == McpScope.RouterProxy);
        Assert.Equal("router_proxy", McpPermissions.Name(McpScope.RouterProxy));
        Assert.False(new McpPermissions().Granted(McpScope.RouterProxy));
        Assert.True(Proxy.Granted(McpScope.RouterProxy));
    }

    [Fact]
    public async Task ThePermissionOffHidesTheRouterToolsAndRefusesThem()
    {
        var (rig, gui) = Setup(new McpPermissions());
        using var _ = rig;
        Assert.Empty(await rig.Tools.ListRouterToolsAsync());
        var r = await rig.Call("gui_status_get");
        Assert.True(r.IsError);
        Assert.Equal("router_proxy", (string?)r.Data["permission"]);
        Assert.Equal(0, gui.ToolLists);
        Assert.Empty(gui.Calls);
    }

    [Fact]
    public async Task WithoutZapretGuiThereIsNothingToRelay()
    {
        using var rig = new Rig(Proxy);
        Assert.Empty(await rig.Tools.ListRouterToolsAsync());
        var r = await rig.Call("gui_status_get");
        Assert.True(r.IsError);
        Assert.Contains("not set up", (string?)r.Data["error"]);
    }

    [Fact]
    public async Task TheListIsPagedPrefixedPassedThroughAndCached()
    {
        var time = new ManualTime();
        var (rig, gui) = Setup(time: time);
        using var _ = rig;
        gui.ToolsPageSize = 2;
        var tools = await rig.Tools.ListRouterToolsAsync();
        Assert.Equal(["gui_status_get", "gui_strategy_apply", "gui_logs_tail", "gui_service_restart"], tools.Select(t => (string?)t["name"]));
        var status = tools[0];
        Assert.Equal("string", (string?)status["inputSchema"]!["properties"]!["id"]!["type"]);
        Assert.True((bool)status["annotations"]!["readOnlyHint"]!);
        Assert.DoesNotContain("confirmation", (string?)status["description"]);
        Assert.Contains("confirmation", (string?)tools[1]["description"]);
        // three pages, then the cache
        int lists = gui.ToolLists;
        Assert.Equal(3, lists);
        await rig.Tools.ListRouterToolsAsync();
        Assert.Equal(lists, gui.ToolLists);
        time.Now += RouterProxy.CacheFor + TimeSpan.FromSeconds(1);
        await rig.Tools.ListRouterToolsAsync();
        Assert.Equal(lists + 3, gui.ToolLists);
        // nothing of ours is touched
        Assert.DoesNotContain(rig.Tools.ListTools(), t => RouterProxy.IsProxied(t.Name));
        // the SDK form keeps the annotations
        var sdk = McpServerSetup.ToRelayedTool(status);
        Assert.Equal("gui_status_get", sdk.Name);
        Assert.True(sdk.Annotations?.ReadOnlyHint);
    }

    [Fact]
    public async Task AReadOnlyToolIsForwardedAtOnceMaskedAndAudited()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        gui.OnTool = (name, args, ct) => Task.FromResult<JsonObject?>(name == "status_get"
            ? Structured(new JsonObject { ["ok"] = true, ["lan"] = "router at 192.168.2.1, client 192.168.2.34", ["id"] = (string?)args["id"] })
            : null);
        var r = await rig.Call("gui_status_get", """{"id":"x1"}""");
        Assert.False(r.IsError, r.Text);
        Assert.Empty(rig.Confirm.Asked);
        Assert.Equal("x1", (string?)r.Data["id"]);
        Assert.DoesNotContain("192.168.2", r.Text);
        Assert.Contains("lan-", r.Text);
        Assert.Equal("x1", (string?)Assert.Single(gui.Calls, c => c.Tool == "status_get").Args["id"]);
        Assert.Contains(rig.Session.Audit.Entries, e => e.Tool == "gui_status_get" && e.Outcome == "ok");
    }

    [Fact]
    public async Task TextAnswersAreMaskedAndBoundedAndErrorsStayErrors()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        gui.OnTool = (name, args, ct) => Task.FromResult<JsonObject?>(name switch
        {
            "logs_tail" => new JsonObject
            {
                ["content"] = new JsonArray(
                    new JsonObject { ["type"] = "text", ["text"] = "peer 10.1.2.3 " + new string('x', AutoTunerTools.MaxAnswerChars * 2) },
                    new JsonObject { ["type"] = "image", ["data"] = "AAAA", ["mimeType"] = "image/png" }),
            },
            "status_get" => new JsonObject { ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = "denied by token" }), ["isError"] = true },
            _ => null,
        });
        var log = await rig.Call("gui_logs_tail");
        Assert.False(log.IsError);
        Assert.DoesNotContain("10.1.2.3", log.Text);
        Assert.True((bool)log.Data["truncated"]!);
        Assert.Equal(1, (int)log.Data["dropped_content_blocks"]!);
        Assert.True(log.Text.Length < AutoTunerTools.MaxAnswerChars + 500);

        var denied = await rig.Call("gui_status_get");
        Assert.True(denied.IsError);
        Assert.Equal("denied by token", (string?)denied.Data["error"]);
    }

    [Fact]
    public async Task AToolThatIsNotReadOnlyWaitsForTheYesWithItsNameAndArguments()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        var first = await rig.Call("gui_strategy_apply", """{"id":"yt-quic"}""");
        Assert.False(first.IsError);
        Assert.Equal("pending_confirmation", (string?)first.Data["status"]);
        Assert.DoesNotContain(gui.Calls, c => c.Tool == "strategy_apply");
        var asked = Assert.Single(rig.Confirm.Asked);
        Assert.Equal("gui_strategy_apply", asked.Tool);
        Assert.Contains("strategy_apply", asked.TextEn);
        Assert.Contains("yt-quic", asked.TextEn);
        Assert.Contains("yt-quic", asked.TextRu);

        rig.Confirm.Answer(true);
        McpToolResult? done = null;
        await Rig.Until(async () => (string?)(done = await rig.Call("gui_strategy_apply", """{"id":"yt-quic"}""")).Data["status"] is not ("pending_confirmation" or "confirmed_running"));
        Assert.True((bool)done!.Data["ok"]!, done.Text);
        Assert.Single(gui.Calls, c => c.Tool == "strategy_apply");

        // explicitly false is not read-only either; declined: nothing is forwarded
        await rig.Call("gui_service_restart");
        rig.Confirm.Answer(false);
        await Rig.Until(async () => (string?)(await rig.Call("gui_service_restart")).Data["status"] == "declined");
        Assert.DoesNotContain(gui.Calls, c => c.Tool == "service_restart");
    }

    [Fact]
    public async Task OurRouterExperimentBlocksChangingToolsButNotReading()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        rig.Host.RouterTuningRunning = true;
        var change = await rig.Call("gui_strategy_apply", """{"id":"a"}""");
        Assert.True(change.IsError);
        Assert.Contains("busy", (string?)change.Data["error"]);
        Assert.Empty(rig.Confirm.Asked);
        var read = await rig.Call("gui_status_get");
        Assert.False(read.IsError, read.Text);
    }

    [Fact]
    public async Task AnUnknownRouterToolIsRefusedAfterARefresh()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        await rig.Tools.ListRouterToolsAsync();
        int lists = gui.ToolLists;
        var r = await rig.Call("gui_shell_exec");
        Assert.True(r.IsError);
        Assert.Contains("no tool", (string?)r.Data["error"]);
        Assert.True(gui.ToolLists > lists);
        Assert.Empty(gui.Calls);
    }

    [Fact]
    public async Task StopCancelsAForwardInFlight()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        gui.OnTool = async (name, args, ct) =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.Infinite, ct);
            return null;
        };
        var call = rig.Call("gui_logs_tail");
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await rig.Session.StopAllAsync();
        var r = await call.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(r.IsError);
        Assert.Contains("stopped", (string?)r.Data["error"]);
    }

    [Fact]
    public async Task TheRelayedToolsAppearInToolsListOverHttp()
    {
        var (rig, gui) = Setup(new McpPermissions(RouterProxy: true));
        using var _ = rig;
        var token = McpHttpServer.NewToken();
        await using var http = await McpHttpServer.StartAsync(rig.Tools, 0, token);
        await using var mcp = await McpClient.CreateAsync(new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = http.Endpoint,
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer " + token },
        }));
        var tools = await mcp.ListToolsAsync();
        Assert.Contains(tools, t => t.Name == "targets_list");
        var status = Assert.Single(tools, t => t.Name == "gui_status_get");
        Assert.True(status.ProtocolTool.Annotations?.ReadOnlyHint);
        var r = await mcp.CallToolAsync("gui_status_get", new Dictionary<string, object?> { ["id"] = "z" });
        Assert.NotEqual(true, r.IsError);
        Assert.Contains(gui.Calls, c => c.Tool == "status_get");
    }

    // ---- the HTTP transport for browser extensions

    private const string Ext = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
    private static readonly string Init = """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ext","version":"1"}}}""";

    [Theory]
    [InlineData("chrome-extension://abcdefghijklmnopabcdefghijklmnop", "chrome-extension://abcdefghijklmnopabcdefghijklmnop")]
    [InlineData(" moz-extension://0A1B2C3D-0000-4000-8000-123456789ABC/ ", "moz-extension://0a1b2c3d-0000-4000-8000-123456789abc")]
    [InlineData("https://claude.ai", null)]
    [InlineData("http://127.0.0.1:3006", null)]
    [InlineData("chrome-extension://", null)]
    [InlineData("chrome-extension://abc/path", null)]
    [InlineData("null", null)]
    public void OnlyExtensionOriginsAreAccepted(string text, string? expected) => Assert.Equal(expected, BridgeOrigins.Normalize(text));

    [Fact]
    public void TheSettingsTextIsSplitIntoValidAndRejected()
    {
        var (valid, invalid) = BridgeOrigins.Parse(Ext + "\n https://claude.ai, " + Ext.ToUpperInvariant() + "\nmoz-extension://f00d");
        Assert.Equal([Ext, "moz-extension://f00d"], valid);
        Assert.Equal(["https://claude.ai"], invalid);
    }

    private static async Task<HttpResponseMessage> Send(HttpClient client, HttpMethod method, Uri uri, string? origin, string? bearer, bool preflight = false)
    {
        var req = new HttpRequestMessage(method, uri);
        if (method == HttpMethod.Post)
            req.Content = new StringContent(Init, Encoding.UTF8, "application/json");
        req.Headers.Accept.ParseAdd("application/json");
        req.Headers.Accept.ParseAdd("text/event-stream");
        if (origin is not null)
            req.Headers.TryAddWithoutValidation("Origin", origin);
        if (bearer is not null)
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (preflight)
        {
            req.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "POST");
            req.Headers.TryAddWithoutValidation("Access-Control-Request-Headers", "authorization, content-type, mcp-session-id");
            req.Headers.TryAddWithoutValidation("Access-Control-Request-Private-Network", "true");
        }
        return await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);
    }

    private static string? Header(HttpResponseMessage r, string name) =>
        r.Headers.TryGetValues(name, out var v) ? string.Join(",", v) : r.Content.Headers.TryGetValues(name, out var c) ? string.Join(",", c) : null;

    [Fact]
    public async Task AllowedExtensionsGetCorsOthersAre403AndTheTokenIsStillRequired()
    {
        using var rig = new Rig();
        var token = McpHttpServer.NewToken();
        var allowed = new List<string>();
        await using var http = await McpHttpServer.StartAsync(rig.Tools, 0, token, () => allowed);
        using var client = new HttpClient();

        // not allowed yet: the preflight and the request are refused
        using (var r = await Send(client, HttpMethod.Options, http.Endpoint, Ext, null, preflight: true))
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        using (var r = await Send(client, HttpMethod.Post, http.Endpoint, Ext, token))
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);

        allowed.Add(Ext);
        using (var r = await Send(client, HttpMethod.Options, http.Endpoint, Ext, null, preflight: true))
        {
            Assert.Equal(HttpStatusCode.NoContent, r.StatusCode);
            Assert.Equal(Ext, Header(r, "Access-Control-Allow-Origin"));
            Assert.Contains("Authorization", Header(r, "Access-Control-Allow-Headers"));
            Assert.Contains("Mcp-Session-Id", Header(r, "Access-Control-Allow-Headers"));
            Assert.Contains("POST", Header(r, "Access-Control-Allow-Methods"));
            Assert.Equal("true", Header(r, "Access-Control-Allow-Private-Network"));
        }
        using (var r = await Send(client, HttpMethod.Post, http.Endpoint, Ext, null))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
            Assert.Equal(Ext, Header(r, "Access-Control-Allow-Origin"));
        }
        using (var r = await Send(client, HttpMethod.Post, http.Endpoint, Ext, "wrong"))
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        using (var r = await Send(client, HttpMethod.Post, http.Endpoint, Ext, token))
        {
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            Assert.Equal(Ext, Header(r, "Access-Control-Allow-Origin"));
            Assert.Contains("Mcp-Session-Id", Header(r, "Access-Control-Expose-Headers"));
        }

        // a web page (claude.ai itself included) and another extension stay out
        foreach (var other in new[] { "https://claude.ai", "chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba", "null" })
        {
            using var r = await Send(client, HttpMethod.Post, http.Endpoint, other, token);
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
            Assert.Null(Header(r, "Access-Control-Allow-Origin"));
        }

        // a local proxy (node, no Origin) needs only the token, and gets no CORS headers
        using (var r = await Send(client, HttpMethod.Post, http.Endpoint, null, token))
        {
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            Assert.Null(Header(r, "Access-Control-Allow-Origin"));
        }
        using (var r = await Send(client, HttpMethod.Post, http.Endpoint, null, null))
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);

        // taken off the list: refused again at once
        allowed.Clear();
        using (var r = await Send(client, HttpMethod.Post, http.Endpoint, Ext, token))
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
    }

    [Fact]
    public async Task LegacySseWorksWithTheTokenOnly()
    {
        using var rig = new Rig();
        var token = McpHttpServer.NewToken();
        await using var http = await McpHttpServer.StartAsync(rig.Tools, 0, token, () => [Ext]);
        using var client = new HttpClient();
        using (var r = await Send(client, HttpMethod.Get, http.SseEndpoint, Ext, null))
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        using (var r = await Send(client, HttpMethod.Get, http.SseEndpoint, "https://evil.example", token))
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);

        await using var mcp = await McpClient.CreateAsync(new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = http.SseEndpoint,
            TransportMode = HttpTransportMode.Sse,
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer " + token, ["Origin"] = Ext },
        }));
        var tools = await mcp.ListToolsAsync();
        Assert.Contains(tools, t => t.Name == "targets_list");
        var r2 = await mcp.CallToolAsync("targets_list", new Dictionary<string, object?>());
        Assert.NotEqual(true, r2.IsError);
    }

    [Fact]
    public void TheProxySnippetsUseTheProxyConfigFormat()
    {
        var stdio = JsonNode.Parse(McpClientConfig.ProxyStdio("/opt/zt/ZapretAutoTuner"))!["mcpServers"]![McpServerSetup.ServerName]!;
        Assert.Equal("stdio", (string?)stdio["type"]);
        Assert.Equal("/opt/zt/ZapretAutoTuner", (string?)stdio["command"]);
        Assert.Equal("mcp", (string?)stdio["args"]![0]);
        var httpEntry = JsonNode.Parse(McpClientConfig.ProxyHttp(new Uri("http://127.0.0.1:4711/mcp"), "tok"))!["mcpServers"]![McpServerSetup.ServerName]!;
        Assert.Equal("streamable-http", (string?)httpEntry["type"]);
        Assert.Equal("http://127.0.0.1:4711/mcp", (string?)httpEntry["url"]);
        Assert.Equal("Bearer tok", (string?)httpEntry["headers"]!["Authorization"]);
        var direct = McpClientConfig.Direct(new Uri("http://127.0.0.1:4711/mcp"), new Uri("http://127.0.0.1:4711/mcp/sse"), "tok");
        Assert.Contains("http://127.0.0.1:4711/mcp/sse", direct);
        Assert.Contains("Authorization: Bearer tok", direct);
    }
}
