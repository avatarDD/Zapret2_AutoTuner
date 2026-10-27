using System.Diagnostics;
using System.Text.Json.Nodes;
using ModelContextProtocol.Client;
using ZapretAutoTuner.Tuning;
using ZapretAutoTuner.Tuning.Tests;

namespace ZapretAutoTuner.Mcp.Tests;

/// <summary>Regression tests of the final review: the search's start, unexpected errors and the router's relayed tools.</summary>
public sealed class FinalReviewTests
{
    private static readonly McpPermissions Proxy = new(RouterProxy: true);

    private static JsonObject Def(string name, bool? readOnly) => new()
    {
        ["name"] = name,
        ["description"] = "zapret-gui " + name,
        ["inputSchema"] = new JsonObject { ["type"] = "object" },
        ["annotations"] = readOnly is null ? null : new JsonObject { ["readOnlyHint"] = readOnly },
    };

    private static (Rig Rig, RouterGui Gui) Setup(McpPermissions? permissions = null, TimeProvider? time = null)
    {
        var gui = new RouterGui { ToolDefinitions = [Def("status_get", true), Def("strategy_apply", null)] };
        var rig = new Rig(permissions ?? Proxy, time: time);
        rig.Host.RouterLink = gui.Mcp();
        return (rig, gui);
    }

    [Fact]
    public async Task AFailureWhileTheSearchStartsLeavesItIdleAndIsAnAuditedError()
    {
        using var rig = new Rig(Rig.All, new BudgetOptions { PerMinute = 10_000 });
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        rig.Host.AgentStarting = () => throw new System.Text.Json.JsonException("broken state file");
        var r = await rig.Call("search_start", """{"target":"blocked.example","mode":"quick"}""");
        Assert.True(r.IsError);
        Assert.Contains("broken state file", (string?)r.Data["error"]);
        Assert.False(rig.Session.Search.Running);
        Assert.Equal("idle", (string?)rig.Session.Search.Status()["state"]);
        Assert.Contains(rig.Session.Audit.Entries, e => e.Tool == "search_start" && e.Outcome.StartsWith("error", StringComparison.Ordinal));

        // a timeout inside (not the client's cancel) is an answer too
        rig.Host.AgentStarting = () => throw new TaskCanceledException("HttpClient.Timeout");
        var t = await rig.Call("search_start", """{"target":"blocked.example","mode":"quick"}""");
        Assert.True(t.IsError);
        Assert.Contains("timed out", (string?)t.Data["error"]);
        Assert.False(rig.Session.Search.Running);

        // and it starts once the cause is gone
        rig.Host.AgentStarting = null;
        var ok = await rig.Call("search_start", """{"target":"blocked.example","mode":"quick"}""");
        Assert.False(ok.IsError, ok.Text);
        await rig.Session.Search.StopAsync();
    }

    [Fact]
    public async Task AStopWhileTheSearchStartsCancelsIt()
    {
        using var rig = new Rig(Rig.All, new BudgetOptions { PerMinute = 10_000 });
        await rig.Call("diagnose", """{"target":"blocked.example","refresh":true}""");
        var gate = new TaskCompletionSource();
        rig.Host.AgentStarting = () => gate.Task;
        var start = rig.Call("search_start", """{"target":"blocked.example","mode":"quick"}""");
        await Rig.Until(() => Task.FromResult(rig.Session.Search.Running));
        var stop = await rig.Call("search_stop");
        Assert.False(stop.IsError);
        Assert.False(rig.Session.Search.Running);
        gate.SetResult();
        var r = await start;
        Assert.True(r.IsError);
        Assert.Contains("stopped", (string?)r.Data["error"]);
        Assert.False(rig.Session.Search.Running);
        Assert.Empty(rig.Host.Engine.Started);
    }

    [Fact]
    public async Task AnUnreachableRouterDoesNotHoldToolsList()
    {
        var time = new ManualTime();
        var (rig, gui) = Setup(time: time);
        using var _ = rig;
        gui.BeforeToolsList = ct => Task.Delay(Timeout.Infinite, ct);
        var sw = Stopwatch.StartNew();
        Assert.Empty(await rig.Tools.ListRouterToolsAsync());
        Assert.True(sw.Elapsed < RouterProxy.FetchTimeout, sw.Elapsed.ToString());
        // the fetch gives up on its own
        await Rig.Until(() => Task.FromResult(rig.Session.Proxy.LastError is not null));
        int lists = gui.ToolLists;
        // backed off: neither tools/list nor an unknown name fetch again at once
        sw.Restart();
        Assert.Empty(await rig.Tools.ListRouterToolsAsync());
        var r = await rig.Call("gui_status_get");
        Assert.True(r.IsError);
        Assert.Contains("not available", (string?)r.Data["error"]);
        await rig.Call("gui_status_get");
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), sw.Elapsed.ToString());
        Assert.True(gui.ToolLists <= lists + 1, $"{gui.ToolLists} vs {lists}");
        lists = gui.ToolLists;

        // the router is back: after the back-off the list is fetched again
        gui.BeforeToolsList = null;
        time.Now += RouterProxy.MaxRetryAfter + TimeSpan.FromSeconds(1);
        await Rig.Until(async () => (await rig.Tools.ListRouterToolsAsync()).Count == 2);
        Assert.True(gui.ToolLists > lists);
    }

    [Fact]
    public async Task OneMalformedRouterToolIsDroppedNotTheWholeList()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        gui.ToolDefinitions =
        [
            Def("status_get", true),
            new JsonObject { ["name"] = "num_description", ["description"] = 5 },
            new JsonObject { ["name"] = "array_title", ["title"] = new JsonArray("a") },
            new JsonObject { ["name"] = "bad_hint", ["annotations"] = new JsonObject { ["readOnlyHint"] = "yes", ["x"] = new JsonArray() } },
            new JsonObject { ["name"] = "type_array", ["inputSchema"] = new JsonObject { ["type"] = new JsonArray("object", "null") } },
            new JsonObject { ["name"] = "dotted.name" },
            new JsonObject { ["name"] = new string('n', 61) },
            new JsonObject { ["name"] = 7 },
        ];
        var names = (await rig.Tools.ListRouterToolsAsync()).Select(t => (string?)t["name"]).ToList();
        Assert.Equal(["gui_status_get", "gui_num_description", "gui_array_title", "gui_bad_hint", "gui_type_array"], names);
        var hint = (await rig.Tools.ListRouterToolsAsync()).Single(t => (string?)t["name"] == "gui_bad_hint");
        Assert.Contains("confirmation", (string?)hint["description"]);

        var token = McpHttpServer.NewToken();
        await using var http = await McpHttpServer.StartAsync(rig.Tools, 0, token);
        await using var mcp = await McpClient.CreateAsync(new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = http.Endpoint,
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer " + token },
        }));
        var tools = await mcp.ListToolsAsync();
        Assert.Contains(tools, t => t.Name == "targets_list");
        Assert.Contains(tools, t => t.Name == "gui_status_get");
    }

    [Theory]
    [InlineData("gui_strategy_apply", """{"args":"--filter-tcp=443 --dpi-desync=fake"}""", "dpi-desync")]
    [InlineData("gui_strategy_apply", """{"profiles":[{"args":"--filter-tcp=443 --lua-desync=luaexec:code=os.execute"}]}""", "luaexec")]
    [InlineData("gui_status_get", """{"id":"--lua-init=@/tmp/evil.lua --lua-desync=multisplit:pos=1"}""", "lua-init")]
    [InlineData("gui_strategy_apply", """{"args":"--lua-desync=nosuchfunc:pos=1"}""", "nosuchfunc")]
    public async Task EngineOptionsInRouterToolArgumentsPassTheRules(string tool, string args, string expected)
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        var r = await rig.Call(tool, args);
        Assert.True(r.IsError, r.Text);
        Assert.Contains(expected, (string?)r.Data["error"]);
        Assert.Contains("refused", (string?)r.Data["error"]);
        Assert.Empty(rig.Confirm.Asked);
        Assert.Empty(gui.Calls);
    }

    [Fact]
    public async Task AValidProfileAndPlainTextGoOnToTheConfirmation()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        var ok = await rig.Call("gui_strategy_apply", """{"args":"--filter-tcp=443 --lua-desync=multisplit:pos=1","note":"plain words - not options"}""");
        Assert.False(ok.IsError, ok.Text);
        Assert.Equal("pending_confirmation", (string?)ok.Data["status"]);
    }

    [Fact]
    public async Task TheConfirmationShowsAllArgumentsWithoutHiddenCharacters()
    {
        var (rig, gui) = Setup();
        using var _ = rig;
        var tooLong = new JsonObject { ["text"] = new string('a', RouterProxy.MaxConfirmChars + 10) };
        var r = await rig.Call("gui_strategy_apply", tooLong.ToJsonString());
        Assert.True(r.IsError);
        Assert.Contains("too long to show", (string?)r.Data["error"]);
        Assert.Empty(rig.Confirm.Asked);

        var bidi = new JsonObject { ["name"] = "safe‮txt.exe" };
        var p = await rig.Call("gui_strategy_apply", bidi.ToJsonString());
        Assert.Equal("pending_confirmation", (string?)p.Data["status"]);
        var asked = Assert.Single(rig.Confirm.Asked);
        Assert.DoesNotContain('‮', asked.TextEn);
        Assert.DoesNotContain('‮', asked.TextRu);
        Assert.Equal("a<U+202E>b<U+200F>\n", Core.SafeText.ForDisplay("a‮b‏\n"));
    }

    [Fact]
    public async Task AKeptRouterVariantBlocksChangingRouterTools()
    {
        var gui = new RouterGui
        {
            Probe = (args, _) => args.Contains("multisplit", StringComparison.Ordinal) ? (true, "ok", 3) : (false, "tls_rst", 0),
            Active = ("yt_quic", [("QUIC", "--filter-udp=443 --lua-desync=fake:blob=fake_default_quic", true)]),
        };
        gui.ToolDefinitions = [.. gui.Tools.Select(n => Def(n, null)), Def("service_restart", false)];
        using var rig = new Rig(new McpPermissions(Probes: true, Control: true, Experiments: true, Export: true, Router: true, RouterProxy: true));
        rig.Host.Router = gui.Experiments();
        rig.Host.RouterLink = gui.Mcp();
        rig.Session.Router.Poll = TimeSpan.FromMilliseconds(1);
        await rig.Call("router_experiment_start", """{"variants":[{"label":"B","strategy":"--lua-desync=multisplit:pos=1"}],"targets":["blocked.example"],"repeats":1,"keep_best":true}""");
        rig.Confirm.Answer(true);
        await Rig.Until(async () => (string?)(await rig.Call("router_experiment_status")).Data["state"] is "finished" or "failed");
        Assert.True(rig.Session.Router.Holding);
        Assert.False(rig.Session.Router.Running);
        var r = await rig.Call("gui_service_restart");
        Assert.True(r.IsError, r.Text);
        Assert.Contains("busy", (string?)r.Data["error"]);
    }
}
