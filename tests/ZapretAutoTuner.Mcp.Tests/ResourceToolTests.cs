using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Resources;
using ZapretAutoTuner.Delivery;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.Mcp.Tests;

/// <summary>Strategy resources over MCP (PLAN 4a.5): typed content, the user's yes for every change, no Lua approval.</summary>
public sealed class ResourceToolTests
{
    private const string Lua = "function zt_twice(ctx, desync) return VERDICT_PASS end\n";

    private static Rig Make(bool export = false)
    {
        var rig = new Rig(new McpPermissions(Resources: true, Export: export));
        rig.Host.Resources = new ResourceStore(rig.Host.Kb);
        return rig;
    }

    private static async Task<McpToolResult> Decided(Rig rig, string tool, string json)
    {
        McpToolResult r = null!;
        await Rig.Until(async () =>
        {
            r = await rig.Call(tool, json);
            return (string?)r.Data["status"] is not ("pending_confirmation" or "confirmed_running");
        });
        return r;
    }

    [Fact]
    public async Task ResourcesAreOffByDefault()
    {
        using var rig = new Rig();
        Assert.DoesNotContain(rig.Tools.ListTools(), t => t.Scope == McpScope.Resources);
        var r = await rig.Call("resource_list");
        Assert.True(r.IsError);
        Assert.Equal("resources", (string?)r.Data["permission"]);
    }

    [Fact]
    public async Task CreatingAHostlistWaitsForTheUser()
    {
        using var rig = Make();
        var json = """{"kind":"hostlist","name":"video","domains":["Example.COM","https://www.example.org/x"]}""";
        var r = await rig.Call("resource_create", json);
        Assert.Equal("pending_confirmation", (string?)r.Data["status"]);
        Assert.Empty(rig.Host.Resources!.List());
        await Rig.Until(() => Task.FromResult(rig.Confirm.Asked.Count == 1));
        Assert.Contains("example.com", rig.Confirm.Asked[0].TextRu, StringComparison.Ordinal);
        rig.Confirm.Answer(true);
        var done = await Decided(rig, "resource_create", json);
        Assert.True((string?)done.Data["status"] == "created", done.Text);
        var stored = rig.Host.Resources.Get(ResourceKind.Hostlist, "video")!;
        Assert.Equal(["example.com", "www.example.org"], stored.Data.Items);
        Assert.Equal("mcp", rig.Host.Resources.Versions(ResourceKind.Hostlist, "video")[0].Origin);

        var get = await rig.Call("resource_get", """{"kind":"hostlist","name":"video"}""");
        Assert.Equal(["example.com", "www.example.org"], get.Data["domains"]!.AsArray().Select(x => (string?)x));
    }

    [Theory]
    [InlineData("""{"kind":"blob","name":"bad-name","hex":"0102"}""")]
    [InlineData("""{"kind":"blob","name":"ok_name","hex":"zz"}""")]
    [InlineData("""{"kind":"hostlist","name":"x","entries":["1.2.3.4"]}""")]
    [InlineData("""{"kind":"lua","name":"x","lua_source":"function multisplit(ctx, desync) end"}""")]
    public async Task BadContentIsRefusedBeforeTheUserIsAsked(string json)
    {
        using var rig = Make();
        var r = await rig.Call("resource_create", json);
        Assert.True(r.IsError);
        Assert.False(string.IsNullOrEmpty((string?)r.Data["error"]));
        Assert.Empty(rig.Confirm.Asked);
    }

    [Fact]
    public async Task ALuaScriptFromTheModelStaysADraft()
    {
        using var rig = Make();
        var json = JsonSerializerText(new JsonObject { ["kind"] = "lua", ["name"] = "twice", ["lua_source"] = Lua });
        await rig.Call("resource_create", json);
        await Rig.Until(() => Task.FromResult(rig.Confirm.Asked.Count == 1));
        Assert.Contains("черновик", rig.Confirm.Asked[0].TextRu, StringComparison.Ordinal);
        Assert.Contains(Lua.Trim(), rig.Confirm.Asked[0].TextEn, StringComparison.Ordinal);
        rig.Confirm.Answer(true);
        var done = await Decided(rig, "resource_create", json);
        Assert.Equal("draft", (string?)done.Data["resource"]!["approval"]);
        Assert.Equal(LuaApproval.Draft, rig.Host.Resources!.List(ResourceKind.LuaScript)[0].Approval);
        // no tool approves, and no tool description offers it
        Assert.DoesNotContain(McpTools.All, t => t.Name.Contains("approve", StringComparison.Ordinal));
        Assert.Contains("cannot approve", McpTools.Find("resource_create")!.Description, StringComparison.Ordinal);

        // the user approves in the window; an edit over MCP is a new draft and the approved version stays in effect
        rig.Host.Resources.Approve("twice", 1, confirmedByUser: true);
        var edit = JsonSerializerText(new JsonObject { ["kind"] = "lua", ["name"] = "twice", ["lua_source"] = Lua + "-- v2\n" });
        await rig.Call("resource_update", edit);
        await Rig.Until(() => Task.FromResult(rig.Confirm.Asked.Count == 2));
        rig.Confirm.Answer(true);
        await Decided(rig, "resource_update", edit);
        var info = rig.Host.Resources.List(ResourceKind.LuaScript)[0];
        Assert.Equal(LuaApproval.ApprovedWithNewDraft, info.Approval);
        Assert.Equal(1, info.ApprovedVersion);
        var diff = await rig.Call("resource_diff", """{"kind":"lua","name":"twice"}""");
        Assert.Equal(1, (int?)diff.Data["from_version"]);
        Assert.Contains("+-- v2", (string?)diff.Data["diff"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task AUsedResourceCannotBeDeleted()
    {
        using var rig = Make();
        rig.Host.Resources!.Create(ResourceInput.Hostlist("video", ["example.com"]));
        var s = new Solution();
        s.Profiles.Add(new Profile { Name = "p", TcpPorts = "443", Hostlists = [new ListRef("video")], Strategy = Strategy.Parse("--lua-desync=multisplit:pos=1") });
        rig.Host.Resources.SetReferences(ResourceStore.CurrentSolutionOwner, s);
        var r = await rig.Call("resource_delete", """{"kind":"hostlist","name":"video"}""");
        Assert.True(r.IsError);
        Assert.Contains(ResourceStore.CurrentSolutionOwner, (string?)r.Data["error"], StringComparison.Ordinal);
        Assert.Empty(rig.Confirm.Asked);

        rig.Host.Resources.ClearReferences(ResourceStore.CurrentSolutionOwner);
        await rig.Call("resource_delete", """{"kind":"hostlist","name":"video"}""");
        await Rig.Until(() => Task.FromResult(rig.Confirm.Asked.Count == 1));
        rig.Confirm.Answer(true);
        var done = await Decided(rig, "resource_delete", """{"kind":"hostlist","name":"video"}""");
        Assert.Equal("deleted", (string?)done.Data["status"]);
        Assert.Empty(rig.Host.Resources.List());
    }

    [Fact]
    public async Task RouterPushNeedsExportAnApprovedScriptAndTheUsersYes()
    {
        using var rig = Make();
        var store = rig.Host.Resources!;
        store.Create(ResourceInput.Lua("twice", Lua));
        int ran = 0;
        rig.Host.Router = (action, kind, name) => new RouterResourceOperation(RouterResources.ZapretGui, action, new ResourceRef(kind, name),
            [new DeliveryStep("записать", "write")], "превью", "preview", _ =>
            {
                ran++;
                return Task.FromResult(new DeliveryResult(true, false, ["put zt-twice"], null));
            });

        var denied = await rig.Call("router_resource_push", """{"kind":"lua","name":"twice"}""");
        Assert.Equal("export", (string?)denied.Data["permission"]);

        rig.Permissions = new McpPermissions(Resources: true, Export: true);
        var draft = await rig.Call("router_resource_push", """{"kind":"lua","name":"twice"}""");
        Assert.True(draft.IsError);
        Assert.Contains("not approved", (string?)draft.Data["error"], StringComparison.Ordinal);
        Assert.Empty(rig.Confirm.Asked);

        store.Approve("twice", 1, confirmedByUser: true);
        var pending = await rig.Call("router_resource_push", """{"kind":"lua","name":"twice"}""");
        Assert.Equal("pending_confirmation", (string?)pending.Data["status"]);
        await Rig.Until(() => Task.FromResult(rig.Confirm.Asked.Count == 1));
        Assert.Contains("write", rig.Confirm.Asked[0].TextEn, StringComparison.Ordinal);
        Assert.Contains("preview", rig.Confirm.Asked[0].TextEn, StringComparison.Ordinal);
        Assert.Equal(0, ran);
        rig.Confirm.Answer(true);
        var done = await Decided(rig, "router_resource_push", """{"kind":"lua","name":"twice"}""");
        Assert.Equal("written", (string?)done.Data["status"]);
        Assert.Equal(1, ran);
    }

    [Fact]
    public async Task WithoutARouterThePushSaysSo()
    {
        using var rig = Make(export: true);
        rig.Host.Resources!.Create(ResourceInput.Ipset("isp", ["203.0.113.0/24"]));
        var r = await rig.Call("router_resource_push", """{"kind":"ipset","name":"isp"}""");
        Assert.True(r.IsError);
        Assert.Contains("no router", (string?)r.Data["error"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task ABugReportDraftIsTextOnly()
    {
        using var rig = new Rig();
        Assert.Contains(rig.Tools.ListTools(), t => t.Name == "bug_report_draft");
        var r = await rig.Call("bug_report_draft", """{"kind":"engine_refused","summary":"winws2 refused fake:blob=x","what_did":"trial on 192.168.1.10","tracker":"zapret2","language":"en"}""");
        Assert.False(r.IsError);
        Assert.Equal("bol-van/zapret2", (string?)r.Data["repository"]);
        Assert.StartsWith("https://github.com/bol-van/zapret2/issues/new?title=", (string?)r.Data["issue_url"], StringComparison.Ordinal);
        Assert.False((bool)r.Data["sent"]!);
        Assert.DoesNotContain("192.168.1.10", (string?)r.Data["body"], StringComparison.Ordinal);
        var bad = await rig.Call("bug_report_draft", """{"kind":"app_error","about":"not-a-target.example"}""");
        Assert.True(bad.IsError);
    }

    private static string JsonSerializerText(JsonObject o) => o.ToJsonString();
}
