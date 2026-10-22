using System.Net;
using System.Text;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Resources;

namespace ZapretAutoTuner.Delivery.Tests;

/// <summary>One resource on the router (PLAN 4a.5): the plan the user sees, and nothing done before the confirmed run.</summary>
public sealed class RouterResourcesTests
{
    private sealed class Gui : HttpMessageHandler
    {
        public List<(string Method, string Path)> Calls { get; } = [];

        public string Strategies { get; set; } = "{\"ok\":true,\"strategies\":[]}";

        public bool LuaValid { get; set; } = true;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            Calls.Add((request.Method.Method, path));
            var body = path switch
            {
                "/api/strategies" => Strategies,
                "/api/lua/check" => LuaValid ? "{\"ok\":true,\"valid\":true,\"errors\":[]}" : "{\"ok\":true,\"valid\":false,\"errors\":[{\"message\":\"'end' expected\"}]}",
                _ => "{\"ok\":true}",
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }

        public bool Wrote => Calls.Any(c => c.Method is "POST" or "PUT" or "DELETE" && c.Path != "/api/lua/check");
    }

    private static (Gui, ZapretGuiClient) Make()
    {
        var gui = new Gui();
        return (gui, new ZapretGuiClient(new HttpClient(gui) { BaseAddress = new Uri("http://router:8080/") }));
    }

    private static ResourceData Hostlist() => ResourceRules.Prepare(ResourceInput.Hostlist("video", ["example.com", "example.org"])).Data;

    [Fact]
    public async Task AGuiPutIsPlannedThenRunOnlyWhenConfirmed()
    {
        var (gui, client) = Make();
        var op = await RouterResources.GuiPutAsync(client, Hostlist());
        Assert.False(gui.Wrote);
        Assert.Equal(RouterResources.ZapretGui, op.Router);
        Assert.Contains("zt-video", op.Text(false), StringComparison.Ordinal);
        Assert.Contains("example.org", op.Text(true), StringComparison.Ordinal);
        var r = await op.RunConfirmedAsync(CancellationToken.None);
        Assert.True(r.Ok);
        Assert.Contains(gui.Calls, c => c is ("PUT", "/api/hostlists/zt-video"));
    }

    [Fact]
    public async Task AScriptTheGuiCallsBrokenIsRefusedBeforeAsking()
    {
        var (gui, client) = Make();
        gui.LuaValid = false;
        var lua = ResourceRules.Prepare(ResourceInput.Lua("twice", "function zt_twice(ctx, desync) return VERDICT_PASS end\n")).Data;
        var e = await Assert.ThrowsAsync<ZapretGuiException>(() => RouterResources.GuiPutAsync(client, lua));
        Assert.Equal("lua_invalid", e.Code);
        Assert.False(gui.Wrote);
    }

    [Fact]
    public async Task AGuiDeleteIsRefusedWhileAStrategyUsesIt()
    {
        var (gui, client) = Make();
        gui.Strategies = "{\"ok\":true,\"strategies\":[{\"id\":\"home\",\"profiles\":[{\"args\":\"--hostlist=lists/zt-video.txt --lua-desync=multisplit\"}]}]}";
        var e = await Assert.ThrowsAsync<ZapretGuiException>(() => RouterResources.GuiDeleteAsync(client, ResourceKind.Hostlist, "video"));
        Assert.Contains("home", e.Message, StringComparison.Ordinal);
        Assert.False(gui.Wrote);

        gui.Strategies = "{\"ok\":true,\"strategies\":[]}";
        var op = await RouterResources.GuiDeleteAsync(client, ResourceKind.Hostlist, "video");
        Assert.False(gui.Wrote);
        Assert.True((await op.RunConfirmedAsync(CancellationToken.None)).Ok);
        Assert.Contains(gui.Calls, c => c is ("DELETE", "/api/hostlists/zt-video"));
    }

    [Fact]
    public async Task AKeeneticPutKeepsTheOldFileAndConnectsOnlyWhenRun()
    {
        var sh = new FakeShell();
        var path = $"{KeeneticExporter.Root}/lists/zt-video.list";
        sh.Files[path] = Encoding.UTF8.GetBytes("old.example\n");
        int connects = 0;
        var op = RouterResources.KeeneticPut(_ =>
        {
            connects++;
            return Task.FromResult<IRemoteShell>(sh);
        }, Hostlist());
        Assert.Equal(0, connects);
        Assert.Contains(path, op.Text(false), StringComparison.Ordinal);
        var r = await op.RunConfirmedAsync(CancellationToken.None);
        Assert.True(r.Ok, r.Error);
        Assert.Equal(1, connects);
        Assert.Equal("example.com\nexample.org\n", Encoding.UTF8.GetString(sh.Files[path]));
        Assert.Equal("old.example\n", Encoding.UTF8.GetString(sh.Files[path + ".bak"]));
    }

    [Fact]
    public async Task AKeeneticDeleteRefusesAFileTheConfUses()
    {
        var sh = new FakeShell();
        var path = $"{KeeneticExporter.Root}/lists/zt-video.list";
        sh.Files[path] = Encoding.UTF8.GetBytes("example.com\n");
        sh.Files[KeeneticDeployer.Conf] = Encoding.UTF8.GetBytes($"NFQWS_ARGS=\"--hostlist={path}\"\n");
        var op = RouterResources.KeeneticDelete(_ => Task.FromResult<IRemoteShell>(sh), ResourceKind.Hostlist, "video");
        var r = await op.RunConfirmedAsync(CancellationToken.None);
        Assert.False(r.Ok);
        Assert.True(sh.Files.ContainsKey(path));
    }
}
