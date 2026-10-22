using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Resources;

namespace ZapretAutoTuner.Delivery.Tests;

/// <summary>Resources on the router (PLAN 4a.5): zapret-gui's REST API and nfqws2-keenetic files.</summary>
public sealed class ZapretGuiResourceTests
{
    private const string Lua = "function zt_twice(ctx, desync) return VERDICT_PASS end\n";

    /// <summary>zapret-gui's answers as api/lua_scripts.py, api/blobs.py, api/hostlists.py and api/ipsets.py give them.</summary>
    private sealed class Gui : HttpMessageHandler
    {
        public List<(string Method, string Path, string Body)> Calls { get; } = [];

        public HashSet<string> Existing { get; } = new(StringComparer.Ordinal);

        public string Strategies { get; set; } = "{\"ok\":true,\"strategies\":[]}";

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            var path = request.RequestUri!.AbsolutePath;
            Calls.Add((request.Method.Method, path, body));
            var name = body.Length > 0 ? (string?)JsonNode.Parse(body)!["name"] : null;
            if (request.Method == HttpMethod.Get)
            {
                return path switch
                {
                    "/api/strategies" => Json(HttpStatusCode.OK, Strategies),
                    "/api/lua" => Json(HttpStatusCode.OK, "{\"ok\":true,\"files\":[{\"name\":\"zapret-lib\",\"is_builtin\":true},{\"name\":\"zt-twice\"}]}"),
                    "/api/blobs" => Json(HttpStatusCode.OK, "{\"ok\":true,\"blobs\":[{\"name\":\"tls_wl\",\"size\":2}]}"),
                    _ => Json(HttpStatusCode.NotFound, "{\"ok\":false,\"error\":\"not found\"}"),
                };
            }
            if (request.Method == HttpMethod.Post && path == "/api/lua/create" && Existing.Contains("lua:" + name))
                return Json(HttpStatusCode.BadRequest, "{\"ok\": false, \"error\": \"\\u0421\\u043a\\u0440\\u0438\\u043f\\u0442 \\u0443\\u0436\\u0435 \\u0441\\u0443\\u0449\\u0435\\u0441\\u0442\\u0432\\u0443\\u0435\\u0442\"}");
            if (request.Method == HttpMethod.Post && path == "/api/lua/create" && name == "zt-bad")
                return Json(HttpStatusCode.BadRequest, "{\"ok\":false,\"error\":\"Недопустимое имя\"}");
            if (request.Method == HttpMethod.Post && path == "/api/hostlists/create" && Existing.Contains("hostlist:" + name))
                return Json(HttpStatusCode.BadRequest, "{\"ok\":false,\"error\":\"Список уже существует\"}");
            if (request.Method == HttpMethod.Post && path == "/api/blobs" && Existing.Contains("blob:" + name))
                return Json(HttpStatusCode.Conflict, "{\"ok\":false,\"error\":\"Блоб с таким именем уже существует\"}");
            if (request.Method == HttpMethod.Post && path == "/api/lua/check")
                return Json(HttpStatusCode.OK, "{\"ok\":true,\"valid\":false,\"errors\":[{\"line\":1,\"message\":\"'end' expected\"}],\"checker\":\"luac\"}");
            return Json(HttpStatusCode.OK, "{\"ok\":true}");
        }

        private static HttpResponseMessage Json(HttpStatusCode code, string body) => new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    }

    private static (Gui Gui, ZapretGuiClient Client) Make()
    {
        var gui = new Gui();
        return (gui, new ZapretGuiClient(new HttpClient(gui) { BaseAddress = new Uri("http://router:8080/") }));
    }

    [Fact]
    public async Task Typed_puts_follow_the_gui_endpoints()
    {
        var (gui, client) = Make();
        gui.Existing.UnionWith(["lua:zt-twice", "blob:tls_wl"]);
        await client.PutHostlistAsync("yt", ["youtube.com"], confirmedByUser: true);
        await client.PutIpsetAsync("cf", ["1.1.1.0/24"], confirmedByUser: true);
        await client.PutBlobAsync("tls_wl", [0x16, 0x03], confirmedByUser: true);
        await client.PutLuaAsync("twice", Lua, confirmedByUser: true);
        await client.PutLuaAsync("other", Lua, confirmedByUser: true);
        Assert.Equal(
        [
            "POST /api/hostlists/create", "PUT /api/hostlists/zt-yt",
            "POST /api/ipsets/create", "PUT /api/ipsets/zt-cf-ipset",
            "POST /api/blobs", "PUT /api/blobs/tls_wl",
            "POST /api/lua/create", "PUT /api/lua/zt-twice",
            "POST /api/lua/create",
        ], gui.Calls.Select(c => $"{c.Method} {c.Path}"));
        Assert.Equal("{\"name\":\"zt-twice\",\"content\":" + JsonValue.Create(Lua).ToJsonString() + "}", gui.Calls[6].Body);
        Assert.Equal("{\"content\":" + JsonValue.Create(Lua).ToJsonString() + "}", gui.Calls[7].Body);
        Assert.Contains("\"entries\":[\"1.1.1.0/24\"]", gui.Calls[3].Body, StringComparison.Ordinal);
        Assert.Contains("\"hex\":\"1603\"", gui.Calls[5].Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Nothing_changes_without_confirmation()
    {
        var (gui, client) = Make();
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.PutHostlistAsync("yt", ["a.com"], confirmedByUser: false));
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.PutIpsetAsync("yt", ["1.1.1.1"], confirmedByUser: false));
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.PutBlobAsync("b", [1], confirmedByUser: false));
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.PutLuaAsync("twice", Lua, confirmedByUser: false));
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.DeleteAsync(ResourceKind.LuaScript, "twice", confirmedByUser: false));
        await Assert.ThrowsAsync<ArgumentException>(() => client.PutLuaAsync("../x", Lua, confirmedByUser: true));
        await Assert.ThrowsAsync<ArgumentException>(() => client.PutBlobAsync("my-blob", [1], confirmedByUser: true));
        Assert.Empty(gui.Calls);
    }

    [Fact]
    public async Task Delete_is_refused_while_a_gui_strategy_uses_the_resource()
    {
        var (gui, client) = Make();
        gui.Strategies = """
            {"ok":true,"strategies":[
              {"id":"zt_a","profiles":[{"args":"--lua-init=@lua/zt-twice.lua --filter-tcp=443 --hostlist=lists/zt-yt.txt --lua-desync=fake:blob=tls_wl:tcp_md5"}]},
              {"id":"zt_b","profiles":[{"args":"--hostlist=lists/zt-yt2.txt --lua-desync=fake:blob=tls_wl2"}]}]}
            """;
        Assert.Equal(["zt_a"], await client.UsersOfAsync(ResourceKind.LuaScript, "twice"));
        Assert.Equal(["zt_a"], await client.UsersOfAsync(ResourceKind.Hostlist, "yt"));
        Assert.Equal(["zt_a"], await client.UsersOfAsync(ResourceKind.Blob, "tls_wl"));
        Assert.Empty(await client.UsersOfAsync(ResourceKind.Ipset, "yt"));
        var e = await Assert.ThrowsAsync<ZapretGuiException>(() => client.DeleteAsync(ResourceKind.LuaScript, "twice", confirmedByUser: true));
        Assert.Equal("in_use", e.Code);
        Assert.DoesNotContain(gui.Calls, c => c.Method == "DELETE");

        await client.DeleteAsync(ResourceKind.Ipset, "yt", confirmedByUser: true);
        await client.DeleteAsync(ResourceKind.LuaScript, "unused", confirmedByUser: true);
        Assert.Equal(["DELETE /api/ipsets/zt-yt-ipset", "DELETE /api/lua/zt-unused"], gui.Calls.Where(c => c.Method == "DELETE").Select(c => $"{c.Method} {c.Path}"));
    }

    [Fact]
    public async Task Lists_and_lua_check_are_read_only()
    {
        var (gui, client) = Make();
        Assert.Equal(["zapret-lib", "zt-twice"], await client.ListAsync(ResourceKind.LuaScript));
        Assert.Equal(["tls_wl"], await client.ListAsync(ResourceKind.Blob));
        var (valid, errors) = await client.CheckLuaAsync("function x(");
        Assert.False(valid);
        Assert.Equal(["'end' expected"], errors);
        Assert.All(gui.Calls, c => Assert.True(c.Method == "GET" || c.Path == "/api/lua/check"));
    }

    [Fact]
    public async Task Save_uploads_the_solution_lua_files_and_the_plan_names_them()
    {
        var (gui, client) = Make();
        var s = new Solution();
        s.Meta.Created = new DateTimeOffset(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);
        s.Meta.Targets = ["discord.com"];
        s.LuaFiles["zt-twice.lua"] = Lua;
        s.Profiles.Add(new Profile { Name = "p", TcpPorts = "443", Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=zt_twice") });
        var plan = await client.PlanAsync(s);
        Assert.Contains(plan.Steps, st => st.En.Contains("Lua script zt-twice", StringComparison.Ordinal));
        gui.Calls.Clear();
        await client.SaveAsync(s, plan, confirmedByUser: true);
        Assert.Equal(["POST /api/lua/create", "POST /api/strategies"], gui.Calls.Select(c => $"{c.Method} {c.Path}"));
        Assert.Contains("--lua-init=@lua/zt-twice.lua", gui.Calls[1].Body, StringComparison.Ordinal);
        // a GUI refusal is reported, not swallowed
        await Assert.ThrowsAsync<ZapretGuiException>(() => client.PutLuaAsync("bad", Lua, confirmedByUser: true));
    }
}

public sealed class KeeneticResourceTests
{
    private static FakeShell Router()
    {
        var sh = new FakeShell();
        sh.Files[KeeneticDeployer.Conf] = Encoding.UTF8.GetBytes(KeeneticExporter.DefaultConf);
        return sh;
    }

    [Fact]
    public async Task Deploy_writes_the_lua_files_of_the_solution()
    {
        var s = new Solution();
        s.Hostlists["yt"] = ["youtube.com"];
        s.LuaFiles["zt-twice.lua"] = "function zt_twice(ctx, desync) end\n";
        s.Profiles.Add(new Profile { Name = "yt", TcpPorts = "443", Hostlists = [new ListRef("yt")], Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=zt_twice") });
        var pkg = KeeneticExporter.Build(s);
        Assert.Contains(KeeneticDeployer.Plan(pkg), st => st.En.Contains("lua/zt-twice.lua", StringComparison.Ordinal));
        var sh = Router();
        var r = await KeeneticDeployer.DeployAsync(sh, pkg, confirmedByUser: true);
        Assert.True(r.Ok, r.Error);
        Assert.Equal("function zt_twice(ctx, desync) end\n", Encoding.UTF8.GetString(sh.Files["/opt/etc/nfqws2/lua/zt-twice.lua"]));
        Assert.Contains("--lua-init=@/opt/etc/nfqws2/lua/zt-twice.lua", Encoding.UTF8.GetString(sh.Files[KeeneticDeployer.Conf]), StringComparison.Ordinal);
        Assert.Contains(sh.Commands, c => c.StartsWith("mkdir -p", StringComparison.Ordinal) && c.Contains("/opt/etc/nfqws2/lua", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Delete_refuses_files_the_conf_uses_and_keeps_a_backup()
    {
        var sh = Router();
        var conf = KeeneticExporter.ReplaceVar(KeeneticExporter.DefaultConf, "NFQWS_BASE_ARGS", "\"--lua-init=@/opt/etc/nfqws2/lua/zt-twice.lua --blob=tls_wl:@/opt/etc/nfqws2/blobs/tls_wl.bin\"");
        sh.Files[KeeneticDeployer.Conf] = Encoding.UTF8.GetBytes(conf);
        sh.Files["/opt/etc/nfqws2/lua/zt-twice.lua"] = [1];
        sh.Files["/opt/etc/nfqws2/blobs/tls_wl.bin"] = [2];
        sh.Files["/opt/etc/nfqws2/lists/zt-old.list"] = [3];

        await Assert.ThrowsAsync<InvalidOperationException>(() => KeeneticDeployer.DeleteResourceAsync(sh, ResourceKind.Hostlist, "old", confirmedByUser: false));
        Assert.False((await KeeneticDeployer.DeleteResourceAsync(sh, ResourceKind.LuaScript, "twice", confirmedByUser: true)).Ok);
        Assert.False((await KeeneticDeployer.DeleteResourceAsync(sh, ResourceKind.Blob, "tls_wl", confirmedByUser: true)).Ok);
        Assert.True(sh.Files.ContainsKey("/opt/etc/nfqws2/lua/zt-twice.lua"));

        Assert.Equal(2, KeeneticDeployer.PlanDelete(ResourceKind.Hostlist, "old").Count);
        var r = await KeeneticDeployer.DeleteResourceAsync(sh, ResourceKind.Hostlist, "old", confirmedByUser: true);
        Assert.True(r.Ok, r.Error);
        Assert.False(sh.Files.ContainsKey("/opt/etc/nfqws2/lists/zt-old.list"));
        Assert.Equal([3], sh.Files["/opt/etc/nfqws2/lists/zt-old.list.bak"]);
        Assert.False((await KeeneticDeployer.DeleteResourceAsync(sh, ResourceKind.Ipset, "none", confirmedByUser: true)).Ok);
        Assert.Throws<ArgumentException>(() => KeeneticDeployer.ResourceFile(ResourceKind.Blob, "../x"));
    }
}
