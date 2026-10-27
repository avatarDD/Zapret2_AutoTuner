using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Delivery.Tests;

/// <summary>A router in memory: files and the commands the deployer runs.</summary>
internal sealed class FakeShell : IRemoteShell
{
    public Dictionary<string, byte[]> Files { get; } = new(StringComparer.Ordinal);

    public List<string> Commands { get; } = [];

    /// <summary>Whether nfqws2 comes up after a restart with the current conf.</summary>
    public Func<string, bool> StartsWith { get; set; } = _ => true;

    public Task<(int Code, string Output)> RunAsync(string command, CancellationToken ct)
    {
        if (Dead)
            throw new Renci.SshNet.Common.SshConnectionException("connection lost");
        Commands.Add(command);
        var words = command.Split(' ');
        string Arg(int i) => words[i].Trim('\'');
        switch (words[0])
        {
            case "test":
                return Task.FromResult((Files.ContainsKey(Arg(2)) ? 0 : 1, ""));
            case "cp":
                Files[Arg(3)] = Files[Arg(2)];
                return Task.FromResult((0, ""));
            case "mv":
                Files[Arg(2)] = Files[Arg(1)];
                Files.Remove(Arg(1));
                return Task.FromResult((0, ""));
            case "rm":
                Files.Remove(Arg(2));
                return Task.FromResult((0, ""));
            case "mkdir":
                return Task.FromResult((0, ""));
        }
        if (command.StartsWith(KeeneticDeployer.Service, StringComparison.Ordinal))
        {
            var conf = Encoding.UTF8.GetString(Files[KeeneticDeployer.Conf]);
            return Task.FromResult(StartsWith(conf) ? (0, "Starting nfqws2... done") : (1, "nfqws2: lua error"));
        }
        return Task.FromResult((127, "unknown command"));
    }

    public Task<byte[]?> ReadAsync(string path, CancellationToken ct) => Task.FromResult(Files.GetValueOrDefault(path));

    /// <summary>A write to a path that matches throws, as a dropped connection would.</summary>
    public Func<string, bool> WriteFails { get; set; } = _ => false;

    /// <summary>After a failed write every command throws too (the connection is gone).</summary>
    public bool Dead { get; set; }

    public Task WriteAsync(string path, byte[] data, CancellationToken ct)
    {
        if (WriteFails(path))
            throw new Renci.SshNet.Common.SshConnectionException("connection lost");
        Files[path] = data;
        return Task.CompletedTask;
    }

    public void Dispose()
    {
    }
}

public sealed class KeeneticDeployerTests
{
    private static Solution Sample()
    {
        var s = new Solution();
        s.Meta.Created = new DateTimeOffset(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);
        s.Hostlists["tcp1"] = ["discord.com"];
        s.Hostlists["tcp2"] = ["youtube.com"];
        s.Blobs["tls_wl"] = [0x16, 0x03, 0x01];
        s.Profiles.Add(new Profile { Name = "tcp1", TcpPorts = "443", Hostlists = [new ListRef("tcp1")], Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=tls_wl:tcp_md5") });
        s.Profiles.Add(new Profile { Name = "tcp2", TcpPorts = "443", Hostlists = [new ListRef("tcp2")], Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=multisplit:pos=midsld") });
        return s;
    }

    private static FakeShell Router()
    {
        var sh = new FakeShell();
        var userConf = KeeneticExporter.ReplaceVar(KeeneticExporter.DefaultConf, "ISP_INTERFACE", "\"ppp0\"");
        sh.Files[KeeneticDeployer.Conf] = Encoding.UTF8.GetBytes(userConf);
        sh.Files["/opt/etc/nfqws2/lists/user.list"] = Encoding.UTF8.GetBytes("my.site\n");
        return sh;
    }

    [Fact]
    public async Task Deploy_merges_only_our_variables_and_keeps_backups()
    {
        var sh = Router();
        var pkg = KeeneticExporter.Build(Sample());
        var r = await KeeneticDeployer.DeployAsync(sh, pkg, confirmedByUser: true);
        Assert.True(r.Ok, r.Error);
        var conf = KeeneticExporter.ParseVars(Encoding.UTF8.GetString(sh.Files[KeeneticDeployer.Conf]));
        Assert.Equal("ppp0", conf["ISP_INTERFACE"]); // the user's own setting stays
        Assert.Equal("$MODE_LIST", conf["NFQWS_EXTRA_ARGS"]);
        Assert.Contains("--name=tcp2", conf["NFQWS_ARGS"], StringComparison.Ordinal);
        Assert.Equal("my.site\nyoutube.com\n", Encoding.UTF8.GetString(sh.Files["/opt/etc/nfqws2/lists/user.list"])); // theirs stay
        Assert.Equal("my.site\n", Encoding.UTF8.GetString(sh.Files["/opt/etc/nfqws2/lists/user.list.bak"]));
        Assert.True(sh.Files.ContainsKey(KeeneticDeployer.Conf + ".bak"));
        Assert.Equal([0x16, 0x03, 0x01], sh.Files["/opt/etc/nfqws2/blobs/tls_wl.bin"]);
    }

    [Fact]
    public async Task Failed_restart_puts_everything_back()
    {
        var sh = Router();
        var before = sh.Files.ToDictionary(kv => kv.Key, kv => kv.Value);
        sh.StartsWith = conf => !conf.Contains("tls_wl", StringComparison.Ordinal);
        var r = await KeeneticDeployer.DeployAsync(sh, KeeneticExporter.Build(Sample()), confirmedByUser: true);
        Assert.False(r.Ok);
        Assert.True(r.RolledBack);
        // the originals are back, files we added are gone; the .bak copies stay next to them
        Assert.Equal(before.Keys.Order(StringComparer.Ordinal), sh.Files.Keys.Where(k => !k.EndsWith(".bak", StringComparison.Ordinal)).Order(StringComparer.Ordinal));
        foreach (var (k, v) in before)
            Assert.Equal(v, sh.Files[k]);
        Assert.Contains(sh.Commands, c => c.StartsWith("/opt/etc/init.d/S51nfqws2 restart", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_lost_connection_mid_write_rolls_back_and_a_failed_rollback_says_so()
    {
        var sh = Router();
        var before = sh.Files.ToDictionary(kv => kv.Key, kv => kv.Value);
        sh.WriteFails = p => p == KeeneticDeployer.Conf;
        var r = await KeeneticDeployer.DeployAsync(sh, KeeneticExporter.Build(Sample()), confirmedByUser: true);
        Assert.False(r.Ok);
        Assert.True(r.RolledBack);
        Assert.Equal(before[KeeneticDeployer.Conf], sh.Files[KeeneticDeployer.Conf]);
        Assert.False(sh.Files.ContainsKey("/opt/etc/nfqws2/blobs/tls_wl.bin"));

        var dead = Router();
        dead.WriteFails = p =>
        {
            dead.Dead = p == KeeneticDeployer.Conf;
            return dead.Dead;
        };
        r = await KeeneticDeployer.DeployAsync(dead, KeeneticExporter.Build(Sample()), confirmedByUser: true);
        Assert.False(r.Ok);
        Assert.False(r.RolledBack);
        Assert.Contains(".bak", r.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Merge_keeps_the_users_udp_ports_and_declarations_and_edits_the_last_assignment()
    {
        var conf = KeeneticExporter.DefaultConf;
        conf = KeeneticExporter.ReplaceVar(conf, "NFQWS_ARGS_UDP", "\"--filter-udp=40000-40100 --lua-desync=fake:blob=my_stun\"");
        conf = KeeneticExporter.ReplaceVar(conf, "UDP_PORTS", "443,1234");
        conf = KeeneticExporter.ReplaceVar(conf, "NFQWS_BASE_ARGS", "\"--blob=my_stun:@/opt/etc/nfqws2/blobs/my_stun.bin\"");
        conf += "NFQWS_EXTRA_ARGS=\"$MODE_AUTO\"\n"; // set again further down: the shell keeps this one
        var merged = KeeneticExporter.ParseVars(KeeneticDeployer.Merge(conf, KeeneticExporter.Build(Sample()).Text));
        var ports = merged["UDP_PORTS"].Split(',');
        Assert.Contains("1234", ports);
        Assert.Contains("40000:40100", ports);
        Assert.Contains("--blob=my_stun:@/opt/etc/nfqws2/blobs/my_stun.bin", merged["NFQWS_BASE_ARGS"], StringComparison.Ordinal);
        Assert.Contains("--blob=tls_wl:", merged["NFQWS_BASE_ARGS"], StringComparison.Ordinal);
        Assert.Equal("$MODE_LIST", merged["NFQWS_EXTRA_ARGS"]);
    }

    [Fact]
    public async Task Nothing_happens_without_confirmation_or_a_package()
    {
        var sh = Router();
        await Assert.ThrowsAsync<InvalidOperationException>(() => KeeneticDeployer.DeployAsync(sh, KeeneticExporter.Build(Sample()), confirmedByUser: false));
        Assert.Empty(sh.Commands);
        var empty = new FakeShell();
        var r = await KeeneticDeployer.DeployAsync(empty, KeeneticExporter.Build(Sample()), confirmedByUser: true);
        Assert.False(r.Ok);
        Assert.Contains("nfqws2.conf", r.Error, StringComparison.Ordinal);
        Assert.NotEmpty(KeeneticDeployer.Plan(KeeneticExporter.Build(Sample())));
    }

    [Fact]
    public void Octal_escapes_every_byte()
    {
        Assert.Equal("\\000\\047\\377", SshRemoteShell.Octal([0, 39, 255]));
        Assert.Equal("'a'\\''b'", SshRemoteShell.Quote("a'b"));
    }
}

public sealed class ZapretGuiClientTests
{
    private sealed class Gui : HttpMessageHandler
    {
        public List<string> Calls { get; } = [];

        public HashSet<string> Existing { get; } = [];

        public string Strategies { get; set; } = "{\"ok\":true,\"strategies\":[]}";

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            var path = request.RequestUri!.AbsolutePath;
            Calls.Add($"{request.Method} {path} {body}");
            Assert.Equal("Basic YWRtaW46c2VjcmV0", request.Headers.Authorization?.ToString());
            if (request.Method == HttpMethod.Get && path == "/api/strategies")
                return Json(HttpStatusCode.OK, Strategies);
            // Bottle's JSON plugin escapes non-ASCII: the body has no Cyrillic letters
            if (request.Method == HttpMethod.Post && path == "/api/hostlists/create" && Existing.Contains((string)JsonNode.Parse(body)!["name"]!))
                return Json(HttpStatusCode.BadRequest, "{\"ok\": false, \"error\": \"\\u0421\\u043f\\u0438\\u0441\\u043e\\u043a \\u0443\\u0436\\u0435 \\u0441\\u0443\\u0449\\u0435\\u0441\\u0442\\u0432\\u0443\\u0435\\u0442\"}");
            if (request.Method == HttpMethod.Post && path == "/api/blobs" && Existing.Contains("blob"))
                return Json(HttpStatusCode.Conflict, "{\"ok\":false,\"error\":\"Блоб с таким именем уже существует\"}");
            return Json(HttpStatusCode.OK, "{\"ok\":true}");
        }

        private static HttpResponseMessage Json(HttpStatusCode code, string body) => new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    }

    private static Solution Sample()
    {
        var s = new Solution();
        s.Meta.Created = new DateTimeOffset(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);
        s.Meta.Targets = ["discord.com"];
        s.Hostlists["tcp1"] = ["discord.com"];
        s.Blobs["tls_wl"] = [0x16, 0x03];
        s.Profiles.Add(new Profile { Name = "tcp1", TcpPorts = "443", Hostlists = [new ListRef("tcp1")], Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=tls_wl:tcp_md5") });
        return s;
    }

    [Fact]
    public async Task Save_creates_lists_and_blobs_then_the_strategy_and_never_applies()
    {
        var gui = new Gui();
        gui.Existing.UnionWith(["zt-tcp1", "blob"]);
        var client = new ZapretGuiClient(new HttpClient(gui) { BaseAddress = new Uri("http://router:8080/") }, password: "secret");
        var plan = await client.PlanAsync(Sample());
        gui.Calls.Clear();
        var id = await client.SaveAsync(Sample(), plan, confirmedByUser: true);
        Assert.Equal("zt_discord_com_2026_10_17", id);
        Assert.Equal(
        [
            "POST /api/hostlists/create",
            "PUT /api/hostlists/zt-tcp1",
            "POST /api/blobs",
            "PUT /api/blobs/tls_wl",
            "POST /api/strategies",
        ], gui.Calls.Select(c => string.Join(' ', c.Split(' ').Take(2))));
        Assert.Contains("\"domains\":[\"discord.com\"]", gui.Calls[1], StringComparison.Ordinal);
        Assert.Contains("\"hex\":\"1603\"", gui.Calls[3], StringComparison.Ordinal);
        Assert.DoesNotContain(gui.Calls, c => c.Contains("/apply", StringComparison.Ordinal));

        await client.ApplyAsync(id, confirmedByUser: true);
        Assert.StartsWith("POST /api/strategies/zt_discord_com_2026_10_17/apply", gui.Calls[^1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task Refuses_without_confirmation_and_reports_gui_errors()
    {
        var gui = new Gui();
        var client = new ZapretGuiClient(new HttpClient(gui) { BaseAddress = new Uri("http://router:8080/") }, password: "secret");
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.SaveAsync(Sample(), new GuiSavePlan("x", []), confirmedByUser: false));
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ApplyAsync("x", confirmedByUser: false));
        Assert.Empty(gui.Calls);
    }

    [Fact]
    public async Task Plan_never_reuses_a_strategy_id_and_names_lists_the_active_strategy_uses()
    {
        var gui = new Gui
        {
            Strategies = """
                {"ok":true,"strategies":[
                  {"id":"zt_discord_com_2026_10_17","is_active":true,"profiles":[{"args":"--hostlist=lists/zt-tcp1.txt --lua-desync=fake"}]},
                  {"id":"zt_discord_com_2026_10_17_2","is_active":false,"profiles":[]}]}
                """,
        };
        var client = new ZapretGuiClient(new HttpClient(gui) { BaseAddress = new Uri("http://router:8080/") }, password: "secret");
        var plan = await client.PlanAsync(Sample());
        Assert.Equal("zt_discord_com_2026_10_17_3", plan.Id);
        Assert.Contains(plan.Steps, st => st.Ru.Contains("zt-tcp1", StringComparison.Ordinal) && st.Ru.Contains("активная", StringComparison.Ordinal));
        Assert.Equal(3, plan.Steps.Count);
    }
}
