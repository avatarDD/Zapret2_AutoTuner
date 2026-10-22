using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>
/// Golden and round-trip tests of the exporters (AGENTS.md rule 8, strategy-export rule 4). Golden files live in
/// tests/testdata/export; run with <c>ZT_UPDATE_GOLDEN=1</c> to rewrite them after a deliberate format change.
/// </summary>
public sealed class ExportTests
{
    private static readonly byte[] WhiteBlob = Convert.FromHexString("160301000401000000");

    /// <summary>A narrow TCP profile with a custom blob, a wide one, and QUIC for the wide one's domains.</summary>
    internal static Solution Sample()
    {
        var s = new Solution();
        s.Meta.Created = new DateTimeOffset(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);
        s.Meta.AutotunerVersion = "0.1.0";
        s.Meta.Zapret2Version = "1.0.5.2";
        s.Meta.Targets = ["discord.com", "youtube.com", "googlevideo.com"];
        s.Hostlists["tcp1"] = ["discord.com"];
        s.Hostlists["tcp2"] = ["youtube.com", "googlevideo.com"];
        s.Hostlists["quic1"] = ["youtube.com", "googlevideo.com"];
        s.Blobs["tls_wl"] = WhiteBlob;
        s.Profiles.Add(new Profile
        {
            Name = "tcp1", TcpPorts = "443", L7 = ["tls"], Hostlists = [new ListRef("tcp1")],
            Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=tls_wl:tcp_md5 --lua-desync=multidisorder:pos=1,midsld"),
        });
        s.Profiles.Add(new Profile
        {
            Name = "tcp2", TcpPorts = "80,443", L7 = ["http", "tls"], Hostlists = [new ListRef("tcp2")],
            Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=multisplit:pos=1:seqovl=5:seqovl_pattern=0x1603030000 --payload=http_req --lua-desync=multisplit:pos=method+2"),
        });
        s.Profiles.Add(new Profile
        {
            Name = "quic1", UdpPorts = "443", L7 = ["quic"], Hostlists = [new ListRef("quic1")],
            Strategy = Strategy.Parse("--payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6"),
        });
        s.HostPins.Add(new HostPin("discord.com", ["162.159.128.233"]));
        return s;
    }

    private static void Golden(ExportPackage pkg, string? name = null)
    {
        var dir = RepoPaths.Testdata("export", name ?? pkg.Format);
        bool update = Environment.GetEnvironmentVariable("ZT_UPDATE_GOLDEN") == "1";
        if (update)
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
            foreach (var (path, bytes) in pkg.Files)
            {
                var file = Path.Combine(dir, path);
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                File.WriteAllBytes(file, bytes);
            }
            return;
        }
        var expected = Directory.GetFiles(dir, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(dir, f).Replace('\\', '/')).Order(StringComparer.Ordinal).ToList();
        Assert.Equal(expected, pkg.Files.Keys.ToList());
        foreach (var (path, bytes) in pkg.Files)
        {
            var want = File.ReadAllBytes(Path.Combine(dir, path));
            if (path.EndsWith(".bin", StringComparison.Ordinal))
                Assert.Equal(want, bytes);
            else
                Assert.Equal(Encoding.UTF8.GetString(want).ReplaceLineEndings("\n"), Encoding.UTF8.GetString(bytes).ReplaceLineEndings("\n"));
        }
    }

    /// <summary>What must survive an export and import: per profile its filters, strategy and list contents; the blobs.</summary>
    private static List<string> Shape(Solution s, Func<Profile, bool>? keep = null) =>
    [
        .. s.Profiles.Where(keep ?? (_ => true)).Select(p => string.Join(" | ",
            p.TcpPorts ?? "-", p.UdpPorts ?? "-", string.Join(',', p.L7), p.Strategy.ToString(),
            string.Join(',', p.Hostlists.SelectMany(l => s.Hostlists.TryGetValue(l.Name, out var d) ? d : [l.ToString()]).Order(StringComparer.Ordinal)),
            string.Join(',', p.Ipsets.SelectMany(l => s.Ipsets[l.Name])))),
        .. s.Blobs.Select(b => $"blob {b.Key} {Convert.ToHexString(b.Value)}"),
    ];

    [Fact]
    public void Zapret2_config_golden_and_round_trip()
    {
        var s = Sample();
        var pkg = Zapret2Exporter.Build(s);
        Golden(pkg);
        Assert.Contains("NFQWS2_PORTS_TCP=80,443", pkg.Text, StringComparison.Ordinal);
        Assert.Contains("--blob=tls_wl:@/opt/zapret2/files/fake/zt_tls_wl.bin", pkg.Text, StringComparison.Ordinal);
        var back = StrategyImporter.Import(pkg.Text, pkg.Files);
        Assert.Equal("zapret2", back.Kind);
        Assert.Equal(Shape(s), Shape(back.Solution));
        Assert.Equal(["tcp1", "tcp2", "quic1"], back.Solution.Profiles.Select(p => p.Name));
    }

    [Fact]
    public void Winws2_golden_and_round_trip()
    {
        var s = Sample();
        var pkg = WinwsExporter.Build(s);
        Golden(pkg);
        var config = pkg.TextOf("zt-config.txt");
        Assert.DoesNotContain("#", config, StringComparison.Ordinal);
        Assert.StartsWith("--wf-tcp-out=80,443 --wf-udp-out=443\n", config, StringComparison.Ordinal);
        // the .cmd points at the @config, the importer follows it
        var back = StrategyImporter.Import(pkg.TextOf("zt-start.cmd"), pkg.Files);
        Assert.Equal("winws2", back.Kind);
        Assert.Equal(Shape(s), Shape(back.Solution));
        Assert.Equal(Shape(s), Shape(StrategyImporter.Import(config, pkg.Files).Solution));
    }

    [Fact]
    public void Argv_line_stands_alone_and_round_trips()
    {
        var s = Sample();
        var pkg = ArgvExporter.Build(s);
        Golden(pkg);
        Assert.DoesNotContain("--qnum", pkg.Text, StringComparison.Ordinal);
        Assert.Contains("--blob=tls_wl:0x160301000401000000", pkg.Text, StringComparison.Ordinal);
        var back = StrategyImporter.Import(pkg.Text);
        Assert.Equal("args", back.Kind);
        // lists come back inline, blobs as hex
        Assert.Equal(["discord.com"], back.Solution.Profiles[0].HostlistDomains);
        Assert.Equal(WhiteBlob, back.Solution.Blobs["tls_wl"]);
        Assert.Equal(s.Profiles.Select(p => p.Strategy.ToString()), back.Solution.Profiles.Select(p => p.Strategy.ToString()));
        var v = new StrategyValidator(new ValidationContext { Platform = EnginePlatform.Linux }).ValidateArgv(ArgTokenizer.Split(pkg.Text));
        Assert.True(v.Ok, string.Join("\n", v.Errors));
    }

    [Fact]
    public void Keenetic_golden_and_round_trip()
    {
        var s = Sample();
        var pkg = KeeneticExporter.Build(s);
        Golden(pkg);
        var vars = KeeneticExporter.ParseVars(pkg.TextOf("nfqws2.conf"));
        // the widest TCP profile is the main one, QUIC for the same domains goes to NFQWS_ARGS_QUIC, the narrow one runs first
        Assert.StartsWith("--name=tcp2 --filter-tcp=80,443", vars["NFQWS_ARGS"], StringComparison.Ordinal);
        Assert.DoesNotContain("--hostlist", vars["NFQWS_ARGS"], StringComparison.Ordinal);
        Assert.StartsWith("--name=quic1", vars["NFQWS_ARGS_QUIC"], StringComparison.Ordinal);
        Assert.Contains("--hostlist=/opt/etc/nfqws2/lists/zt-tcp1.list", vars["NFQWS_ARGS_CUSTOM"], StringComparison.Ordinal);
        Assert.Equal("$MODE_LIST", vars["NFQWS_EXTRA_ARGS"]);
        Assert.Equal("80,443", vars["TCP_PORTS"]);
        // the package UDP profile keeps its ports, in iptables syntax
        Assert.Equal("443,590:600,1400,3478:3481,5349,19294:19344,49152:65535", vars["UDP_PORTS"]);
        Assert.Contains("--blob=tls_wl:@/opt/etc/nfqws2/blobs/tls_wl.bin", vars["NFQWS_BASE_ARGS"], StringComparison.Ordinal);
        Assert.Equal("youtube.com\ngooglevideo.com\n", pkg.TextOf("lists/user.list"));
        // untouched package variables stay
        Assert.Equal("eth3", vars["ISP_INTERFACE"]);
        Assert.Equal(KeeneticExporter.ParseVars(KeeneticExporter.DefaultConf)["NFQWS_ARGS_UDP"], vars["NFQWS_ARGS_UDP"]);

        // the init script's argv: custom first, then the package UDP, QUIC, the main profile; ipset copies come along
        var back = StrategyImporter.Import(pkg.TextOf("nfqws2.conf"), pkg.Files);
        Assert.Equal("keenetic", back.Kind);
        bool Ours(Profile p) => p.IpsetIps.Count == 0 && p.UdpPorts?.Contains("590", StringComparison.Ordinal) != true;
        var ours = Shape(back.Solution, Ours);
        Assert.Equal(Shape(s).Order(StringComparer.Ordinal), ours.Order(StringComparer.Ordinal));
        Assert.Equal(["tcp1", "quic1", "tcp2"], back.Solution.Profiles.Where(Ours).Select(p => p.Name));
        // the package's own UDP profile has fake without blob (the exporter warns); --fastpath-workaround is keenetic's patch
        Assert.Contains(pkg.Warnings, w => w.Contains("NFQWS_ARGS_UDP", StringComparison.Ordinal));
        var argv = StrategyImporter.KeeneticArgv(new Dictionary<string, string>(vars) { ["NFQWS_ARGS_UDP"] = "" });
        argv.Remove("--fastpath-workaround=auto");
        var v = new StrategyValidator(new ValidationContext { Platform = EnginePlatform.Linux }).ValidateArgv(argv);
        Assert.True(v.Ok, string.Join("\n", v.Errors));

        // the fragment alone (no NFQWS_ARGS_IPSET, no UDP profile) gives exactly our profiles
        var frag = StrategyImporter.Import(pkg.Text, pkg.Files);
        Assert.Equal(Shape(s).Order(StringComparer.Ordinal), Shape(frag.Solution).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Keenetic_puts_quic_for_other_domains_into_custom()
    {
        var s = Sample();
        s.Hostlists["quic1"] = ["youtube.com"];
        var vars = KeeneticExporter.ParseVars(KeeneticExporter.Build(s).TextOf("nfqws2.conf"));
        Assert.Equal("", vars["NFQWS_ARGS_QUIC"]);
        Assert.Contains("--filter-udp=443", vars["NFQWS_ARGS_CUSTOM"], StringComparison.Ordinal);
        Assert.Contains("--hostlist=/opt/etc/nfqws2/lists/zt-quic1.list", vars["NFQWS_ARGS_CUSTOM"], StringComparison.Ordinal);
    }

    [Fact]
    public void Zapret_gui_golden_and_round_trip()
    {
        var s = Sample();
        var pkg = ZapretGuiExporter.Build(s);
        Golden(pkg);
        var strategy = JsonNode.Parse(pkg.TextOf("strategy.json"))!.AsObject();
        Assert.Equal("zt_discord_com_2026_10_17", (string?)strategy["id"]);
        var args = strategy["profiles"]!.AsArray().Select(p => (string)p!["args"]!).ToList();
        Assert.All(args, a => Assert.DoesNotContain("--new", a, StringComparison.Ordinal));
        Assert.All(args, a => Assert.DoesNotContain("--name=", a, StringComparison.Ordinal));
        Assert.All(args, a => Assert.DoesNotContain("--blob=", a, StringComparison.Ordinal));
        Assert.Contains("--hostlist=lists/zt-tcp1.txt", args[0], StringComparison.Ordinal);

        // the GUI's own import of the text gives the same profiles as the JSON (blob declaration aside)
        var gui = ZapretGuiConvert.Convert(pkg.Text);
        Assert.True(gui.Ok);
        Assert.Equal("zapret2", gui.Kind);
        Assert.Equal(args, gui.Profiles.Select(p => p.Args.Replace("--blob=tls_wl:@bin/tls_wl.bin ", "", StringComparison.Ordinal)));
        Assert.Empty(gui.Warnings);

        foreach (var file in new[] { "strategy.json", "zapret-gui-backup.json", "zapret-autotuner-bundle.json" })
        {
            var back = StrategyImporter.Import(pkg.TextOf(file), pkg.Files);
            // strategy.json alone has no lists; the files next to it carry them
            Assert.Equal(Shape(s), Shape(back.Solution));
        }
        var bundle = StrategyImporter.Import(pkg.TextOf("zapret-autotuner-bundle.json"));
        Assert.Equal(Shape(s), Shape(bundle.Solution));
        Assert.Equal(s.HostPins.Select(p => p.Domain), bundle.Solution.HostPins.Select(p => p.Domain));
        var backup = JsonNode.Parse(pkg.TextOf("zapret-gui-backup.json"))!;
        Assert.Equal(1792238400, (long)backup["created_at"]!);
        Assert.Null(backup["settings"]);
    }

    private const string UserLua = """
        -- zt_twice: the payload goes out twice
        function zt_twice(ctx, desync)
            return VERDICT_PASS
        end
        """;

    /// <summary>The sample with a user Lua script (PLAN 4a.5) whose function the narrow profile calls.</summary>
    private static Solution WithLua()
    {
        var s = Sample();
        s.LuaFiles["zt-twice.lua"] = UserLua;
        s.Profiles[0].Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=tls_wl:tcp_md5 --lua-desync=zt_twice:count=2 --lua-desync=multidisorder:pos=1,midsld");
        return s;
    }

    private static readonly ValidationContext LuaContext = new ValidationContext { Platform = EnginePlatform.Linux }
        .WithUserLua(new Dictionary<string, string> { ["zt_twice"] = "zt-twice.lua" }, new Dictionary<string, string>());

    [Fact]
    public void Lua_files_golden_and_round_trip_in_every_format()
    {
        var s = WithLua();

        var z2 = Zapret2Exporter.Build(s);
        Golden(z2, "zapret2-lua");
        Assert.Contains("--lua-init=@/opt/zapret2/lua/zt-twice.lua\n--blob=", z2.Text, StringComparison.Ordinal);
        Assert.Equal(UserLua, z2.TextOf("lua/zt-twice.lua"));
        var back = StrategyImporter.Import(z2.Text, z2.Files).Solution;
        Assert.Equal(Shape(s), Shape(back));
        Assert.Equal(s.LuaFiles, back.LuaFiles);

        var win = WinwsExporter.Build(s);
        Golden(win, "winws2-lua");
        Assert.Contains("--lua-init=@lua/zapret-auto.lua --lua-init=@lua/zt-twice.lua\n", win.TextOf("zt-config.txt"), StringComparison.Ordinal);
        back = StrategyImporter.Import(win.TextOf("zt-start.cmd"), win.Files).Solution;
        Assert.Equal(Shape(s), Shape(back));
        Assert.Equal(s.LuaFiles, back.LuaFiles);

        var keen = KeeneticExporter.Build(s);
        Golden(keen, "keenetic-lua");
        var vars = KeeneticExporter.ParseVars(keen.TextOf("nfqws2.conf"));
        Assert.Contains("--lua-init=@/opt/etc/nfqws2/lua/zapret-auto.lua\n--lua-init=@/opt/etc/nfqws2/lua/zt-twice.lua", vars["NFQWS_BASE_ARGS"], StringComparison.Ordinal);
        back = StrategyImporter.Import(keen.Text, keen.Files).Solution;
        Assert.Equal(Shape(s).Order(StringComparer.Ordinal), Shape(back).Order(StringComparer.Ordinal));
        Assert.Equal(s.LuaFiles, back.LuaFiles);
        var keenArgv = StrategyImporter.KeeneticArgv(new Dictionary<string, string>(vars) { ["NFQWS_ARGS_UDP"] = "" });
        keenArgv.Remove("--fastpath-workaround=auto");
        var v = new StrategyValidator(LuaContext).ValidateArgv(keenArgv);
        Assert.True(v.Ok, string.Join("\n", v.Errors));

        var gui = ZapretGuiExporter.Build(s);
        Golden(gui, "zapret-gui-lua");
        var strategy = JsonNode.Parse(gui.TextOf("strategy.json"))!.AsObject();
        var args = strategy["profiles"]!.AsArray().Select(p => (string)p!["args"]!).ToList();
        Assert.StartsWith("--lua-init=@lua/zt-twice.lua --filter-tcp=443", args[0], StringComparison.Ordinal);
        Assert.Contains(gui.Warnings, w => w.Contains("Lua", StringComparison.Ordinal));
        // the GUI's import of the text maps the path to its @lua/ placeholder, the same as the JSON
        var converted = ZapretGuiConvert.Convert(gui.Text);
        Assert.True(converted.Ok);
        Assert.Contains("--lua-init=@lua/zt-twice.lua", converted.Profiles[0].Args, StringComparison.Ordinal);
        foreach (var file in new[] { "strategy.json", "zapret-autotuner-bundle.json" })
        {
            back = StrategyImporter.Import(gui.TextOf(file), gui.Files).Solution;
            Assert.Equal(Shape(s), Shape(back));
            Assert.Equal(s.LuaFiles, back.LuaFiles);
        }
        // the bundle carries the script without any files next to it
        Assert.Equal(s.LuaFiles, StrategyImporter.Import(gui.TextOf("zapret-autotuner-bundle.json")).Solution.LuaFiles);

        var line = ArgvExporter.Build(s);
        Assert.Contains("--lua-init=@/opt/zapret2/lua/zt-twice.lua", line.Text, StringComparison.Ordinal);
        Assert.Contains(line.Warnings, w => w.Contains("lua/", StringComparison.Ordinal));
        v = new StrategyValidator(LuaContext).ValidateArgv(ArgTokenizer.Split(line.Text));
        Assert.True(v.Ok, string.Join("\n", v.Errors));
        back = StrategyImporter.Import(line.Text, line.Files).Solution;
        Assert.Equal(s.LuaFiles, back.LuaFiles);
    }

    [Theory]
    [InlineData("zapret-lib.lua")]
    [InlineData("../evil.lua")]
    [InlineData("noext")]
    public void Exporters_refuse_bad_lua_file_names(string file)
    {
        var s = Sample();
        s.LuaFiles[file] = "x = 1";
        Assert.Throws<ExportException>(() => Zapret2Exporter.Build(s));
        Assert.Throws<ExportException>(() => KeeneticExporter.Build(s));
    }

    [Fact]
    public void Exporters_refuse_names_and_values_the_target_rejects()
    {
        var s = Sample();
        s.Hostlists["x-ipset"] = ["a.com"];
        s.Profiles[0].Hostlists.Add(new ListRef("x-ipset"));
        Assert.Throws<ExportException>(() => ZapretGuiExporter.Build(s));

        var bad = Sample();
        bad.Blobs["big"] = new byte[17 * 1024];
        Assert.Throws<ExportException>(() => Zapret2Exporter.Build(bad));

        var quote = Sample();
        quote.Profiles[0].Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=0x00:tls_mod=rnd,sni=a$b.com");
        Assert.Throws<ExportException>(() => KeeneticExporter.Build(quote));
    }

    [Fact]
    public void Phase0_profile_carries_ipcache_hostname_everywhere()
    {
        var s = Sample();
        s.Profiles[0].Strategy = Strategy.Parse("--lua-desync=wssize:wsize=1:scale=6");
        Assert.Contains("--ipcache-hostname", KeeneticExporter.Build(s).TextOf("nfqws2.conf"), StringComparison.Ordinal);
        Assert.StartsWith("--ipcache-hostname ", (string?)ZapretGuiExporter.StrategyJson(s)["profiles"]![0]!["args"], StringComparison.Ordinal);
        Assert.Contains("--ipcache-hostname", Zapret2Exporter.Build(s).Text, StringComparison.Ordinal);
        Assert.Contains("--ipcache-hostname", WinwsExporter.Build(s).Text, StringComparison.Ordinal);
    }

    [Fact]
    public void Zip_is_deterministic()
    {
        var a = KeeneticExporter.Build(Sample()).ToZip();
        var b = KeeneticExporter.Build(Sample()).ToZip();
        Assert.Equal(a, b);
        using var zip = new ZipArchive(new MemoryStream(a));
        Assert.Contains(zip.Entries, e => e.FullName == "nfqws2.conf");
    }

    /// <summary>Sample plus a provider ipset with the same name as a hostlist, an exclude and a "&lt;" range.</summary>
    private static Solution WithIpsetAndExclude()
    {
        var s = Sample();
        s.Ipsets["tcp1"] = ["162.159.128.0/24"];
        s.Hostlists["skip"] = ["status.discord.com"];
        s.Profiles.Insert(0, new Profile
        {
            Name = "ip1", TcpPorts = "443", Ipsets = [new ListRef("tcp1")], HostlistExcludes = [new ListRef("skip")],
            Strategy = Strategy.Parse("--out-range=<n3 --lua-desync=multisplit:pos=1"),
        });
        return s;
    }

    [Fact]
    public void Ipsets_and_excludes_get_their_own_files_and_ranges_are_quoted()
    {
        var s = WithIpsetAndExclude();
        var z = Zapret2Exporter.Build(s);
        Assert.Equal("discord.com\n", Encoding.UTF8.GetString(z.Files["ipset/zt-tcp1.txt"]));
        Assert.Equal("162.159.128.0/24\n", Encoding.UTF8.GetString(z.Files["ipset/zt-tcp1-ipset.txt"]));

        var w = WinwsExporter.Build(s);
        Assert.Contains("--ipset=lists/zt-tcp1-ipset.txt", w.Text, StringComparison.Ordinal);
        Assert.True(w.Files.ContainsKey("lists/zt-tcp1-ipset.txt"));
        Assert.True(w.Files.ContainsKey("lists/zt-skip.txt"));
        Assert.Contains("'--out-range=<n3'", w.Text, StringComparison.Ordinal);
        Assert.Contains("--out-range=<n3", ArgTokenizer.Split(w.Text));

        var k = KeeneticExporter.Build(s);
        Assert.True(k.Files.ContainsKey("lists/zt-tcp1-ipset.list"));
        Assert.True(k.Files.ContainsKey("lists/zt-skip.list"));

        var a = ArgvExporter.Build(s);
        Assert.Contains("--hostlist-exclude-domains=status.discord.com", a.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("--hostlist-exclude=", a.Text, StringComparison.Ordinal);
        var win = ArgvExporter.Build(s, EnginePlatform.Windows, "lua").Text;
        Assert.Contains("\"--out-range=<n3\"", win, StringComparison.Ordinal);
        Assert.DoesNotContain("'", win, StringComparison.Ordinal);

        // and they come back
        var back = StrategyImporter.Import(Encoding.UTF8.GetString(z.Files["config.fragment"]), z.Files.ToDictionary(f => "/opt/zapret2/" + f.Key, f => f.Value)).Solution;
        Assert.Equal(["162.159.128.0/24"], back.Ipsets["tcp1"]);
        Assert.Equal(["discord.com"], back.Hostlists["tcp1"]);
    }

    [Fact]
    public void Malformed_json_is_a_failed_import_not_a_crash()
    {
        Assert.Empty(StrategyImporter.Import("""{"format":"zapret-autotuner-bundle","strategy":{"profiles":[]},"blobs":[{"name":"b","base64":"!!"}]}""").Solution.Profiles);
        Assert.Empty(StrategyImporter.Import("""{"format":"zapret-gui-backup","strategies":{"a":1}}""").Solution.Profiles);
    }

    [Fact]
    public void Import_reports_what_it_could_not_carry()
    {
        var r = StrategyImporter.Import("NFQWS2_OPT=\"--filter-tcp=443 --hostlist=/opt/zapret2/ipset/missing.txt --lua-desync=fake:blob=nope\"");
        Assert.Equal("zapret2", r.Kind);
        Assert.Contains(r.Warnings, w => w.Contains("missing.txt", StringComparison.Ordinal));
        Assert.Equal("/opt/zapret2/ipset/missing.txt", r.Solution.Profiles[0].Hostlists[0].Path);
        Assert.Contains(StrategyImporter.Import("NFQWS_OPT=\"--dpi-desync=fake\"").Warnings, w => w.Contains("zapret v1", StringComparison.Ordinal));
        Assert.Empty(StrategyImporter.Import("hello").Solution.Profiles);
    }
}

/// <summary>
/// The C# port of zapret-gui profile_import.convert against the Python itself: expected outputs are written by
/// tools/golden/zapret_gui_convert.py from the zapret-gui checkout, with the environment of its own tests.
/// </summary>
public sealed class ZapretGuiConvertTests
{
    private static readonly HashSet<string> Have = ["/l/lua/zapret-antidpi.lua", "/l/fake/tls_google.bin", "/l/lists/other.txt"];

    private static readonly ZapretGuiEnv Env = new()
    {
        LuaPath = "/l/lua", BinPath = "/l/fake", ListsPath = "/l/lists", IpsetPath = "/l/ipset",
        Exists = Have.Contains, IfaceExists = i => i == "eth3",
    };

    public static TheoryData<string> Cases()
    {
        var d = new TheoryData<string>();
        foreach (var f in Directory.GetFiles(RepoPaths.Testdata("zapret-gui-convert"), "*.txt").Order(StringComparer.Ordinal))
            d.Add(Path.GetFileNameWithoutExtension(f));
        return d;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Port_matches_the_python(string name)
    {
        var text = File.ReadAllText(RepoPaths.Testdata("zapret-gui-convert", name + ".txt")).ReplaceLineEndings("\n");
        var want = JsonNode.Parse(File.ReadAllText(RepoPaths.Testdata("zapret-gui-convert", name + ".expected.json")))!;
        var got = ZapretGuiConvert.Convert(text, Env);
        Assert.Equal((bool)want["ok"]!, got.Ok);
        Assert.Equal((string)want["kind"]!, got.Kind);
        Assert.Equal((string)want["kind_title"]!, got.KindTitle);
        Assert.Equal(want["profiles"]!.AsArray().Select(p => $"{p!["id"]}|{p["name"]}|{p["enabled"]}|{p["args"]}"),
            got.Profiles.Select(p => $"{p.Id}|{p.Name}|{(p.Enabled ? "true" : "false")}|{p.Args}"));
        Assert.Equal(want["warnings"]!.AsArray().Select(w => (string)w!), got.Warnings);
        Assert.Equal(want["dropped"]!.AsArray().Select(w => (string)w!), got.Dropped);
        Assert.Equal((string?)want["error"], got.Error);
    }
}
