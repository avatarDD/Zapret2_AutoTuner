using System.Diagnostics;
using System.Net;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Tests;

public sealed class EngineArgsTests
{
    private static Profile TlsProfile(string strategy = "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5 --lua-desync=multisplit:pos=1,midsld") =>
        new() { TcpPorts = "443", L7 = ["tls"], Strategy = Strategy.Parse(strategy) };

    private static Profile QuicProfile() =>
        new() { UdpPorts = "443", L7 = ["quic"], Strategy = Strategy.Parse("--payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6") };

    [Fact]
    public void Linux_argv_has_globals_first_and_lua_in_order()
    {
        var argv = EngineArgsBuilder.Build(new EngineLaunch
        {
            Platform = EnginePlatform.Linux,
            LuaDir = "/opt/zt/lua",
            Blobs = new Dictionary<string, string> { ["tls_google"] = "/opt/zt/files/fake/tls_clienthello_www_google_com.bin" },
            Profiles = [TlsProfile(), QuicProfile()],
        });
        Assert.Equal(
            [
                "--qnum=300", "--fwmark=0x40000000",
                "--lua-init=@/opt/zt/lua/zapret-lib.lua", "--lua-init=@/opt/zt/lua/zapret-antidpi.lua", "--lua-init=@/opt/zt/lua/zapret-auto.lua",
                "--blob=tls_google:@/opt/zt/files/fake/tls_clienthello_www_google_com.bin",
                "--filter-tcp=443", "--filter-l7=tls", "--payload=tls_client_hello", "--lua-desync=fake:blob=fake_default_tls:tcp_md5", "--lua-desync=multisplit:pos=1,midsld",
                "--new",
                "--filter-udp=443", "--filter-l7=quic", "--payload=quic_initial", "--lua-desync=fake:blob=fake_default_quic:repeats=6",
            ],
            argv);
        Assert.All(argv, a => Assert.Contains("=", a.Replace("--new", "--new=", StringComparison.Ordinal)));
    }

    [Fact]
    public void Windows_argv_derives_the_windivert_filter()
    {
        var argv = EngineArgsBuilder.Build(new EngineLaunch
        {
            Platform = EnginePlatform.Windows,
            LuaDir = @"C:\zt\lua",
            Profiles = [TlsProfile(), QuicProfile()],
            TargetAddresses = [IPAddress.Parse("1.2.3.4"), IPAddress.Parse("5.6.7.8")],
            WinDivertTcpEmpty = true,
        });
        Assert.Equal("--wf-tcp-empty=1", argv[0]);
        Assert.Contains("--wf-l3=ipv4", argv);
        Assert.Contains("--wf-tcp-out=443", argv);
        Assert.Contains("--wf-udp-out=443", argv);
        Assert.DoesNotContain(argv, a => a.StartsWith("--wf-tcp-in", StringComparison.Ordinal));
        Assert.Contains("--wf-raw-filter=(ip.DstAddr==1.2.3.4 or ip.SrcAddr==1.2.3.4 or ip.DstAddr==5.6.7.8 or ip.SrcAddr==5.6.7.8)", argv);
        Assert.Contains("--lua-init=@C:/zt/lua/zapret-lib.lua", argv);
        Assert.DoesNotContain(argv, a => a.StartsWith("--qnum", StringComparison.Ordinal));
    }

    [Fact]
    public void Circular_adds_incoming_interception_on_windows()
    {
        var circ = TlsProfile("--out-range=-s34228 --in-range=-s5556 --lua-desync=circular --in-range=x --payload=tls_client_hello --lua-desync=multisplit:pos=1:strategy=1");
        var argv = EngineArgsBuilder.Build(new EngineLaunch { Platform = EnginePlatform.Windows, LuaDir = "lua", Profiles = [circ] });
        Assert.Contains("--wf-tcp-in=443", argv);
    }

    [Fact]
    public void Built_argv_passes_the_validator()
    {
        foreach (var platform in new[] { EnginePlatform.Linux, EnginePlatform.Windows })
        {
            var argv = EngineArgsBuilder.Build(new EngineLaunch { Platform = platform, LuaDir = "lua", Profiles = [TlsProfile(), QuicProfile()] });
            var r = new StrategyValidator(new ValidationContext { Platform = platform }).ValidateArgv(argv);
            Assert.True(r.Ok, r.ToString());
        }
    }

    [Fact]
    public void Config_file_has_no_hash_comments_and_round_trips()
    {
        var argv = new List<string> { "--wf-tcp-out=443", "--wf-raw-filter=(ip.DstAddr==1.2.3.4 or ip.SrcAddr==1.2.3.4)", "--hostlist=C:/Program Files/zt/x.txt", "--filter-tcp=443", "--lua-desync=multisplit:pos=1" };
        var text = EngineArgsBuilder.ToConfigFile(argv);
        Assert.DoesNotContain(text.Split('\n'), l => l.StartsWith('#'));
        Assert.Equal(argv, ArgTokenizer.Split(text));
    }

    [Fact]
    public void Config_file_rejects_command_substitution_and_size()
    {
        Assert.Throws<ArgumentException>(() => EngineArgsBuilder.ToConfigFile(["--comment=$(rm -rf /)"]));
        Assert.Throws<ArgumentException>(() => EngineArgsBuilder.ToConfigFile([.. Enumerable.Repeat("--hostlist-domains=" + new string('a', 1000), 20)]));
    }

    [Fact]
    public void Nft_ruleset_contains_sets_marks_and_limits()
    {
        var script = NftRuleset.Build([new NftQueueRule
        {
            QueueNum = 301,
            TcpPorts = "80,443",
            UdpPorts = "443",
            Targets = [IPAddress.Parse("1.2.3.4"), IPAddress.Parse("2001:db8::1")],
            Incoming = true,
        }]);
        Assert.Contains("table inet ztuner {", script);
        Assert.Contains("type filter hook postrouting priority 101;", script);
        Assert.Contains("meta mark & 0x40000000 == 0x40000000 return", script);
        Assert.Contains("set t4_0 { type ipv4_addr; elements = { 1.2.3.4 } }", script);
        Assert.Contains("ip daddr @t4_0 tcp dport { 80, 443 } ct original packets 1-20 queue num 301 bypass", script);
        Assert.Contains("ip6 daddr @t6_0 udp dport { 443 } ct original packets 1-5 queue num 301 bypass", script);
        Assert.Contains("ip saddr @t4_0 tcp sport { 80, 443 } ct reply packets 1-10 queue num 301 bypass", script);
        Assert.StartsWith("add table inet ztuner\ndelete table inet ztuner\n", script);
    }

    [Fact]
    public void Nft_ruleset_is_accepted_by_nft_check_mode()
    {
        if (!OperatingSystem.IsLinux() || !File.Exists("/usr/sbin/nft") || Environment.UserName != "root")
            return; // nft -c needs the binary and netlink access
        var script = NftRuleset.Build([new NftQueueRule { QueueNum = 300, TcpPorts = "443,1000-2000", UdpPorts = "443", Targets = [IPAddress.Parse("1.2.3.4")], Incoming = true }]);
        var psi = new ProcessStartInfo("/usr/sbin/nft", "-c -f -") { RedirectStandardInput = true, RedirectStandardError = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        p.StandardInput.Write(script);
        p.StandardInput.Close();
        var err = p.StandardError.ReadToEnd();
        p.WaitForExit();
        // Containers without the nft_queue module reject the rules at the kernel stage; the syntax is still checked.
        bool syntaxOnlyKernelErrors = err.Split('\n').Where(l => l.Contains("Error:", StringComparison.Ordinal)).All(l => l.Contains("Could not process rule", StringComparison.Ordinal));
        Assert.True(p.ExitCode == 0 || syntaxOnlyKernelErrors, err + "\n" + script);
    }

    [Theory]
    [InlineData("desync profile 2 (zt_tls) matches", EngineEventKind.ProfileMatched, 2, "zt_tls")]
    [InlineData("using cached desync profile 1 (noname) ", EngineEventKind.ProfileMatched, 1, "noname")]
    [InlineData("desync profile not found", EngineEventKind.ProfileNotFound, null, null)]
    [InlineData("* lua 'fake_1_1' : desync", EngineEventKind.LuaDesync, null, "fake_1_1")]
    [InlineData("lua cutoff from 'multisplit_1_2' in=1 out=1", EngineEventKind.LuaCutoff, null, "multisplit_1_2")]
    [InlineData("DELAY desync until reasm is complete (#2)", EngineEventKind.ReasmDelay, null, null)]
    [InlineData("rawpacket_queue failed !", EngineEventKind.ReasmFailed, null, null)]
    [InlineData("blob 'zt_tls' unavailable", EngineEventKind.BlobUnavailable, null, "zt_tls")]
    [InlineData("bad identifier 'my-fake'", EngineEventKind.BadIdentifier, null, "my-fake")]
    [InlineData("lua/zapret-lib.lua:4: Incompatible NFQWS2_COMPAT_VER. Use pktws and lua scripts from the same release !", EngineEventKind.IncompatibleLua, null, null)]
    [InlineData("auto hostlist (profile 1 (default)) : example.com : fail counter 1/3", EngineEventKind.AutoHostlist, 1, null)]
    [InlineData("invalid packet range value : z5", EngineEventKind.StartupError, null, null)]
    public void Log_lines_become_events(string line, EngineEventKind kind, int? profile, string? name)
    {
        var e = EngineLogParser.Parse(line)!;
        Assert.Equal(kind, e.Kind);
        Assert.Equal(profile, e.Profile);
        Assert.Equal(name, e.Name);
    }

    [Fact]
    public void Unrelated_log_lines_are_ignored() => Assert.Null(EngineLogParser.Parse("packet: id=1 len=60 outbound"));

    [Fact]
    public void Fatal_events_are_explained_in_russian()
    {
        var e = EngineLogParser.Parse("blob 'zt_tls' unavailable")!;
        Assert.Contains("zt_tls", EngineLogParser.Explain(e));
        Assert.True(EngineLogParser.IsFatal(EngineLogParser.Parse("bad identifier 'x-y'")!));
    }
}

public sealed class ArgvValidatorTests
{
    private static readonly string[] StdLua = ["--lua-init=@lua/zapret-lib.lua", "--lua-init=@lua/zapret-antidpi.lua"];

    /// <summary>Validates argv with the standard lua files loaded first (unless the test sets --lua-init itself).</summary>
    private static ValidationResult Check(EnginePlatform platform, params string[] argv) =>
        new StrategyValidator(new ValidationContext { Platform = platform })
            .ValidateArgv(argv.Any(a => a.StartsWith("--lua-init", StringComparison.Ordinal)) ? argv : [.. StdLua, .. argv]);

    [Fact]
    public void Functions_of_files_not_loaded_are_errors()
    {
        var bare = new StrategyValidator(new ValidationContext { Platform = EnginePlatform.Linux })
            .ValidateArgv(["--filter-tcp=443", "--lua-desync=multisplit"]);
        Assert.Contains(bare.Errors, i => i.Code == "func.notloaded");
        // a custom lua file may define anything: no check
        var custom = new StrategyValidator(new ValidationContext { Platform = EnginePlatform.Linux })
            .ValidateArgv(["--lua-init=@lua/zapret-lib.lua", "--lua-init=@/home/u/my.lua", "--filter-tcp=443", "--lua-desync=multisplit"]);
        Assert.True(custom.Ok, custom.ToString());
    }

    [Theory]
    [InlineData("--dpi-desync=fake", "argv.parse")]
    [InlineData("--nosuch=1", "argv.parse")]
    [InlineData("--qnum", "argv.parse")]
    public void Bad_options(string opt, string code)
    {
        Assert.Contains(Check(EnginePlatform.Linux, opt, "--filter-tcp=443", "--lua-desync=multisplit").Errors, i => i.Code == code);
    }

    [Fact]
    public void Value_after_space_is_reported()
    {
        Assert.Contains(Check(EnginePlatform.Linux, "--filter-tcp", "443").Errors, i => i.Code == "argv.parse");
    }

    [Fact]
    public void Platform_specific_options()
    {
        Assert.Contains(Check(EnginePlatform.Linux, "--wf-tcp-out=443", "--filter-tcp=443", "--lua-desync=multisplit").Errors, i => i.Code == "argv.platform");
        Assert.Contains(Check(EnginePlatform.Windows, "--qnum=300", "--wf-tcp-out=443", "--filter-tcp=443", "--lua-desync=multisplit").Errors, i => i.Code == "argv.platform");
        Assert.Contains(Check(EnginePlatform.Windows, "--user=nobody", "--wf-tcp-out=443", "--filter-tcp=443", "--lua-desync=multisplit").Errors, i => i.Code == "argv.platform");
        Assert.Contains(Check(EnginePlatform.Linux, "--fastpath-workaround=auto", "--filter-tcp=443", "--lua-desync=multisplit").Errors, i => i.Code == "argv.platform");
        Assert.True(Check(EnginePlatform.Keenetic, "--fastpath-workaround=auto", "--qnum=300", "--filter-tcp=443", "--lua-desync=multisplit").Ok);
    }

    [Fact]
    public void Lua_order_is_enforced()
    {
        var r = Check(EnginePlatform.Linux, "--lua-init=@lua/zapret-antidpi.lua", "--lua-init=@lua/zapret-lib.lua", "--filter-tcp=443", "--lua-desync=multisplit");
        Assert.Contains(r.Errors, i => i.Code == "argv.lua_order");
        Assert.Contains(r.Errors, i => i.Code == "argv.lua_lib_first");
    }

    [Fact]
    public void Late_blob_is_a_warning()
    {
        var r = Check(EnginePlatform.Linux, "--filter-tcp=443", "--lua-desync=fake:blob=b1:tcp_md5", "--blob=b1:0x0000");
        Assert.True(r.Ok, r.ToString());
        Assert.Contains(r.Warnings, i => i.Code == "argv.late_global");
    }

    [Fact]
    public void Blob_declared_in_argv_satisfies_profiles_and_bad_names_fail()
    {
        Assert.True(Check(EnginePlatform.Linux, "--blob=zt_wl:0x1603", "--filter-tcp=443", "--lua-desync=fake:blob=zt_wl:tcp_md5").Ok);
        Assert.Contains(Check(EnginePlatform.Linux, "--blob=zt-wl:0x1603", "--filter-tcp=443", "--lua-desync=multisplit").Errors, i => i.Code == "blob.name");
    }

    [Fact]
    public void Blob_files_are_checked_for_existence_and_size()
    {
        var v = new StrategyValidator(new ValidationContext { Platform = EnginePlatform.Linux });
        var r = v.ValidateArgv(["--blob=big:@/x/big.bin", "--blob=gone:@/x/gone.bin", "--filter-tcp=443", "--lua-desync=multisplit"], p => p.EndsWith("big.bin", StringComparison.Ordinal) ? 20000 : null);
        Assert.Contains(r.Errors, i => i.Code == "blob.size");
        Assert.Contains(r.Errors, i => i.Code == "blob.file");
    }

    [Fact]
    public void Windows_ports_must_be_intercepted()
    {
        var r = Check(EnginePlatform.Windows, "--wf-tcp-out=443", "--filter-tcp=80,443", "--lua-desync=multisplit");
        Assert.Contains(r.Errors, i => i.Code == "wf.uncovered" && i.Ru.Contains("80", StringComparison.Ordinal));
        Assert.True(Check(EnginePlatform.Windows, "--wf-raw=tcp", "--filter-tcp=80", "--lua-desync=multisplit").Ok);
    }

    [Fact]
    public void Profile_errors_are_reported_with_profile_number()
    {
        var r = Check(EnginePlatform.Linux, "--filter-tcp=443", "--lua-desync=multisplit", "--new", "--filter-tcp=443", "--lua-desync=fake:blob=fake_default_tls");
        var issue = Assert.Single(r.Errors);
        Assert.Equal("fake.nofooling", issue.Code);
        Assert.Equal("профиль 2: fake", issue.Where);
    }
}
