using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Tests;

public sealed class ValidatorTests
{
    private static readonly StrategyValidator V = new(new ValidationContext
    {
        DeclaredBlobs = new Dictionary<string, long?> { ["tls_google"] = 681, ["tls_clienthello"] = 517 },
    });

    private static Profile Tcp(string strategy, Action<Profile>? tweak = null)
    {
        var p = new Profile { TcpPorts = "443", L7 = ["tls"], Strategy = Strategy.Parse(strategy) };
        tweak?.Invoke(p);
        return p;
    }

    private static Profile Udp(string strategy) => new() { UdpPorts = "443", L7 = ["quic"], Strategy = Strategy.Parse(strategy) };

    [Theory]
    [InlineData("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000 --lua-desync=multidisorder:pos=1,midsld")]
    [InlineData("--payload=tls_client_hello --lua-desync=multisplit:pos=1:seqovl=5:seqovl_pattern=0x1603030000")]
    [InlineData("--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000 --lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up")]
    [InlineData("--lua-desync=hostfakesplit:host=ozon.ru:midhost=host-2:tcp_md5:tcp_ts_up")]
    [InlineData("--payload=tls_client_hello --lua-desync=tls_client_hello_clone:blob=myclone --lua-desync=fake:blob=myclone:tcp_md5")]
    [InlineData("--payload=tls_client_hello --lua-desync=fake:blob=%tls_google:badsum")]
    [InlineData("--out-range=-s34228 --in-range=-s5556 --lua-desync=circular:fails=3 --in-range=x --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5:strategy=1 --lua-desync=multidisorder:pos=1,midsld:strategy=2:final")]
    [InlineData("--in-range=-s1 --lua-desync=oob:urp=b")]
    [InlineData("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:ip_autottl=-1,3-20 --lua-desync=multisplit:pos=sniext+1")]
    [InlineData("--lua-desync=fakedsplit:pos=midsld:tcp_flags_unset=ACK --lua-desync=tcpseg:pos=0,-1:seqovl=5 --lua-desync=drop")]
    public void Field_tested_strategies_are_valid(string s)
    {
        var r = V.ValidateProfile(Tcp(s));
        Assert.True(r.Ok, r.ToString());
    }

    [Fact]
    public void Quic_fake_without_fooling_is_fine()
    {
        var r = V.ValidateProfile(Udp("--payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6"));
        Assert.True(r.Ok, r.ToString());
    }

    public static TheoryData<string, string> BadCases() => new()
    {
        { "--lua-desync=nosuchfunc", "func.unknown" },
        { "--lua-desync=fake:tcp_md5", "arg.required" },
        { "--lua-desync=fake:blob=fake_default_tls", "fake.nofooling" },
        { "--lua-desync=fakedsplit:pos=2", "fake.nofooling" },
        { "--lua-desync=rst", "fake.nofooling" },
        { "--lua-desync=fake:blob=my_fake:tcp_md5", "blob.missing" },
        { "--lua-desync=multisplit:pos=1:seqovl=5:seqovl_pattern=nope", "blob.missing" },
        { "--lua-desync=fake:blob=fake_default_tls:tcp_md5:tls_mod=sni=%nosuch", "blob.subst" },
        { "--lua-desync=multisplit:pos=1:bogus=1", "arg.unknown" },
        { "--lua-desync=multisplit:pos=1:seqovl=abc", "arg.int" },
        { "--lua-desync=multisplit:pos=1:repeats=0", "arg.range" },
        { "--lua-desync=multisplit:pos=1:ipfrag_pos_tcp=12", "arg.multiple" },
        { "--lua-desync=http_hostcase:spell=HoSTT", "arg.length" },
        { "--lua-desync=multisplit:pos=1:dir=up", "arg.enum" },
        { "--lua-desync=multisplit:pos=nosuchmarker", "arg.marker" },
        { "--lua-desync=fakedsplit:pos=1,2:tcp_md5", "arg.marker" },
        { "--lua-desync=tcpseg:pos=1 --lua-desync=drop", "arg.count" },
        { "--lua-desync=multisplit:pos=1:payload=tls_hello", "payload.unknown" },
        { "--payload=tls --lua-desync=multisplit:pos=1", "payload.unknown" },
        { "--lua-desync=fake:blob=fake_default_tls:tcp_md5:tls_mod=bogus", "tlsmod.unknown" },
        { "--lua-desync=syndata:tls_mod=dupsid", "tlsmod.unknown" },
        { "--lua-desync=fake:blob=fake_default_tls:tcp_md5:tls_mod=sni", "tlsmod.sni" },
        { "--lua-desync=fake:blob=fake_default_tls:tcp_flags_set=XYZ", "arg.tcpflag" },
        { "--lua-desync=fake:blob=fake_default_tls:ip_autottl=auto", "arg.autottl" },
        { "--lua-desync=fake:blob=fake_default_tls:tcp_md5=zz", "arg.hex" },
        { "--lua-desync=multisplit:seqovl", "arg.novalue" },
        { "--lua-desync=multidisorder:pos=2,midsld:seqovl=3", "seqovl.pos" },
        { "--lua-desync=oob", "oob.inrange" },
        { "--in-range=-s1 --lua-desync=oob --lua-desync=multisplit:pos=1", "oob.resender" },
        { "--lua-desync=http_methodeol --lua-desync=http_domcase", "http.methodeol.order" },
        { "--in-range=-s5556 --lua-desync=circular --lua-desync=multisplit:pos=1:strategy=1 --lua-desync=multisplit:pos=2:strategy=3", "circular.gap" },
        { "--in-range=-s5556 --lua-desync=circular --lua-desync=multisplit:pos=1", "circular.empty" },
        { "--in-range=-s5556 --lua-desync=circular --lua-desync=multisplit:pos=1:strategy=x", "circular.number" },
        { "--in-range=z5 --lua-desync=multisplit", "range.bad" },
        { "--out-range=d10 --lua-desync=multisplit", "range.bad" },
        { "--lua-desync=condition:iff=cond_maybe", "arg.iff" },
        { "--lua-desync=fake:blob=my-blob:optional:tcp_md5", "blob.name" },
        { "--lua-desync=tls_client_hello_clone:blob=bad.name", "blob.name" },
    };

    [Theory]
    [MemberData(nameof(BadCases))]
    public void Each_error_is_reported_with_a_russian_message(string strategy, string code)
    {
        var r = V.ValidateProfile(Tcp(strategy));
        var issue = Assert.Single(r.Issues, i => i.Code == code);
        Assert.Equal(Severity.Error, issue.Severity);
        Assert.False(r.Ok);
        Assert.Matches("[а-яА-Я]", issue.Ru);
        Assert.NotEmpty(issue.En);
    }

    [Fact]
    public void Phase0_technique_in_hostlist_profile_is_an_error_unless_ipcache_hostname()
    {
        var p = Tcp("--lua-desync=wssize:wsize=1:scale=6", x => x.Hostlists = [new ListRef("zt-yt")]);
        Assert.Contains(V.ValidateProfile(p).Errors, i => i.Code == "phase0.hostlist");
        var withCache = new StrategyValidator(new ValidationContext { IpcacheHostname = true });
        Assert.DoesNotContain(withCache.ValidateProfile(p).Issues, i => i.Code == "phase0.hostlist");
    }

    [Fact]
    public void Function_from_unloaded_file_is_an_error()
    {
        var v = new StrategyValidator(new ValidationContext { LoadedFunctions = new HashSet<string> { "fake", "multisplit" } });
        Assert.Contains(v.ValidateProfile(Tcp("--lua-desync=circular --lua-desync=multisplit:strategy=1")).Errors, i => i.Code == "func.notloaded");
    }

    [Fact]
    public void Custom_lua_function_is_accepted_when_loaded()
    {
        var v = new StrategyValidator(new ValidationContext { LoadedFunctions = new HashSet<string> { "zt_example" } });
        Assert.True(v.ValidateProfile(Tcp("--lua-desync=zt_example:x=1")).Ok);
    }

    [Fact]
    public void Tcp_ts_on_windows_client_is_a_warning()
    {
        var client = ClientProfile.BuiltIn[0] with { TcpTimestamps = false };
        var v = new StrategyValidator(new ValidationContext { Client = client });
        var r = v.ValidateProfile(Tcp("--lua-desync=fake:blob=fake_default_tls:tcp_ts=-1000"));
        Assert.True(r.Ok);
        Assert.Contains(r.Warnings, i => i.Code == "fooling.tcp_ts");
    }

    [Theory]
    [InlineData("--lua-desync=tcpseg:pos=0,-1", "tcpseg.nodrop")]
    [InlineData("--lua-desync=circular --lua-desync=multisplit:strategy=1", "circular.inrange")]
    [InlineData("--lua-desync=synack", "synack.nat")]
    [InlineData("--lua-desync=wgobfs:secret=x", "func.twosided")]
    [InlineData("--lua-desync=multisplit:pos=1:nodrop=1", "arg.flagvalue")]
    public void Warnings(string strategy, string code)
    {
        var r = V.ValidateProfile(Tcp(strategy));
        Assert.Contains(r.Warnings, i => i.Code == code);
    }

    [Fact]
    public void Udp_ttl_fooling_warns()
    {
        Assert.Contains(V.ValidateProfile(Udp("--lua-desync=fake:blob=fake_default_quic:ip_ttl=4")).Warnings, i => i.Code == "fooling.udp_ttl");
    }

    [Theory]
    [InlineData("--filter-l7=tlsx", "l7.unknown")]
    [InlineData("ports", "ports.bad")]
    public void Profile_filters(string what, string code)
    {
        var p = Tcp("--lua-desync=multisplit");
        if (what == "ports")
            p.TcpPorts = "443,70000";
        else
            p.L7 = ["tlsx"];
        Assert.Contains(V.ValidateProfile(p).Errors, i => i.Code == code);
    }

    [Theory]
    [InlineData("a", true)]
    [InlineData("x", true)]
    [InlineData("-d10", true)]
    [InlineData("<n2", true)]
    [InlineData("-s34228", true)]
    [InlineData("n2-d10", true)]
    [InlineData("s1<s100", true)]
    [InlineData("d5-", true)]
    [InlineData("d10", false)]
    [InlineData("q1-q2", false)]
    [InlineData("", false)]
    public void Packet_ranges(string range, bool ok) => Assert.Equal(ok, PacketRange.IsValid(range));

    [Theory]
    [InlineData("1", true)]
    [InlineData("-1", true)]
    [InlineData("midsld+1", true)]
    [InlineData("host-2", true)]
    [InlineData("sniext", true)]
    [InlineData("40000", false)]
    [InlineData("foo", false)]
    [InlineData("midsld+x", false)]
    public void Position_markers(string m, bool ok) =>
        Assert.Equal(ok, PositionMarker.TryParse(m, Catalog.LuaCatalog.Default.PositionMarkers, out _));
}
