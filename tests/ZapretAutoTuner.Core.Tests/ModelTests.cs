using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Tests;

public sealed class ModelTests
{
    [Theory]
    [InlineData("fake:blob=fake_default_tls:tcp_md5")]
    [InlineData("multisplit:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000")]
    [InlineData("fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000")]
    [InlineData("circular")]
    [InlineData(@"luaexec:code=a\:b")]
    public void LuaCall_round_trips(string text)
    {
        Assert.Equal(text, LuaCall.Parse(text).ToString());
    }

    [Fact]
    public void LuaCall_parses_flags_values_and_escapes()
    {
        var c = LuaCall.Parse(@"fake:blob=x:tcp_md5:tls_mod=sni=a.b:code=1\:2");
        Assert.Equal("fake", c.Function);
        Assert.Equal("x", c["blob"]);
        Assert.True(c.Args.Single(a => a.Name == "tcp_md5").IsFlag);
        Assert.Equal("sni=a.b", c["tls_mod"]);
        Assert.Equal("1:2", c["code"]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("my-func:x=1")]
    [InlineData("fake::x")]
    [InlineData("fake:bad-arg=1")]
    [InlineData("end")]
    public void LuaCall_rejects_bad_identifiers(string text)
    {
        Assert.Throws<FormatException>(() => LuaCall.Parse(text));
    }

    [Fact]
    public void LuaCall_with_and_without()
    {
        var c = LuaCall.Parse("fake:blob=x:repeats=2").With("repeats", "6").Without("blob");
        Assert.Equal("fake:repeats=6", c.ToString());
    }

    [Fact]
    public void Strategy_parses_and_formats()
    {
        const string s = "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5 --lua-desync=multidisorder:pos=1,midsld";
        var st = Strategy.Parse(s);
        Assert.Equal(2, st.InstanceCount);
        Assert.Equal(s, st.ToString());
        Assert.Equal(st, Strategy.Parse(s));
    }

    [Theory]
    [InlineData("--payload")]
    [InlineData("--filter-tcp=443")]
    [InlineData("--dpi-desync=fake")]
    public void Strategy_rejects_non_strategy_options(string s)
    {
        Assert.Throws<FormatException>(() => Strategy.Parse(s));
    }

    [Fact]
    public void Profile_builds_args_in_engine_order()
    {
        var p = new Profile
        {
            TcpPorts = "443",
            L7 = ["tls"],
            Hostlists = [new ListRef("zt-youtube")],
            Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=multisplit:pos=1"),
        };
        Assert.Equal(
            "--filter-tcp=443 --filter-l7=tls --hostlist=lists/zt-youtube.txt --payload=tls_client_hello --lua-desync=multisplit:pos=1",
            string.Join(' ', p.ToArgs((r, _) => $"lists/{r.Name}.txt")));
    }

    [Theory]
    [InlineData("youtube.com", TargetKind.Domain, "youtube.com", 443, L4Kind.Tcp)]
    [InlineData("https://www.YouTube.com/watch?v=1", TargetKind.Domain, "www.youtube.com", 443, L4Kind.Tcp)]
    [InlineData("http://example.org", TargetKind.Domain, "example.org", 80, L4Kind.Tcp)]
    [InlineData("discord.media:50000/udp", TargetKind.Domain, "discord.media", 50000, L4Kind.Udp)]
    [InlineData("1.2.3.4", TargetKind.Ip, "1.2.3.4", 443, L4Kind.Tcp)]
    [InlineData("1.2.3.4:8443", TargetKind.Ip, "1.2.3.4", 8443, L4Kind.Tcp)]
    [InlineData("[2001:db8::1]:443/udp", TargetKind.Ip, "2001:db8::1", 443, L4Kind.Udp)]
    [InlineData("2001:db8::1", TargetKind.Ip, "2001:db8::1", 443, L4Kind.Tcp)]
    [InlineData("104.16.0.0/13", TargetKind.Cidr, "104.16.0.0/13", 443, L4Kind.Tcp)]
    [InlineData("пример.рф", TargetKind.Domain, "xn--e1afmkfd.xn--p1ai", 443, L4Kind.Tcp)]
    public void Target_parses_user_input(string line, TargetKind kind, string value, int port, L4Kind proto)
    {
        var t = Target.ParseInput(line)!;
        Assert.Equal(kind, t.Kind);
        Assert.Equal(value, t.Value);
        Assert.Equal(port, t.Port);
        Assert.Equal(proto, t.Protocol);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("# comment")]
    public void Target_skips_empty_lines(string line) => Assert.Null(Target.ParseInput(line));

    [Theory]
    [InlineData("not a host")]
    [InlineData("localhost")]
    [InlineData("example.com:99999")]
    [InlineData("10.0.0.0/40")]
    public void Target_rejects_garbage(string line) => Assert.Throws<FormatException>(() => Target.ParseInput(line));

    [Fact]
    public void Target_url_keeps_path()
    {
        Assert.Equal("https://example.com/a/b?c=1", Target.ParseInput("example.com/a/b?c=1")!.Url);
    }

    [Theory]
    [InlineData(new[] { "80,443", "443", "1000-2000,1500-2500" }, '-', "80,443,1000-2500")]
    [InlineData(new[] { "50000-50100", "50101" }, ':', "50000:50101")]
    [InlineData(new[] { "443" }, '-', "443")]
    public void PortList_unions_and_formats(string[] lists, char sep, string expected)
    {
        Assert.Equal(expected, PortList.Union(lists, sep));
    }

    [Theory]
    [InlineData("--a=1 --b='x y' \"--c=z w\"", new[] { "--a=1", "--b=x y", "--c=z w" })]
    [InlineData(@"--lua-desync=luaexec:code=a\:b", new[] { @"--lua-desync=luaexec:code=a\:b" })]
    [InlineData("  \n --x=1 \t\n", new[] { "--x=1" })]
    public void ArgTokenizer_splits_like_a_shell(string text, string[] expected)
    {
        Assert.Equal(expected, ArgTokenizer.Split(text));
    }

    [Theory]
    [InlineData("--filter-tcp=443", "--filter-tcp=443")]
    [InlineData("--hostlist=C:/Program Files/x.txt", "'--hostlist=C:/Program Files/x.txt'")]
    [InlineData(@"--lua-desync=luaexec:code=a\:b", @"'--lua-desync=luaexec:code=a\:b'")]
    [InlineData("--filter-tcp=~80", "'--filter-tcp=~80'")]
    public void ArgTokenizer_quotes_only_when_needed(string word, string expected)
    {
        Assert.Equal(expected, ArgTokenizer.Quote(word));
        Assert.Equal([word], ArgTokenizer.Split(ArgTokenizer.Quote(word)));
    }

    [Theory]
    [InlineData("zt_tls", true)]
    [InlineData("_x1", true)]
    [InlineData("1x", false)]
    [InlineData("my-fake", false)]
    [InlineData("tls.google", false)]
    [InlineData("function", false)]
    public void Lua_identifiers(string s, bool ok) => Assert.Equal(ok, Identifiers.IsLuaIdentifier(s));

    [Fact]
    public void Identifier_conversion()
    {
        Assert.Equal("my_fake", Identifiers.ToLuaIdentifier("my-fake"));
        Assert.Equal("_1x", Identifiers.ToLuaIdentifier("1x"));
        Assert.Equal("end_", Identifiers.ToLuaIdentifier("end"));
        Assert.Equal("YouTube___Discord", Identifiers.ToListName("YouTube + Discord"));
    }
}
