using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Resources;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>The typed checks of strategy resources (PLAN 4a.5): names, lists, blobs and Lua scripts.</summary>
public sealed class ResourceRulesTests
{
    [Theory]
    [InlineData("youtube", true)]
    [InlineData("my-list_2", true)]
    [InlineData("YouTube", false)]
    [InlineData("a.b", false)]
    [InlineData("", false)]
    [InlineData("../etc", false)]
    [InlineData("abcdefghijabcdefghijabcdefghijabcdefghijabcdefghi", false)] // 49
    public void Names_are_lower_case_latin_digits_dash_underscore(string name, bool ok) =>
        Assert.Equal(ok, ResourceRules.CheckName(ResourceKind.Hostlist, name).Count == 0);

    [Theory]
    [InlineData("youtube.txt", "youtube")]
    [InlineData("YouTube.list.txt", "youtube")]
    [InlineData(@"C:\zapret\lists\list-general.txt", "list-general")]
    [InlineData("\"/opt/zapret2/ipset/my_ips.txt\"", "my_ips")]
    [InlineData("discord", "discord")]
    [InlineData(".hidden", ".hidden")]
    public void A_file_name_becomes_a_resource_name(string input, string name) => Assert.Equal(name, ResourceNames.Normalize(input));

    [Theory]
    [InlineData("tls_wl", true)]
    [InlineData("my-fake", false)] // engine: bad identifier
    [InlineData("1st", false)]
    [InlineData("end", false)] // Lua keyword
    [InlineData("fake_default_tls", false)] // built into the engine
    [InlineData("tls_clienthello", false)] // shipped by the keenetic package
    public void Blob_names_must_be_lua_identifiers_and_not_builtin(string name, bool ok) =>
        Assert.Equal(ok, ResourceRules.CheckName(ResourceKind.Blob, name).Count == 0);

    [Fact]
    public void Domains_are_normalised_the_way_nfqws2_reads_a_hostlist()
    {
        var (domains, problems) = ResourceRules.NormalizeDomains(
        [
            "https://WWW.YouTube.com/watch?v=1",
            "youtube.com.",
            "# comment",
            "",
            "*.googlevideo.com",
            "^exact.example.org",
            "пример.рф",
            "user@host.example:8443/path",
            "www.youtube.com",
        ]);
        Assert.Equal(["www.youtube.com", "youtube.com", "googlevideo.com", "^exact.example.org", "xn--e1afmkfd.xn--p1ai", "host.example"], domains);
        var wildcard = Assert.Single(problems);
        Assert.False(wildcard.IsError);
        Assert.Equal("domain.wildcard", wildcard.Code);
    }

    [Theory]
    [InlineData("1.2.3.4", "domain.ip")]
    [InlineData("[2001:db8::1]", "domain.ip")]
    [InlineData("a*b.com", "domain.wildcard")]
    [InlineData("bad_label-.com", "domain.bad")]
    [InlineData("sp ace.com", "domain.bad")]
    public void Bad_domains_are_errors(string input, string code)
    {
        var (domains, problems) = ResourceRules.NormalizeDomains([input]);
        Assert.Empty(domains);
        Assert.Contains(problems, p => p.IsError && p.Code == code);
    }

    [Fact]
    public void Ipset_entries_go_through_cidr_parsing()
    {
        var (entries, problems) = ResourceRules.NormalizeIpset(["1.2.3.4", "10.0.0.5/8", "2001:DB8::/32", "::ffff:5.6.7.8", "1.2.3.4/32", "; note"]);
        Assert.Equal(["1.2.3.4", "10.0.0.0/8", "2001:db8::/32", "5.6.7.8"], entries);
        var hostBits = Assert.Single(problems);
        Assert.Equal("ipset.hostbits", hostBits.Code);
        Assert.False(hostBits.IsError);

        var (_, bad) = ResourceRules.NormalizeIpset(["300.1.1.1", "1.2.3.0/33", "example.com"]);
        Assert.Equal(3, bad.Count(p => p.IsError));
    }

    [Fact]
    public void Blobs_come_from_hex_or_base64_up_to_the_engine_limit()
    {
        Assert.Equal([0x16, 0x03, 0x01], ResourceRules.ParseBlob("0x160301").Bytes);
        Assert.Equal([0x16, 0x03, 0x01], ResourceRules.ParseBlob("16 03:01").Bytes);
        Assert.Equal([0x16, 0x03, 0x01], ResourceRules.ParseBlob("FgMB").Bytes); // base64
        Assert.Equal([0xde, 0xad], ResourceRules.ParseBlob("base64:3q0=").Bytes);
        Assert.Contains(ResourceRules.ParseBlob("0x16030").Problems, p => p.Code == "blob.format");
        Assert.Contains(ResourceRules.ParseBlob("").Problems, p => p.Code == "blob.empty");
        Assert.Empty(ResourceRules.ParseBlob(Convert.ToHexString(new byte[StrategyValidator.MaxBlobSize])).Problems);
        Assert.Contains(ResourceRules.ParseBlob(Convert.ToBase64String(new byte[StrategyValidator.MaxBlobSize + 1])).Problems, p => p.Code == "blob.size");
    }

    [Fact]
    public void Prepare_refuses_errors_and_keeps_warnings()
    {
        var (data, warnings) = ResourceRules.Prepare(ResourceInput.Hostlist("yt", ["*.youtube.com", "YOUTUBE.com"]));
        Assert.Equal(["youtube.com"], data.Items);
        Assert.Single(warnings);
        var e = Assert.Throws<ResourceException>(() => ResourceRules.Prepare(ResourceInput.Hostlist("yt", ["1.2.3.4"])));
        Assert.Contains("ipset", e.Ru, StringComparison.Ordinal);
        Assert.Contains("ipset", e.En, StringComparison.Ordinal);
        Assert.Throws<ResourceException>(() => ResourceRules.Prepare(ResourceInput.Hostlist("Bad Name", ["a.com"])));
        Assert.Throws<ResourceException>(() => ResourceRules.Prepare(ResourceInput.Hostlist("empty", ["# only a comment"])));
        Assert.Throws<ResourceException>(() => ResourceRules.Prepare(ResourceInput.Blob("big", new byte[16385])));
    }
}

public sealed class LuaScriptCheckTests
{
    private const string Good = """
        -- my desync: sends the payload twice
        local function helper(x) return x end
        function zt_twice(ctx, desync)
            if desync.dis.payload then
                for i = 1, 2 do
                    local s = "end ) ] } -- not code"
                    local t = [[ function end ]]
                end
            end
            repeat local y = helper(1) until y
            return VERDICT_PASS
        end
        zt_other = function(ctx, desync) return nil end
        """;

    [Fact]
    public void Finds_desync_functions_and_skips_strings_and_comments()
    {
        var c = LuaScriptCheck.Check(Good);
        Assert.True(c.Ok, string.Join("\n", c.Problems));
        Assert.Equal(["zt_twice", "zt_other"], c.DesyncFunctions);
        Assert.DoesNotContain("helper", c.GlobalFunctions); // local
        Assert.Empty(c.Problems);
    }

    [Theory]
    [InlineData("function zt_a(ctx, desync)\n if x then\n return 1\nend", "lua.syntax")] // if not closed
    [InlineData("function zt_a(ctx, desync)\n return 1\nend\nend", "lua.syntax")] // extra end
    [InlineData("function zt_a(ctx, desync)\n local t = { 1, 2\nend", "lua.syntax")]
    [InlineData("function zt_a(ctx, desync)\n local s = \"open\nend", "lua.syntax")]
    [InlineData("function zt_a(ctx, desync)\n repeat x() end", "lua.syntax")]
    [InlineData("--[[ never closed\nfunction zt_a(ctx, desync) end", "lua.syntax")]
    [InlineData("function fake(ctx, desync) return end", "lua.collision")] // zapret-antidpi.lua
    [InlineData("multisplit = function(ctx, desync) end", "lua.collision")]
    [InlineData("   \n ", "lua.empty")]
    public void Refuses_broken_blocks_and_library_names(string source, string code)
    {
        var c = LuaScriptCheck.Check(source);
        Assert.False(c.Ok);
        Assert.Contains(c.Problems, p => p.IsError && p.Code == code);
    }

    [Fact]
    public void Size_utf8_and_risky_calls()
    {
        Assert.Contains(LuaScriptCheck.Check("x = 1 --" + new string('a', ResourceRules.MaxLuaBytes)).Problems, p => p.Code == "lua.size");
        Assert.Contains(LuaScriptCheck.Check("x = '\uD800'").Problems, p => p.Code == "lua.utf8");
        var risky = LuaScriptCheck.Check("function zt_x(ctx, desync) os.execute('reboot') end");
        Assert.True(risky.Ok); // the approval dialog shows it, it does not block
        Assert.Contains(risky.Problems, p => !p.IsError && p.Code == "lua.risky" && p.Ru.Contains("os.execute", StringComparison.Ordinal));
        Assert.Contains(LuaScriptCheck.Check("function helper(a) return a end").Problems, p => !p.IsError && p.Code == "lua.nodesync");
    }
}

public sealed class LineDiffTests
{
    [Fact]
    public void Shows_added_and_removed_lines_with_context()
    {
        var d = LineDiff.Compute("a\nb\nc\nd\n", "a\nB\nc\nd\ne\n");
        Assert.Equal(2, d.Added);
        Assert.Equal(1, d.Removed);
        Assert.Equal([" a", "-b", "+B", " c", " d", "+e"], d.Lines.Select(l => l.ToString()));
        Assert.Equal("@@ -1 +1 @@\n a\n-b\n+B\n c\n d\n+e\n", d.ToUnified());
        Assert.False(LineDiff.Compute("x\r\ny", "x\ny").HasChanges);
        Assert.Equal(["+x"], LineDiff.Compute(null, "x").Lines.Select(l => l.ToString()));
    }
}

public sealed class ResourceRefsTests
{
    [Fact]
    public void Solution_refers_to_lists_blobs_and_lua()
    {
        var s = new Solution();
        s.Hostlists["yt"] = ["youtube.com"];
        s.LuaFiles["zt-twice.lua"] = "function zt_twice(ctx, desync) end";
        s.Profiles.Add(new Profile
        {
            Name = "p", TcpPorts = "443", Hostlists = [new ListRef("yt")], Ipsets = [new ListRef("cf")], HostlistExcludes = [new ListRef("x", "/abs/path.txt")],
            Strategy = Strategy.Parse("--lua-desync=fake:blob=tls_wl:tcp_md5 --lua-desync=fake:blob=fake_default_tls:tcp_md5:pattern=0x00 --lua-desync=zt_mine:data=%my_blob"),
        });
        var refs = ResourceRefs.Of(s, new Dictionary<string, string> { ["zt_mine"] = "mine" });
        Assert.Equal(
        [
            "hostlist yt", "ipset cf", "blob my_blob", "blob tls_wl", "Lua script mine", "Lua script twice",
        ], refs.Select(r => r.ToString()));
        Assert.Equal(["/d/zt-mine.lua"], ResourceRefs.LuaPathsFor(s.Profiles.Select(p => p.Strategy), new Dictionary<string, string> { ["zt_mine"] = "/d/zt-mine.lua", ["zt_unused"] = "/d/zt-unused.lua" }));
    }

    [Fact]
    public void Resource_data_goes_into_the_solution_model()
    {
        var s = new Solution();
        ResourceRules.Prepare(ResourceInput.Hostlist("yt", ["youtube.com"])).Data.ApplyTo(s);
        ResourceRules.Prepare(ResourceInput.Ipset("cf", ["1.1.1.0/24"])).Data.ApplyTo(s);
        ResourceRules.Prepare(ResourceInput.Blob("tls_wl", "0x1603")).Data.ApplyTo(s);
        ResourceRules.Prepare(ResourceInput.Lua("twice", "function zt_twice(ctx, desync) end")).Data.ApplyTo(s);
        Assert.Equal(["youtube.com"], s.Hostlists["yt"]);
        Assert.Equal(["1.1.1.0/24"], s.Ipsets["cf"]);
        Assert.Equal([0x16, 0x03], s.Blobs["tls_wl"]);
        Assert.Equal("function zt_twice(ctx, desync) end", s.LuaFiles["zt-twice.lua"]);
        var back = ResourceData.FromBytes(ResourceKind.Hostlist, "yt", ResourceRules.Prepare(ResourceInput.Hostlist("yt", ["a.com", "b.com"])).Data.ToBytes());
        Assert.Equal(["a.com", "b.com"], back.Items);
    }
}
