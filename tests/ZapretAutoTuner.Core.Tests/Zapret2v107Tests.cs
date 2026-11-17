using System.Net;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Hosts;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Resources;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>What zapret2 1.0.7 changed for us: <c>!</c> in hostlists, list repeats, <c>--wf-priority</c>, the 16K filter.</summary>
public sealed class Zapret2v107Tests
{
    private static readonly string[] StdLua = ["--lua-init=@lua/zapret-lib.lua", "--lua-init=@lua/zapret-antidpi.lua"];

    private static ValidationResult Check(EnginePlatform platform, params string[] argv) =>
        new StrategyValidator(new ValidationContext { Platform = platform }).ValidateArgv([.. StdLua, .. argv]);

    [Theory]
    [InlineData("vk.com", "vk.com", false, false)]
    [InlineData("^vk.com", "vk.com", true, false)]
    [InlineData("!vk.com", "vk.com", false, true)]
    [InlineData("!^VK.com", "vk.com", true, true)]
    [InlineData("^!vk.com", "vk.com", true, true)]
    public void Hostlist_prefixes_mix_in_any_order(string line, string domain, bool strict, bool exempt)
    {
        var e = HostlistEntry.Parse(line);
        Assert.Equal((domain, strict, exempt), (e.Domain, e.Strict, e.Exempt));
        Assert.Equal((exempt ? "!" : "") + (strict ? "^" : "") + domain, e.ToString());
    }

    [Theory]
    // the manual's example: "com" and "!vk.com" are every .com but vk.com
    [InlineData(new[] { "com", "!vk.com" }, "mail.com", true)]
    [InlineData(new[] { "com", "!vk.com" }, "vk.com", false)]
    [InlineData(new[] { "com", "!vk.com" }, "m.vk.com", false)]
    // a strict exemption leaves the subdomains in
    [InlineData(new[] { "com", "!^vk.com" }, "m.vk.com", true)]
    [InlineData(new[] { "com", "!^vk.com" }, "vk.com", false)]
    // a strict entry matches only the full name
    [InlineData(new[] { "^youtube.com" }, "youtube.com", true)]
    [InlineData(new[] { "^youtube.com" }, "www.youtube.com", false)]
    // the closest name decides: an include under an exemption wins for its subtree
    [InlineData(new[] { "!google.com", "mail.google.com" }, "x.mail.google.com", true)]
    [InlineData(new[] { "!google.com", "mail.google.com" }, "google.com", false)]
    // the first entry for a name wins
    [InlineData(new[] { "vk.com", "!vk.com" }, "vk.com", true)]
    [InlineData(new[] { "example.org" }, "Example.ORG.", true)]
    public void Hostlist_matching_follows_the_engine(string[] list, string host, bool match) =>
        Assert.Equal(match, HostlistEntry.Matches(list, host));

    [Fact]
    public void Exemptions_survive_normalisation_and_conflicts_are_reported()
    {
        var (domains, problems) = ResourceRules.NormalizeDomains(["com", "^!VK.com", "!https://m.example.org/x", "vk.com", "^!vk.com"]);
        Assert.Equal(["com", "!^vk.com", "!m.example.org"], domains);
        var dup = Assert.Single(problems);
        Assert.Equal("domain.duplicate", dup.Code);
        Assert.False(dup.IsError);
        Assert.Equal("vk.com", dup.Item);
    }

    [Fact]
    public void A_repeated_list_file_is_written_once()
    {
        var p = new Profile
        {
            TcpPorts = "443",
            Hostlists = [new("a", "/l/a.txt"), new("a2", "/l/a.txt"), new("auto", "/l/auto.txt")],
            HostlistAuto = new("auto", "/l/auto.txt"),
            HostlistExcludes = [new("x", "/l/x.txt"), new("x", "/l/x.txt")],
            Ipsets = [new("i", "/l/i.txt"), new("i", "/l/i.txt")],
            IpsetExcludes = [new("i", "/l/i.txt")],
            Strategy = Strategy.Parse("--lua-desync=multisplit"),
        };
        var args = p.ToArgs();
        Assert.Equal(["--hostlist=/l/a.txt"], args.Where(a => a.StartsWith("--hostlist=", StringComparison.Ordinal)));
        Assert.Equal(["--hostlist-auto=/l/auto.txt"], args.Where(a => a.StartsWith("--hostlist-auto=", StringComparison.Ordinal)));
        Assert.Single(args, "--hostlist-exclude=/l/x.txt");
        Assert.Single(args, "--ipset=/l/i.txt");
        // another list type may name the same file
        Assert.Single(args, "--ipset-exclude=/l/i.txt");

        var r = Check(EnginePlatform.Linux, ["--filter-tcp=443", "--hostlist=/l/a.txt", "--hostlist-auto=/l/a.txt", "--ipset=/l/i.txt", "--ipset=/l/i.txt", "--lua-desync=multisplit"]);
        Assert.Equal(2, r.Issues.Count(i => i.Code == "list.repeat"));
        Assert.True(r.Ok, r.ToString());
    }

    [Theory]
    [InlineData("--wf-priority=2000", true)]
    [InlineData("--wf-priority=-30000", true)]
    [InlineData("--wf-priority=30001", false)]
    [InlineData("--wf-priority=high", false)]
    public void Wf_priority_is_checked(string opt, bool ok)
    {
        var r = Check(EnginePlatform.Windows, opt, "--wf-tcp-out=443", "--filter-tcp=443", "--lua-desync=multisplit");
        Assert.Equal(ok, !r.Errors.Any(i => i.Code == "wf.priority"));
        // nfqws2 on Linux has no such option
        Assert.Contains(Check(EnginePlatform.Linux, opt, "--filter-tcp=443", "--lua-desync=multisplit").Errors, i => i.Code == "argv.platform");
    }

    [Fact]
    public void A_raw_filter_over_16k_is_refused()
    {
        var big = "--wf-raw-filter=(" + string.Join(" or ", Enumerable.Range(0, 900).Select(i => $"ip.DstAddr==10.0.{i / 256}.{i % 256}")) + ")";
        Assert.True(big.Length > EngineArgsBuilder.WinDivertMaxFilter);
        Assert.Contains(Check(EnginePlatform.Windows, big, "--wf-tcp-out=443", "--filter-tcp=443", "--lua-desync=multisplit").Errors, i => i.Code == "wf.filter_size");
        Assert.Throws<ArgumentException>(() => EngineArgsBuilder.WinDivertOptions(new EngineLaunch
        {
            Platform = EnginePlatform.Windows,
            LuaDir = "lua",
            Profiles = [new Profile { TcpPorts = "443", Strategy = Strategy.Parse("--lua-desync=multisplit") }],
            TargetAddresses = [.. Enumerable.Range(0, 300).Select(i => IPAddress.Parse($"10.1.{i / 256}.{i % 256}"))],
        }));
    }

    [Fact]
    public void Windows_launch_sets_the_priority_when_asked()
    {
        var launch = new EngineLaunch
        {
            Platform = EnginePlatform.Windows,
            LuaDir = "lua",
            Profiles = [new Profile { TcpPorts = "443", Strategy = Strategy.Parse("--lua-desync=multisplit") }],
            WinDivertPriority = EngineArgsBuilder.TrialWinDivertPriority,
        };
        var argv = EngineArgsBuilder.Build(launch);
        Assert.Equal("--wf-priority=2000", argv[0]);
        Assert.True(new StrategyValidator(new ValidationContext { Platform = EnginePlatform.Windows }).ValidateArgv(argv).Ok);
        Assert.DoesNotContain(EngineArgsBuilder.Build(new EngineLaunch { Platform = EnginePlatform.Windows, LuaDir = "lua", Profiles = launch.Profiles }),
            a => a.StartsWith("--wf-priority", StringComparison.Ordinal));
        Assert.Throws<ArgumentException>(() => EngineArgsBuilder.Build(new EngineLaunch { Platform = EnginePlatform.Windows, LuaDir = "lua", Profiles = launch.Profiles, WinDivertPriority = 40000 }));
    }
}
