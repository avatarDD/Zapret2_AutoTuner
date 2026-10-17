using System.Diagnostics;
using System.Net;
using ZapretAutoTuner.Core.Engine;

namespace ZapretAutoTuner.Core.Tests;

public class FirewallTests
{
    private static readonly NftQueueRule Rule = new()
    {
        QueueNum = 301,
        TcpPorts = "80,443",
        UdpPorts = "443,50000-50100",
        Targets = [IPAddress.Parse("203.0.113.10"), IPAddress.Parse("2001:db8::10")],
        Incoming = true,
    };

    [Fact]
    public void Iptables_v4_script_has_mark_skip_limits_and_bypass()
    {
        var s = IptablesRuleset.Build([Rule], ipv6: false);
        Assert.StartsWith("*mangle\n:ztuner_post - [0:0]\n:ztuner_pre - [0:0]\n", s, StringComparison.Ordinal);
        Assert.Contains("-A ztuner_post -m mark --mark 0x40000000/0x40000000 -j RETURN", s, StringComparison.Ordinal);
        Assert.Contains("-A ztuner_post -d 203.0.113.10 -p tcp -m multiport --dports 80,443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:20 -j NFQUEUE --queue-num 301 --queue-bypass", s, StringComparison.Ordinal);
        Assert.Contains("-A ztuner_post -d 203.0.113.10 -p udp -m multiport --dports 443,50000:50100 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:5", s, StringComparison.Ordinal);
        Assert.Contains("-A ztuner_pre -s 203.0.113.10 -p tcp -m multiport --sports 80,443 -m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:10", s, StringComparison.Ordinal);
        Assert.DoesNotContain("2001:db8", s, StringComparison.Ordinal);
        Assert.EndsWith("COMMIT\n", s, StringComparison.Ordinal);
    }

    [Fact]
    public void Iptables_v6_script_only_has_v6_targets()
    {
        var s = IptablesRuleset.Build([Rule], ipv6: true);
        Assert.Contains("-d 2001:db8::10 -p tcp", s, StringComparison.Ordinal);
        Assert.DoesNotContain("203.0.113.10", s, StringComparison.Ordinal);
    }

    [Fact]
    public void Iptables_skips_rule_whose_targets_are_all_other_family()
    {
        var v4only = Rule with { Targets = [IPAddress.Parse("198.51.100.1")] };
        var s = IptablesRuleset.Build([v4only], ipv6: true);
        Assert.DoesNotContain("NFQUEUE", s, StringComparison.Ordinal);
    }

    [Fact]
    public void Multiport_is_split_at_15_slots()
    {
        var ports = string.Join(',', Enumerable.Range(1, 20).Select(i => (i * 10).ToString(System.Globalization.CultureInfo.InvariantCulture))) + ",1000-2000";
        var chunks = IptablesRuleset.MultiportChunks(ports);
        Assert.Equal(2, chunks.Count);
        Assert.Equal(15, chunks[0].Split(',').Length);
        Assert.EndsWith("1000:2000", chunks[1], StringComparison.Ordinal);
    }

    [Fact]
    public void Iptables_script_is_accepted_by_iptables_restore_test_mode()
    {
        if (!Environment.IsPrivilegedProcess || !File.Exists("/usr/sbin/iptables-restore"))
            return; // needs root and iptables; CI runs it in the integration job
        foreach (var (tool, v6) in new[] { ("/usr/sbin/iptables-restore", false), ("/usr/sbin/ip6tables-restore", true) })
        {
            var psi = new ProcessStartInfo(tool, "--test --noflush") { RedirectStandardInput = true, RedirectStandardError = true, UseShellExecute = false };
            using var p = Process.Start(psi)!;
            p.StandardInput.Write(IptablesRuleset.Build([Rule], v6));
            p.StandardInput.Close();
            var err = p.StandardError.ReadToEnd();
            p.WaitForExit();
            Assert.True(p.ExitCode == 0, tool + ": " + err);
        }
    }

    [Theory]
    [InlineData("--user=root")]
    [InlineData("--uid=0")]
    [InlineData("--daemon")]
    [InlineData("--pidfile=/tmp/x")]
    [InlineData("--qnum=5")]
    [InlineData("--fwmark=0x1")]
    [InlineData("--debug=@/etc/shadow")]
    [InlineData("--writable=/etc")]
    [InlineData("--hostlist-auto=relative.txt")]
    [InlineData("--hostlist-auto=/data/../etc/passwd")]
    public void Policy_rejects(string opt)
    {
        var problems = EngineArgvPolicy.Check([opt, "--filter-tcp=443", "--lua-desync=fake:blob=fake_default_tls"], [Root]);
        Assert.Single(problems);
    }

    [Theory]
    [InlineData("--debug")]
    [InlineData("--debug=1")]
    [InlineData("--writable={root}/w")]
    [InlineData("--hostlist-auto={root}/auto.txt")]
    [InlineData("--debug=@{root}/log.txt")]
    public void Policy_allows(string opt)
    {
        Assert.Empty(EngineArgvPolicy.Check([opt.Replace("{root}", Root, StringComparison.Ordinal)], [Root]));
    }

    [Fact]
    public void Policy_lets_the_agent_add_managed_options()
    {
        Assert.Empty(EngineArgvPolicy.Check(["--qnum=300", "--fwmark=0x40000000"], [Root], managedAllowed: true));
    }

    [Fact]
    public void Policy_limits_blob_files_to_read_roots()
    {
        var engineDir = OperatingSystem.IsWindows() ? @"C:\app\zapret2" : "/app/zapret2";
        string P(string rel) => Path.Combine(engineDir, rel);
        Assert.Empty(EngineArgvPolicy.Check(["--blob=a:@" + P("files/fake/x.bin"), "--blob=b:0x1603", "--blob=c:+5@" + Path.Combine(Root, "c.bin")], [Root], [Root, engineDir]));
        Assert.Single(EngineArgvPolicy.Check(["--blob=a:@/etc/shadow"], [Root], [Root, engineDir]));
    }

    private static string Root => OperatingSystem.IsWindows() ? @"C:\data" : "/data";
}
