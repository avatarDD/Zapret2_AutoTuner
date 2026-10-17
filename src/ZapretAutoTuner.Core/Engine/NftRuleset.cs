using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Engine;

/// <summary>One queue binding: which traffic goes to which NFQUEUE.</summary>
public sealed record NftQueueRule
{
    public required int QueueNum { get; init; }

    public string TcpPorts { get; init; } = "";

    public string UdpPorts { get; init; } = "";

    /// <summary>Only packets to/from these addresses; empty — any address (protection mode).</summary>
    public IReadOnlyList<IPAddress> Targets { get; init; } = [];

    /// <summary>Also queue the first incoming packets (detectors, autottl, circular).</summary>
    public bool Incoming { get; init; }

    /// <summary>Outgoing packets per connection that reach the queue (zapret2: TCP 20, UDP 5).</summary>
    public int TcpOutPackets { get; init; } = 20;

    public int UdpOutPackets { get; init; } = 5;

    public int TcpInPackets { get; init; } = 10;

    public int UdpInPackets { get; init; } = 3;
}

/// <summary>
/// The nftables table AutoTuner owns on Linux (<c>inet ztuner</c>, nfqws2-engine §12). Rules follow zapret2's
/// common/nft.sh: postnat hook (priority 101) for outgoing, prerouting (-99) for incoming, <c>ct original/reply
/// packets</c> limits, and packets carrying the engine's fwmark skip the queue.
/// </summary>
public static class NftRuleset
{
    public const string Table = "ztuner";

    /// <summary>Script for <c>nft -f -</c> that (re)creates the table atomically.</summary>
    public static string Build(IReadOnlyList<NftQueueRule> rules, uint fwmark = 0x40000000)
    {
        var mark = "0x" + fwmark.ToString("X8", CultureInfo.InvariantCulture);
        var sb = new StringBuilder();
        // "add" then "delete" makes the script work whether or not the table exists
        sb.Append("add table inet ").Append(Table).Append('\n');
        sb.Append("delete table inet ").Append(Table).Append('\n');
        sb.Append("table inet ").Append(Table).Append(" {\n");
        for (int i = 0; i < rules.Count; i++)
        {
            var v4 = rules[i].Targets.Where(t => t.AddressFamily == AddressFamily.InterNetwork).Distinct().ToList();
            var v6 = rules[i].Targets.Where(t => t.AddressFamily == AddressFamily.InterNetworkV6).Distinct().ToList();
            if (v4.Count > 0)
                sb.Append($"  set t4_{i} {{ type ipv4_addr; elements = {{ {string.Join(", ", v4)} }} }}\n");
            if (v6.Count > 0)
                sb.Append($"  set t6_{i} {{ type ipv6_addr; elements = {{ {string.Join(", ", v6)} }} }}\n");
        }

        sb.Append("  chain post {\n    type filter hook postrouting priority 101; policy accept;\n");
        sb.Append($"    meta mark & {mark} == {mark} return\n");
        for (int i = 0; i < rules.Count; i++)
            AppendRules(sb, rules[i], i, outgoing: true);
        sb.Append("  }\n");

        if (rules.Any(r => r.Incoming))
        {
            sb.Append("  chain pre {\n    type filter hook prerouting priority -99; policy accept;\n");
            for (int i = 0; i < rules.Count; i++)
            {
                if (rules[i].Incoming)
                    AppendRules(sb, rules[i], i, outgoing: false);
            }
            sb.Append("  }\n");
        }
        sb.Append("}\n");
        return sb.ToString();
    }

    /// <summary>Script that removes the table; harmless if it does not exist.</summary>
    public static string BuildRemove() => $"add table inet {Table}\ndelete table inet {Table}\n";

    private static void AppendRules(StringBuilder sb, NftQueueRule r, int i, bool outgoing)
    {
        var addrMatches = new List<string>();
        var dir = outgoing ? "daddr" : "saddr";
        bool hasV4 = r.Targets.Any(t => t.AddressFamily == AddressFamily.InterNetwork);
        bool hasV6 = r.Targets.Any(t => t.AddressFamily == AddressFamily.InterNetworkV6);
        if (r.Targets.Count == 0)
            addrMatches.Add("");
        if (hasV4)
            addrMatches.Add($"ip {dir} @t4_{i} ");
        if (hasV6)
            addrMatches.Add($"ip6 {dir} @t6_{i} ");

        var portDir = outgoing ? "dport" : "sport";
        var ct = outgoing ? "ct original packets" : "ct reply packets";
        foreach (var addr in addrMatches)
        {
            if (r.TcpPorts.Length > 0)
            {
                int n = outgoing ? r.TcpOutPackets : r.TcpInPackets;
                sb.Append($"    {addr}tcp {portDir} {{ {NftPorts(r.TcpPorts)} }} {ct} 1-{n} queue num {r.QueueNum} bypass\n");
            }
            if (r.UdpPorts.Length > 0)
            {
                int n = outgoing ? r.UdpOutPackets : r.UdpInPackets;
                sb.Append($"    {addr}udp {portDir} {{ {NftPorts(r.UdpPorts)} }} {ct} 1-{n} queue num {r.QueueNum} bypass\n");
            }
        }
    }

    private static string NftPorts(string ports) => string.Join(", ", PortList.ParseRanges(ports).Select(p => p.From == p.To ? p.From.ToString(CultureInfo.InvariantCulture) : $"{p.From}-{p.To}"));

    /// <summary>sysctls the engine needs while the table is active (nfqws2-engine §12).</summary>
    public static IReadOnlyDictionary<string, string> RequiredSysctls { get; } = new Dictionary<string, string>
    {
        ["net/netfilter/nf_conntrack_tcp_be_liberal"] = "1",
        ["net/netfilter/nf_conntrack_checksum"] = "0",
    };
}
