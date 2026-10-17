using System.Globalization;
using System.Net.Sockets;
using System.Text;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Engine;

/// <summary>
/// iptables fallback for systems without nftables (nfqws2-engine §12). Mirrors zapret2's common/ipt.sh: own
/// chains in the mangle table, <c>connbytes</c> packet limits, <c>NFQUEUE --queue-bypass</c>, packets with the
/// engine's fwmark skip the queue. One script per address family, applied with <c>iptables-restore --noflush</c>;
/// the jumps from POSTROUTING/PREROUTING are managed separately (<see cref="JumpRules"/>).
/// </summary>
public static class IptablesRuleset
{
    public const string PostChain = "ztuner_post";
    public const string PreChain = "ztuner_pre";

    /// <summary>multiport accepts at most 15 ports, a range counts as two.</summary>
    public const int MultiportMax = 15;

    /// <summary>Restore script for one family (<paramref name="ipv6"/> selects ip6tables).</summary>
    public static string Build(IReadOnlyList<NftQueueRule> rules, bool ipv6, uint fwmark = 0x40000000)
    {
        var mark = "0x" + fwmark.ToString("X8", CultureInfo.InvariantCulture);
        var family = ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        var sb = new StringBuilder("*mangle\n");
        // declaring a chain in --noflush mode creates it or flushes it
        sb.Append(':').Append(PostChain).Append(" - [0:0]\n");
        sb.Append(':').Append(PreChain).Append(" - [0:0]\n");
        sb.Append($"-A {PostChain} -m mark --mark {mark}/{mark} -j RETURN\n");
        foreach (var r in rules)
        {
            // a rule limited to the other family's addresses has nothing to do here
            var targets = r.Targets.Where(t => t.AddressFamily == family).Distinct().Select(t => t.ToString()).ToList();
            if (r.Targets.Count > 0 && targets.Count == 0)
                continue;
            AppendRules(sb, r, targets, outgoing: true);
            if (r.Incoming)
                AppendRules(sb, r, targets, outgoing: false);
        }
        sb.Append("COMMIT\n");
        return sb.ToString();
    }

    private static void AppendRules(StringBuilder sb, NftQueueRule r, List<string> targets, bool outgoing)
    {
        var chain = outgoing ? PostChain : PreChain;
        var addrOpt = outgoing ? "-d" : "-s";
        var portOpt = outgoing ? "--dports" : "--sports";
        var dir = outgoing ? "original" : "reply";
        var addrs = targets.Count == 0 ? [""] : targets.Select(t => $"{addrOpt} {t} ").ToList();
        foreach (var (proto, ports, n) in new[]
        {
            ("tcp", r.TcpPorts, outgoing ? r.TcpOutPackets : r.TcpInPackets),
            ("udp", r.UdpPorts, outgoing ? r.UdpOutPackets : r.UdpInPackets),
        })
        {
            if (ports.Length == 0)
                continue;
            foreach (var chunk in MultiportChunks(ports))
            {
                foreach (var a in addrs)
                {
                    sb.Append($"-A {chain} {a}-p {proto} -m multiport {portOpt} {chunk} ")
                      .Append($"-m connbytes --connbytes-dir={dir} --connbytes-mode=packets --connbytes 1:{n} ")
                      .Append($"-j NFQUEUE --queue-num {r.QueueNum} --queue-bypass\n");
                }
            }
        }
    }

    /// <summary>Splits a port list into multiport arguments of at most 15 slots each (<c>80,443,1000:2000</c>).</summary>
    public static List<string> MultiportChunks(string ports)
    {
        var chunks = new List<string>();
        var cur = new List<string>();
        int slots = 0;
        foreach (var (from, to) in PortList.ParseRanges(ports))
        {
            int need = from == to ? 1 : 2;
            if (slots + need > MultiportMax)
            {
                chunks.Add(string.Join(',', cur));
                cur.Clear();
                slots = 0;
            }
            cur.Add(from == to ? from.ToString(CultureInfo.InvariantCulture) : $"{from}:{to}");
            slots += need;
        }
        if (cur.Count > 0)
            chunks.Add(string.Join(',', cur));
        return chunks;
    }

    /// <summary>The jumps from the built-in chains into ours, as iptables arguments after <c>-t mangle</c>.</summary>
    public static IReadOnlyList<(string Chain, string Target)> JumpRules { get; } =
    [
        ("POSTROUTING", PostChain),
        ("PREROUTING", PreChain),
    ];
}
