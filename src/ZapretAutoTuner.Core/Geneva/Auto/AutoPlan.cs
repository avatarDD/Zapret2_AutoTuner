using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Geneva.Auto;

/// <summary>
/// The traffic of one service that goes through geneva: its server addresses and ports, or (peer-to-peer) everything
/// the program sends from its local port. Nothing else reaches the queue.
/// </summary>
public sealed record AutoTarget
{
    public IReadOnlyList<IPAddress> Addresses { get; init; } = [];

    public string TcpPorts { get; init; } = "";

    public string UdpPorts { get; init; } = "";

    /// <summary>The ports are the program's local ports, not the servers'; <see cref="Addresses"/> is empty.</summary>
    public bool ByLocalPort { get; init; }
}

/// <summary>One strategy and the services it is applied to: one <c>geneva run</c> with its own queue.</summary>
public sealed record AutoGroup(string Strategy, IReadOnlyList<string> Services, IReadOnlyList<AutoTarget> Targets);

/// <summary>
/// One strategy applied by the site's name (geneva_c 2.0, <c>run --ext</c> profiles with host lists): every connection
/// to a listed name gets it, whatever address the CDN gave, so a new address works at once and sites behind one
/// address with different strategies do not share a group.
/// </summary>
public sealed record AutoHostProfile(string Strategy, bool Udp, IReadOnlyList<string> Domains, IReadOnlyList<string> Services);

/// <summary>Turns the book into what the Agent applies (skill <c>geneva</c>, §9).</summary>
public static class AutoPlan
{
    /// <summary>
    /// The groups: the active services by strategy, the biggest groups first, at most <see cref="AutoRules.MaxGroups"/>.
    /// <paramref name="trial"/> adds a strategy being tried on one service (the quick check of known strategies).
    /// </summary>
    /// <para><paramref name="byName"/>: the sites the running name-based process covers (<see cref="ByNameCovers"/>). An
    /// address that such sites with different strategies share goes to no group: the name decides which strategy its
    /// connection gets. A site it does not cover (no process, a port it does not catch) keeps its addresses.</para>
    public static List<AutoGroup> Groups(IEnumerable<AutoService> services, (AutoService Service, string Strategy)? trial = null,
        IReadOnlySet<string>? byName = null)
    {
        var active = services.Where(s => s.IsActive && (trial is null || s.Key != trial.Value.Service.Key))
            .Select(s => (Service: s, Strategy: s.Strategy!)).ToList();
        if (trial is { } tried)
            active.Add((tried.Service, tried.Strategy));
        HashSet<string> shared = [];
        if (byName is { Count: > 0 })
        {
            bool Named((AutoService Service, string Strategy) x) => x.Service.Kind == AutoKind.Web
                && (trial is null || x.Service.Key != trial.Value.Service.Key) && byName.Contains(x.Service.Key);
            // an address is left to the names only when every active service on it is a site the names cover
            var uncovered = active.Where(x => !Named(x)).SelectMany(x => x.Service.Addresses.Select(a => a.Ip)).ToHashSet(StringComparer.Ordinal);
            shared = [.. active.Where(Named)
                .SelectMany(x => x.Service.Addresses.Select(a => (a.Ip, x.Strategy)))
                .Where(x => !uncovered.Contains(x.Ip))
                .GroupBy(x => x.Ip, StringComparer.Ordinal)
                .Where(g => g.Select(x => x.Strategy).Distinct(StringComparer.Ordinal).Count() > 1)
                .Select(g => g.Key)];
            if (shared.Count > 0)
            {
                active = [.. active.Select(x => !Named(x) ? x : (Service: Without(x.Service, shared), x.Strategy))];
            }
        }
        var ordered = active
            .GroupBy(x => x.Strategy, StringComparer.Ordinal)
            .Select(g => new AutoGroup(g.Key, [.. g.Select(x => x.Service.Key)], [.. g.Select(x => Target(x.Service)).Where(x => x is not null).Select(x => x!)]))
            .Where(g => g.Targets.Count > 0)
            // the tried strategy always gets its group: it is what is being checked
            .OrderByDescending(g => trial is not null && g.Strategy == trial.Value.Strategy && g.Services.Contains(trial.Value.Service.Key))
            .ThenByDescending(g => g.Services.Count)
            .ThenBy(g => g.Strategy, StringComparer.Ordinal);
        // One packet meets one strategy: two sites behind one CDN address would otherwise queue the same packets to two
        // groups, and which one gets them would depend on the rules' order (Linux) or on WinDivert (Windows). An
        // address and transport (or a local port) belongs to the first group that names it.
        var claimed = new HashSet<(string Proto, IPAddress Address)>();
        var claimedPorts = new HashSet<(string Proto, string Ports)>();
        var result = new List<AutoGroup>();
        foreach (var g in ordered)
        {
            var targets = new List<AutoTarget>();
            foreach (var t in g.Targets)
            {
                if (t.ByLocalPort)
                {
                    var tcp = t.TcpPorts.Length > 0 && claimedPorts.Add(("tcp", t.TcpPorts)) ? t.TcpPorts : "";
                    var udp = t.UdpPorts.Length > 0 && claimedPorts.Add(("udp", t.UdpPorts)) ? t.UdpPorts : "";
                    if (tcp.Length > 0 || udp.Length > 0)
                        targets.Add(t with { TcpPorts = tcp, UdpPorts = udp });
                    continue;
                }
                List<IPAddress> Free(string proto, string ports) =>
                    ports.Length == 0 ? [] : [.. t.Addresses.Distinct().Where(a => !claimed.Contains((proto, a)))];
                var tcpFree = Free("tcp", t.TcpPorts);
                var udpFree = Free("udp", t.UdpPorts);
                if (tcpFree.Count > 0 && tcpFree.SequenceEqual(udpFree))
                {
                    targets.Add(t with { Addresses = tcpFree });
                    continue;
                }
                if (tcpFree.Count > 0)
                    targets.Add(new AutoTarget { Addresses = tcpFree, TcpPorts = t.TcpPorts });
                if (udpFree.Count > 0)
                    targets.Add(new AutoTarget { Addresses = udpFree, UdpPorts = t.UdpPorts });
            }
            if (targets.Count == 0)
                continue;
            foreach (var t in targets.Where(t => !t.ByLocalPort))
            {
                foreach (var a in t.Addresses)
                {
                    if (t.TcpPorts.Length > 0)
                        claimed.Add(("tcp", a));
                    if (t.UdpPorts.Length > 0)
                        claimed.Add(("udp", a));
                }
            }
            result.Add(g with { Targets = targets });
            if (result.Count == AutoRules.MaxGroups)
                break;
        }
        return result;
    }

    private static AutoService Without(AutoService s, HashSet<string> addresses)
    {
        var c = s.Clone();
        c.Addresses.RemoveAll(a => addresses.Contains(a.Ip));
        return c;
    }

    /// <summary>
    /// The strategies applied by name: one profile per strategy and transport of the applied sites (and QUIC with
    /// <paramref name="quic"/>), each with the sites' domains. A site's family (<see cref="AutoFamilies"/>) joins its
    /// profile, unless a member has its own life in the book (its own strategy, a probe or search under way): YouTube's
    /// videos get the site's strategy before they ever fail. The service on trial is left out (its address group
    /// decides); a domain belongs to the first profile that names it; at most <see cref="AutoRules.MaxHostProfiles"/>.
    /// </summary>
    public static List<AutoHostProfile> HostProfiles(IEnumerable<AutoService> services, string? trialKey = null, bool quic = false, bool families = true)
    {
        var all = services.ToList();
        var busy = all.Where(s => s.Kind is AutoKind.Web or AutoKind.Quic
                && (s.IsActive || s.Status is AutoStatus.Searching or AutoStatus.Blocked or AutoStatus.Suspected or AutoStatus.NotFound or AutoStatus.Degraded))
            .Select(s => (Site: AutoFamilies.SiteOf(s), Udp: s.Kind == AutoKind.Quic))
            .ToHashSet();
        var active = all.Where(s => s.IsActive && s.Key != trialKey && (s.Kind == AutoKind.Web || (quic && s.Kind == AutoKind.Quic)))
            .GroupBy(s => (s.Strategy!, Udp: s.Kind == AutoKind.Quic))
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key.Item1, StringComparer.Ordinal)
            .ToList();
        var claimed = new HashSet<(string, bool)>();
        var result = new List<AutoHostProfile>();
        foreach (var g in active)
        {
            var udp = g.Key.Udp;
            var domains = new List<string>();
            foreach (var s in g.OrderBy(x => x.Key, StringComparer.Ordinal))
            {
                var site = AutoFamilies.SiteOf(s);
                if (claimed.Add((site, udp)))
                    domains.Add(site);
            }
            if (families)
            {
                foreach (var family in g.Select(AutoFamilies.Of).Where(f => f is not null).Distinct(StringComparer.Ordinal))
                {
                    foreach (var d in AutoFamilies.Domains(family!))
                    {
                        if (!busy.Contains((d, udp)) && claimed.Add((d, udp)))
                            domains.Add(d);
                    }
                }
            }
            if (domains.Count == 0)
                continue;
            result.Add(new AutoHostProfile(g.Key.Item1, udp, domains, [.. g.Select(x => x.Key)]));
            if (result.Count == AutoRules.MaxHostProfiles)
                break;
        }
        return result;
    }

    /// <summary>
    /// The sites the name-based process covers: those named in <paramref name="profiles"/> whose ports are all ones it
    /// catches (<see cref="AutoRules.HostTcpPorts"/>).
    /// </summary>
    public static HashSet<string> ByNameCovers(IEnumerable<AutoService> services, IEnumerable<AutoHostProfile> profiles)
    {
        var named = profiles.Where(p => !p.Udp).SelectMany(p => p.Services).ToHashSet(StringComparer.Ordinal);
        var ports = AutoRules.HostTcpPorts.Split(',').Select(p => int.Parse(p, CultureInfo.InvariantCulture)).ToHashSet();
        return [.. services.Where(s => s.Kind == AutoKind.Web && named.Contains(s.Key) && s.Ports.All(ports.Contains)).Select(s => s.Key)];
    }

    /// <summary>The traffic of one service; null when nothing is known to aim at (no address seen).</summary>
    public static AutoTarget? Target(AutoService s)
    {
        string Ports(int fallback) => s.Ports.Count > 0
            ? PortList.Format(PortList.Merge(s.Ports.Select(p => (p, p)).ToList()))
            : fallback.ToString(CultureInfo.InvariantCulture);
        if (s.Kind == AutoKind.LocalPort)
        {
            if (s.LocalPort is < 1 or > 65535)
                return null;
            var lp = s.LocalPort.ToString(CultureInfo.InvariantCulture);
            return new AutoTarget { ByLocalPort = true, TcpPorts = s.Transport == L4Kind.Tcp ? lp : "", UdpPorts = s.Transport == L4Kind.Udp ? lp : "" };
        }
        var addresses = s.Addresses.Select(a => IPAddress.TryParse(a.Ip, out var ip) ? ip : null).Where(a => a is not null).Select(a => a!).ToList();
        if (addresses.Count == 0)
            return null;
        return s.Kind switch
        {
            // a resolver is asked over UDP, and over TCP for big answers
            AutoKind.Dns => new AutoTarget { Addresses = addresses, TcpPorts = "53", UdpPorts = "53" },
            AutoKind.Web => new AutoTarget { Addresses = addresses, TcpPorts = Ports(443) },
            AutoKind.Quic => new AutoTarget { Addresses = addresses, UdpPorts = Ports(443) },
            _ when s.Transport == L4Kind.Udp => new AutoTarget { Addresses = addresses, UdpPorts = Ports(s.Port) },
            _ => new AutoTarget { Addresses = addresses, TcpPorts = Ports(s.Port) },
        };
    }

    /// <summary>
    /// The WinDivert filter of a group (geneva_c's <c>--filter</c>, Windows): outgoing packets to the targets and the
    /// answers from them. The groups' filters do not overlap, so several <c>geneva run</c> work side by side.
    /// </summary>
    public static string WinDivertFilter(IEnumerable<AutoTarget> targets)
    {
        var outs = new List<string>();
        var ins = new List<string>();
        foreach (var t in targets)
        {
            foreach (var (proto, ports) in new[] { ("tcp", t.TcpPorts), ("udp", t.UdpPorts) })
            {
                if (ports.Length == 0)
                    continue;
                if (t.ByLocalPort)
                {
                    outs.Add($"({proto} and {PortMatch(proto + ".SrcPort", ports)})");
                    ins.Add($"({proto} and {PortMatch(proto + ".DstPort", ports)})");
                    continue;
                }
                foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
                {
                    var list = t.Addresses.Where(a => a.AddressFamily == family).Distinct().ToList();
                    if (list.Count == 0)
                        continue;
                    var ip = family == AddressFamily.InterNetwork ? "ip" : "ipv6";
                    outs.Add($"({proto} and {AddrMatch(ip + ".DstAddr", list)} and {PortMatch(proto + ".DstPort", ports)})");
                    ins.Add($"({proto} and {AddrMatch(ip + ".SrcAddr", list)} and {PortMatch(proto + ".SrcPort", ports)})");
                }
            }
        }
        if (outs.Count == 0)
            return "false";
        return $"(outbound and ({string.Join(" or ", outs)})) or (inbound and ({string.Join(" or ", ins)}))";
    }

    private static string AddrMatch(string field, IReadOnlyList<IPAddress> list) =>
        list.Count == 1 ? $"{field} == {list[0]}" : "(" + string.Join(" or ", list.Select(a => $"{field} == {a}")) + ")";

    private static string PortMatch(string field, string ports)
    {
        var parts = PortList.ParseRanges(ports).Select(r => r.From == r.To
            ? $"{field} == {r.From.ToString(CultureInfo.InvariantCulture)}"
            : $"({field} >= {r.From.ToString(CultureInfo.InvariantCulture)} and {field} <= {r.To.ToString(CultureInfo.InvariantCulture)})").ToList();
        return parts.Count == 1 ? parts[0] : "(" + string.Join(" or ", parts) + ")";
    }

    /// <summary>A short description of a target for the log and the page.</summary>
    public static string Describe(AutoTarget t)
    {
        var sb = new StringBuilder();
        if (t.ByLocalPort)
            sb.Append("локальный порт ");
        else
            sb.Append(string.Join(", ", t.Addresses.Take(3))).Append(t.Addresses.Count > 3 ? $" (+{t.Addresses.Count - 3})" : "").Append(' ');
        if (t.TcpPorts.Length > 0)
            sb.Append("tcp ").Append(t.TcpPorts).Append(' ');
        if (t.UdpPorts.Length > 0)
            sb.Append("udp ").Append(t.UdpPorts);
        return sb.ToString().Trim();
    }
}

/// <summary>
/// The strategies the quick check tries before geneva's search: the ones already working for other services, then
/// classic Geneva strategies for the transport (each passes <c>geneva check</c>: tests and the Agent).
/// </summary>
public static class AutoCandidates
{
    /// <summary>TCP: segmentation, fakes with a broken checksum or a low TTL, a RST that the server drops (Geneva's library).</summary>
    public static IReadOnlyList<string> Tcp { get; } =
    [
        @"[TCP:flags:PA]-fragment{tcp:-1:True}-| \/",
        @"[TCP:flags:PA]-fragment{tcp:8:True}-| \/",
        @"[TCP:flags:PA]-fragment{tcp:-1:False}-| \/",
        @"[TCP:flags:PA]-duplicate(tamper{TCP:chksum:corrupt},)-| \/",
        @"[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:4},)-| \/",
        @"[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/",
        @"[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/",
        // Windows sends its SYN as SEC (ECN): both forms
        @"[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:SA},)-| [TCP:flags:SEC]-duplicate(tamper{TCP:flags:replace:SA},)-| \/",
        @"[TCP:flags:PA]-fragment{ip:-1:True}-| \/",
    ];

    /// <summary>UDP: a junk or broken copy before the real datagram (what DPI sees first), IP fragmentation.</summary>
    public static IReadOnlyList<string> Udp { get; } =
    [
        @"[UDP:sport:*]-duplicate(tamper{UDP:load:corrupt},)-| \/",
        @"[UDP:sport:*]-duplicate(tamper{UDP:chksum:corrupt},)-| \/",
        @"[UDP:sport:*]-duplicate(tamper{IP:ttl:replace:3},)-| \/",
        @"[UDP:sport:*]-fragment{ip:-1:True}-| \/",
        @"[UDP:sport:*]-fragment{ip:-1:False}-| \/",
        @"[UDP:sport:*]-duplicate(tamper{UDP:load:corrupt}(duplicate,),)-| \/",
    ];

    /// <summary>
    /// zapret2's working methods as geneva_c 2.0 x-actions (<c>--ext</c>): splits and disorders at the SNI, fakes with
    /// a low or automatic TTL, MD5 or a broken checksum, a fake host, a split TLS record. They act on the ClientHello
    /// only (the default <c>payload=known</c>), whole even when the browser sends it in two packets.
    /// </summary>
    public static IReadOnlyList<string> XTcp { get; } =
    [
        @"[TCP:flags:PA]-xdisorder{pos=1,midsld}-| \/",
        @"[TCP:flags:PA]-xsplit{pos=1,midsld}-| \/",
        @"[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=auto:-2:3-20}(xdisorder{pos=1,midsld},)-| \/",
        @"[TCP:flags:PA]-xfake{blob=fake_default_tls;md5}(xsplit{pos=1,midsld},)-| \/",
        @"[TCP:flags:PA]-xfake{blob=fake_default_tls;badsum;tlsmod=rnd,rndsni,dupsid}(xsplit{pos=midsld},)-| \/",
        @"[TCP:flags:PA]-xfakedsplit{pos=midsld;ttl=4}-| \/",
        @"[TCP:flags:PA]-xhostfake{ttl=auto:-2:3-20}-| \/",
        @"[TCP:flags:PA]-xtlsrec{pos=sniext+1}-| \/",
        @"[TCP:flags:PA]-xsplit{pos=sniext+1}-| \/",
        @"[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=4;repeats=2}(xdisorder{pos=midsld},)-| \/",
    ];

    /// <summary>QUIC as zapret2 does it: fake Initials before the real one, the Initial in IP fragments.</summary>
    public static IReadOnlyList<string> XQuic { get; } =
    [
        @"[UDP:dport:443]-xfake{blob=fake_quic_initial;repeats=6;ttl=4}-| \/",
        @"[UDP:dport:443]-xfake{blob=fake_default_quic;repeats=6;badsum}-| \/",
        @"[UDP:dport:443]-xsend{ipfrag;ipfrag_pos_udp=8}-| \/",
    ];

    /// <summary>DNS: Geneva's question compression, then the UDP tricks.</summary>
    public static IReadOnlyList<string> Dns { get; } =
    [
        @"[UDP:dport:53]-tamper{DNS:qd:compress}-| \/",
        @"[UDP:dport:53]-duplicate(tamper{UDP:chksum:corrupt},)-| \/",
    ];

    /// <summary>
    /// What to try on <paramref name="s"/>: shared strategies (imported, or the program's starting set) that name this
    /// service first, then the strategies of the running groups of its transport (so it joins a group instead of
    /// opening a new one), the ones found before, the other shared ones, the classics and <paramref name="extra"/>
    /// (Geneva's library on a wider round), at most <paramref name="max"/>.
    /// </summary>
    /// <para><paramref name="family"/>: the strategy working for another member of the service's family, tried first.
    /// <paramref name="ext"/>: geneva_c knows x-actions (2.0): zapret2's methods follow the classics (sites and QUIC),
    /// beyond <paramref name="max"/>.</para>
    public static List<string> For(AutoService s, IEnumerable<string> running, IEnumerable<string> found,
        IEnumerable<GenevaSharedStrategy>? shared = null, IEnumerable<string>? extra = null, int max = AutoRules.MaxQuickCandidates,
        string? family = null, bool ext = false)
    {
        var classics = s.Kind == AutoKind.Dns ? [.. Dns, .. Udp] : s.Transport == L4Kind.Udp ? Udp : Tcp;
        IReadOnlyList<string> xs = !ext ? [] : s.Kind == AutoKind.Quic ? XQuic : s.Kind == AutoKind.Web || (s.Transport == L4Kind.Tcp && s.App == "tls") ? XTcp : [];
        var sharedList = (shared ?? []).ToList();
        var named = sharedList.Where(x => GenevaShare.Names(x, s.Name, s.Host)).Select(x => x.Strategy);
        var others = sharedList.Select(x => x.Strategy).Where(x => Fits(s, x));
        // the shared strategies were found for sites and QUIC; a resolver tries its own classics before them
        var head = (family is null ? [] : new[] { family }).Where(c => Fits(s, c))
            .Concat(named.Where(c => Fits(s, c)))
            .Concat(running.Where(c => Fits(s, c)))
            .Concat(found.Where(c => Fits(s, c)))
            .Concat(s.Kind == AutoKind.Dns ? classics.Concat(others) : others.Concat(classics))
            .Where(c => GenevaStrategyText.Problem(c) is null && (ext || !GenevaStrategyText.NeedsExt(c)))
            .Distinct(StringComparer.Ordinal)
            .Take(max)
            .ToList();
        var rest = xs.Concat((extra ?? []).Where(c => Fits(s, c)))
            .Where(c => GenevaStrategyText.Problem(c) is null && (ext || !GenevaStrategyText.NeedsExt(c)) && !head.Contains(c, StringComparer.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .Take(max + xs.Count - Math.Min(head.Count, max));
        return [.. head, .. rest];
    }

    /// <summary>A strategy that can act on the service's packets: TCP trees for TCP, UDP (or DNS, IP) trees for UDP.</summary>
    public static bool Fits(AutoService s, string strategy) => s.Transport == L4Kind.Udp
        ? strategy.Contains("[UDP:", StringComparison.OrdinalIgnoreCase) || strategy.Contains("[IP:", StringComparison.OrdinalIgnoreCase) || strategy.Contains("[DNS", StringComparison.OrdinalIgnoreCase)
        : strategy.Contains("[TCP:", StringComparison.OrdinalIgnoreCase) || strategy.Contains("[IP:", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// geneva's search space for the service (<c>--protos</c>). <paramref name="wide"/>: the wider search after the
    /// usual one found nothing twice; a site's search may then change IP headers too (fragments, TTL, options).
    /// </summary>
    public static string Protos(AutoService s, bool wide = false) =>
        s.Kind == AutoKind.Dns ? "UDP,IP,DNS,DNSQR" : s.Transport == L4Kind.Udp ? "UDP,IP" : wide ? "TCP,IP" : "TCP";
}
