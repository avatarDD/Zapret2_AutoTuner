using System.Net;
using System.Net.Sockets;

namespace ZapretAutoTuner.Probes.Dns;

/// <summary>
/// Decides <c>DNS_POISON</c> (dpi-diagnostics §2.1) from the resolver answers. DoH is the reference: it cannot be
/// replaced on path. CDNs legitimately answer differently per resolver (geo DNS, ECS, ISP caches such as Google GGC
/// inside the ISP), so a mere difference is never enough for "poisoned".
/// <list type="number">
/// <item><b>Trusted set</b> = union of DoH addresses, minus stub/sinkhole and block-page addresses. A DoH answer that
/// only had such addresses counts as filtered (<c>DOH_FILTERED</c>, info) and adds nothing.</item>
/// <item><c>SYSTEM_SINKHOLE</c> / <c>SYSTEM_BLOCK_PAGE</c> → <b>Poisoned</b>: the system answer has a loopback,
/// unspecified, private, CGNAT or link-local address, or a known ISP block-page IP — unless every DoH answer has the
/// same address (the name genuinely points there). Needs no DoH at all.</item>
/// <item><c>SYSTEM_NO_ANSWER</c> → <b>Poisoned</b>: the system says NXDOMAIN or has no addresses while the trusted
/// set is not empty.</item>
/// <item>System and trusted sets intersect → <c>SYSTEM_MATCH</c>, clean.</item>
/// <item>Disjoint, but every system address shares a /24 (IPv4) or /48 (IPv6) with a trusted address →
/// <c>SYSTEM_RELATED</c>, clean (same CDN cluster).</item>
/// <item>Disjoint and unrelated → <c>SYSTEM_DISJOINT</c>, <b>Suspicious</b>, except: the plain UDP answer of an operator
/// agrees with the system (shared address or prefix) while the DoH answer of the <i>same operator</i> (same name in
/// the resolver list, e.g. Google UDP 8.8.8.8 vs Google DoH) is disjoint and unrelated to it. The same backend
/// answering differently only over the unencrypted transport means on-path spoofing → <c>ON_PATH_SPOOF</c>,
/// <b>Poisoned</b>.</item>
/// <item>Without the system involved: a public UDP answer with a sinkhole address (<c>UDP_SINKHOLE</c>) or a UDP/DoH
/// operator pair that disagrees (<c>UDP_SPOOFED</c>) → Suspicious: plain DNS is intercepted on path, which matters
/// for routers that use plain DNS.</item>
/// <item>System fails (timeout, error, SERVFAIL) while DoH works → <c>SYSTEM_FAILED</c>, Suspicious. DoH says
/// NXDOMAIN while the system has addresses → <c>SYSTEM_INVENTED</c>, Suspicious (NXDOMAIN rewriting). All agree on
/// NXDOMAIN → <c>NOT_EXIST</c>, clean.</item>
/// <item>No usable DoH answer and nothing conclusive → <b>Unknown</b> (<c>DOH_UNAVAILABLE</c>).</item>
/// </list>
/// The verdict is the worst severity among the findings; Clean needs a successful comparison, otherwise Unknown.
/// </summary>
public static class DnsVerdictRules
{
    public static DnsVerdict Evaluate(IReadOnlyList<DnsResolverAnswer> answers, DnsResolverCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(answers);
        ArgumentNullException.ThrowIfNull(catalog);
        var findings = new List<DnsFinding>();
        bool compared = false;

        var system = answers.FirstOrDefault(a => a.Kind == DnsResolverKind.System);
        var doh = answers.Where(a => a.Kind == DnsResolverKind.Doh).ToList();
        var udp = answers.Where(a => a.Kind == DnsResolverKind.Udp).ToList();

        bool IsStub(IPAddress a) => catalog.IsSinkhole(a, out _) || catalog.IsBlockPage(a, out _);

        // 1. trusted set
        var trusted = new List<IPAddress>();
        foreach (var d in doh.Where(d => d.HasAddresses))
        {
            var good = d.Addresses.Where(a => !IsStub(a)).ToList();
            if (good.Count == 0)
            {
                findings.Add(new DnsFinding("DOH_FILTERED", DnsFindingSeverity.Info,
                    $"{d.Resolver} (DoH) вернул заглушку — ответ не учитывается",
                    $"{d.Resolver} (DoH) returned a stub address; its answer is ignored",
                    [Describe(d)]));
                continue;
            }
            foreach (var a in good)
            {
                if (!trusted.Contains(a))
                    trusted.Add(a);
            }
        }
        var dohOk = doh.Where(d => d.HasAddresses).ToList();
        bool dohNx = doh.Any(d => d.Status == DnsAnswerStatus.NxDomain) && dohOk.Count == 0;

        // 2. stubs and block pages in the system answer
        if (system is { HasAddresses: true })
        {
            var sink = new List<string>();
            var block = new List<string>();
            foreach (var a in system.Addresses)
            {
                if (dohOk.Count > 0 && dohOk.All(d => d.Addresses.Contains(a)))
                    continue; // the name genuinely points there
                if (catalog.IsBlockPage(a, out var isp))
                    block.Add($"{a} ({isp})");
                else if (catalog.IsSinkhole(a, out var note))
                    sink.Add($"{a} ({note})");
            }
            if (block.Count > 0)
            {
                findings.Add(new DnsFinding("SYSTEM_BLOCK_PAGE", DnsFindingSeverity.Poison,
                    "Системный DNS вернул адрес страницы блокировки провайдера",
                    "System DNS returned an ISP block-page address",
                    block));
            }
            if (sink.Count > 0)
            {
                findings.Add(new DnsFinding("SYSTEM_SINKHOLE", DnsFindingSeverity.Poison,
                    "Системный DNS вернул адрес-заглушку (локальный или частный адрес)",
                    "System DNS returned a stub address (loopback, private or unspecified)",
                    sink));
            }
        }

        // 3–6. compare the system answer with the trusted set
        if (system is not null && trusted.Count > 0)
        {
            switch (system.Status)
            {
                case DnsAnswerStatus.NxDomain or DnsAnswerStatus.NoData:
                    compared = true;
                    findings.Add(new DnsFinding("SYSTEM_NO_ANSWER", DnsFindingSeverity.Poison,
                        system.Status == DnsAnswerStatus.NxDomain
                            ? "Системный DNS говорит, что домена нет (NXDOMAIN), а DoH возвращает адреса"
                            : "Системный DNS не вернул адресов, а DoH возвращает адреса",
                        system.Status == DnsAnswerStatus.NxDomain
                            ? "System DNS says the domain does not exist (NXDOMAIN) while DoH returns addresses"
                            : "System DNS returned no addresses while DoH does",
                        [Describe(system), .. dohOk.Select(Describe)]));
                    break;
                case DnsAnswerStatus.Ok when system.HasAddresses:
                    compared = true;
                    CompareSystem(system, trusted, udp, dohOk, findings);
                    break;
                default:
                    findings.Add(new DnsFinding("SYSTEM_FAILED", DnsFindingSeverity.Suspicious,
                        "Системный DNS не ответил или вернул ошибку, а DoH работает",
                        "System DNS failed or timed out while DoH works",
                        [Describe(system)]));
                    break;
            }
        }
        else if (system is not null && dohNx)
        {
            compared = true;
            if (system.HasAddresses)
            {
                findings.Add(new DnsFinding("SYSTEM_INVENTED", DnsFindingSeverity.Suspicious,
                    "DoH говорит, что домена нет, а системный DNS возвращает адреса (подмена NXDOMAIN)",
                    "DoH says the domain does not exist while system DNS returns addresses (NXDOMAIN rewriting)",
                    [Describe(system)]));
            }
            else if (system.Status == DnsAnswerStatus.NxDomain)
            {
                findings.Add(new DnsFinding("NOT_EXIST", DnsFindingSeverity.Info,
                    "Домен не существует (NXDOMAIN и в системном DNS, и в DoH)",
                    "The domain does not exist (NXDOMAIN in both system DNS and DoH)",
                    []));
            }
        }

        // 7. plain UDP interception, independent of the system answer
        foreach (var u in udp.Where(u => u.HasAddresses))
        {
            var stubs = u.Addresses.Where(a => IsStub(a) && !dohOk.Any(d => d.Addresses.Contains(a))).ToList();
            if (stubs.Count > 0)
            {
                findings.Add(new DnsFinding("UDP_SINKHOLE", DnsFindingSeverity.Suspicious,
                    $"Открытый DNS {u.Resolver} (UDP 53) вернул заглушку: незашифрованный DNS подменяется по пути",
                    $"Plain DNS {u.Resolver} (UDP 53) returned a stub address: unencrypted DNS is replaced on path",
                    [.. stubs.Select(a => a.ToString())]));
            }
        }
        if (!findings.Any(f => f.Code == "ON_PATH_SPOOF"))
        {
            foreach (var (u, d) in OperatorPairs(udp, dohOk))
            {
                if (!Agrees(u.Addresses, d.Addresses))
                {
                    findings.Add(new DnsFinding("UDP_SPOOFED", DnsFindingSeverity.Suspicious,
                        $"{u.Resolver}: ответы по UDP 53 и по DoH не совпадают — возможна подмена незашифрованного DNS",
                        $"{u.Resolver}: UDP 53 and DoH answers differ; unencrypted DNS may be spoofed on path",
                        [Describe(u), Describe(d)]));
                }
            }
        }

        if (trusted.Count == 0 && !dohNx)
        {
            findings.Add(new DnsFinding("DOH_UNAVAILABLE", DnsFindingSeverity.Info,
                "Ни один DoH-резолвер не дал адресов — сравнивать не с чем",
                "No DoH resolver returned addresses; nothing to compare with",
                [.. doh.Select(Describe)]));
        }

        var worst = findings.Count == 0 ? DnsFindingSeverity.Info : findings.Max(f => f.Severity);
        var kind = worst switch
        {
            DnsFindingSeverity.Poison => DnsVerdictKind.Poisoned,
            DnsFindingSeverity.Suspicious => DnsVerdictKind.Suspicious,
            _ => compared ? DnsVerdictKind.Clean : DnsVerdictKind.Unknown,
        };
        return new DnsVerdict { Kind = kind, Reasons = findings };
    }

    private static void CompareSystem(DnsResolverAnswer system, List<IPAddress> trusted, List<DnsResolverAnswer> udp, List<DnsResolverAnswer> dohOk, List<DnsFinding> findings)
    {
        var sys = system.Addresses;
        if (sys.Any(trusted.Contains))
        {
            findings.Add(new DnsFinding("SYSTEM_MATCH", DnsFindingSeverity.Info,
                "Системный DNS совпадает с DoH",
                "System DNS agrees with DoH",
                [.. sys.Where(trusted.Contains).Select(a => a.ToString())]));
            return;
        }
        if (sys.All(a => trusted.Any(t => SamePrefix(a, t))))
        {
            findings.Add(new DnsFinding("SYSTEM_RELATED", DnsFindingSeverity.Info,
                "Адреса системного DNS отличаются от DoH, но из тех же сетей (/24, /48) — обычное поведение CDN",
                "System DNS addresses differ from DoH but are in the same /24 or /48 networks (normal CDN behaviour)",
                [Describe(system), "DoH: " + string.Join(", ", trusted)]));
            return;
        }
        foreach (var (u, d) in OperatorPairs(udp, dohOk))
        {
            if (Agrees(u.Addresses, sys) && !Agrees(u.Addresses, d.Addresses))
            {
                findings.Add(new DnsFinding("ON_PATH_SPOOF", DnsFindingSeverity.Poison,
                    $"{u.Resolver} по UDP 53 отвечает как системный DNS, а тот же {d.Resolver} по DoH — иначе: ответы подменяются по пути",
                    $"{u.Resolver} over UDP 53 answers like system DNS while the same {d.Resolver} over DoH differs: answers are spoofed on path",
                    [Describe(system), Describe(u), Describe(d)]));
                return;
            }
        }
        findings.Add(new DnsFinding("SYSTEM_DISJOINT", DnsFindingSeverity.Suspicious,
            "Адреса системного DNS не пересекаются с DoH и из других сетей. Это может быть CDN, а может быть подмена — проверьте по адресам DoH",
            "System DNS addresses do not overlap DoH and are in other networks. It may be a CDN or a spoof; test the DoH addresses too",
            [Describe(system), "DoH: " + string.Join(", ", trusted)]));
    }

    /// <summary>Same operator reached over UDP 53 and DoH (matched by resolver name), both with addresses.</summary>
    private static IEnumerable<(DnsResolverAnswer Udp, DnsResolverAnswer Doh)> OperatorPairs(List<DnsResolverAnswer> udp, List<DnsResolverAnswer> dohOk)
    {
        foreach (var u in udp.Where(u => u.HasAddresses))
        {
            var d = dohOk.FirstOrDefault(d => string.Equals(d.Resolver, u.Resolver, StringComparison.OrdinalIgnoreCase));
            if (d is not null)
                yield return (u, d);
        }
    }

    /// <summary>Two answers agree when they share an address or every address of <paramref name="a"/> shares a prefix with <paramref name="b"/>.</summary>
    internal static bool Agrees(IReadOnlyList<IPAddress> a, IReadOnlyList<IPAddress> b) =>
        a.Any(b.Contains) || (a.Count > 0 && a.All(x => b.Any(y => SamePrefix(x, y))));

    /// <summary>Same /24 for IPv4, same /48 for IPv6.</summary>
    internal static bool SamePrefix(IPAddress a, IPAddress b)
    {
        a = DnsResolverCatalog.Normalize(a);
        b = DnsResolverCatalog.Normalize(b);
        if (a.AddressFamily != b.AddressFamily)
            return false;
        int bytes = a.AddressFamily == AddressFamily.InterNetwork ? 3 : 6;
        Span<byte> x = stackalloc byte[16], y = stackalloc byte[16];
        a.TryWriteBytes(x, out _);
        b.TryWriteBytes(y, out _);
        return x[..bytes].SequenceEqual(y[..bytes]);
    }

    private static string Describe(DnsResolverAnswer a) => a.Status == DnsAnswerStatus.Ok
        ? $"{a.Resolver} [{a.Kind}]: {string.Join(", ", a.Addresses)}"
        : $"{a.Resolver} [{a.Kind}]: {a.Status}{(a.Error is null ? "" : " — " + a.Error)}";
}
