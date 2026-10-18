using System.Net;
using ZapretAutoTuner.Core.Dns;

namespace ZapretAutoTuner.Probes.Dns;

/// <summary>Outcome of asking one resolver for A (and AAAA).</summary>
public enum DnsAnswerStatus
{
    /// <summary>At least one address.</summary>
    Ok,

    /// <summary>NOERROR without addresses (or the OS reported "no data").</summary>
    NoData,

    NxDomain,

    /// <summary>SERVFAIL, REFUSED or another error RCODE.</summary>
    ServerError,

    Timeout,

    /// <summary>Network, protocol or format error.</summary>
    Error,
}

/// <summary>What one resolver said about the host.</summary>
public sealed class DnsResolverAnswer
{
    public required string Resolver { get; init; }

    public required DnsResolverKind Kind { get; init; }

    public string Server { get; init; } = "";

    public required DnsAnswerStatus Status { get; init; }

    /// <summary>A and AAAA addresses of the end of the CNAME chain, IPv4-mapped addresses normalized to IPv4.</summary>
    public IReadOnlyList<IPAddress> Addresses { get; init; } = [];

    /// <summary>CNAME chain from the host to the canonical name (empty for the system resolver).</summary>
    public IReadOnlyList<string> CnameChain { get; init; } = [];

    /// <summary>RCODE of the A query (null for the system resolver or when no response arrived).</summary>
    public DnsResponseCode? ResponseCode { get; init; }

    public string? Error { get; init; }

    public TimeSpan Duration { get; init; }

    public bool HasAddresses => Status == DnsAnswerStatus.Ok && Addresses.Count > 0;

    public override string ToString() => $"{Resolver} [{Kind}] {Status}: {string.Join(", ", Addresses)}{(Error is null ? "" : " — " + Error)}";
}

/// <summary>HTTPS RR (type 65) of the host as seen through DoH: HTTP/3, ECH and address hints.</summary>
public sealed class HttpsRecordSummary
{
    /// <summary>Resolver the records came from.</summary>
    public required string Source { get; init; }

    /// <summary>ServiceMode records, lowest priority first.</summary>
    public required IReadOnlyList<SvcbData> Records { get; init; }

    /// <summary>AliasMode target when the name only has an alias record.</summary>
    public string? AliasTarget { get; init; }

    /// <summary>Union of alpn ids in record order (h3, h2, http/1.1, ...).</summary>
    public IReadOnlyList<string> Alpn { get; init; } = [];

    public bool SupportsHttp3 => Alpn.Contains("h3");

    public bool NoDefaultAlpn { get; init; }

    public int? Port { get; init; }

    /// <summary>ECHConfigList of the first record that has one.</summary>
    public byte[]? EchConfigList { get; init; }

    public bool HasEch => EchConfigList is not null;

    public IReadOnlyList<IPAddress> Ipv4Hints { get; init; } = [];

    public IReadOnlyList<IPAddress> Ipv6Hints { get; init; } = [];

    /// <summary>Builds the summary from the HTTPS answer records of one response; null when there are none.</summary>
    public static HttpsRecordSummary? From(string source, IEnumerable<DnsRecord> records)
    {
        var svcb = records.Where(r => r.Svcb is not null).Select(r => r.Svcb!).ToList();
        if (svcb.Count == 0)
            return null;
        var service = svcb.Where(s => !s.IsAliasMode).OrderBy(s => s.Priority).ToList();
        var alpn = new List<string>();
        var v4 = new List<IPAddress>();
        var v6 = new List<IPAddress>();
        foreach (var s in service)
        {
            alpn.AddRange(s.Alpn.Where(a => !alpn.Contains(a)));
            v4.AddRange(s.Ipv4Hints.Where(a => !v4.Contains(a)));
            v6.AddRange(s.Ipv6Hints.Where(a => !v6.Contains(a)));
        }
        return new HttpsRecordSummary
        {
            Source = source,
            Records = service,
            AliasTarget = service.Count == 0 ? svcb[0].TargetName : null,
            Alpn = alpn,
            NoDefaultAlpn = service.Count > 0 && service.All(s => s.NoDefaultAlpn),
            Port = service.Select(s => s.Port).FirstOrDefault(p => p is not null),
            EchConfigList = service.Select(s => s.Ech).FirstOrDefault(e => e is not null),
            Ipv4Hints = v4,
            Ipv6Hints = v6,
        };
    }
}

public enum DnsFindingSeverity
{
    Info,
    Suspicious,
    Poison,
}

/// <summary>One reason of the verdict, with the addresses or answers that prove it.</summary>
public sealed record DnsFinding(string Code, DnsFindingSeverity Severity, string MessageRu, string MessageEn, IReadOnlyList<string> Evidence)
{
    public override string ToString() => $"{Code}: {MessageEn}";
}

public enum DnsVerdictKind
{
    /// <summary>Nothing to compare with: no DoH answer and nothing conclusive in the system answer.</summary>
    Unknown,

    Clean,

    /// <summary>Differences a CDN can explain, or failures; not enough for <c>DNS_POISON</c>.</summary>
    Suspicious,

    /// <summary><c>DNS_POISON</c> (dpi-diagnostics §2.1): further tests must use the DoH addresses.</summary>
    Poisoned,
}

public sealed class DnsVerdict
{
    public const string Label = "DNS_POISON";

    public required DnsVerdictKind Kind { get; init; }

    public bool Poisoned => Kind == DnsVerdictKind.Poisoned;

    public IReadOnlyList<DnsFinding> Reasons { get; init; } = [];
}

/// <summary>Result of <see cref="DnsProbe.RunAsync"/>.</summary>
public sealed class DnsReport
{
    /// <summary>The host as queried (ASCII, lower case).</summary>
    public required string Host { get; init; }

    /// <summary>Every resolver's answer: system first, then the transports in the given order.</summary>
    public required IReadOnlyList<DnsResolverAnswer> Answers { get; init; }

    public DnsResolverAnswer? SystemAnswer => Answers.FirstOrDefault(a => a.Kind == DnsResolverKind.System);

    /// <summary>HTTPS RR from the first DoH resolver that returned one; null when there is none or HTTPS was not queried.</summary>
    public HttpsRecordSummary? Https { get; init; }

    /// <summary>Union of DoH addresses without stub/sinkhole entries: the addresses further tests should use.</summary>
    public IReadOnlyList<IPAddress> TrustedAddresses { get; init; } = [];

    public required DnsVerdict Verdict { get; init; }

    public TimeSpan Duration { get; init; }
}

/// <summary>Answer for one client subnet in the ECS search (dpi-diagnostics §2a).</summary>
public sealed record DnsSubnetAnswer(DnsClientSubnet Subnet, IReadOnlyList<IPAddress> Addresses, int? ScopePrefix, string? Error);
