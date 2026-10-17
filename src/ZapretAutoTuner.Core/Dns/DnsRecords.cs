using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ZapretAutoTuner.Core.Dns;

/// <summary>DNS RR types the probes use (RFC 1035, RFC 3596, RFC 6891, RFC 9460). Other values pass through as numbers.</summary>
public enum DnsRecordType : ushort
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    OPT = 41,
    SVCB = 64,
    HTTPS = 65,
}

/// <summary>Response codes (RFC 1035 §4.1.1, RFC 6895). Extended codes from EDNS are combined into this value.</summary>
public enum DnsResponseCode : ushort
{
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}

/// <summary>A question entry.</summary>
public sealed record DnsQuestion(string Name, DnsRecordType Type, ushort Class);

/// <summary>
/// A resource record. <see cref="Data"/> is the RDATA as it appears on the wire (compression pointers inside it are
/// not expanded); the typed fields are filled for the types listed in <see cref="DnsRecordType"/> that the probes use.
/// </summary>
public sealed class DnsRecord
{
    public required string Name { get; init; }

    public required DnsRecordType Type { get; init; }

    /// <summary>Class (1 = IN). For OPT this is the requestor's UDP payload size.</summary>
    public required ushort Class { get; init; }

    public required uint Ttl { get; init; }

    public required byte[] Data { get; init; }

    /// <summary>A/AAAA address.</summary>
    public IPAddress? Address { get; init; }

    /// <summary>CNAME, NS or PTR target (compression expanded).</summary>
    public string? Target { get; init; }

    /// <summary>SVCB/HTTPS data (RFC 9460).</summary>
    public SvcbData? Svcb { get; init; }

    public override string ToString() => Type switch
    {
        DnsRecordType.A or DnsRecordType.AAAA => $"{Name} {Type} {Address}",
        DnsRecordType.CNAME or DnsRecordType.NS or DnsRecordType.PTR => $"{Name} {Type} {Target}",
        DnsRecordType.SVCB or DnsRecordType.HTTPS => $"{Name} {Type} {Svcb}",
        _ => $"{Name} TYPE{(ushort)Type} ({Data.Length} B)",
    };
}

/// <summary>One SvcParam as on the wire: key and raw value.</summary>
public sealed record SvcParam(ushort Key, byte[] Value);

/// <summary>
/// SVCB / HTTPS RDATA (RFC 9460 §2.2): priority, target name and SvcParams. Known keys are decoded, every key
/// (known or not) is also kept raw in <see cref="Parameters"/>.
/// </summary>
public sealed class SvcbData
{
    public const ushort KeyMandatory = 0;
    public const ushort KeyAlpn = 1;
    public const ushort KeyNoDefaultAlpn = 2;
    public const ushort KeyPort = 3;
    public const ushort KeyIpv4Hint = 4;
    public const ushort KeyEch = 5;
    public const ushort KeyIpv6Hint = 6;

    public ushort Priority { get; private init; }

    /// <summary>Target name; "." means the owner name itself.</summary>
    public string TargetName { get; private init; } = ".";

    /// <summary>AliasMode (priority 0): only <see cref="TargetName"/> is meaningful.</summary>
    public bool IsAliasMode => Priority == 0;

    public IReadOnlyList<SvcParam> Parameters { get; private init; } = [];

    public IReadOnlyList<string> Alpn { get; private init; } = [];

    public bool NoDefaultAlpn { get; private init; }

    public int? Port { get; private init; }

    public IReadOnlyList<IPAddress> Ipv4Hints { get; private init; } = [];

    public IReadOnlyList<IPAddress> Ipv6Hints { get; private init; } = [];

    /// <summary>ECHConfigList bytes (key 5), not interpreted.</summary>
    public byte[]? Ech { get; private init; }

    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.Append(Priority.ToString(CultureInfo.InvariantCulture)).Append(' ').Append(TargetName);
        if (Alpn.Count > 0)
            sb.Append(" alpn=").Append(string.Join(',', Alpn));
        if (NoDefaultAlpn)
            sb.Append(" no-default-alpn");
        if (Port is { } port)
            sb.Append(" port=").Append(port.ToString(CultureInfo.InvariantCulture));
        if (Ipv4Hints.Count > 0)
            sb.Append(" ipv4hint=").Append(string.Join(',', Ipv4Hints));
        if (Ech is { } ech)
            sb.Append(" ech=").Append(Convert.ToBase64String(ech));
        if (Ipv6Hints.Count > 0)
            sb.Append(" ipv6hint=").Append(string.Join(',', Ipv6Hints));
        return sb.ToString();
    }

    /// <summary>Decodes the SvcParams part of the RDATA (after priority and target name).</summary>
    internal static SvcbData Create(ushort priority, string target, ReadOnlySpan<byte> p)
    {
        var all = new List<SvcParam>();
        var alpn = new List<string>();
        var v4 = new List<IPAddress>();
        var v6 = new List<IPAddress>();
        bool noDefault = false;
        int? port = null;
        byte[]? ech = null;
        int pos = 0;
        while (pos < p.Length)
        {
            if (p.Length - pos < 4)
                throw new FormatException("DNS: обрезанный SvcParam");
            ushort key = BinaryPrimitives.ReadUInt16BigEndian(p[pos..]);
            int len = BinaryPrimitives.ReadUInt16BigEndian(p[(pos + 2)..]);
            pos += 4;
            if (p.Length - pos < len)
                throw new FormatException("DNS: значение SvcParam выходит за RDATA");
            var v = p.Slice(pos, len);
            pos += len;
            all.Add(new SvcParam(key, v.ToArray()));
            switch (key)
            {
                case KeyAlpn:
                    for (int i = 0; i < v.Length;)
                    {
                        int l = v[i++];
                        if (l == 0 || v.Length - i < l)
                            throw new FormatException("DNS: неверный список alpn");
                        alpn.Add(Encoding.Latin1.GetString(v.Slice(i, l)));
                        i += l;
                    }
                    break;
                case KeyNoDefaultAlpn:
                    if (len != 0)
                        throw new FormatException("DNS: no-default-alpn должен быть пустым");
                    noDefault = true;
                    break;
                case KeyPort:
                    if (len != 2)
                        throw new FormatException("DNS: неверная длина port");
                    port = BinaryPrimitives.ReadUInt16BigEndian(v);
                    break;
                case KeyIpv4Hint:
                    if (len == 0 || len % 4 != 0)
                        throw new FormatException("DNS: неверная длина ipv4hint");
                    for (int i = 0; i < len; i += 4)
                        v4.Add(new IPAddress(v.Slice(i, 4)));
                    break;
                case KeyEch:
                    ech = v.ToArray();
                    break;
                case KeyIpv6Hint:
                    if (len == 0 || len % 16 != 0)
                        throw new FormatException("DNS: неверная длина ipv6hint");
                    for (int i = 0; i < len; i += 16)
                        v6.Add(new IPAddress(v.Slice(i, 16)));
                    break;
            }
        }
        return new SvcbData
        {
            Priority = priority,
            TargetName = target,
            Parameters = all,
            Alpn = alpn,
            NoDefaultAlpn = noDefault,
            Port = port,
            Ipv4Hints = v4,
            Ipv6Hints = v6,
            Ech = ech,
        };
    }
}

/// <summary>An EDNS(0) option (RFC 6891 §6.1.2).</summary>
public sealed record DnsEdnsOption(ushort Code, byte[] Data);

/// <summary>The OPT pseudo-record of a message.</summary>
public sealed class DnsEdns
{
    public ushort UdpPayloadSize { get; init; }

    public byte Version { get; init; }

    public bool DnssecOk { get; init; }

    public IReadOnlyList<DnsEdnsOption> Options { get; init; } = [];

    /// <summary>The Client Subnet option echoed by the server, if any (its scope prefix tells how far the answer applies).</summary>
    public DnsClientSubnet? ClientSubnet { get; init; }
}

/// <summary>
/// EDNS Client Subnet (RFC 7871): the client network a recursive resolver passes to the authoritative server so a
/// CDN answers with edges for that region. On the wire the address is cut to <c>ceil(SourcePrefix / 8)</c> bytes
/// and the bits past the prefix are zero.
/// </summary>
public sealed class DnsClientSubnet
{
    public const ushort OptionCode = 8;

    public DnsClientSubnet(IPAddress address, int sourcePrefix, int scopePrefix = 0)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        if (address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            throw new ArgumentException("ECS: поддерживаются только IPv4 и IPv6", nameof(address));
        int max = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (sourcePrefix < 0 || sourcePrefix > max)
            throw new ArgumentOutOfRangeException(nameof(sourcePrefix), "ECS: длина префикса вне диапазона");
        if (scopePrefix < 0 || scopePrefix > max)
            throw new ArgumentOutOfRangeException(nameof(scopePrefix), "ECS: длина scope-префикса вне диапазона");
        Address = Mask(address, sourcePrefix);
        SourcePrefix = sourcePrefix;
        ScopePrefix = scopePrefix;
    }

    /// <summary>Network address with the host bits cleared.</summary>
    public IPAddress Address { get; }

    public int SourcePrefix { get; }

    public int ScopePrefix { get; }

    /// <summary>1 = IPv4, 2 = IPv6 (IANA address family numbers).</summary>
    public ushort Family => Address.AddressFamily == AddressFamily.InterNetwork ? (ushort)1 : (ushort)2;

    /// <summary>Parses <c>203.0.113.0/24</c> or <c>2001:db8::/48</c>.</summary>
    public static DnsClientSubnet Parse(string cidr)
    {
        var net = IPNetwork.Parse(cidr);
        return new DnsClientSubnet(net.BaseAddress, net.PrefixLength);
    }

    /// <summary>The option value (family, source prefix, scope prefix, truncated address), without code and length.</summary>
    public byte[] Encode()
    {
        int n = (SourcePrefix + 7) / 8;
        var r = new byte[4 + n];
        BinaryPrimitives.WriteUInt16BigEndian(r, Family);
        r[2] = (byte)SourcePrefix;
        r[3] = (byte)ScopePrefix;
        Address.GetAddressBytes().AsSpan(0, n).CopyTo(r.AsSpan(4));
        return r;
    }

    /// <summary>Decodes an option value; returns null when it is malformed.</summary>
    public static DnsClientSubnet? TryDecode(ReadOnlySpan<byte> v)
    {
        if (v.Length < 4)
            return null;
        ushort family = BinaryPrimitives.ReadUInt16BigEndian(v);
        int size = family switch { 1 => 4, 2 => 16, _ => 0 };
        int source = v[2], scope = v[3];
        if (size == 0 || source > size * 8 || scope > size * 8 || v.Length - 4 != (source + 7) / 8)
            return null;
        var bytes = new byte[size];
        v[4..].CopyTo(bytes);
        return new DnsClientSubnet(new IPAddress(bytes), source, scope);
    }

    public override string ToString() => $"{Address}/{SourcePrefix.ToString(CultureInfo.InvariantCulture)}";

    private static IPAddress Mask(IPAddress a, int prefix)
    {
        var b = a.GetAddressBytes();
        for (int i = 0; i < b.Length; i++)
        {
            int bits = Math.Clamp(prefix - (i * 8), 0, 8);
            b[i] &= (byte)(0xFF << (8 - bits));
        }
        return new IPAddress(b);
    }
}

/// <summary>Result of following the CNAME chain for a name inside one response.</summary>
/// <param name="CanonicalName">The last name in the chain (the queried name when there is no CNAME).</param>
/// <param name="Chain">Names from the queried name to <paramref name="CanonicalName"/>, inclusive.</param>
/// <param name="Addresses">A/AAAA addresses owned by the canonical name, in answer order, without duplicates.</param>
public sealed record DnsChainResult(string CanonicalName, IReadOnlyList<string> Chain, IReadOnlyList<IPAddress> Addresses);
