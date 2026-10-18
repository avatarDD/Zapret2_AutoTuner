using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZapretAutoTuner.Probes.Dns;

/// <summary>A public resolver reached over plain UDP/TCP 53.</summary>
public sealed class UdpResolverSpec
{
    public required string Name { get; init; }

    public required string Address { get; init; }

    public int Port { get; init; } = 53;
}

/// <summary>A DoH resolver: URL plus the IP connections go to, so its host name is never resolved.</summary>
public sealed class DohResolverSpec
{
    public required string Name { get; init; }

    public required string Url { get; init; }

    public required string Bootstrap { get; init; }

    /// <summary>The resolver forwards EDNS Client Subnet (needed for the alternate-IP search, §2a).</summary>
    public bool Ecs { get; init; }
}

public sealed class SinkholeSpec
{
    public required string Cidr { get; init; }

    public string? Note { get; init; }
}

public sealed class BlockPageSpec
{
    public required string Address { get; init; }

    public string? Isp { get; init; }

    public string? Note { get; init; }
}

public sealed class DnsResolverCatalogData
{
    public List<UdpResolverSpec> Udp { get; init; } = [];

    public List<DohResolverSpec> Doh { get; init; } = [];

    public List<SinkholeSpec> Sinkholes { get; init; } = [];

    public List<BlockPageSpec> BlockPages { get; init; } = [];
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true)]
[JsonSerializable(typeof(DnsResolverCatalogData))]
internal sealed partial class DnsJsonContext : JsonSerializerContext;

/// <summary>
/// Default resolvers and the stub / sinkhole / block-page address lists (data file <c>Data/dns-resolvers.json</c>).
/// </summary>
public sealed class DnsResolverCatalog
{
    private const string ResourceName = "ZapretAutoTuner.Probes.Data.dns-resolvers.json";

    private static readonly Lazy<DnsResolverCatalog> s_default = new(Load);

    private readonly List<(IPNetwork Net, string Note)> _sinkholes;
    private readonly Dictionary<IPAddress, string> _blockPages;

    public DnsResolverCatalog(DnsResolverCatalogData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        Data = data;
        _sinkholes = [.. data.Sinkholes.Select(s => (IPNetwork.Parse(s.Cidr), s.Note ?? s.Cidr))];
        _blockPages = data.BlockPages.ToDictionary(b => Normalize(IPAddress.Parse(b.Address)), b => b.Isp ?? b.Note ?? b.Address);
    }

    public static DnsResolverCatalog Default => s_default.Value;

    public DnsResolverCatalogData Data { get; }

    public static DnsResolverCatalog Load()
    {
        using var s = typeof(DnsResolverCatalog).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"resource {ResourceName} is missing");
        var data = JsonSerializer.Deserialize(s, DnsJsonContext.Default.DnsResolverCatalogData)
            ?? throw new InvalidOperationException("dns-resolvers.json is empty");
        return new DnsResolverCatalog(data);
    }

    /// <summary>True when the address is loopback, unspecified, private, CGNAT or link-local (a stub, not a site).</summary>
    public bool IsSinkhole(IPAddress address, out string? note)
    {
        var a = Normalize(address);
        foreach (var (net, n) in _sinkholes)
        {
            if (net.BaseAddress.AddressFamily == a.AddressFamily && net.Contains(a))
            {
                note = n;
                return true;
            }
        }
        note = null;
        return false;
    }

    /// <summary>True when the address is a known ISP block page.</summary>
    public bool IsBlockPage(IPAddress address, out string? isp) => _blockPages.TryGetValue(Normalize(address), out isp);

    /// <summary>Creates the default transports: public UDP resolvers, then DoH. The caller owns (disposes) them.</summary>
    public List<IDnsTransport> CreateTransports(TimeSpan udpTimeout, TimeSpan dohTimeout)
    {
        var list = new List<IDnsTransport>();
        foreach (var u in Data.Udp)
            list.Add(new UdpDnsTransport(new IPEndPoint(IPAddress.Parse(u.Address), u.Port), u.Name, udpTimeout));
        foreach (var d in Data.Doh)
            list.Add(CreateDoh(d, dohTimeout));
        return list;
    }

    public static DohTransport CreateDoh(DohResolverSpec spec, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return new DohTransport(new Uri(spec.Url), IPAddress.Parse(spec.Bootstrap), spec.Name, timeout);
    }

    /// <summary>IPv4-mapped IPv6 addresses compare as IPv4.</summary>
    internal static IPAddress Normalize(IPAddress a) => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a;
}
