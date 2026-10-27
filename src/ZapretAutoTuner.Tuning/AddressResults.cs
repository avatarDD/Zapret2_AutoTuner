using System.Globalization;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Providers;
using ZapretAutoTuner.Core.Unify;

namespace ZapretAutoTuner.Tuning;

/// <summary>Results of the address-based modes (PLAN 6.3–6.4) in the unifier's terms (<see cref="Unifier.AddIpProfiles"/>).</summary>
public static class AddressResults
{
    /// <summary>
    /// A provider's strategy over its whole aggregated range list. The name is the provider id: exporters add the
    /// <c>-ipset</c> suffix to the file themselves.
    /// </summary>
    public static IpResult Provider(Provider p, IEnumerable<Cidr> ranges, Strategy strategy, string ports = "443") =>
        new(p.Id, ranges.Select(r => r.ToString()).ToList(), L4Kind.Tcp, ports, ["tls"], strategy);

    /// <summary>
    /// A program's endpoints filtered by address (the ones without a usable name), one profile per strategy and
    /// protocol: the endpoints that share a strategy share an ipset. Name-based endpoints go to the hostlist pipeline.
    /// </summary>
    public static List<IpResult> Program(string programId, IEnumerable<EndpointStrategy> found)
    {
        var slug = Slug(programId);
        return found
            .Where(f => !(f.Endpoint.Host is not null && f.Endpoint.App is AppProtocol.Tls or AppProtocol.Quic or AppProtocol.Http))
            .GroupBy(f => (f.Candidate.L4, Key: f.Candidate.Strategy.ToString()))
            .Select((g, i) =>
            {
                var list = g.ToList();
                var l7 = list.Select(f => ProtocolDetector.L7Name(f.Endpoint.App)).ToList();
                return new IpResult(
                    i == 0 ? slug : $"{slug}-{i + 1}",
                    list.Select(f => f.Endpoint.Remote.Address.ToString()).Distinct().ToList(),
                    g.Key.L4,
                    PortList.Union(list.Select(f => f.Endpoint.Remote.Port.ToString(CultureInfo.InvariantCulture))),
                    // the L7 filter only when every endpoint of the group was recognised: unknown traffic has no name
                    l7.All(n => n is not null) ? l7.Distinct().Select(n => n!).ToList() : [],
                    list[0].Candidate.Strategy);
            })
            .ToList();
    }

    /// <summary>A file-name-safe lower-case name from a program id (a path or a package family).</summary>
    public static string Slug(string id)
    {
        var name = Path.GetFileNameWithoutExtension(id.TrimEnd('/', '\\'));
        var chars = name.ToLowerInvariant().Select(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' ? c : '-').ToArray();
        var slug = string.Join('-', new string(chars).Split('-', StringSplitOptions.RemoveEmptyEntries));
        return slug.Length == 0 ? "program" : slug[..Math.Min(slug.Length, 40)];
    }
}
