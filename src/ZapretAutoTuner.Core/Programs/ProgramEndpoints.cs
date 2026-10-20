using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Dns;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Core.Programs;

/// <summary>A socket of the program seen while it ran (from the Agent's ListConnections).</summary>
public sealed record ObservedSocket(L4Kind Protocol, IPEndPoint Local, IPEndPoint? Remote);

/// <summary>
/// Where the program connects, with what it speaks and how it went (PLAN 6.2–6.3): one entry per remote address,
/// port and protocol.
/// </summary>
public sealed record ProgramEndpoint
{
    public required L4Kind Protocol { get; init; }

    public required IPEndPoint Remote { get; init; }

    /// <summary>The name: SNI of the ClientHello, else the DNS answer the program got for the address.</summary>
    public string? Host { get; init; }

    public AppProtocol App { get; init; }

    public FlowHealth Health { get; init; }

    public int Flows { get; init; }

    public long BytesOut { get; init; }

    public long BytesIn { get; init; }

    public int PacketsOut { get; init; }

    public int PacketsIn { get; init; }

    /// <summary>The program's first datagrams or segment to this endpoint, for a replay probe.</summary>
    public IReadOnlyList<byte[]> InitialPayloads { get; init; } = [];

    /// <summary>The program sent more before the answer than was kept: there is nothing faithful to replay.</summary>
    public bool InitialPayloadsTruncated { get; init; }

    /// <summary>
    /// The target the search works on: a domain for TLS, QUIC and HTTP with a name (the usual pipeline), else the
    /// address with its port and protocol.
    /// </summary>
    public Target ToTarget() => Host is not null && App is AppProtocol.Tls or AppProtocol.Quic or AppProtocol.Http
        ? new Target { Kind = TargetKind.Domain, Value = Host, Port = Remote.Port, Protocol = Protocol }
        : new Target { Kind = TargetKind.Ip, Value = Remote.Address.ToString(), Port = Remote.Port, Protocol = Protocol };

    public override string ToString() =>
        $"{Protocol.ToString().ToLowerInvariant()} {Remote}{(Host is null ? "" : " " + Host)} {App} {Health} out={PacketsOut}/{BytesOut} in={PacketsIn}/{BytesIn}";
}

public static class ProgramEndpoints
{
    /// <summary>
    /// The program's endpoints: the captured flows whose local port belonged to one of its sockets, grouped by remote
    /// address, port and protocol. LAN, loopback, multicast and DNS are left out: there is nothing to unblock there.
    /// </summary>
    /// <param name="captureEnd">The end of the capture (by default the last packet of any flow): flows opened just
    /// before it are too young to judge.</param>
    public static List<ProgramEndpoint> FromRecording(IEnumerable<ObservedSocket> sockets, IReadOnlyList<Flow> flows, IEnumerable<CapturedPacket>? packets = null, DateTime? captureEnd = null)
    {
        var end = captureEnd ?? (flows.Count > 0 ? flows.Max(f => f.LastSeen) : DateTime.MinValue);
        var mine = sockets.Select(s => (s.Protocol, s.Local.Port)).ToHashSet();
        var names = packets is null ? new Dictionary<IPAddress, string>() : DnsNames(packets);
        return flows
            .Where(f => mine.Contains((L4(f), f.Client.Port)) && IsInternet(f.Server.Address) && f.Server.Port != 53)
            .GroupBy(f => (L4(f), f.Server))
            .Select(g =>
            {
                var list = g.ToList();
                var sni = list.Select(f => f.ClientHello?.Sni).FirstOrDefault(s => !string.IsNullOrEmpty(s));
                var app = list.Select(f => f.AppProtocol).FirstOrDefault(a => a != AppProtocol.Unknown);
                var healths = list.Select(f => FlowVerdict.Judge(f, end)).ToList();
                return new ProgramEndpoint
                {
                    Protocol = g.Key.Item1,
                    Remote = g.Key.Server,
                    Host = sni ?? names.GetValueOrDefault(Norm(g.Key.Server.Address)),
                    App = app,
                    // one working flow is enough to call the endpoint working; else the worst failure seen
                    Health = healths.Contains(FlowHealth.Ok) ? FlowHealth.Ok : healths.Where(h => h != FlowHealth.Unknown).DefaultIfEmpty(FlowHealth.Unknown).Max(),
                    Flows = list.Count,
                    BytesOut = list.Sum(f => f.BytesOut),
                    BytesIn = list.Sum(f => f.BytesIn),
                    PacketsOut = list.Sum(f => f.PacketsOut),
                    PacketsIn = list.Sum(f => f.PacketsIn),
                    InitialPayloads = list.FirstOrDefault(f => f.InitialPayloadsOut.Count > 0 && !f.InitialPayloadsTruncated)?.InitialPayloadsOut ?? [],
                    InitialPayloadsTruncated = list.All(f => f.InitialPayloadsOut.Count == 0 || f.InitialPayloadsTruncated) && list.Any(f => f.InitialPayloadsTruncated),
                };
            })
            .OrderByDescending(e => e.BytesOut + e.BytesIn)
            .ToList();
    }

    /// <summary>Address → name from the DNS answers in the capture (CNAME chains end at the asked name).</summary>
    public static Dictionary<IPAddress, string> DnsNames(IEnumerable<CapturedPacket> packets)
    {
        var d = new Dictionary<IPAddress, string>();
        foreach (var cp in packets)
        {
            var ip = cp.Parse();
            if (ip is null || !ip.IsUdp || ip.SourcePort != 53 || !DnsMessage.TryParse(ip.Payload.Span, out var m) || m is null || !m.IsResponse)
                continue;
            var asked = (m.Questions.Count > 0 ? m.Questions[0] : null)?.Name.TrimEnd('.').ToLowerInvariant();
            if (asked is null)
                continue;
            foreach (var a in m.Answers.Where(a => a.Address is not null))
                d[Norm(a.Address!)] = asked;
        }
        return d;
    }

    /// <summary>A public unicast address (not private, loopback, link-local, CGNAT, multicast or unspecified).</summary>
    public static bool IsInternet(IPAddress a)
    {
        a = Norm(a);
        if (IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any))
            return false;
        if (a.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = a.GetAddressBytes();
            return !(b[0] == 10 || b[0] == 0 || b[0] >= 224 || (b[0] == 172 && (b[1] & 0xF0) == 16) || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && (b[1] & 0xC0) == 64));
        }
        return !(a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6Multicast || a.IsIPv6UniqueLocal);
    }

    private static IPAddress Norm(IPAddress a) => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a;

    private static L4Kind L4(Flow f) => f.Protocol == "udp" ? L4Kind.Udp : L4Kind.Tcp;
}
