using System.Net;

namespace ZapretAutoTuner.Core.Packets;

/// <summary>Was a RST sent by the server or injected on the way (dpi-diagnostics §2, "признаки DPI")?</summary>
public enum RstOrigin
{
    Unknown,
    Server,
    Injected,
}

public sealed record RstInfo(DateTime Time, int Ttl, int? IpId, bool FromServer, RstOrigin Origin, IReadOnlyList<string> Reasons);

/// <summary>One TCP or UDP conversation, oriented client → server.</summary>
public sealed class Flow
{
    public required string Protocol { get; init; }

    public required IPEndPoint Client { get; init; }

    public required IPEndPoint Server { get; init; }

    public DateTime FirstSeen { get; set; }

    public DateTime LastSeen { get; set; }

    public int PacketsOut { get; set; }

    public int PacketsIn { get; set; }

    public long BytesOut { get; set; }

    public long BytesIn { get; set; }

    public DateTime? SynTime { get; set; }

    public DateTime? SynAckTime { get; set; }

    public int? SynAckTtl { get; set; }

    public int? SynAckIpId { get; set; }

    /// <summary>Server IPIDs seen in non-RST packets (to judge whether a RST's IPID fits).</summary>
    public List<int> ServerIpIds { get; } = [];

    /// <summary>
    /// The client's ClientHello: the last one seen, because desync fakes (same sequence numbers, another SNI) are
    /// sent before the real one. All of them are in <see cref="ClientHellos"/>.
    /// </summary>
    public TlsClientHello? ClientHello => ClientHellos.Count > 0 ? ClientHellos[^1] : null;

    /// <summary>Every distinct ClientHello in the flow, in order (fakes first when a strategy is running).</summary>
    public List<TlsClientHello> ClientHellos { get; } = [];

    /// <summary>Client data segments the ClientHello spanned (2+ means a multi-packet CH, kyber).</summary>
    public int ClientHelloSegments { get; set; }

    public DateTime? ClientHelloTime { get; set; }

    public List<RstInfo> Rsts { get; } = [];

    public int Retransmissions { get; set; }

    /// <summary>Time of the last incoming payload byte.</summary>
    public DateTime? LastDataIn { get; set; }

    /// <summary>The client's payloads before the server sends any data (at most 4 of up to 1500 bytes): what a replay sends.</summary>
    public List<byte[]> InitialPayloadsOut { get; } = [];

    /// <summary>What the first client payload speaks.</summary>
    public AppProtocol AppProtocol { get; set; }

    public TimeSpan? HandshakeRtt => SynTime is { } s && SynAckTime is { } a ? a - s : null;

    public override string ToString() => $"{Protocol} {Client} > {Server} out={BytesOut} in={BytesIn} sni={ClientHello?.Sni}";
}

/// <summary>
/// Groups captured packets into flows and extracts what the classifier needs: ClientHello (TCP reassembly or
/// QUIC Initial decryption), byte counts, retransmissions and RST origin (TTL / IPID / timing against the
/// SYN,ACK of the same flow).
/// </summary>
public static class FlowAnalyzer
{
    /// <summary>A RST whose TTL differs from the SYN,ACK by at least this much is treated as injected.</summary>
    public const int TtlTolerance = 2;

    public static List<Flow> Analyze(IEnumerable<CapturedPacket> packets)
    {
        var flows = new Dictionary<(string, IPEndPoint, IPEndPoint), FlowState>();
        var order = new List<FlowState>();
        foreach (var cp in packets.OrderBy(p => p.TimestampUtc))
        {
            var ip = cp.Parse();
            if (ip is null || !(ip.IsTcp || ip.IsUdp))
                continue;
            var proto = ip.IsTcp ? "tcp" : "udp";
            var src = new IPEndPoint(ip.Source, ip.SourcePort);
            var dst = new IPEndPoint(ip.Destination, ip.DestinationPort);
            FlowState? st;
            bool outgoing;
            if (flows.TryGetValue((proto, src, dst), out st))
            {
                outgoing = true;
            }
            else if (flows.TryGetValue((proto, dst, src), out st))
            {
                outgoing = false;
            }
            else
            {
                // the client is whoever sent the SYN (or the first datagram); a flow seen from the middle is
                // oriented by the lower port being the server
                bool srcIsClient = ip.IsTcp
                    ? ip.Has(TcpFlags.Syn) ? !ip.Has(TcpFlags.Ack) : ip.SourcePort > ip.DestinationPort
                    : true;
                var client = srcIsClient ? src : dst;
                var server = srcIsClient ? dst : src;
                st = new FlowState(new Flow { Protocol = proto, Client = client, Server = server, FirstSeen = cp.TimestampUtc });
                flows[(proto, client, server)] = st;
                order.Add(st);
                outgoing = srcIsClient;
            }
            st.Add(cp, ip, outgoing);
        }
        return order.Select(s => s.Flow).ToList();
    }

    private sealed class FlowState
    {
        private readonly SortedDictionary<uint, byte[]> _clientData = [];
        /// <summary>Client data within this many bytes of the stream start is searched for ClientHellos.</summary>
        private const int HelloWindow = 65536;

        private readonly HashSet<(uint, int, int)> _seenOut = [];
        private readonly List<ReadOnlyMemory<byte>> _quicInitials = [];
        private uint? _clientIsn;
        private byte[]? _lastHello;
        private bool _chDone;

        public FlowState(Flow f)
        {
            Flow = f;
        }

        public Flow Flow { get; }

        public void Add(CapturedPacket cp, IpPacket ip, bool outgoing)
        {
            var f = Flow;
            f.LastSeen = cp.TimestampUtc;
            int len = ip.Payload.Length;
            if (outgoing && len > 0 && f.BytesIn == 0 && f.InitialPayloadsOut.Count < 4)
            {
                if (f.InitialPayloadsOut.Count == 0)
                    f.AppProtocol = ip.IsUdp ? ProtocolDetector.DetectUdp(ip.Payload.Span, f.Server.Port) : ProtocolDetector.DetectTcp(ip.Payload.Span, f.Server.Address);
                f.InitialPayloadsOut.Add(ip.Payload[..Math.Min(len, 1500)].ToArray());
            }
            if (outgoing)
            {
                f.PacketsOut++;
                f.BytesOut += len;
            }
            else
            {
                f.PacketsIn++;
                f.BytesIn += len;
                if (len > 0)
                    f.LastDataIn = cp.TimestampUtc;
            }

            if (ip.IsUdp)
            {
                if (outgoing && !_chDone && QuicInitial.IsInitial(ip.Payload.Span))
                {
                    _quicInitials.Add(ip.Payload);
                    if (QuicInitial.TryParseClientHello(_quicInitials, out var ch, out _) == TlsParseStatus.Ok)
                    {
                        f.ClientHellos.Add(ch!);
                        f.ClientHelloSegments = _quicInitials.Count;
                        f.ClientHelloTime = cp.TimestampUtc;
                        _chDone = true;
                    }
                }
                return;
            }

            if (outgoing)
            {
                if (ip.Has(TcpFlags.Syn))
                {
                    f.SynTime ??= cp.TimestampUtc;
                    _clientIsn = ip.Seq;
                }
                if (len > 0)
                {
                    // a retransmission repeats the bytes; a desync fake reuses the sequence number with other bytes
                    var key = (ip.Seq, len, ContentHash(ip.Payload.Span));
                    if (!_seenOut.Add(key))
                        f.Retransmissions++;
                    else if (!_chDone)
                        AddClientData(cp, ip);
                }
            }
            else
            {
                if (ip.Has(TcpFlags.Syn | TcpFlags.Ack))
                {
                    f.SynAckTime ??= cp.TimestampUtc;
                    f.SynAckTtl ??= ip.Ttl;
                    f.SynAckIpId ??= ip.IpId;
                }
                if (ip.Has(TcpFlags.Rst))
                    f.Rsts.Add(JudgeRst(cp, ip));
                else if (ip.IpId is { } id)
                    f.ServerIpIds.Add(id);
            }
            if (outgoing && ip.Has(TcpFlags.Rst))
                f.Rsts.Add(new RstInfo(cp.TimestampUtc, ip.Ttl, ip.IpId, false, RstOrigin.Unknown, ["RST от клиента"]));
        }

        private void AddClientData(CapturedPacket cp, IpPacket ip)
        {
            if (_clientIsn is null)
            {
                // flow seen without its SYN: assume this segment starts the stream
                _clientIsn = ip.Seq - 1;
            }
            _clientData[ip.Seq] = ip.Payload.ToArray();
            // contiguous bytes from ISN+1
            uint next = _clientIsn.Value + 1;
            var buf = new List<byte>();
            int segs = 0;
            foreach (var (seq, data) in _clientData)
            {
                int skip = (int)(next - seq);
                if (skip < 0)
                    break;
                if (skip < data.Length)
                {
                    buf.AddRange(data.AsSpan(skip));
                    next = seq + (uint)data.Length;
                    segs++;
                }
            }
            if (buf.Count == 0)
                return;
            var bytes = buf.ToArray();
            var st = TlsClientHello.TryParseRecords(bytes, out var ch);
            if (st == TlsParseStatus.Ok)
            {
                // the same hello again (a later segment past its end) is not a new one
                var raw = bytes.AsSpan(0, Math.Min(bytes.Length, 5 + ch!.HandshakeLength));
                if (_lastHello is null || !raw.SequenceEqual(_lastHello))
                {
                    _lastHello = raw.ToArray();
                    Flow.ClientHellos.Add(ch);
                    Flow.ClientHelloSegments = segs;
                    Flow.ClientHelloTime = cp.TimestampUtc;
                }
            }
            else if (st == TlsParseStatus.NotTls && Flow.ClientHellos.Count == 0)
            {
                _chDone = true;
            }
            if (ip.Seq - _clientIsn.Value > HelloWindow)
                _chDone = true;
        }

        private static int ContentHash(ReadOnlySpan<byte> b)
        {
            var h = new HashCode();
            h.AddBytes(b);
            return h.ToHashCode();
        }

        private RstInfo JudgeRst(CapturedPacket cp, IpPacket ip)
        {
            var f = Flow;
            var reasons = new List<string>();
            int injected = 0, server = 0;
            if (f.SynAckTtl is { } t)
            {
                int d = Math.Abs(ip.Ttl - t);
                if (d >= TtlTolerance)
                {
                    injected++;
                    reasons.Add($"TTL {ip.Ttl} против {t} у SYN,ACK");
                }
                else
                {
                    server++;
                    reasons.Add($"TTL {ip.Ttl} совпадает с SYN,ACK");
                }
            }
            if (ip.IpId is { } id && f.SynAckIpId is { } sid)
            {
                // a server's IPID either stays 0 (DF, Linux) or grows a little; an injected RST often has 0 or a
                // value far away from the server's sequence
                int last = f.ServerIpIds.Count > 0 ? f.ServerIpIds[^1] : sid;
                int dist = Math.Abs((id - last + 0x10000) % 0x10000);
                dist = Math.Min(dist, 0x10000 - dist);
                bool serverZero = sid == 0 && f.ServerIpIds.All(x => x == 0);
                if (serverZero ? id != 0 : dist > 1000)
                {
                    injected++;
                    reasons.Add($"IPID {id} не похож на серверный ({last})");
                }
            }
            if (f.HandshakeRtt is { } rtt && f.ClientHelloTime is { } chTime && rtt > TimeSpan.FromMilliseconds(2))
            {
                var after = cp.TimestampUtc - chTime;
                if (after >= TimeSpan.Zero && after < rtt / 2)
                {
                    injected++;
                    reasons.Add($"RST через {after.TotalMilliseconds:F1} мс после ClientHello при RTT {rtt.TotalMilliseconds:F1} мс");
                }
            }
            var origin = injected > 0 && injected >= server ? RstOrigin.Injected
                : server > 0 ? RstOrigin.Server
                : RstOrigin.Unknown;
            return new RstInfo(cp.TimestampUtc, ip.Ttl, ip.IpId, true, origin, reasons);
        }
    }
}
