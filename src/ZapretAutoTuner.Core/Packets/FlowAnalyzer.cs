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

    /// <summary>
    /// The client's payloads before the server sends any data: what a replay sends. UDP: the first
    /// <see cref="FlowAnalyzer.MaxInitialDatagrams"/> datagrams, whole. TCP: the distinct segments (retransmissions
    /// left out), whole (a WinDivert capture sees pre-LSO segments up to 64 KB), up to
    /// <see cref="FlowAnalyzer.MaxInitialBytes"/> in all.
    /// </summary>
    public List<byte[]> InitialPayloadsOut { get; } = [];

    /// <summary>The client sent more before the server answered than <see cref="InitialPayloadsOut"/> holds: a replay
    /// of it would not be what the program sent, so it is not replayed.</summary>
    public bool InitialPayloadsTruncated { get; set; }

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

    /// <summary>UDP datagrams kept for a replay.</summary>
    public const int MaxInitialDatagrams = 4;

    /// <summary>Client bytes kept for a replay (TCP).</summary>
    public const int MaxInitialBytes = 64 * 1024;

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
                // the client is whoever sent the SYN; a TCP flow seen from the middle is oriented by the lower port
                // being the server; UDP has no handshake (the server may speak first or the capture start late)
                bool srcIsClient = ip.IsTcp
                    ? ip.Has(TcpFlags.Syn) ? !ip.Has(TcpFlags.Ack) : ip.SourcePort > ip.DestinationPort
                    : UdpSourceIsClient(src, dst);
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

    /// <summary>
    /// Which end of a UDP conversation is the client: the local (private, loopback, link-local) end when only one is,
    /// else the end without a well-known port (below 1024), else the end with an ephemeral port (49152 and up, the
    /// IANA range Windows uses), else whoever sent the first datagram.
    /// </summary>
    public static bool UdpSourceIsClient(IPEndPoint src, IPEndPoint dst)
    {
        bool srcLocal = !Programs.ProgramEndpoints.IsInternet(src.Address), dstLocal = !Programs.ProgramEndpoints.IsInternet(dst.Address);
        // multicast and broadcast are never a client
        if (IsGroup(dst.Address) != IsGroup(src.Address))
            return IsGroup(dst.Address);
        if (srcLocal != dstLocal)
            return srcLocal;
        bool srcWellKnown = src.Port < 1024, dstWellKnown = dst.Port < 1024;
        if (srcWellKnown != dstWellKnown)
            return dstWellKnown;
        bool srcEphemeral = src.Port >= 49152, dstEphemeral = dst.Port >= 49152;
        if (srcEphemeral != dstEphemeral)
            return srcEphemeral;
        return true;
    }

    private static bool IsGroup(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6)
            a = a.MapToIPv4();
        if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = a.GetAddressBytes();
            return b[0] >= 224 || (b[0] == 255 && b[3] == 255);
        }
        return a.IsIPv6Multicast;
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
            // a retransmission repeats the bytes; a desync fake reuses the sequence number with other bytes
            bool retransmission = ip.IsTcp && outgoing && len > 0 && !_seenOut.Add((ip.Seq, len, ContentHash(ip.Payload.Span)));
            if (outgoing && len > 0 && f.BytesIn == 0 && !retransmission)
                AddInitial(ip);
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
                if (retransmission)
                    f.Retransmissions++;
                else if (len > 0 && !_chDone)
                    AddClientData(cp, ip);
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

        private int _initialBytes;

        /// <summary>What the client sends before the server's first data, for a replay; the protocol from the first of it.</summary>
        private void AddInitial(IpPacket ip)
        {
            var f = Flow;
            if (f.InitialPayloadsTruncated)
                return;
            if (f.InitialPayloadsOut.Count == 0)
                f.AppProtocol = ip.IsUdp ? ProtocolDetector.DetectUdp(ip.Payload.Span) : ProtocolDetector.DetectTcp(ip.Payload.Span);
            bool full = ip.IsUdp
                ? f.InitialPayloadsOut.Count >= MaxInitialDatagrams
                : _initialBytes + ip.Payload.Length > MaxInitialBytes;
            if (full)
            {
                // UDP: later datagrams are not needed to reach the server; TCP: a partial stream is not what was sent
                if (ip.IsTcp)
                    f.InitialPayloadsTruncated = true;
                return;
            }
            f.InitialPayloadsOut.Add(ip.Payload.ToArray());
            _initialBytes += ip.Payload.Length;
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
