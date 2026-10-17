using System.Buffers.Binary;
using System.Net;

namespace ZapretAutoTuner.Core.Packets;

[Flags]
public enum TcpFlags : byte
{
    None = 0,
    Fin = 0x01,
    Syn = 0x02,
    Rst = 0x04,
    Psh = 0x08,
    Ack = 0x10,
    Urg = 0x20,
    Ece = 0x40,
    Cwr = 0x80,
}

/// <summary>
/// An IPv4/IPv6 packet with its TCP or UDP header, parsed from a raw L3 buffer (LINKTYPE_RAW, as delivered by
/// AF_PACKET SOCK_DGRAM and WinDivert). Fragments other than the first carry no L4 header.
/// </summary>
public sealed class IpPacket
{
    public int Version { get; private init; }

    public IPAddress Source { get; private init; } = IPAddress.None;

    public IPAddress Destination { get; private init; } = IPAddress.None;

    /// <summary>TTL (IPv4) or hop limit (IPv6).</summary>
    public int Ttl { get; private init; }

    /// <summary>IPv4 identification; null for IPv6.</summary>
    public int? IpId { get; private init; }

    /// <summary>6 = TCP, 17 = UDP, other values for anything else (after IPv6 extension headers).</summary>
    public int Protocol { get; private init; }

    public bool IsFragment { get; private init; }

    public int SourcePort { get; private init; }

    public int DestinationPort { get; private init; }

    public uint Seq { get; private init; }

    public uint Ack { get; private init; }

    public TcpFlags Flags { get; private init; }

    public int Window { get; private init; }

    /// <summary>TCP options present (MSS, timestamps…), raw.</summary>
    public ReadOnlyMemory<byte> TcpOptions { get; private init; }

    /// <summary>L4 payload (TCP data or UDP datagram body).</summary>
    public ReadOnlyMemory<byte> Payload { get; private init; }

    public int TotalLength { get; private init; }

    public bool IsTcp => Protocol == 6 && !IsFragment;

    public bool IsUdp => Protocol == 17 && !IsFragment;

    public bool Has(TcpFlags f) => (Flags & f) == f;

    public static IpPacket? Parse(ReadOnlyMemory<byte> data)
    {
        var s = data.Span;
        if (s.Length < 1)
            return null;
        int ver = s[0] >> 4;
        IPAddress src, dst;
        int ttl, proto, l4;
        int? ipid = null;
        bool frag = false;
        int total;
        if (ver == 4)
        {
            if (s.Length < 20)
                return null;
            int ihl = (s[0] & 0x0F) * 4;
            if (ihl < 20 || s.Length < ihl)
                return null;
            total = Math.Min(BinaryPrimitives.ReadUInt16BigEndian(s[2..]), s.Length);
            // offloaded outgoing packets may show total length 0 (TSO): use the buffer
            if (total < ihl)
                total = s.Length;
            ipid = BinaryPrimitives.ReadUInt16BigEndian(s[4..]);
            int fragField = BinaryPrimitives.ReadUInt16BigEndian(s[6..]);
            frag = (fragField & 0x1FFF) != 0;
            ttl = s[8];
            proto = s[9];
            src = new IPAddress(s.Slice(12, 4));
            dst = new IPAddress(s.Slice(16, 4));
            l4 = ihl;
        }
        else if (ver == 6)
        {
            if (s.Length < 40)
                return null;
            total = Math.Min(40 + BinaryPrimitives.ReadUInt16BigEndian(s[4..]), s.Length);
            if (total <= 40)
                total = s.Length;
            proto = s[6];
            ttl = s[7];
            src = new IPAddress(s.Slice(8, 16));
            dst = new IPAddress(s.Slice(24, 16));
            l4 = 40;
            // walk extension headers: hop-by-hop 0, routing 43, fragment 44, destination 60
            while (proto is 0 or 43 or 44 or 60)
            {
                if (l4 + 8 > total)
                    return null;
                int next = s[l4];
                if (proto == 44)
                {
                    frag = (BinaryPrimitives.ReadUInt16BigEndian(s[(l4 + 2)..]) & 0xFFF8) != 0;
                    l4 += 8;
                }
                else
                {
                    l4 += (s[l4 + 1] + 1) * 8;
                }
                proto = next;
            }
        }
        else
        {
            return null;
        }

        int sport = 0, dport = 0, win = 0;
        uint seq = 0, ack = 0;
        var flags = TcpFlags.None;
        ReadOnlyMemory<byte> opts = default, payload = default;
        if (!frag && proto == 6 && total >= l4 + 20)
        {
            var t = s[l4..total];
            sport = BinaryPrimitives.ReadUInt16BigEndian(t);
            dport = BinaryPrimitives.ReadUInt16BigEndian(t[2..]);
            seq = BinaryPrimitives.ReadUInt32BigEndian(t[4..]);
            ack = BinaryPrimitives.ReadUInt32BigEndian(t[8..]);
            int off = (t[12] >> 4) * 4;
            flags = (TcpFlags)t[13];
            win = BinaryPrimitives.ReadUInt16BigEndian(t[14..]);
            if (off < 20 || off > t.Length)
                return null;
            opts = data.Slice(l4 + 20, off - 20);
            payload = data[(l4 + off)..total];
        }
        else if (!frag && proto == 17 && total >= l4 + 8)
        {
            var u = s[l4..total];
            sport = BinaryPrimitives.ReadUInt16BigEndian(u);
            dport = BinaryPrimitives.ReadUInt16BigEndian(u[2..]);
            payload = data[(l4 + 8)..total];
        }
        else if (!frag && proto is 6 or 17)
        {
            return null;
        }

        return new IpPacket
        {
            Version = ver,
            Source = src,
            Destination = dst,
            Ttl = ttl,
            IpId = ipid,
            Protocol = proto,
            IsFragment = frag,
            SourcePort = sport,
            DestinationPort = dport,
            Seq = seq,
            Ack = ack,
            Flags = flags,
            Window = win,
            TcpOptions = opts,
            Payload = payload,
            TotalLength = total,
        };
    }

    public override string ToString() => IsTcp || IsUdp
        ? $"{(IsTcp ? "TCP" : "UDP")} {Source}:{SourcePort} > {Destination}:{DestinationPort} ttl={Ttl} len={Payload.Length}{(IsTcp ? " " + Flags : "")}"
        : $"IPv{Version} proto={Protocol} {Source} > {Destination}";
}
