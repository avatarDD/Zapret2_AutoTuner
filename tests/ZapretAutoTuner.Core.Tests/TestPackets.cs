using System.Buffers.Binary;
using System.Net;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>Raw IPv4 packets built by hand (checksums are not checked by the parser).</summary>
internal static class TestPackets
{
    private static readonly DateTime T0 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public static byte[] Udp(string src, int sport, string dst, int dport, byte[] payload)
    {
        var l4 = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(l4, (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(l4.AsSpan(2), (ushort)dport);
        BinaryPrimitives.WriteUInt16BigEndian(l4.AsSpan(4), (ushort)l4.Length);
        payload.CopyTo(l4, 8);
        return Ipv4(src, dst, 17, l4);
    }

    public static byte[] Tcp(string src, int sport, string dst, int dport, TcpFlags flags, uint seq, uint ack, byte[]? payload = null, int ttl = 64)
    {
        payload ??= [];
        var l4 = new byte[20 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(l4, (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(l4.AsSpan(2), (ushort)dport);
        BinaryPrimitives.WriteUInt32BigEndian(l4.AsSpan(4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(l4.AsSpan(8), ack);
        l4[12] = 5 << 4;
        l4[13] = (byte)flags;
        BinaryPrimitives.WriteUInt16BigEndian(l4.AsSpan(14), 65535);
        payload.CopyTo(l4, 20);
        return Ipv4(src, dst, 6, l4, ttl);
    }

    public static byte[] Ipv4(string src, string dst, int proto, byte[] l4, int ttl = 64)
    {
        var p = new byte[20 + l4.Length];
        p[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), 1);
        p[8] = (byte)ttl;
        p[9] = (byte)proto;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(p, 12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(p, 16);
        l4.CopyTo(p, 20);
        return p;
    }

    /// <summary>Packets one millisecond apart, in order.</summary>
    public static List<CapturedPacket> Capture(params byte[][] packets) =>
        packets.Select((p, i) => new CapturedPacket(T0.AddMilliseconds(i), p, p.Length)).ToList();

    /// <summary>A DNS response for one A record (the answer name points at the question).</summary>
    public static byte[] DnsAResponse(string name, string address)
    {
        var ms = new MemoryStream();
        ms.Write([0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        foreach (var label in name.Split('.'))
        {
            ms.WriteByte((byte)label.Length);
            ms.Write(System.Text.Encoding.ASCII.GetBytes(label));
        }
        ms.Write([0, 0, 1, 0, 1]);
        ms.Write([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        ms.Write(IPAddress.Parse(address).GetAddressBytes());
        return ms.ToArray();
    }

    public static byte[] DnsQuery(string name)
    {
        var ms = new MemoryStream();
        ms.Write([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        foreach (var label in name.Split('.'))
        {
            ms.WriteByte((byte)label.Length);
            ms.Write(System.Text.Encoding.ASCII.GetBytes(label));
        }
        ms.Write([0, 0, 1, 0, 1]);
        return ms.ToArray();
    }

    public static byte[] Stun(int extra = 0)
    {
        var b = new byte[20 + extra];
        BinaryPrimitives.WriteUInt16BigEndian(b, 0x0001);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2), (ushort)extra);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), 0x2112A442);
        return b;
    }
}
