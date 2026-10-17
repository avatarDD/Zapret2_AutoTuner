using System.Buffers.Binary;
using System.Text;

namespace ZapretAutoTuner.Core.Packets;

public enum PacketDirection
{
    Unknown = 0,
    Inbound = 1,
    Outbound = 2,
}

/// <summary>One captured packet: an L3 buffer (IPv4/IPv6) with capture time and direction.</summary>
public sealed record CapturedPacket(DateTime TimestampUtc, ReadOnlyMemory<byte> Data, int OriginalLength, PacketDirection Direction = PacketDirection.Unknown)
{
    public IpPacket? Parse() => IpPacket.Parse(Data);
}

/// <summary>
/// Writes pcapng with one interface of LINKTYPE_RAW (101): every packet is an IP packet, the same for AF_PACKET
/// cooked capture and WinDivert. Direction goes into the EPB flags option, so Wireshark shows in/out.
/// </summary>
public sealed class PcapNgWriter
{
    public const ushort LinkTypeRaw = 101;

    private readonly Stream _out;

    public PcapNgWriter(Stream output, int snaplen = 65535, string? application = null, string? interfaceName = null)
    {
        _out = output;
        WriteSectionHeader(application ?? $"{AppInfo.Name} {AppInfo.Version}");
        WriteInterface(snaplen, interfaceName);
    }

    private void WriteSectionHeader(string app)
    {
        var body = new List<byte>();
        Append32(body, 0x1A2B3C4D);   // byte-order magic
        Append16(body, 1);            // major
        Append16(body, 0);            // minor
        Append64(body, ulong.MaxValue); // section length unknown
        AppendOption(body, 4, Encoding.UTF8.GetBytes(app)); // shb_userappl
        AppendOption(body, 0, []);
        WriteBlock(0x0A0D0D0A, body);
    }

    private void WriteInterface(int snaplen, string? name)
    {
        var body = new List<byte>();
        Append16(body, LinkTypeRaw);
        Append16(body, 0);
        Append32(body, (uint)snaplen);
        if (name is not null)
            AppendOption(body, 2, Encoding.UTF8.GetBytes(name)); // if_name
        AppendOption(body, 9, [6]); // if_tsresol: microseconds
        AppendOption(body, 0, []);
        WriteBlock(1, body);
    }

    public void Write(CapturedPacket p)
    {
        var body = new List<byte>(p.Data.Length + 40);
        Append32(body, 0); // interface id
        long us = (p.TimestampUtc - DateTime.UnixEpoch).Ticks / 10;
        Append32(body, (uint)((ulong)us >> 32));
        Append32(body, (uint)us);
        Append32(body, (uint)p.Data.Length);
        Append32(body, (uint)Math.Max(p.OriginalLength, p.Data.Length));
        body.AddRange(p.Data.Span);
        Pad(body);
        if (p.Direction != PacketDirection.Unknown)
        {
            var flags = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(flags, (uint)p.Direction);
            AppendOption(body, 2, flags); // epb_flags: bits 0-1 direction
            AppendOption(body, 0, []);
        }
        WriteBlock(6, body);
    }

    private void WriteBlock(uint type, List<byte> body)
    {
        uint len = (uint)(body.Count + 12);
        Span<byte> h = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(h, type);
        BinaryPrimitives.WriteUInt32LittleEndian(h[4..], len);
        _out.Write(h);
        _out.Write(body.ToArray());
        _out.Write(h[4..]);
    }

    private static void AppendOption(List<byte> b, ushort code, ReadOnlySpan<byte> value)
    {
        Append16(b, code);
        Append16(b, (ushort)value.Length);
        b.AddRange(value);
        Pad(b);
    }

    private static void Pad(List<byte> b)
    {
        while (b.Count % 4 != 0)
            b.Add(0);
    }

    private static void Append16(List<byte> b, ushort v)
    {
        b.Add((byte)v);
        b.Add((byte)(v >> 8));
    }

    private static void Append32(List<byte> b, uint v)
    {
        for (int i = 0; i < 4; i++)
            b.Add((byte)(v >> (8 * i)));
    }

    private static void Append64(List<byte> b, ulong v)
    {
        for (int i = 0; i < 8; i++)
            b.Add((byte)(v >> (8 * i)));
    }

    public static byte[] ToBytes(IEnumerable<CapturedPacket> packets, int snaplen = 65535)
    {
        using var ms = new MemoryStream();
        var w = new PcapNgWriter(ms, snaplen);
        foreach (var p in packets)
            w.Write(p);
        return ms.ToArray();
    }
}

/// <summary>
/// Reads pcapng and classic pcap (tcpdump, Wireshark, our own captures) into L3 packets. Supported link types:
/// RAW (101, also 12/14), Ethernet (1), Linux cooked SLL (113) and SLL2 (276), BSD loopback (0, 108).
/// </summary>
public static class PcapReader
{
    public static List<CapturedPacket> Read(byte[] file)
    {
        if (file.Length < 4)
            throw new FormatException("file too short");
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(file);
        return magic switch
        {
            0x0A0D0D0A => ReadNg(file),
            0xA1B2C3D4 or 0xD4C3B2A1 or 0xA1B23C4D or 0x4D3CB2A1 => ReadClassic(file),
            _ => throw new FormatException("not a pcap or pcapng file"),
        };
    }

    private static List<CapturedPacket> ReadClassic(byte[] f)
    {
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(f);
        bool le = magic is 0xA1B2C3D4 or 0xA1B23C4D;
        bool nano = magic is 0xA1B23C4D or 0x4D3CB2A1;
        uint U32(int o) => le ? BinaryPrimitives.ReadUInt32LittleEndian(f.AsSpan(o)) : BinaryPrimitives.ReadUInt32BigEndian(f.AsSpan(o));
        int link = (int)(U32(20) & 0x0FFFFFFF);
        var list = new List<CapturedPacket>();
        int pos = 24;
        while (pos + 16 <= f.Length)
        {
            long sec = U32(pos), frac = U32(pos + 4);
            int incl = (int)U32(pos + 8), orig = (int)U32(pos + 12);
            pos += 16;
            if (incl < 0 || pos + incl > f.Length)
                break;
            var ts = DateTime.UnixEpoch.AddSeconds(sec).AddTicks(nano ? frac / 100 : frac * 10);
            if (StripLink(link, f.AsMemory(pos, incl), out var l3, out var dir))
                list.Add(new CapturedPacket(ts, l3, orig, dir));
            pos += incl;
        }
        return list;
    }

    private static List<CapturedPacket> ReadNg(byte[] f)
    {
        var list = new List<CapturedPacket>();
        var links = new List<(int Link, long TicksPerUnit)>();
        bool le = true;
        int pos = 0;
        uint U32(int o) => le ? BinaryPrimitives.ReadUInt32LittleEndian(f.AsSpan(o)) : BinaryPrimitives.ReadUInt32BigEndian(f.AsSpan(o));
        ushort U16(int o) => le ? BinaryPrimitives.ReadUInt16LittleEndian(f.AsSpan(o)) : BinaryPrimitives.ReadUInt16BigEndian(f.AsSpan(o));
        while (pos + 12 <= f.Length)
        {
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(f.AsSpan(pos));
            if (type == 0x0A0D0D0A)
            {
                le = BinaryPrimitives.ReadUInt32LittleEndian(f.AsSpan(pos + 8)) == 0x1A2B3C4D;
                links.Clear();
            }
            else if (!le)
            {
                type = BinaryPrimitives.ReadUInt32BigEndian(f.AsSpan(pos));
            }
            int len = (int)U32(pos + 4);
            if (len < 12 || pos + len > f.Length)
                break;
            int body = pos + 8, end = pos + len - 4;
            switch (type)
            {
                case 1: // IDB
                {
                    int link = U16(body);
                    long tpu = 10; // default microseconds
                    foreach (var (code, ofs, olen) in Options(f, body + 8, end, U16))
                    {
                        if (code == 9 && olen >= 1)
                        {
                            byte r = f[ofs];
                            double units = (r & 0x80) != 0 ? Math.Pow(2, r & 0x7F) : Math.Pow(10, r);
                            tpu = Math.Max(1, (long)Math.Round(1e7 / units));
                        }
                    }
                    links.Add((link, tpu));
                    break;
                }
                case 6: // EPB
                {
                    int ifid = (int)U32(body);
                    ulong ts = ((ulong)U32(body + 4) << 32) | U32(body + 8);
                    int cap = (int)U32(body + 12), orig = (int)U32(body + 16);
                    int data = body + 20;
                    if (ifid >= links.Count || data + cap > end)
                        break;
                    var dir = PacketDirection.Unknown;
                    int optStart = data + ((cap + 3) & ~3);
                    foreach (var (code, ofs, olen) in Options(f, optStart, end, U16))
                    {
                        if (code == 2 && olen == 4)
                            dir = (PacketDirection)(U32(ofs) & 3);
                    }
                    var time = DateTime.UnixEpoch.AddTicks((long)ts * links[ifid].TicksPerUnit);
                    if (StripLink(links[ifid].Link, f.AsMemory(data, cap), out var l3, out var linkDir))
                        list.Add(new CapturedPacket(time, l3, orig, dir != PacketDirection.Unknown ? dir : linkDir));
                    break;
                }
                case 3: // SPB: no timestamp, interface 0
                {
                    if (links.Count == 0)
                        break;
                    int orig = (int)U32(body);
                    int cap = Math.Min(orig, end - body - 4);
                    if (StripLink(links[0].Link, f.AsMemory(body + 4, cap), out var l3, out var linkDir))
                        list.Add(new CapturedPacket(DateTime.UnixEpoch, l3, orig, linkDir));
                    break;
                }
            }
            pos += len;
        }
        return list;
    }

    private static IEnumerable<(int Code, int Offset, int Length)> Options(byte[] f, int pos, int end, Func<int, ushort> u16)
    {
        while (pos + 4 <= end)
        {
            int code = u16(pos), len = u16(pos + 2);
            if (code == 0 || pos + 4 + len > end)
                yield break;
            yield return (code, pos + 4, len);
            pos += 4 + ((len + 3) & ~3);
        }
    }

    /// <summary>Removes the link-layer header, leaving the IP packet. False for non-IP frames.</summary>
    public static bool StripLink(int link, ReadOnlyMemory<byte> frame, out ReadOnlyMemory<byte> l3, out PacketDirection dir)
    {
        var s = frame.Span;
        l3 = default;
        dir = PacketDirection.Unknown;
        int ethertype;
        int ofs;
        switch (link)
        {
            case 101 or 12 or 14:
                l3 = frame;
                return frame.Length > 0 && (s[0] >> 4) is 4 or 6;
            case 1:
                if (s.Length < 14)
                    return false;
                ofs = 12;
                ethertype = BinaryPrimitives.ReadUInt16BigEndian(s[ofs..]);
                while (ethertype is 0x8100 or 0x88A8 && s.Length >= ofs + 6)
                {
                    ofs += 4;
                    ethertype = BinaryPrimitives.ReadUInt16BigEndian(s[ofs..]);
                }
                ofs += 2;
                break;
            case 113: // SLL: pkttype(2) hatype(2) halen(2) addr(8) protocol(2)
                if (s.Length < 16)
                    return false;
                dir = BinaryPrimitives.ReadUInt16BigEndian(s) == 4 ? PacketDirection.Outbound : PacketDirection.Inbound;
                ethertype = BinaryPrimitives.ReadUInt16BigEndian(s[14..]);
                ofs = 16;
                break;
            case 276: // SLL2: protocol(2) reserved(2) ifindex(4) hatype(2) pkttype(1) halen(1) addr(8)
                if (s.Length < 20)
                    return false;
                ethertype = BinaryPrimitives.ReadUInt16BigEndian(s);
                dir = s[10] == 4 ? PacketDirection.Outbound : PacketDirection.Inbound;
                ofs = 20;
                break;
            case 0 or 108: // 4-byte address family, host or network order
                if (s.Length < 4)
                    return false;
                l3 = frame[4..];
                return l3.Length > 0 && (l3.Span[0] >> 4) is 4 or 6;
            default:
                return false;
        }
        if (ethertype is not (0x0800 or 0x86DD) || ofs >= s.Length)
            return false;
        l3 = frame[ofs..];
        return true;
    }
}
