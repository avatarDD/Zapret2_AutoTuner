using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ZapretAutoTuner.Core.Packets;

/// <summary>A CRYPTO frame from a decrypted Initial packet.</summary>
public sealed record QuicCryptoFrame(long Offset, byte[] Data);

/// <summary>A client Initial packet after removing header protection and decrypting (RFC 9001 §5).</summary>
public sealed class QuicInitialPacket
{
    public uint Version { get; init; }

    public byte[] Dcid { get; init; } = [];

    public byte[] Scid { get; init; } = [];

    public long PacketNumber { get; init; }

    public List<QuicCryptoFrame> Crypto { get; } = [];

    /// <summary>Size of this QUIC packet within the datagram.</summary>
    public int PacketLength { get; init; }
}

/// <summary>
/// Decrypts QUIC v1 (RFC 9001) and v2 (RFC 9369) client Initial packets, whose keys derive from the Destination
/// Connection ID, and reassembles the ClientHello from CRYPTO frames spread over one or more datagrams.
/// </summary>
public static class QuicInitial
{
    public const uint Version1 = 0x00000001;
    public const uint Version2 = 0x6B3343CF;

    private static readonly byte[] SaltV1 = Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    private static readonly byte[] SaltV2 = Convert.FromHexString("0dede3def700a6db819381be6e269dcbf9bd2ed9");

    /// <summary>Is the datagram a long-header Initial of a version we can decrypt?</summary>
    public static bool IsInitial(ReadOnlySpan<byte> d)
    {
        if (d.Length < 7 || (d[0] & 0xC0) != 0xC0)
            return false;
        uint v = BinaryPrimitives.ReadUInt32BigEndian(d[1..]);
        int type = (d[0] >> 4) & 3;
        return (v == Version1 && type == 0) || (v == Version2 && type == 1);
    }

    /// <summary>
    /// Initial packets of the datagram (coalesced packets are walked; non-Initial ones are skipped). Packets that do
    /// not decrypt (server Initials, corrupt data) are ignored.
    /// </summary>
    public static List<QuicInitialPacket> DecryptDatagram(ReadOnlySpan<byte> datagram) => DecryptDatagram(datagram, null);

    /// <summary>As <see cref="DecryptDatagram(ReadOnlySpan{byte})"/>; with <paramref name="serverKeyDcid"/> it opens server Initials.</summary>
    public static List<QuicInitialPacket> DecryptDatagram(ReadOnlySpan<byte> datagram, byte[]? serverKeyDcid)
    {
        var list = new List<QuicInitialPacket>();
        int pos = 0;
        while (pos < datagram.Length && (datagram[pos] & 0x80) != 0)
        {
            var rest = datagram[pos..];
            int len = LongPacketLength(rest);
            if (len <= 0)
                break;
            if (IsInitial(rest) && TryDecrypt(rest[..len], serverKeyDcid, out var p))
                list.Add(p!);
            pos += len;
        }
        return list;
    }

    /// <summary>Length of the long-header packet at the start of <paramref name="d"/>, or -1.</summary>
    private static int LongPacketLength(ReadOnlySpan<byte> d)
    {
        if (d.Length < 7)
            return -1;
        int p = 5;
        int dcidLen = d[p++];
        p += dcidLen;
        if (p >= d.Length)
            return -1;
        int scidLen = d[p++];
        p += scidLen;
        uint v = BinaryPrimitives.ReadUInt32BigEndian(d[1..]);
        int type = (d[0] >> 4) & 3;
        bool initial = (v == Version1 && type == 0) || (v == Version2 && type == 1);
        bool retry = (v == Version1 && type == 3) || (v == Version2 && type == 0);
        if (retry)
            return d.Length;
        if (initial)
        {
            if (!ReadVarint(d, ref p, out long tokenLen) || p + tokenLen > d.Length)
                return -1;
            p += (int)tokenLen;
        }
        if (!ReadVarint(d, ref p, out long length) || p + length > d.Length)
            return -1;
        return p + (int)length;
    }

    public static bool TryDecrypt(ReadOnlySpan<byte> pkt, out QuicInitialPacket? result) => TryDecrypt(pkt, null, out result);

    /// <summary>
    /// Decrypts an Initial. With <paramref name="serverKeyDcid"/> (the client's original DCID) it opens a server
    /// Initial; without, a client Initial whose keys derive from its own DCID.
    /// </summary>
    public static bool TryDecrypt(ReadOnlySpan<byte> pkt, byte[]? serverKeyDcid, out QuicInitialPacket? result)
    {
        result = null;
        if (!IsInitial(pkt))
            return false;
        uint version = BinaryPrimitives.ReadUInt32BigEndian(pkt[1..]);
        int p = 5;
        int dcidLen = pkt[p++];
        if (dcidLen > 20 || p + dcidLen >= pkt.Length)
            return false;
        var dcid = pkt.Slice(p, dcidLen).ToArray();
        p += dcidLen;
        int scidLen = pkt[p++];
        if (scidLen > 20 || p + scidLen > pkt.Length)
            return false;
        var scid = pkt.Slice(p, scidLen).ToArray();
        p += scidLen;
        if (!ReadVarint(pkt, ref p, out long tokenLen) || p + tokenLen > pkt.Length)
            return false;
        p += (int)tokenLen;
        if (!ReadVarint(pkt, ref p, out long length) || p + length > pkt.Length || length < 20)
            return false;
        int pnOffset = p;
        int end = pnOffset + (int)length;

        var (key, iv, hp) = serverKeyDcid is null ? ClientKeys(dcid, version) : ServerKeys(serverKeyDcid, version);

        // header protection: sample starts 4 bytes after the packet number offset
        if (pnOffset + 4 + 16 > end)
            return false;
        var mask = new byte[16];
        using (var aes = Aes.Create())
        {
            aes.Key = hp;
            aes.EncryptEcb(pkt.Slice(pnOffset + 4, 16), mask, PaddingMode.None);
        }
        var header = pkt[..(pnOffset + 4)].ToArray();
        header[0] ^= (byte)(mask[0] & 0x0F);
        int pnLen = (header[0] & 3) + 1;
        long pn = 0;
        for (int i = 0; i < pnLen; i++)
        {
            header[pnOffset + i] ^= mask[1 + i];
            pn = (pn << 8) | header[pnOffset + i];
        }
        var aad = header.AsSpan(0, pnOffset + pnLen);

        var nonce = (byte[])iv.Clone();
        for (int i = 0; i < 8; i++)
            nonce[nonce.Length - 1 - i] ^= (byte)(pn >> (8 * i));

        var cipher = pkt[(pnOffset + pnLen)..(end - 16)];
        var tag = pkt[(end - 16)..end];
        var plain = new byte[cipher.Length];
        try
        {
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(nonce, cipher, tag, plain, aad);
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }

        var r = new QuicInitialPacket { Version = version, Dcid = dcid, Scid = scid, PacketNumber = pn, PacketLength = end };
        if (!ParseFrames(plain, r.Crypto))
            return false;
        result = r;
        return true;
    }

    private static bool ParseFrames(ReadOnlySpan<byte> f, List<QuicCryptoFrame> crypto)
    {
        int p = 0;
        while (p < f.Length)
        {
            if (!ReadVarint(f, ref p, out long type))
                return false;
            switch (type)
            {
                case 0x00: // PADDING
                case 0x01: // PING
                    break;
                case 0x02:
                case 0x03: // ACK
                {
                    if (!ReadVarint(f, ref p, out _) || !ReadVarint(f, ref p, out _) || !ReadVarint(f, ref p, out long ranges) || !ReadVarint(f, ref p, out _))
                        return false;
                    for (long i = 0; i < ranges; i++)
                    {
                        if (!ReadVarint(f, ref p, out _) || !ReadVarint(f, ref p, out _))
                            return false;
                    }
                    if (type == 0x03)
                    {
                        for (int i = 0; i < 3; i++)
                        {
                            if (!ReadVarint(f, ref p, out _))
                                return false;
                        }
                    }
                    break;
                }
                case 0x06: // CRYPTO
                {
                    if (!ReadVarint(f, ref p, out long ofs) || !ReadVarint(f, ref p, out long len) || p + len > f.Length)
                        return false;
                    crypto.Add(new QuicCryptoFrame(ofs, f.Slice(p, (int)len).ToArray()));
                    p += (int)len;
                    break;
                }
                case 0x1C: // CONNECTION_CLOSE
                {
                    if (!ReadVarint(f, ref p, out _) || !ReadVarint(f, ref p, out _) || !ReadVarint(f, ref p, out long rlen) || p + rlen > f.Length)
                        return false;
                    p += (int)rlen;
                    break;
                }
                default:
                    // other frames are not allowed in Initial packets
                    return false;
            }
        }
        return true;
    }

    public static bool ReadVarint(ReadOnlySpan<byte> d, ref int p, out long value)
    {
        value = 0;
        if (p >= d.Length)
            return false;
        int len = 1 << (d[p] >> 6);
        if (p + len > d.Length)
            return false;
        value = d[p] & 0x3F;
        for (int i = 1; i < len; i++)
            value = (value << 8) | d[p + i];
        p += len;
        return true;
    }

    public static (byte[] Key, byte[] Iv, byte[] Hp) ClientKeys(byte[] dcid, uint version) => Keys(dcid, version, "client in");

    /// <summary>Keys of server Initials, derived from the client's original Destination Connection ID.</summary>
    public static (byte[] Key, byte[] Iv, byte[] Hp) ServerKeys(byte[] dcid, uint version) => Keys(dcid, version, "server in");

    private static (byte[] Key, byte[] Iv, byte[] Hp) Keys(byte[] dcid, uint version, string side)
    {
        bool v2 = version == Version2;
        var initial = HKDF.Extract(HashAlgorithmName.SHA256, dcid, v2 ? SaltV2 : SaltV1);
        var secret = ExpandLabel(initial, side, 32);
        var prefix = v2 ? "quicv2 " : "quic ";
        return (ExpandLabel(secret, prefix + "key", 16), ExpandLabel(secret, prefix + "iv", 12), ExpandLabel(secret, prefix + "hp", 16));
    }

    /// <summary>
    /// Builds Initial datagrams carrying <paramref name="crypto"/> (a ClientHello, or a ServerHello for test servers)
    /// in CRYPTO frames, split over as many datagrams as needed and padded to <paramref name="datagramSize"/> like
    /// browsers do. Keys come from <paramref name="keyDcid"/> (client: its DCID; server: the client's original DCID).
    /// </summary>
    public static List<byte[]> BuildInitials(byte[] crypto, byte[] dcid, byte[] scid, uint version = Version1, bool server = false,
        byte[]? keyDcid = null, int datagramSize = 1200, long firstPacketNumber = 0)
    {
        var (key, iv, hp) = server ? ServerKeys(keyDcid ?? dcid, version) : ClientKeys(keyDcid ?? dcid, version);
        int type = version == Version2 ? 1 : 0;
        const int pnLen = 2;
        var header = new List<byte> { (byte)(0xC0 | (type << 4) | (pnLen - 1)) };
        header.AddRange([(byte)(version >> 24), (byte)(version >> 16), (byte)(version >> 8), (byte)version]);
        header.Add((byte)dcid.Length);
        header.AddRange(dcid);
        header.Add((byte)scid.Length);
        header.AddRange(scid);
        header.Add(0); // token length
        int headerLen = header.Count + 2 + pnLen; // + 2-byte length varint + packet number
        int room = datagramSize - headerLen - 16 - 9; // tag, CRYPTO frame type/offset/length varints
        if (room < 64)
            throw new ArgumentOutOfRangeException(nameof(datagramSize));

        var datagrams = new List<byte[]>();
        long pn = firstPacketNumber;
        for (int offset = 0; offset < crypto.Length || datagrams.Count == 0; offset += room, pn++)
        {
            int n = Math.Min(room, crypto.Length - offset);
            var frames = new List<byte> { 0x06 };
            AppendVarint(frames, offset);
            AppendVarint(frames, n);
            frames.AddRange(crypto.AsSpan(offset, n));
            int payloadLen = Math.Max(frames.Count, datagramSize - headerLen - 16);
            frames.AddRange(new byte[payloadLen - frames.Count]); // PADDING frames

            var hdr = new List<byte>(header);
            int length = pnLen + payloadLen + 16;
            hdr.Add((byte)(0x40 | (length >> 8)));
            hdr.Add((byte)length);
            int pnOffset = hdr.Count;
            hdr.Add((byte)(pn >> 8));
            hdr.Add((byte)pn);
            var aad = hdr.ToArray();

            var nonce = (byte[])iv.Clone();
            for (int i = 0; i < 8; i++)
                nonce[nonce.Length - 1 - i] ^= (byte)(pn >> (8 * i));
            var cipher = new byte[payloadLen];
            var tag = new byte[16];
            using (var gcm = new AesGcm(key, 16))
                gcm.Encrypt(nonce, frames.ToArray(), cipher, tag, aad);

            var pkt = new byte[aad.Length + cipher.Length + 16];
            aad.CopyTo(pkt, 0);
            cipher.CopyTo(pkt, aad.Length);
            tag.CopyTo(pkt, aad.Length + cipher.Length);

            var mask = new byte[16];
            using (var aes = Aes.Create())
            {
                aes.Key = hp;
                aes.EncryptEcb(pkt.AsSpan(pnOffset + 4, 16), mask, PaddingMode.None);
            }
            pkt[0] ^= (byte)(mask[0] & 0x0F);
            for (int i = 0; i < pnLen; i++)
                pkt[pnOffset + i] ^= mask[1 + i];
            datagrams.Add(pkt);
        }
        return datagrams;
    }

    private static void AppendVarint(List<byte> b, long v)
    {
        if (v < 0x40)
        {
            b.Add((byte)v);
        }
        else if (v < 0x4000)
        {
            b.Add((byte)(0x40 | (v >> 8)));
            b.Add((byte)v);
        }
        else
        {
            b.Add((byte)(0x80 | (v >> 24)));
            b.Add((byte)(v >> 16));
            b.Add((byte)(v >> 8));
            b.Add((byte)v);
        }
    }

    /// <summary>HKDF-Expand-Label from TLS 1.3 (RFC 8446 §7.1) with an empty context.</summary>
    public static byte[] ExpandLabel(byte[] secret, string label, int length)
    {
        var full = Encoding.ASCII.GetBytes("tls13 " + label);
        var info = new byte[2 + 1 + full.Length + 1];
        BinaryPrimitives.WriteUInt16BigEndian(info, (ushort)length);
        info[2] = (byte)full.Length;
        full.CopyTo(info, 3);
        info[^1] = 0;
        return HKDF.Expand(HashAlgorithmName.SHA256, secret, length, info);
    }

    /// <summary>
    /// The ClientHello from client Initial datagrams (Chrome splits a kyber CH over two or more). CRYPTO frames are
    /// placed by offset; parsing succeeds once the bytes from offset 0 cover the whole handshake message.
    /// </summary>
    public static TlsParseStatus TryParseClientHello(IEnumerable<ReadOnlyMemory<byte>> datagrams, out TlsClientHello? hello, out QuicInitialPacket? first)
    {
        hello = null;
        first = null;
        var buf = new SortedDictionary<long, byte[]>();
        byte[]? dcid = null;
        bool any = false;
        foreach (var d in datagrams)
        {
            foreach (var pkt in DecryptDatagram(d.Span))
            {
                // only the first connection's packets (same original DCID)
                dcid ??= pkt.Dcid;
                if (!pkt.Dcid.AsSpan().SequenceEqual(dcid))
                    continue;
                first ??= pkt;
                any = true;
                foreach (var c in pkt.Crypto)
                    buf[c.Offset] = c.Data;
            }
            var contiguous = Contiguous(buf);
            if (contiguous.Length > 0)
            {
                var st = TlsClientHello.TryParseHandshake(contiguous, out hello);
                if (st != TlsParseStatus.NeedMore)
                    return st;
            }
        }
        return any ? TlsParseStatus.NeedMore : TlsParseStatus.NotTls;
    }

    private static byte[] Contiguous(SortedDictionary<long, byte[]> frames)
    {
        using var ms = new MemoryStream();
        long next = 0;
        foreach (var (ofs, data) in frames)
        {
            if (ofs > next)
                break;
            long skip = next - ofs;
            if (skip < data.Length)
            {
                ms.Write(data, (int)skip, data.Length - (int)skip);
                next = ofs + data.Length;
            }
        }
        return ms.ToArray();
    }
}
