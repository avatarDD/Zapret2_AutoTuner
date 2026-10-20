using System.Buffers.Binary;
using System.Net;

namespace ZapretAutoTuner.Core.Packets;

/// <summary>What a flow speaks, as far as the engine's own detector can tell it apart (nfqws2-engine §5, protocol.c).</summary>
public enum AppProtocol
{
    Unknown,
    Tls,
    Http,
    Quic,
    Stun,
    WireGuard,
    Discord,
    Dtls,
    Dns,
    Mtproto,
}

/// <summary>
/// Recognises the first client payload of a flow exactly the way nfqws2's <c>protocol.c</c> does (the testers and their
/// order in <c>desync.c</c>), so that a program's flows map to the engine's <c>--filter-l7</c> and <c>--payload</c>
/// names (dpi-diagnostics §8). A flow the engine would call unknown is unknown here too: a strategy filtered by a
/// payload type the engine never assigns would do nothing.
/// </summary>
public static class ProtocolDetector
{
    /// <summary>Telegram's announced networks (AS62041, AS59930, AS62014, AS211157, AS44907). Not used for detection
    /// (the engine does not look at addresses); kept for reports and provider lists.</summary>
    public static IReadOnlyList<(IPAddress Network, int Prefix)> TelegramNetworks { get; } =
    [
        .. new[]
        {
            "91.105.192.0/23", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
            "91.108.56.0/22", "95.161.64.0/20", "149.154.160.0/20", "185.76.151.0/24",
            "2001:67c:4e8::/48", "2001:b28:f23c::/46", "2001:b28:f23f::/48", "2a0a:f280::/32",
        }.Select(c => (IPAddress.Parse(c[..c.IndexOf('/', StringComparison.Ordinal)]), int.Parse(c[(c.IndexOf('/', StringComparison.Ordinal) + 1)..], System.Globalization.CultureInfo.InvariantCulture))),
    ];

    /// <summary>
    /// udp_standard_protocol_probe: QUIC Initial, Discord IP discovery, STUN, DNS query/response, (DHT), DTLS
    /// ClientHello/ServerHello, (uTP), WireGuard initiation/response/cookie/keepalive. WireGuard data is recognised by
    /// the engine only in a flow already known as WireGuard (<paramref name="knownWireGuard"/>).
    /// </summary>
    public static AppProtocol DetectUdp(ReadOnlySpan<byte> p, bool knownWireGuard = false)
    {
        if (QuicInitial.IsInitial(p))
            return AppProtocol.Quic;
        if (IsDiscordIpDiscovery(p))
            return AppProtocol.Discord;
        if (IsStun(p))
            return AppProtocol.Stun;
        if (IsDnsQuery(p) || IsDnsResponse(p))
            return AppProtocol.Dns;
        if (IsDtls(p) && p[0] == 0x16 && p[13] is 1 or 2)
            return AppProtocol.Dtls;
        if (IsWireGuard(p) || (knownWireGuard && IsWireGuardData(p)))
            return AppProtocol.WireGuard;
        return AppProtocol.Unknown;
    }

    /// <summary>The TCP testers: TLS ClientHello (partial is fine), HTTP request, then MTProto on the first data packet.</summary>
    public static AppProtocol DetectTcp(ReadOnlySpan<byte> p)
    {
        if (IsTlsClientHelloPartial(p))
            return AppProtocol.Tls;
        if (IsHttpRequest(p))
            return AppProtocol.Http;
        if (IsMtproto(p))
            return AppProtocol.Mtproto;
        return AppProtocol.Unknown;
    }

    /// <summary>IsStunMessage: two zero bits, a length that is a multiple of 4 and fits, the magic cookie.</summary>
    public static bool IsStun(ReadOnlySpan<byte> p) =>
        p.Length >= 20 && (p[0] & 0xC0) == 0 && (p[3] & 3) == 0 && BinaryPrimitives.ReadUInt32BigEndian(p[4..]) == 0x2112A442
        && BinaryPrimitives.ReadUInt16BigEndian(p[2..]) <= p.Length - 20;

    /// <summary>IsDiscordIpDiscoveryRequest: type 1, length 70, 74 bytes in all, the 64-byte address still zero.</summary>
    public static bool IsDiscordIpDiscovery(ReadOnlySpan<byte> p) =>
        p.Length == 74 && p[0] == 0 && p[1] == 1 && p[2] == 0 && p[3] == 70 && !p.Slice(8, 64).ContainsAnyExcept((byte)0);

    /// <summary>The WireGuard messages the engine recognises in any flow: initiation 148, response 92, cookie 64,
    /// keepalive 32 bytes, each with its type and three zero bytes.</summary>
    public static bool IsWireGuard(ReadOnlySpan<byte> p) =>
        p.Length >= 4 && BinaryPrimitives.ReadUInt32BigEndian(p) switch
        {
            0x01000000 => p.Length == 148,
            0x02000000 => p.Length == 92,
            0x03000000 => p.Length == 64,
            0x04000000 => p.Length == 32,
            _ => false,
        };

    /// <summary>IsWireguardData: type 4 and at least 52 bytes (only in a flow already known as WireGuard).</summary>
    public static bool IsWireGuardData(ReadOnlySpan<byte> p) => p.Length >= 52 && BinaryPrimitives.ReadUInt32BigEndian(p) == 0x04000000;

    /// <summary>IsDTLS: a record type 20–23, version fe ff / fe fd / fe fc / 01 00, a record length that fits.</summary>
    public static bool IsDtls(ReadOnlySpan<byte> p) =>
        p.Length > 13 && p[0] is >= 0x14 and <= 0x17
        && ((p[1] == 0xFE && p[2] is 0xFF or 0xFD or 0xFC) || (p[1] == 0x01 && p[2] == 0x00))
        && BinaryPrimitives.ReadUInt16BigEndian(p[11..]) + 13 <= p.Length;

    /// <summary>IsDNSQuery: QR 0 and standard opcode, one question, no answers or authority, at most 3 additional.</summary>
    public static bool IsDnsQuery(ReadOnlySpan<byte> p) =>
        p.Length >= 12 && (p[2] & 0xFE) == 0 && p.Slice(4, 6).SequenceEqual((ReadOnlySpan<byte>)[0, 1, 0, 0, 0, 0])
        && BinaryPrimitives.ReadUInt16BigEndian(p[10..]) <= 3;

    /// <summary>IsDNSResponse: QR 1 and standard opcode, one question, at most 100 records of each kind.</summary>
    public static bool IsDnsResponse(ReadOnlySpan<byte> p) =>
        p.Length >= 12 && (p[2] & 0xF8) == 0x80 && BinaryPrimitives.ReadUInt16BigEndian(p[4..]) == 1
        && BinaryPrimitives.ReadUInt16BigEndian(p[6..]) <= 100 && BinaryPrimitives.ReadUInt16BigEndian(p[8..]) <= 100
        && BinaryPrimitives.ReadUInt16BigEndian(p[10..]) <= 100;

    /// <summary>IsTLSClientHelloPartial: a handshake record of version 3.x (x ≤ 3) holding a ClientHello header.</summary>
    public static bool IsTlsClientHelloPartial(ReadOnlySpan<byte> p) =>
        p.Length >= 6 && p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x03
        && p.Length - 5 >= 6 && p[5] == 0x01 && p[9] == 0x03 && p[10] <= 0x03;

    /// <summary>
    /// IsMTProto: the obfuscated2 header is 64 bytes; AES-256-CTR with the key at 8..40 and the IV at 40..56 turns
    /// bytes 56..60 into <c>EF EF EF EF</c> (the engine accepts only this tag). Only block 3 of the keystream is needed:
    /// AES(IV + 3), bytes 8..12, XOR the payload at 56..60.
    /// </summary>
    public static bool IsMtproto(ReadOnlySpan<byte> p)
    {
        if (p.Length < 64)
            return false;
        Span<byte> keystream = stackalloc byte[16];
        Obfuscated2Keystream(p, keystream);
        for (int i = 0; i < 4; i++)
        {
            if ((keystream[8 + i] ^ p[56 + i]) != 0xEF)
                return false;
        }
        return true;
    }

    /// <summary>Keystream block 3 of an obfuscated2 header (it covers bytes 48..64).</summary>
    public static void Obfuscated2Keystream(ReadOnlySpan<byte> header, Span<byte> block)
    {
        Span<byte> counter = stackalloc byte[16];
        header.Slice(40, 16).CopyTo(counter);
        // ctr_add(iv, 3): a 128-bit big-endian counter
        ulong lo = BinaryPrimitives.ReadUInt64BigEndian(counter[8..]);
        ulong sum = lo + 3;
        BinaryPrimitives.WriteUInt64BigEndian(counter[8..], sum);
        if (sum < lo)
            BinaryPrimitives.WriteUInt64BigEndian(counter, BinaryPrimitives.ReadUInt64BigEndian(counter) + 1);
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = header.Slice(8, 32).ToArray();
        aes.EncryptEcb(counter, block, System.Security.Cryptography.PaddingMode.None);
    }

    private static readonly string[] HttpMethods = ["GET ", "POST ", "HEAD ", "OPTIONS ", "PUT ", "DELETE ", "CONNECT ", "TRACE ", "PATCH "];

    /// <summary>IsHttp: a known method, a URI, then <c>HTTP/1.</c>.</summary>
    public static bool IsHttpRequest(ReadOnlySpan<byte> p)
    {
        if (p.Length < 4)
            return false;
        bool method = false;
        foreach (var m in HttpMethods)
            method |= StartsWithAscii(p, m);
        if (!method)
            return false;
        int i = 0;
        static bool Space(byte c) => c is (byte)' ' or (byte)'\t';
        static bool Eol(byte c) => c is (byte)'\r' or (byte)'\n';
        while (i < p.Length && !Space(p[i]) && !Eol(p[i]))
            i++;
        if (i == p.Length || !Space(p[i]))
            return false;
        while (i < p.Length && Space(p[i]))
            i++;
        while (i < p.Length && !Space(p[i]) && !Eol(p[i]))
            i++;
        if (i == p.Length || !Space(p[i]))
            return false;
        while (i < p.Length && Space(p[i]))
            i++;
        if (p.Length - i < 10 || Eol(p[i]))
            return false;
        return StartsWithAscii(p[i..], "HTTP/1.");
    }

    private static bool StartsWithAscii(ReadOnlySpan<byte> p, string s)
    {
        if (p.Length < s.Length)
            return false;
        for (int i = 0; i < s.Length; i++)
        {
            if (p[i] != s[i])
                return false;
        }
        return true;
    }

    public static bool InTelegram(IPAddress a) => TelegramNetworks.Any(n => InNetwork(a, n.Network, n.Prefix));

    public static bool InNetwork(IPAddress a, IPAddress network, int prefix)
    {
        if (a.IsIPv4MappedToIPv6)
            a = a.MapToIPv4();
        if (a.AddressFamily != network.AddressFamily)
            return false;
        var x = a.GetAddressBytes();
        var y = network.GetAddressBytes();
        int full = prefix / 8, rest = prefix % 8;
        if (!x.AsSpan(0, full).SequenceEqual(y.AsSpan(0, full)))
            return false;
        return rest == 0 || (x[full] >> (8 - rest)) == (y[full] >> (8 - rest));
    }

    /// <summary>The engine's <c>--filter-l7</c> name, or null when nfqws2 has none for it.</summary>
    public static string? L7Name(AppProtocol p) => p switch
    {
        AppProtocol.Tls => "tls",
        AppProtocol.Http => "http",
        AppProtocol.Quic => "quic",
        AppProtocol.Stun => "stun",
        AppProtocol.WireGuard => "wireguard",
        AppProtocol.Discord => "discord",
        AppProtocol.Dtls => "dtls",
        AppProtocol.Dns => "dns",
        AppProtocol.Mtproto => "mtproto",
        _ => null,
    };
}
