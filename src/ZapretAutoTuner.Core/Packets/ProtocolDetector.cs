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
/// Recognises the first client payload of a flow the way nfqws2's <c>protocol.c</c> does, so that a program's flows
/// map to the engine's <c>--filter-l7</c> and <c>--payload</c> names (dpi-diagnostics §8). MTProto has no signature
/// (obfuscated2 is 64 random bytes): it is guessed from the length and Telegram's networks.
/// </summary>
public static class ProtocolDetector
{
    /// <summary>Telegram's announced networks (AS62041, AS59930, AS62014, AS211157, AS44907).</summary>
    public static IReadOnlyList<(IPAddress Network, int Prefix)> TelegramNetworks { get; } =
    [
        .. new[]
        {
            "91.105.192.0/23", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
            "91.108.56.0/22", "95.161.64.0/20", "149.154.160.0/20", "185.76.151.0/24",
            "2001:67c:4e8::/48", "2001:b28:f23c::/46", "2001:b28:f23f::/48", "2a0a:f280::/32",
        }.Select(c => (IPAddress.Parse(c[..c.IndexOf('/', StringComparison.Ordinal)]), int.Parse(c[(c.IndexOf('/', StringComparison.Ordinal) + 1)..], System.Globalization.CultureInfo.InvariantCulture))),
    ];

    public static AppProtocol DetectUdp(ReadOnlySpan<byte> p, int serverPort)
    {
        if (QuicInitial.IsInitial(p))
            return AppProtocol.Quic;
        if (IsStun(p))
            return AppProtocol.Stun;
        if (IsDiscordIpDiscovery(p))
            return AppProtocol.Discord;
        if (IsWireGuard(p))
            return AppProtocol.WireGuard;
        if (p.Length >= 13 && p[0] is >= 20 and <= 23 && p[1] == 0xFE)
            return AppProtocol.Dtls;
        return serverPort == 53 ? AppProtocol.Dns : AppProtocol.Unknown;
    }

    public static AppProtocol DetectTcp(ReadOnlySpan<byte> p, IPAddress server)
    {
        if (p.Length >= 3 && p[0] == 0x16 && p[1] == 0x03)
            return AppProtocol.Tls;
        if (IsHttpRequest(p))
            return AppProtocol.Http;
        // abridged (0xef) and intermediate/padded (0xee×4, 0xdd×4) transports start with a tag; obfuscated2 is 64
        // random bytes, told apart only by where it goes
        if (p.Length > 0 && (p[0] == 0xef || (p.Length >= 4 && (BinaryPrimitives.ReadUInt32BigEndian(p) is 0xeeeeeeee or 0xdddddddd))))
            return AppProtocol.Mtproto;
        if (p.Length >= 64 && InTelegram(server))
            return AppProtocol.Mtproto;
        return AppProtocol.Unknown;
    }

    /// <summary>RFC 5389: two zero bits, a length that matches, the magic cookie.</summary>
    public static bool IsStun(ReadOnlySpan<byte> p) =>
        p.Length >= 20 && (p[0] & 0xC0) == 0 && BinaryPrimitives.ReadUInt32BigEndian(p[4..]) == 0x2112A442
        && BinaryPrimitives.ReadUInt16BigEndian(p[2..]) + 20 == p.Length;

    /// <summary>Discord voice IP discovery: type 1, length 70, 74 bytes in all.</summary>
    public static bool IsDiscordIpDiscovery(ReadOnlySpan<byte> p) =>
        p.Length == 74 && BinaryPrimitives.ReadUInt16BigEndian(p) == 1 && BinaryPrimitives.ReadUInt16BigEndian(p[2..]) == 70;

    /// <summary>WireGuard: message type 1–4, three reserved zero bytes, the fixed size of the type.</summary>
    public static bool IsWireGuard(ReadOnlySpan<byte> p) =>
        p.Length >= 32 && p[1] == 0 && p[2] == 0 && p[3] == 0 && p[0] switch
        {
            1 => p.Length == 148,
            2 => p.Length == 92,
            3 => p.Length == 64,
            4 => p.Length % 16 == 0,
            _ => false,
        };

    private static bool IsHttpRequest(ReadOnlySpan<byte> p)
    {
        foreach (var m in new[] { "GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "DELETE ", "CONNECT ", "PATCH " })
        {
            if (p.Length >= m.Length && p[..m.Length].SequenceEqual(System.Text.Encoding.ASCII.GetBytes(m)))
                return true;
        }
        return false;
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
