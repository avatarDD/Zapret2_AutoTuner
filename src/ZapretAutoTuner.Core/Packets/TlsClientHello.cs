using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ZapretAutoTuner.Core.Packets;

public enum TlsParseStatus
{
    Ok,

    /// <summary>The bytes so far are a valid prefix: the ClientHello continues in the next segment(s).</summary>
    NeedMore,

    NotTls,
}

/// <summary>
/// A parsed TLS ClientHello (from TCP records or QUIC CRYPTO frames): what the classifier and client profiles need —
/// SNI, ALPN, versions, groups (kyber), ECH, size — plus JA3 and JA4 fingerprints.
/// </summary>
public sealed class TlsClientHello
{
    public const ushort ExtServerName = 0x0000;
    public const ushort ExtSupportedGroups = 0x000A;
    public const ushort ExtSignatureAlgorithms = 0x000D;
    public const ushort ExtAlpn = 0x0010;
    public const ushort ExtPadding = 0x0015;
    public const ushort ExtPreSharedKey = 0x0029;
    public const ushort ExtSupportedVersions = 0x002B;
    public const ushort ExtKeyShare = 0x0033;
    public const ushort ExtEcPointFormats = 0x000B;
    public const ushort ExtEch = 0xFE0D;

    /// <summary>Post-quantum hybrid groups ("kyber"): X25519MLKEM768, X25519Kyber768Draft00, SecP256r1MLKEM768, SecP384r1MLKEM1024, pure ML-KEM.</summary>
    public static readonly IReadOnlySet<ushort> PostQuantumGroups = new HashSet<ushort> { 0x11EC, 0x6399, 0x11EB, 0x11ED, 0x0200, 0x0201, 0x0202 };

    public ushort LegacyVersion { get; private init; }

    public byte[] SessionId { get; private init; } = [];

    public List<ushort> CipherSuites { get; } = [];

    /// <summary>Extension types in wire order (GREASE included).</summary>
    public List<ushort> Extensions { get; } = [];

    public string? Sni { get; private set; }

    public List<string> Alpn { get; } = [];

    public List<ushort> SupportedVersions { get; } = [];

    public List<ushort> SupportedGroups { get; } = [];

    public List<ushort> SignatureAlgorithms { get; } = [];

    public List<ushort> KeyShareGroups { get; } = [];

    public List<byte> EcPointFormats { get; } = [];

    /// <summary>Length of the handshake message (type and length bytes included).</summary>
    public int HandshakeLength { get; private init; }

    public bool HasEch => Extensions.Contains(ExtEch);

    public bool HasPostQuantumKeyShare => KeyShareGroups.Any(PostQuantumGroups.Contains);

    public bool OffersPostQuantum => SupportedGroups.Any(PostQuantumGroups.Contains);

    /// <summary>Highest offered version: supported_versions without GREASE, else legacy_version.</summary>
    public ushort MaxVersion => SupportedVersions.Where(v => !IsGrease(v)).DefaultIfEmpty(LegacyVersion).Max();

    public static bool IsGrease(ushort v) => (v & 0x0F0F) == 0x0A0A && (v >> 8) == (v & 0xFF);

    /// <summary>
    /// Parses a ClientHello from the start of a TCP stream (TLS records, possibly several, possibly cut).
    /// </summary>
    public static TlsParseStatus TryParseRecords(ReadOnlySpan<byte> stream, out TlsClientHello? hello)
    {
        hello = null;
        // gather handshake bytes from consecutive handshake records
        var hs = new List<byte>();
        int pos = 0;
        while (true)
        {
            if (stream.Length - pos < 5)
                return pos == 0 && stream.Length > 0 && stream[0] != 0x16 ? TlsParseStatus.NotTls : TlsParseStatus.NeedMore;
            if (stream[pos] != 0x16 || stream[pos + 1] != 3)
                return TlsParseStatus.NotTls;
            int rlen = BinaryPrimitives.ReadUInt16BigEndian(stream[(pos + 3)..]);
            if (rlen == 0 || rlen > 16384 + 2048)
                return TlsParseStatus.NotTls;
            int avail = Math.Min(rlen, stream.Length - pos - 5);
            hs.AddRange(stream.Slice(pos + 5, avail));
            if (hs.Count >= 4)
            {
                if (hs[0] != 1)
                    return TlsParseStatus.NotTls;
                int need = 4 + ((hs[1] << 16) | (hs[2] << 8) | hs[3]);
                if (hs.Count >= need)
                    return TryParseHandshake(hs.ToArray().AsSpan(0, need), out hello);
            }
            if (avail < rlen)
                return TlsParseStatus.NeedMore;
            pos += 5 + rlen;
        }
    }

    /// <summary>Parses a handshake message (type 1, 3-byte length, body), e.g. from QUIC CRYPTO frames.</summary>
    public static TlsParseStatus TryParseHandshake(ReadOnlySpan<byte> m, out TlsClientHello? hello)
    {
        hello = null;
        if (m.Length < 4)
            return TlsParseStatus.NeedMore;
        if (m[0] != 1)
            return TlsParseStatus.NotTls;
        int len = (m[1] << 16) | (m[2] << 8) | m[3];
        if (m.Length < 4 + len)
            return TlsParseStatus.NeedMore;
        try
        {
            hello = Parse(m.Slice(4, len), 4 + len);
            return TlsParseStatus.Ok;
        }
        catch (Exception e) when (e is ArgumentOutOfRangeException or IndexOutOfRangeException or FormatException)
        {
            return TlsParseStatus.NotTls;
        }
    }

    private static TlsClientHello Parse(ReadOnlySpan<byte> b, int total)
    {
        int p = 0;
        ushort U16(ReadOnlySpan<byte> s, int o) => BinaryPrimitives.ReadUInt16BigEndian(s[o..]);
        var legacy = U16(b, p);
        p += 2 + 32;
        int sidLen = b[p++];
        var sid = b.Slice(p, sidLen).ToArray();
        p += sidLen;
        var ch = new TlsClientHello { LegacyVersion = legacy, SessionId = sid, HandshakeLength = total };
        int csLen = U16(b, p);
        p += 2;
        for (int i = 0; i < csLen; i += 2)
            ch.CipherSuites.Add(U16(b, p + i));
        p += csLen;
        int compLen = b[p++];
        p += compLen;
        if (p + 2 > b.Length)
            return ch; // no extensions (SSLv3-style hello)
        int extEnd = p + 2 + U16(b, p);
        p += 2;
        if (extEnd > b.Length)
            throw new FormatException("extensions overflow");
        while (p + 4 <= extEnd)
        {
            ushort type = U16(b, p);
            int len = U16(b, p + 2);
            var e = b.Slice(p + 4, len);
            ch.Extensions.Add(type);
            ch.ParseExtension(type, e);
            p += 4 + len;
        }
        return ch;
    }

    private void ParseExtension(ushort type, ReadOnlySpan<byte> e)
    {
        static ushort U16(ReadOnlySpan<byte> s, int o) => BinaryPrimitives.ReadUInt16BigEndian(s[o..]);
        switch (type)
        {
            case ExtServerName:
            {
                int end = 2 + U16(e, 0);
                for (int p = 2; p + 3 <= end;)
                {
                    int nlen = U16(e, p + 1);
                    if (e[p] == 0)
                        Sni = Encoding.ASCII.GetString(e.Slice(p + 3, nlen));
                    p += 3 + nlen;
                }
                break;
            }
            case ExtAlpn:
            {
                int end = 2 + U16(e, 0);
                for (int p = 2; p < end;)
                {
                    int l = e[p];
                    Alpn.Add(Encoding.ASCII.GetString(e.Slice(p + 1, l)));
                    p += 1 + l;
                }
                break;
            }
            case ExtSupportedVersions:
                for (int p = 1; p + 1 < 1 + e[0]; p += 2)
                    SupportedVersions.Add(U16(e, p));
                break;
            case ExtSupportedGroups:
                for (int p = 2; p + 1 < 2 + U16(e, 0); p += 2)
                    SupportedGroups.Add(U16(e, p));
                break;
            case ExtSignatureAlgorithms:
                for (int p = 2; p + 1 < 2 + U16(e, 0); p += 2)
                    SignatureAlgorithms.Add(U16(e, p));
                break;
            case ExtKeyShare:
            {
                int end = 2 + U16(e, 0);
                for (int p = 2; p + 4 <= end;)
                {
                    KeyShareGroups.Add(U16(e, p));
                    p += 4 + U16(e, p + 2);
                }
                break;
            }
            case ExtEcPointFormats:
                for (int p = 1; p < 1 + e[0]; p++)
                    EcPointFormats.Add(e[p]);
                break;
        }
    }

    private static string VersionCode(ushort v) => v switch
    {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xFEFF => "d1",
        0xFEFD => "d2",
        0xFEFC => "d3",
        _ => "00",
    };

    private static string Hex4(ushort v) => v.ToString("x4", CultureInfo.InvariantCulture);

    private static string Hash12(string s) => s.Length == 0
        ? "000000000000"
        : Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(s)))[..12];

    private string AlpnCode()
    {
        if (Alpn.Count == 0 || Alpn[0].Length == 0)
            return "00";
        var a = Alpn[0];
        if (char.IsAsciiLetterOrDigit(a[0]) && char.IsAsciiLetterOrDigit(a[^1]))
            return $"{a[0]}{a[^1]}";
        var hex = Convert.ToHexStringLower(Encoding.Latin1.GetBytes(a));
        return $"{hex[0]}{hex[^1]}";
    }

    /// <summary>JA4 parts before hashing: (a, sorted ciphers, sorted extensions + "_" + signature algorithms).</summary>
    public (string A, string Ciphers, string Extensions) Ja4Parts(bool quic = false)
    {
        var ciphers = CipherSuites.Where(c => !IsGrease(c)).ToList();
        var exts = Extensions.Where(x => !IsGrease(x)).ToList();
        var a = $"{(quic ? 'q' : 't')}{VersionCode(MaxVersion)}{(Sni is null ? 'i' : 'd')}" +
                $"{Math.Min(ciphers.Count, 99):D2}{Math.Min(exts.Count, 99):D2}{AlpnCode()}";
        var c = string.Join(',', ciphers.Select(Hex4).Order(StringComparer.Ordinal));
        var e = string.Join(',', exts.Where(x => x is not ExtServerName and not ExtAlpn).Select(Hex4).Order(StringComparer.Ordinal));
        var sig = SignatureAlgorithms.Where(x => !IsGrease(x)).Select(Hex4).ToList();
        if (sig.Count > 0)
            e += "_" + string.Join(',', sig);
        return (a, c, e);
    }

    /// <summary>JA4 (FoxIO): <c>t13d1516h2_8daaf6152771_02713d6af862</c>.</summary>
    public string Ja4(bool quic = false)
    {
        var (a, c, e) = Ja4Parts(quic);
        bool noExt = Extensions.All(x => IsGrease(x) || x is ExtServerName or ExtAlpn);
        return $"{a}_{Hash12(c)}_{(noExt ? "000000000000" : Hash12(e))}";
    }

    /// <summary>JA4_r: the raw, unhashed form.</summary>
    public string Ja4Raw(bool quic = false)
    {
        var (a, c, e) = Ja4Parts(quic);
        return $"{a}_{c}_{e}";
    }

    /// <summary>JA3 string <c>version,ciphers,extensions,groups,point formats</c> (GREASE removed).</summary>
    public string Ja3String()
    {
        static string J(IEnumerable<ushort> v) => string.Join('-', v.Where(x => !IsGrease(x)).Select(x => x.ToString(CultureInfo.InvariantCulture)));
        return $"{LegacyVersion},{J(CipherSuites)},{J(Extensions)},{J(SupportedGroups)},{string.Join('-', EcPointFormats)}";
    }

    public string Ja3() => Convert.ToHexStringLower(MD5.HashData(Encoding.ASCII.GetBytes(Ja3String())));
}
