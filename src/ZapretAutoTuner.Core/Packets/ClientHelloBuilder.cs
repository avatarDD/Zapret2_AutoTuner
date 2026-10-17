using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZapretAutoTuner.Core.Packets;

/// <summary>The shape of a real client's ClientHello (data, <c>Packets/Data/client-hellos.json</c>).</summary>
public sealed class ClientHelloSpec
{
    // settable, not init: the JSON source generator would reset init-only properties missing from the file to null

    public string Id { get; set; } = "";

    public string Name { get; set; } = "";

    public string Source { get; set; } = "";

    public string RecordVersion { get; set; } = "0301";

    public string LegacyVersion { get; set; } = "0303";

    /// <summary>A 32-byte legacy session id (TLS 1.3 middlebox compatibility).</summary>
    public bool SessionId { get; set; } = true;

    /// <summary>Chrome shuffles extensions (except GREASE and padding) in every hello.</summary>
    public bool PermuteExtensions { get; set; }

    public List<string> Ciphers { get; set; } = [];

    public List<string> Extensions { get; set; } = [];

    public List<string> SignatureAlgorithms { get; set; } = [];

    public List<string> DelegatedCredentials { get; set; } = [];

    public List<string> Groups { get; set; } = [];

    public List<string> KeyShares { get; set; } = [];

    public List<string> Versions { get; set; } = [];

    public List<string> Alpn { get; set; } = [];

    /// <summary>ALPS (application_settings) protocols.</summary>
    public List<string> Alps { get; set; } = [];

    public List<int> CertCompression { get; set; } = [];

    public List<int> PskModes { get; set; } = [];

    public int? RecordSizeLimit { get; set; }

    private static readonly Lazy<IReadOnlyList<ClientHelloSpec>> AllLazy = new(() =>
    {
        using var s = typeof(ClientHelloSpec).Assembly.GetManifestResourceStream("ZapretAutoTuner.Core.Packets.client-hellos.json")
            ?? throw new InvalidOperationException("client-hellos.json is missing");
        return JsonSerializer.Deserialize(s, PacketsJsonContext.Default.ClientHelloSpecFile)?.Specs
            ?? throw new InvalidOperationException("client-hellos.json is empty");
    });

    public static IReadOnlyList<ClientHelloSpec> All => AllLazy.Value;

    public static ClientHelloSpec Get(string id) =>
        All.FirstOrDefault(s => s.Id == id) ?? throw new KeyNotFoundException($"нет профиля ClientHello '{id}'");

    public override string ToString() => Id;
}

public sealed class ClientHelloSpecFile
{
    public List<ClientHelloSpec> Specs { get; init; } = [];
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true)]
[JsonSerializable(typeof(ClientHelloSpecFile))]
internal sealed partial class PacketsJsonContext : JsonSerializerContext;

/// <summary>Per-hello choices on top of a spec.</summary>
public sealed record ClientHelloOptions
{
    /// <summary>SNI; null or an IP address means no server_name extension.</summary>
    public string? Sni { get; init; }

    /// <summary>Keep post-quantum groups and key shares (X25519MLKEM768…). False removes them.</summary>
    public bool Kyber { get; init; } = true;

    /// <summary>Send an ECH GREASE extension; null keeps the spec as it is.</summary>
    public bool? Ech { get; init; }

    /// <summary>Overrides the spec's ALPN (h3 for QUIC).</summary>
    public IReadOnlyList<string>? Alpn { get; init; }

    /// <summary>QUIC: no TLS 1.2 ciphers, no record layer extensions, transport parameters with this source CID.</summary>
    public byte[]? QuicScid { get; init; }

    /// <summary>Fixed randomness for reproducible tests.</summary>
    public int? Seed { get; init; }
}

/// <summary>
/// Builds ClientHello messages shaped like real clients (dpi-diagnostics §5): order of ciphers and extensions, GREASE,
/// post-quantum key shares of the right size, ALPS, ECH GREASE and BoringSSL padding. Key shares are well-formed
/// random keys, so a server answers with a ServerHello; the probe never finishes the handshake.
/// </summary>
public static class ClientHelloBuilder
{
    private static readonly ushort[] GreaseValues = [.. Enumerable.Range(0, 16).Select(i => (ushort)(0x0A0A + (i * 0x1010)))];

    /// <summary>The handshake message (type 1, 3-byte length, body).</summary>
    public static byte[] BuildHandshake(ClientHelloSpec spec, ClientHelloOptions o)
    {
        var rnd = o.Seed is { } seed ? new Random(seed) : Random.Shared;
        // BoringSSL picks distinct GREASE values per slot; the key share reuses the group's
        var g = GreaseValues.OrderBy(_ => rnd.Next()).Take(6).ToArray();
        ushort gCipher = g[0], gGroup = g[1], gExt1 = g[2], gExt2 = g[3], gVersion = g[4];

        bool quic = o.QuicScid is not null;
        bool sniOk = o.Sni is { Length: > 0 } s && !IPAddress.TryParse(s, out _);
        var groups = Filter(spec.Groups, o.Kyber);
        var shares = Filter(spec.KeyShares, o.Kyber);
        if (shares.Count == 0 && spec.Versions.Count > 0)
            shares = groups.Where(x => x != "grease").Take(1).ToList();

        var ext = new List<string>(spec.Extensions);
        if (!sniOk)
            ext.Remove("0000");
        if (o.Ech == false)
            ext.Remove("fe0d");
        else if (o.Ech == true && !ext.Contains("fe0d"))
        {
            // before the trailing GREASE and padding
            int at = ext.Count;
            while (at > 1 && (ext[at - 1].StartsWith("grease", StringComparison.Ordinal) || ext[at - 1] == "0015"))
                at--;
            ext.Insert(at, "fe0d");
        }
        if (quic)
        {
            ext.RemoveAll(e => e is "0015" or "0016" or "0023" or "ff01" or "000b" or "0005" or "0012" or "001c");
            if (!ext.Contains("0039"))
                ext.Add("0039");
        }
        if (spec.PermuteExtensions)
        {
            // GREASE stays first and last, padding last; the rest is shuffled like Chrome does
            var fixedFirst = ext.TakeWhile(e => e.StartsWith("grease", StringComparison.Ordinal)).ToList();
            var tail = ext.Skip(fixedFirst.Count).Reverse().TakeWhile(e => e.StartsWith("grease", StringComparison.Ordinal) || e == "0015").Reverse().ToList();
            var middle = ext.Skip(fixedFirst.Count).Take(ext.Count - fixedFirst.Count - tail.Count).OrderBy(_ => rnd.Next()).ToList();
            ext = [.. fixedFirst, .. middle, .. tail];
        }

        var body = new Writer();
        body.U16(Hex(spec.LegacyVersion));
        body.Bytes(RandomBytes(rnd, 32));
        if (spec.SessionId && !quic)
        {
            body.U8(32);
            body.Bytes(RandomBytes(rnd, 32));
        }
        else
        {
            body.U8(0);
        }
        var ciphers = spec.Ciphers.Select(c => c == "grease" ? gCipher : Hex(c)).Where(c => !quic || c >> 8 == 0x13 || IsGreaseValue(c)).ToList();
        body.U16((ushort)(ciphers.Count * 2));
        foreach (var c in ciphers)
            body.U16(c);
        body.U8(1);
        body.U8(0);

        var exts = new Writer();
        int greaseSeen = 0;
        int paddingAt = -1;
        foreach (var e in ext)
        {
            if (e == "0015")
            {
                paddingAt = exts.Length;
                continue;
            }
            if (e.StartsWith("grease", StringComparison.Ordinal))
            {
                exts.U16(greaseSeen++ == 0 ? gExt1 : gExt2);
                var data = e.Length > 7 ? Convert.FromHexString(e[7..]) : [];
                exts.U16((ushort)data.Length);
                exts.Bytes(data);
                continue;
            }
            int colon = e.IndexOf(':', StringComparison.Ordinal);
            ushort type = Hex(colon < 0 ? e : e[..colon]);
            byte[] content = colon >= 0 ? Convert.FromHexString(e[(colon + 1)..]) : Content(type, spec, o, groups, shares, gGroup, gVersion, rnd, quic);
            exts.U16(type);
            exts.U16((ushort)content.Length);
            exts.Bytes(content);
        }

        var extBytes = exts.ToArray();
        if (paddingAt >= 0)
        {
            // BoringSSL: pad a hello of 256..511 bytes (with the 4-byte header) up to 512
            int unpadded = 4 + body.Length + 2 + extBytes.Length;
            if (unpadded is > 0xFF and < 0x200)
            {
                int padLen = 0x200 - unpadded;
                padLen = padLen >= 5 ? padLen - 4 : 1;
                var pad = new Writer();
                pad.U16(TlsClientHello.ExtPadding);
                pad.U16((ushort)padLen);
                pad.Bytes(new byte[padLen]);
                extBytes = [.. extBytes.AsSpan(0, paddingAt), .. pad.ToArray(), .. extBytes.AsSpan(paddingAt)];
            }
        }
        body.U16((ushort)extBytes.Length);
        body.Bytes(extBytes);

        var b = body.ToArray();
        var msg = new byte[4 + b.Length];
        msg[0] = 1;
        msg[1] = (byte)(b.Length >> 16);
        msg[2] = (byte)(b.Length >> 8);
        msg[3] = (byte)b.Length;
        b.CopyTo(msg, 4);
        return msg;
    }

    /// <summary>The hello in TLS records (one record up to 16384 bytes, as browsers send it).</summary>
    public static byte[] BuildRecord(ClientHelloSpec spec, ClientHelloOptions o)
    {
        var hs = BuildHandshake(spec, o);
        var w = new Writer();
        ushort rv = Hex(spec.RecordVersion);
        for (int p = 0; p < hs.Length; p += 16384)
        {
            int n = Math.Min(16384, hs.Length - p);
            w.U8(0x16);
            w.U16(rv);
            w.U16((ushort)n);
            w.Bytes(hs.AsSpan(p, n));
        }
        return w.ToArray();
    }

    private static List<string> Filter(List<string> groups, bool kyber) =>
        kyber ? [.. groups] : [.. groups.Where(x => x == "grease" || !TlsClientHello.PostQuantumGroups.Contains(Hex(x)))];

    private static bool IsGreaseValue(ushort v) => TlsClientHello.IsGrease(v);

    private static byte[] Content(ushort type, ClientHelloSpec spec, ClientHelloOptions o, List<string> groups, List<string> shares,
        ushort gGroup, ushort gVersion, Random rnd, bool quic)
    {
        var w = new Writer();
        switch (type)
        {
            case TlsClientHello.ExtServerName:
            {
                var name = Encoding.ASCII.GetBytes(o.Sni!);
                w.U16((ushort)(name.Length + 3));
                w.U8(0);
                w.U16((ushort)name.Length);
                w.Bytes(name);
                break;
            }
            case 0x0005: // status_request: OCSP, no responders, no extensions
                w.Bytes([1, 0, 0, 0, 0]);
                break;
            case TlsClientHello.ExtSupportedGroups:
                List16(w, groups.Select(x => x == "grease" ? gGroup : Hex(x)));
                break;
            case TlsClientHello.ExtEcPointFormats:
                w.Bytes([1, 0]);
                break;
            case TlsClientHello.ExtSignatureAlgorithms:
                List16(w, spec.SignatureAlgorithms.Select(Hex));
                break;
            case TlsClientHello.ExtAlpn:
                Protocols(w, o.Alpn ?? spec.Alpn);
                break;
            case 0x0012: // signed_certificate_timestamp
            case 0x0016: // encrypt_then_mac
            case 0x0017: // extended_master_secret
            case 0x0023: // session_ticket
            case 0x0031: // post_handshake_auth
                break;
            case 0x001B: // compress_certificate
                w.U8((byte)(spec.CertCompression.Count * 2));
                foreach (var a in spec.CertCompression)
                    w.U16((ushort)a);
                break;
            case 0x001C: // record_size_limit
                w.U16((ushort)(spec.RecordSizeLimit ?? 16385));
                break;
            case 0x0022: // delegated_credentials
                List16(w, spec.DelegatedCredentials.Select(Hex));
                break;
            case TlsClientHello.ExtSupportedVersions:
            {
                var v = spec.Versions.Select(x => x == "grease" ? gVersion : Hex(x)).Where(x => !quic || x == 0x0304 || IsGreaseValue(x)).ToList();
                w.U8((byte)(v.Count * 2));
                foreach (var x in v)
                    w.U16(x);
                break;
            }
            case 0x002D: // psk_key_exchange_modes
                w.U8((byte)spec.PskModes.Count);
                foreach (var m in spec.PskModes)
                    w.U8((byte)m);
                break;
            case TlsClientHello.ExtKeyShare:
            {
                var list = new Writer();
                foreach (var s in shares)
                {
                    ushort grp = s == "grease" ? gGroup : Hex(s);
                    var key = s == "grease" ? [0] : KeyShare(grp, rnd);
                    list.U16(grp);
                    list.U16((ushort)key.Length);
                    list.Bytes(key);
                }
                w.U16((ushort)list.Length);
                w.Bytes(list.ToArray());
                break;
            }
            case 0x0039: // quic_transport_parameters
                QuicTransportParameters(w, o.QuicScid ?? []);
                break;
            case 0x44CD: // application_settings (ALPS), new and old code points
            case 0x4469:
                Protocols(w, spec.Alps);
                break;
            case TlsClientHello.ExtEch:
            {
                // GREASE ECH (draft-ietf-tls-esni §6.2): outer, HKDF-SHA256 + AES-128-GCM, random config id and payload
                w.U8(0);
                w.U16(0x0001);
                w.U16(0x0001);
                w.U8((byte)rnd.Next(256));
                w.U16(32);
                w.Bytes(RandomBytes(rnd, 32));
                int payload = 144 + (32 * rnd.Next(4));
                w.U16((ushort)payload);
                w.Bytes(RandomBytes(rnd, payload));
                break;
            }
            case 0xFF01: // renegotiation_info, empty
                w.U8(0);
                break;
            default:
                throw new InvalidOperationException($"спецификация {spec.Id}: тело расширения 0x{type:x4} не задано");
        }
        return w.ToArray();
    }

    private static void QuicTransportParameters(Writer w, byte[] scid)
    {
        static void Param(Writer w, ulong id, ReadOnlySpan<byte> value)
        {
            Varint(w, id);
            Varint(w, (ulong)value.Length);
            w.Bytes(value);
        }
        static byte[] V(ulong v)
        {
            var t = new Writer();
            Varint(t, v);
            return t.ToArray();
        }
        Param(w, 0x01, V(30000));      // max_idle_timeout
        Param(w, 0x03, V(1472));       // max_udp_payload_size
        Param(w, 0x04, V(15728640));   // initial_max_data
        Param(w, 0x05, V(6291456));    // initial_max_stream_data_bidi_local
        Param(w, 0x06, V(6291456));    // initial_max_stream_data_bidi_remote
        Param(w, 0x07, V(6291456));    // initial_max_stream_data_uni
        Param(w, 0x08, V(100));        // initial_max_streams_bidi
        Param(w, 0x09, V(103));        // initial_max_streams_uni
        Param(w, 0x0F, scid);          // initial_source_connection_id
    }

    private static void Varint(Writer w, ulong v)
    {
        if (v < 0x40)
        {
            w.U8((byte)v);
        }
        else if (v < 0x4000)
        {
            w.U16((ushort)(0x4000 | v));
        }
        else if (v < 0x40000000)
        {
            w.U16((ushort)(0x8000 | (v >> 16)));
            w.U16((ushort)v);
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(v));
        }
    }

    /// <summary>A well-formed public key share for the group (sizes from RFC 8446, RFC 9180 and draft-kwiatkowski-tls-ecdhe-mlkem).</summary>
    internal static byte[] KeyShare(ushort group, Random rnd) => group switch
    {
        0x001D => RandomBytes(rnd, 32),
        0x001E => RandomBytes(rnd, 56),
        0x0017 => [4, .. RandomBytes(rnd, 64)],
        0x0018 => [4, .. RandomBytes(rnd, 96)],
        0x0019 => [4, .. RandomBytes(rnd, 132)],
        0x11EC => [.. MlKem768PublicKey(rnd), .. RandomBytes(rnd, 32)],           // X25519MLKEM768: ML-KEM first
        0x6399 => [.. RandomBytes(rnd, 32), .. MlKem768PublicKey(rnd)],           // X25519Kyber768Draft00: X25519 first
        0x11EB => [4, .. RandomBytes(rnd, 64), .. MlKem768PublicKey(rnd)],        // SecP256r1MLKEM768
        0x0201 => MlKem768PublicKey(rnd),
        0x0100 => RandomBytes(rnd, 256), // ffdhe2048
        0x0101 => RandomBytes(rnd, 384), // ffdhe3072
        0x0102 => RandomBytes(rnd, 512),
        0x0103 => RandomBytes(rnd, 768),
        0x0104 => RandomBytes(rnd, 1024),
        _ => RandomBytes(rnd, 32),
    };

    /// <summary>
    /// An ML-KEM-768 encapsulation key that passes the modulus check (FIPS 203 §7.2): three polynomials of 256
    /// coefficients below q = 3329, packed in 12 bits, then a 32-byte seed.
    /// </summary>
    internal static byte[] MlKem768PublicKey(Random rnd)
    {
        var key = new byte[1184];
        for (int i = 0; i < 384; i++)
        {
            int a = rnd.Next(3329), b = rnd.Next(3329);
            key[3 * i] = (byte)a;
            key[(3 * i) + 1] = (byte)((a >> 8) | ((b & 0xF) << 4));
            key[(3 * i) + 2] = (byte)(b >> 4);
        }
        RandomBytes(rnd, 32).CopyTo(key, 1152);
        return key;
    }

    private static void Protocols(Writer w, IEnumerable<string> names)
    {
        var list = new Writer();
        foreach (var n in names)
        {
            var b = Encoding.ASCII.GetBytes(n);
            list.U8((byte)b.Length);
            list.Bytes(b);
        }
        w.U16((ushort)list.Length);
        w.Bytes(list.ToArray());
    }

    private static void List16(Writer w, IEnumerable<ushort> values)
    {
        var v = values.ToList();
        w.U16((ushort)(v.Count * 2));
        foreach (var x in v)
            w.U16(x);
    }

    private static byte[] RandomBytes(Random rnd, int n)
    {
        var b = new byte[n];
        if (ReferenceEquals(rnd, Random.Shared))
            RandomNumberGenerator.Fill(b);
        else
            rnd.NextBytes(b);
        return b;
    }

    private static ushort Hex(string s) => ushort.Parse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private sealed class Writer
    {
        private readonly MemoryStream _ms = new();

        public int Length => (int)_ms.Length;

        public void U8(byte v) => _ms.WriteByte(v);

        public void U16(ushort v)
        {
            Span<byte> b = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(b, v);
            _ms.Write(b);
        }

        public void Bytes(ReadOnlySpan<byte> b) => _ms.Write(b);

        public byte[] ToArray() => _ms.ToArray();
    }
}
