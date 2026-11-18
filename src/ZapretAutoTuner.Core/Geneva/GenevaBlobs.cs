using System.Text;

namespace ZapretAutoTuner.Core.Geneva;

/// <summary>
/// zapret2's fake payloads (<c>files/fake/*.bin</c> of the bundled, verified zapret2) as geneva_c 2.0 blobs: the Agent
/// hands every file to a geneva with extensions (<c>--ext-blob z2_NAME:@FILE</c>), so a strategy names any of them
/// (<c>xfake{blob=z2_tls_clienthello_vk_com}</c>), and the "Авто" mode tries them all. geneva's own blobs
/// (<c>fake_default_tls</c>, <c>fake_default_http</c>, <c>fake_default_quic</c>, <c>fake_quic_initial</c>) need nothing.
/// </summary>
public static class GenevaBlobs
{
    public const string Prefix = "z2_";

    /// <summary>geneva_c's limit of a blob from a file.</summary>
    public const long MaxFileSize = 1 << 20;

    /// <summary>geneva_c's longest blob name (BLOB_NAME_MAX 64 with the terminator): a longer one fails the whole start.</summary>
    public const int MaxNameLength = 63;

    /// <summary>The blob name of a fake file: <c>z2_</c> and its name without <c>.bin</c>, other than [a-z0-9_] as <c>_</c>.</summary>
    public static string NameOf(string file)
    {
        var stem = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
        var b = new StringBuilder(Prefix, Prefix.Length + stem.Length);
        foreach (var c in stem)
            b.Append(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' ? c : '_');
        return b.ToString();
    }

    /// <summary>The fake files of <paramref name="dir"/> (sorted, at most <see cref="MaxFileSize"/>); empty when it is missing.</summary>
    public static List<(string Name, string Path)> Files(string? dir)
    {
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
            return [];
        return [.. Directory.EnumerateFiles(dir, "*.bin")
            .Where(f => new FileInfo(f).Length is > 0 and <= MaxFileSize)
            .Select(f => (Name: NameOf(f), Path: f))
            .Where(x => x.Name.Length <= MaxNameLength)
            .GroupBy(x => x.Name, StringComparer.Ordinal)
            .Select(g => g.OrderBy(x => x.Path, StringComparer.Ordinal).First())
            .OrderBy(x => x.Name, StringComparer.Ordinal)];
    }

    /// <summary>geneva's options that load every fake of <paramref name="dir"/>.</summary>
    public static List<string> Argv(string? dir) =>
        [.. Files(dir).SelectMany(f => new[] { "--ext-blob", $"{f.Name}:@{f.Path}" })];

    /// <summary>What a blob is the fake of, by zapret2's file names.</summary>
    public static BlobKind KindOf(string name)
    {
        var n = name.StartsWith(Prefix, StringComparison.Ordinal) ? name[Prefix.Length..] : name;
        if (n.StartsWith("tls_clienthello", StringComparison.Ordinal))
            return BlobKind.TlsHello;
        if (n.StartsWith("quic_initial", StringComparison.Ordinal) || n.StartsWith("quic2_", StringComparison.Ordinal))
            return BlobKind.QuicInitial;
        if (n.StartsWith("http_", StringComparison.Ordinal))
            return BlobKind.Http;
        if (n.StartsWith("dht_", StringComparison.Ordinal))
            return BlobKind.Dht;
        if (n.StartsWith("zero_", StringComparison.Ordinal))
            return BlobKind.Zero;
        // what goes over TCP: BGP, Bitcoin, RDP, RTSP, SMTP, a TLS alert or answer
        if (n.StartsWith("bgp", StringComparison.Ordinal) || n.StartsWith("bitcoin", StringComparison.Ordinal) || n.StartsWith("rdp", StringComparison.Ordinal)
            || n.StartsWith("rtsp", StringComparison.Ordinal) || n.StartsWith("smtp", StringComparison.Ordinal) || n.StartsWith("tls_", StringComparison.Ordinal))
            return BlobKind.TcpOther;
        // WireGuard, STUN, DTLS, DNS, NTP, SIP, ISAKMP, SNMP, Discord's IP discovery, a QUIC short header
        return BlobKind.UdpOther;
    }
}

public enum BlobKind
{
    TlsHello,
    QuicInitial,
    Http,
    Dht,
    Zero,
    TcpOther,
    UdpOther,
}
