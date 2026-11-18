using System.Text;

namespace ZapretAutoTuner.Core.Geneva;

/// <summary>
/// zapret2's fake payloads (<c>files/fake/*.bin</c> of the bundled, verified zapret2) as geneva_c 2.0 blobs: the Agent
/// hands every file to a geneva with extensions (<c>--ext-blob z2_NAME:@FILE</c>), so a strategy names any of them
/// (<c>xfake{blob=z2_tls_clienthello_vk_com}</c>), and the "Авто" mode tries them all. geneva's own blobs
/// (<c>fake_default_tls</c>, <c>fake_default_http</c>, <c>fake_default_quic</c>, <c>fake_quic_initial</c>) need nothing.
/// </summary>
/// <para>The names are a contract with zapret-gui (<c>core/geneva_ext.py</c>): a strategy found here runs on a router and
/// back. Both sides check <see cref="NameOf"/> against the same file, <c>tests/testdata/geneva-share/z2-blob-names.json</c>.
/// The prefix <c>z2_</c> is only for zapret2's fakes.</para>
public static class GenevaBlobs
{
    public const string Prefix = "z2_";

    /// <summary>geneva_c's limit of a blob from a file.</summary>
    public const long MaxFileSize = 1 << 20;

    /// <summary>geneva_c's longest blob name (BLOB_NAME_MAX 64 with the terminator): a longer one fails the whole start.</summary>
    public const int MaxNameLength = 63;

    /// <summary>
    /// The blob name of a fake file: <c>z2_</c> and its name without the extension, A–Z as a–z, anything else outside
    /// [a-z0-9_] as <c>_</c> (only ASCII is lowered, so zapret-gui's Python gives the same name).
    /// </summary>
    /// <para>A character is a Unicode code point (<see cref="System.Text.Rune"/>, as Python's <c>str</c>): an emoji is one
    /// <c>_</c>, not two.</para>
    public static string NameOf(string file)
    {
        var stem = Path.GetFileNameWithoutExtension(file);
        var b = new StringBuilder(Prefix, Prefix.Length + stem.Length);
        foreach (var r in stem.EnumerateRunes())
        {
            var c = r.Value;
            var l = c is >= 'A' and <= 'Z' ? c + ('a' - 'A') : c;
            b.Append(l is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' ? (char)l : '_');
        }
        return b.ToString();
    }

    private static readonly System.Text.RegularExpressions.Regex Ref = new(
        @"(?<![A-Za-z0-9_])z2_[a-z0-9_]+", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>The fakes of zapret2 a strategy names (<c>z2_*</c>), in order, without repeats.</summary>
    public static List<string> Refs(string? strategy) =>
        string.IsNullOrEmpty(strategy) ? [] : [.. Ref.Matches(strategy).Select(m => m.Value).Distinct(StringComparer.Ordinal)];

    /// <summary>
    /// Whether every fake the strategy names is among <paramref name="blobs"/>: geneva_c looks a blob up by name on each
    /// packet, and one it never loaded is silently not sent, so the strategy would be judged without its fake.
    /// </summary>
    public static bool Available(string strategy, IEnumerable<string>? blobs)
    {
        var refs = Refs(strategy);
        if (refs.Count == 0)
            return true;
        var have = blobs as IReadOnlyCollection<string> ?? [.. blobs ?? []];
        return refs.All(have.Contains);
    }

    /// <summary>
    /// The fake files of <paramref name="dir"/> (sorted, at most <see cref="MaxFileSize"/>); empty when it is missing. The
    /// same choice as zapret-gui's <c>blob_files</c>: only <c>*.bin</c> in that case (Windows matches <c>.BIN</c> too), no
    /// links, no empty name (a file <c>.bin</c>).
    /// </summary>
    public static List<(string Name, string Path)> Files(string? dir)
    {
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
            return [];
        return [.. Directory.EnumerateFiles(dir, "*.bin")
            .Where(f => f.EndsWith(".bin", StringComparison.Ordinal))
            .Select(f => new FileInfo(f))
            .Where(f => f.LinkTarget is null && f.Length is > 0 and <= MaxFileSize)
            .Select(f => (Name: NameOf(f.FullName), Path: f.FullName))
            .Where(x => x.Name.Length is > 3 and <= MaxNameLength)
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
