using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ZapretAutoTuner.Probes.Http;

/// <summary>
/// Russia's national CA (Минцифры): the root many .ru sites chain to and this system's store usually lacks. Its two
/// certificates come from the official page https://www.gosuslugi.ru/crt (files russian_trusted_root_ca_pem.crt and
/// russian_trusted_sub_ca_pem.crt on gu-st.ru) and are pinned here by SHA-256: a file that differs is never trusted.
/// A certificate is accepted only when its chain really builds to this root (signatures checked), so a forged
/// certificate that merely names the issuer fails.
/// </summary>
public static class NationalRoots
{
    /// <summary>SHA-256 of "Russian Trusted Root CA" (2022–2032).</summary>
    public const string RootSha256 = "D26D2D0231B7C39F92CC738512BA54103519E4405D68B5BD703E9788CA8ECF31";

    /// <summary>SHA-256 of "Russian Trusted Sub CA" (2022–2027); a later one comes in the server's own chain.</summary>
    public const string SubSha256 = "BBBDE2103E790B999EC62BD03CF625A5A2E7C316E10AFE6A490EEDEAD8B3FD9B";

    private static readonly Lazy<(X509Certificate2 Root, X509Certificate2 Sub)> Certs = new(Load);

    /// <summary>The sites the national root is trusted for (<see cref="Core.Diagnostics.NationalZone"/>).</summary>
    public static bool Covers(string host) => Core.Diagnostics.NationalZone.Covers(host);

    public static X509Certificate2 Root => Certs.Value.Root;

    public static X509Certificate2 Sub => Certs.Value.Sub;

    private static (X509Certificate2, X509Certificate2) Load() =>
        (Read("russian_trusted_root_ca.pem", RootSha256), Read("russian_trusted_sub_ca.pem", SubSha256));

    private static X509Certificate2 Read(string name, string sha256)
    {
        using var s = typeof(NationalRoots).Assembly.GetManifestResourceStream("ZapretAutoTuner.Probes.Data." + name)
            ?? throw new InvalidOperationException("no embedded " + name);
        using var reader = new StreamReader(s);
        var cert = X509Certificate2.CreateFromPem(reader.ReadToEnd());
        var actual = Convert.ToHexString(SHA256.HashData(cert.RawData));
        if (!string.Equals(actual, sha256, StringComparison.Ordinal))
            throw new CryptographicException($"{name}: SHA-256 {actual}, pinned {sha256}");
        return cert;
    }

    /// <summary>
    /// <paramref name="leaf"/> chains to the Минцифры root: through the bundled sub CA or an intermediate the server
    /// sent (<paramref name="presented"/>), every signature and validity period checked (revocation is not: the probe
    /// works where the CRL hosts may be blocked). A missing intermediate is never downloaded: a server must send it, as
    /// browsers without AIA fetching (Firefox) need too. <paramref name="serverAuth"/>: the leaf must be for TLS servers.
    /// </summary>
    public static bool Chains(X509Certificate2 leaf, IEnumerable<X509Certificate2>? presented = null, bool serverAuth = true) =>
        Chains(leaf, presented, serverAuth, Root, Sub);

    /// <summary><see cref="Chains(X509Certificate2, IEnumerable{X509Certificate2}?, bool)"/> to another root (tests stand in a CA of their own).</summary>
    internal static bool Chains(X509Certificate2 leaf, IEnumerable<X509Certificate2>? presented, bool serverAuth, X509Certificate2 root, X509Certificate2? sub)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        if (sub is not null)
            chain.ChainPolicy.ExtraStore.Add(sub);
        foreach (var c in presented ?? [])
        {
            if (!c.RawData.AsSpan().SequenceEqual(leaf.RawData))
                chain.ChainPolicy.ExtraStore.Add(c);
        }
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        // no requests for missing intermediates (AIA): the probe sends nothing anywhere but to the site it checks
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        if (serverAuth)
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        try
        {
            return chain.Build(leaf);
        }
        finally
        {
            // the elements are new certificate objects the chain does not dispose (a probe runs this often)
            foreach (var e in chain.ChainElements)
                e.Certificate.Dispose();
        }
    }
}
