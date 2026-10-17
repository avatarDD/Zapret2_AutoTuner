using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>A self-signed CA and leaf certificates for the stand server (as in the Probes tests).</summary>
internal static class TestCerts
{
    private static readonly Lazy<(X509Certificate2 Ca, RSA Key)> CaLazy = new(() =>
    {
        var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=ZT Test CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var ca = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return (ca, key);
    });

    public static X509Certificate2 Ca => CaLazy.Value.Ca;

    public static X509Certificate2Collection Roots => [Ca];

    public static X509Certificate2 Leaf(params string[] names)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest($"CN={names[0]}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        foreach (var n in names)
            san.AddDnsName(n);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var serial = RandomNumberGenerator.GetBytes(8);
        using var cert = req.Create(Ca.SubjectName, X509SignatureGenerator.CreateForRSA(CaLazy.Value.Key, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), serial);
        using var withKey = cert.CopyWithPrivateKey(key);
        // re-import: SslStream on Linux needs a key it can hand to OpenSSL
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx), null);
    }
}
