using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZapretAutoTuner.Probes.Http;

namespace ZapretAutoTuner.Probes.Tests;

/// <summary>The Минцифры root: bundled, pinned, and trusted only through a chain that really builds to it.</summary>
public sealed class NationalRootsTests
{
    private const string NationalName = "C=RU, O=The Ministry of Digital Development and Communications, CN=";

    [Fact]
    public void The_bundled_certificates_are_the_pinned_ones_and_the_sub_ca_is_signed_by_the_root()
    {
        Assert.Equal(NationalRoots.RootSha256, Convert.ToHexString(SHA256.HashData(NationalRoots.Root.RawData)));
        Assert.Equal(NationalRoots.SubSha256, Convert.ToHexString(SHA256.HashData(NationalRoots.Sub.RawData)));
        Assert.Contains("CN=Russian Trusted Root CA", NationalRoots.Root.Subject, StringComparison.Ordinal);
        Assert.Contains("CN=Russian Trusted Sub CA", NationalRoots.Sub.Subject, StringComparison.Ordinal);
        Assert.Equal(NationalRoots.Root.SubjectName.RawData, NationalRoots.Sub.IssuerName.RawData);
        // the sub CA's signature verifies with the root's key (while it is valid: see the test below)
        if (DateTime.UtcNow < NationalRoots.Sub.NotAfter.ToUniversalTime())
            Assert.True(NationalRoots.Chains(NationalRoots.Sub, serverAuth: false));
    }

    [Fact]
    public void The_bundled_sub_ca_is_refreshed_before_it_expires()
    {
        // sites that send only their leaf rely on the bundled sub CA: two months before it expires, take the current
        // certificates from https://www.gosuslugi.ru/crt, check them and pin the new SHA-256
        var left = NationalRoots.Sub.NotAfter.ToUniversalTime() - DateTime.UtcNow;
        Assert.True(left > TimeSpan.FromDays(60), $"Russian Trusted Sub CA expires {NationalRoots.Sub.NotAfter:yyyy-MM-dd}: refresh it from gosuslugi.ru/crt");
    }

    [Fact]
    public void A_forged_chain_that_only_names_the_national_issuer_fails()
    {
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest(NationalName + "Russian Trusted Root CA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var fakeRoot = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        using var subKey = RSA.Create(2048);
        var subReq = new CertificateRequest(NationalName + "Russian Trusted Sub CA", subKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        subReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var fakeSub = subReq.Create(fakeRoot, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(6), [1, 2, 3, 4]);

        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=www.sberbank.ru", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("www.sberbank.ru");
        leafReq.CertificateExtensions.Add(san.Build());
        using var subWithKey = fakeSub.CopyWithPrivateKey(subKey);
        using var leaf = leafReq.Create(subWithKey, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(1), [5, 6, 7, 8]);

        Assert.Contains("CN=Russian Trusted Sub CA", leaf.Issuer, StringComparison.Ordinal);
        Assert.False(NationalRoots.Chains(leaf, [fakeSub, fakeRoot]));
        Assert.False(NationalRoots.Chains(leaf));
        // a self-signed certificate under the root's own name is not the root either
        Assert.False(NationalRoots.Chains(fakeRoot));
    }

    [Theory]
    [InlineData("www.sberbank.ru", true)]
    [InlineData("gosuslugi.ru.", true)]
    [InlineData("xn--80ajghhoc2aj1c8b.xn--p1ai", true)]
    [InlineData("example.su", true)]
    [InlineData("site.xn--p1acf", true)]
    [InlineData("site.moscow", true)]
    [InlineData("youtube.com", false)]
    [InlineData("ru.example.com", false)]
    [InlineData("example.run", false)]
    public void The_national_root_covers_russian_sites_only(string host, bool covered) => Assert.Equal(covered, NationalRoots.Covers(host));

    [Fact]
    public void A_leaf_sent_alone_chains_through_the_bundled_intermediate()
    {
        // the production wiring: the root trusted, the sub CA from the bundle, the server sending only its leaf
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Test National Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using var subKey = RSA.Create(2048);
        var subReq = new CertificateRequest("CN=Test National Sub", subKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        subReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var sub = subReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(6), [1, 2, 3, 4]);
        using var subWithKey = sub.CopyWithPrivateKey(subKey);
        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=bank.ru", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var leaf = leafReq.Create(subWithKey, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(1), [5, 6, 7, 8]);

        Assert.True(NationalRoots.Chains(leaf, [], true, root, sub));
        // without the intermediate (none bundled, none sent) the chain does not build: nothing is downloaded
        Assert.False(NationalRoots.Chains(leaf, [], true, root, null));
    }
}
