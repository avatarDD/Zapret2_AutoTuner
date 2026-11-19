using ZapretAutoTuner.Core.Diagnostics;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>A site whose root this system does not trust (the national CA of many .ru sites) is not a block.</summary>
public sealed class CertNameOnlyTests
{
    private static ProbeResult Page(bool certValid, bool nameOk, string issuer = "CN=Russian Trusted Sub CA, O=The Ministry of Digital Development and Communications, C=RU") => new()
    {
        Host = "www.sberbank.ru",
        Address = "203.0.113.7",
        ConnectOk = true,
        TlsOk = true,
        HttpStatus = 200,
        Complete = true,
        BodyBytes = 300_000,
        CertValid = certValid,
        CertNameOk = nameOk,
        CertIssuer = issuer,
    };

    [Fact]
    public void An_untrusted_root_with_the_right_name_passes_for_the_auto_mode_only()
    {
        var p = Page(certValid: false, nameOk: true);
        Assert.False(p.Passes(ProbeLevel.L2Body));
        Assert.True(p.PassesNameOnly(ProbeLevel.L2Body));
        // a certificate for another name is what a MITM shows: still a failure
        Assert.False(Page(certValid: false, nameOk: false).PassesNameOnly(ProbeLevel.L2Body));
        // any other untrusted root may be a MITM's own certificate, which can name any host
        Assert.False(Page(certValid: false, nameOk: true, issuer: "CN=Some Proxy CA").PassesNameOnly(ProbeLevel.L2Body));
        // the page itself must still come whole
        Assert.False((p with { Complete = false, BodyBytes = 1000 }).PassesNameOnly(ProbeLevel.L2Body));
        Assert.True(Page(certValid: true, nameOk: true).PassesNameOnly(ProbeLevel.L2Body));
    }
}
