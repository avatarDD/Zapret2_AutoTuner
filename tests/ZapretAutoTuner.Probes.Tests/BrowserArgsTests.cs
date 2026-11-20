using ZapretAutoTuner.Probes.Browser;

namespace ZapretAutoTuner.Probes.Tests;

/// <summary>Chromium's switches for the check: HTTP/3 off only when asked, the pinned address as a resolver rule.</summary>
public sealed class BrowserArgsTests
{
    [Fact]
    public void Quic_is_turned_off_only_when_asked()
    {
        Assert.DoesNotContain("--disable-quic", BrowserProbe.ChromiumArgs(new BrowserProbeOptions { Url = "https://a.example/" }));
        var args = BrowserProbe.ChromiumArgs(new BrowserProbeOptions
        {
            Url = "https://a.example/",
            DisableQuic = true,
            Resolve = new Dictionary<string, string> { ["a.example"] = "203.0.113.7" },
        });
        Assert.Contains("--disable-quic", args);
        Assert.Contains("--host-resolver-rules=MAP a.example 203.0.113.7", args);
    }
}
