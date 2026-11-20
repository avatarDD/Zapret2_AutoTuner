using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Tuning.Geneva;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>The final check of a geneva strategy in the program's browser: the URL and the verdict.</summary>
public sealed class GenevaBrowserCheckTests
{
    [Theory]
    [InlineData(443, "https://a.example/")]
    [InlineData(80, "http://a.example/")]
    [InlineData(8443, "https://a.example:8443/")]
    public void The_url_follows_the_port(int port, string url) => Assert.Equal(url, GenevaBrowserCheck.Url("a.example", port));

    [Theory]
    [InlineData(8080, false, "http://a.example:8080/")]
    [InlineData(80, true, "https://a.example:80/")]
    [InlineData(443, true, "https://a.example/")]
    [InlineData(80, false, "http://a.example/")]
    public void The_url_follows_the_search_scheme(int port, bool tls, string url) => Assert.Equal(url, GenevaBrowserCheck.Url("a.example", port, tls));

    [Fact]
    public void A_page_whose_document_failed_did_not_open()
    {
        var v = GenevaBrowserCheck.Judge(new PageLoad { Url = "https://a.example/", Error = "net::ERR_CONNECTION_RESET" }, "a.example");
        Assert.Equal(new GenevaBrowserVerdict(false, "net::ERR_CONNECTION_RESET"), v);
        Assert.True(GenevaBrowserCheck.Judge(new PageLoad { Url = "https://a.example/", LoadFired = true }, "a.example").Ok);
    }

    [Fact]
    public void An_unknown_root_is_no_verdict()
    {
        // a chain to a national root the system lacks: the probes allow it when the name is right, the browser cannot say
        Assert.Null(GenevaBrowserCheck.Judge(new PageLoad { Url = "https://a.example/", Error = "net::ERR_CERT_AUTHORITY_INVALID at https://a.example/" }, "a.example").Ok);
        Assert.False(GenevaBrowserCheck.Judge(new PageLoad { Url = "https://a.example/", Error = "net::ERR_CERT_COMMON_NAME_INVALID" }, "a.example").Ok);
    }

    [Fact]
    public async Task No_browser_is_no_verdict_and_a_load_that_throws_is_a_failure()
    {
        Assert.Null(await GenevaBrowserCheck.RunAsync((_, _, _, _, _) => Task.FromResult<PageLoad?>(null), "a.example", 443, true, null, default));
        var failed = await GenevaBrowserCheck.RunAsync((_, _, _, _, _) => throw new InvalidOperationException("crashed"), "a.example", 443, true, null, default);
        Assert.Equal(new GenevaBrowserVerdict(false, "crashed"), failed);
    }

    [Fact]
    public async Task A_cancellation_by_the_caller_is_passed_on()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => GenevaBrowserCheck.RunAsync((_, _, _, _, ct) => Task.FromCanceled<PageLoad?>(ct), "a.example", 443, true, null, cts.Token));
    }
}
