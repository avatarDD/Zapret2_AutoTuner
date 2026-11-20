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
        // the probes accepted the chain before the browser opens the page: a root the browser lacks (Минцифры, an
        // antivirus or corporate root Chromium does not read on Linux) says nothing about the strategy
        Assert.Null(GenevaBrowserCheck.Judge(new PageLoad { Url = "https://bank.ru/", Error = "net::ERR_CERT_AUTHORITY_INVALID at https://bank.ru/" }, "bank.ru").Ok);
        Assert.Null(GenevaBrowserCheck.Judge(new PageLoad { Url = "https://a.example/", Error = "net::ERR_CERT_AUTHORITY_INVALID at https://a.example/" }, "a.example").Ok);
        Assert.False(GenevaBrowserCheck.Judge(new PageLoad { Url = "https://bank.ru/", Error = "net::ERR_CERT_COMMON_NAME_INVALID" }, "bank.ru").Ok);
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

    private static PageLoad YouTube(bool videoOk, bool adsOk = true) => new()
    {
        Url = "https://www.youtube.com/",
        LoadFired = true,
        Requests =
        [
            new PageRequest { Url = "https://www.youtube.com/", ResourceType = "document", Status = 200, Bytes = 500_000, Duration = TimeSpan.FromSeconds(1) },
            new PageRequest { Url = "https://i.ytimg.com/vi/x/hq.jpg", ResourceType = "image", Status = 200, Bytes = 40_000, Duration = TimeSpan.FromSeconds(1) },
            videoOk
                ? new PageRequest { Url = "https://rr1---sn-abc.googlevideo.com/videoplayback", ResourceType = "media", Status = 200, Bytes = 900_000, Duration = TimeSpan.FromSeconds(2) }
                : new PageRequest { Url = "https://rr1---sn-abc.googlevideo.com/videoplayback", ResourceType = "media", Error = "net::ERR_CONNECTION_RESET" },
            adsOk
                ? new PageRequest { Url = "https://cdn.other.example/app.js", ResourceType = "script", Status = 200, Bytes = 9_000, Duration = TimeSpan.FromSeconds(1) }
                : new PageRequest { Url = "https://cdn.other.example/app.js", ResourceType = "script", Error = "net::ERR_CONNECTION_RESET" },
        ],
    };

    [Fact]
    public void Related_resources_the_strategy_reaches_must_load_too()
    {
        static bool Family(string h) => GenevaBrowserCheck.Under(h, "googlevideo.com") || GenevaBrowserCheck.Under(h, "ytimg.com");
        var ok = GenevaBrowserCheck.Judge(YouTube(videoOk: true), "www.youtube.com", Family);
        Assert.True(ok.Ok);
        Assert.Contains("rr1---sn-abc.googlevideo.com", ok.RelatedOk);
        Assert.Contains("i.ytimg.com", ok.RelatedOk);

        var cut = GenevaBrowserCheck.Judge(YouTube(videoOk: false), "www.youtube.com", Family);
        Assert.False(cut.Ok);
        Assert.Contains("googlevideo.com", cut.Detail, StringComparison.Ordinal);

        // not reached by the strategy: another service's block, named but not failed
        var other = GenevaBrowserCheck.Judge(YouTube(videoOk: true, adsOk: false), "www.youtube.com", Family);
        Assert.True(other.Ok);
        Assert.Contains("cdn.other.example", other.NotCovered);
        // and without anything reached only the site itself counts, as before
        Assert.True(GenevaBrowserCheck.Judge(YouTube(videoOk: false), "www.youtube.com").Ok);
    }

    [Theory]
    [InlineData("googlevideo.com", true)]
    [InlineData("rr1---sn-abc.googlevideo.com", true)]
    [InlineData("notgooglevideo.com", false)]
    [InlineData("googlevideo.com.evil.example", false)]
    public void Under_takes_the_domain_and_its_subdomains(string host, bool under) => Assert.Equal(under, GenevaBrowserCheck.Under(host, "googlevideo.com"));

    [Fact]
    public void A_video_still_streaming_when_the_page_is_read_is_not_a_failure()
    {
        var load = YouTube(videoOk: true) with
        {
            Requests = [.. YouTube(videoOk: true).Requests, new PageRequest { Url = "https://rr1---sn-abc.googlevideo.com/videoplayback?2", ResourceType = "media" }],
        };
        Assert.True(GenevaBrowserCheck.Judge(load, "www.youtube.com", h => GenevaBrowserCheck.Under(h, "googlevideo.com")).Ok);
    }

    [Fact]
    public void The_site_and_its_family_come_from_the_host_itself()
    {
        Assert.Equal(["youtube.com", "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com", "youtubei.googleapis.com", "yt.be"],
            GenevaBrowserCheck.SiteAndFamily("www.youtube.com"));
        // a family member under a shared domain: not the whole googleapis.com
        var api = GenevaBrowserCheck.SiteAndFamily("youtubei.googleapis.com");
        Assert.DoesNotContain("googleapis.com", api);
        Assert.Contains("googlevideo.com", api);
        Assert.Empty(GenevaBrowserCheck.SiteAndFamily("1.2.3.4"));
        Assert.Equal(["example.com"], GenevaBrowserCheck.SiteAndFamily("www.example.com"));
    }

    [Fact]
    public async Task What_the_user_keeps_out_of_geneva_is_not_judged()
    {
        var excluded = Core.Geneva.Auto.AutoNameList.Exclusions(["ytimg.com"]);
        Assert.True(await GenevaBrowserCheck.ExcludedAsync(excluded, "i.ytimg.com", default));
        Assert.False(await GenevaBrowserCheck.ExcludedAsync(excluded, "googlevideo.com", default));

        // a covered domain that failed and turns out to be kept out of geneva (by a subnet): not held against the strategy
        var load = new PageLoad
        {
            Url = "https://www.youtube.com/",
            LoadFired = true,
            Requests =
            [
                new PageRequest { Url = "https://www.youtube.com/", ResourceType = "document", Status = 200, Duration = TimeSpan.FromSeconds(1) },
                new PageRequest { Url = "https://rr1.googlevideo.com/v", ResourceType = "media", Error = "net::ERR_CONNECTION_RESET" },
            ],
        };
        var family = GenevaBrowserCheck.SiteAndFamily("www.youtube.com");
        bool Covered(string h) => family.Any(d => GenevaBrowserCheck.Under(h, d));
        var asked = new List<string>();
        var judged = await GenevaBrowserCheck.RunAsync((_, _, _, _, _) => Task.FromResult<PageLoad?>(load), "www.youtube.com", 443, true, null, default, Covered,
            (h, _) => { asked.Add(h); return Task.FromResult(h.EndsWith("googlevideo.com", StringComparison.Ordinal)); });
        Assert.True(judged!.Ok);
        Assert.Equal(["rr1.googlevideo.com"], asked);
        // without it the failure counts
        Assert.False((await GenevaBrowserCheck.RunAsync((_, _, _, _, _) => Task.FromResult<PageLoad?>(load), "www.youtube.com", 443, true, null, default, Covered))!.Ok);
    }
}
