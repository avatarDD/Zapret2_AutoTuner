using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Probes.Http;

namespace ZapretAutoTuner.Probes.Tests;

public class PageCheckTests
{
    private static ProbeResult Page(long body, bool complete = true, RateReading? rate = null) => new()
    {
        Host = "x.test", Address = "198.51.100.1", ConnectOk = true, TlsOk = true, CertValid = true, HttpStatus = 200,
        BodyBytes = body, BytesIn = body + 300, Complete = complete, Rate = rate,
    };

    private static readonly RateReading Shelf = new(20_000, 0.02, 21_000, 5, 200_000);

    [Fact]
    public async Task A_shelf_at_the_baseline_is_a_shaper_and_sets_the_speed()
    {
        var cap = new LinkCapacity();
        cap.Observe(2_000_000);
        var asked = new List<ProbeCriteria>();
        var r = await PageCheck.RunAsync(ProbeCriteria.Default, learn: true, cap, (c, _) =>
        {
            asked.Add(c);
            return Task.FromResult(Page(300_000, complete: false, rate: Shelf));
        }, default);
        Assert.False(r.Passes);
        Assert.Equal(ProbeError.Throttled, r.Probe.Error);
        Assert.Equal(60_000, r.Criteria.MinRate);
        Assert.NotNull(r.Finding);
        Assert.Equal(ProbeCriteria.TrialRateBytes, asked.Single().RateBytes); // the speed was measured
        Assert.Equal(2_000_000, cap.Current());                               // the shelf did not become the link
    }

    [Fact]
    public async Task A_small_page_cut_when_padded_is_the_16k_cutoff()
    {
        var asked = new List<ProbeCriteria>();
        var r = await PageCheck.RunAsync(ProbeCriteria.Default, learn: true, new LinkCapacity(), (c, _) =>
        {
            asked.Add(c);
            return Task.FromResult(c.PadBytes > 0
                ? Page(0, complete: false) with { Error = ProbeError.Stalled, StalledAt = 0, BytesIn = 4_000, BytesOut = 26_000, WireBytesIn = 16_000 }
                : Page(3_000));
        }, default);
        Assert.False(r.Passes);
        Assert.Equal(3, asked.Count); // the plain page, then the padded one twice: the cut must happen again
        Assert.Equal(128 * 1024, r.Criteria.MinBytes);
        Assert.Equal(ProbeCriteria.VolumePad, r.Criteria.PadBytes);
    }

    [Fact]
    public async Task A_server_that_refuses_a_big_request_is_not_a_cutoff()
    {
        // a reset right after the 24 KB request, before any answer: the server's own limit, not DPI
        var r = await PageCheck.RunAsync(ProbeCriteria.Default, learn: true, new LinkCapacity(), (c, _) => Task.FromResult(c.PadBytes > 0
            ? Page(0, complete: false) with { Error = ProbeError.HttpReset, BytesIn = 0, BytesOut = 26_000, WireBytesIn = 5_000 }
            : Page(3_000)), default);
        Assert.True(r.Passes);
        Assert.Null(r.Finding);
        Assert.Equal(ProbeCriteria.Default, r.Criteria);
    }

    [Fact]
    public async Task An_open_page_passes_and_a_strategy_is_not_rechecked()
    {
        int calls = 0;
        var ok = await PageCheck.RunAsync(ProbeCriteria.Default, learn: true, new LinkCapacity(), (_, _) => { calls++; return Task.FromResult(Page(3_000)); }, default);
        Assert.True(ok.Passes);
        Assert.Null(ok.Finding);
        Assert.Equal(2, calls); // the plain page and the padded one, both passed

        calls = 0;
        var trial = await PageCheck.RunAsync(ProbeCriteria.Default, learn: false, new LinkCapacity(), (_, _) => { calls++; return Task.FromResult(Page(3_000, rate: Shelf)); }, default);
        Assert.True(trial.Passes);
        Assert.Equal(1, calls);
    }
}
