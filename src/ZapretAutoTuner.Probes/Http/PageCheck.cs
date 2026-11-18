using ZapretAutoTuner.Core.Diagnostics;

namespace ZapretAutoTuner.Probes.Http;

/// <summary>What <see cref="PageCheck"/> saw: the attempt that decides, the criterion to judge the page by from now on, and what it found.</summary>
public sealed record PageCheckResult(ProbeResult Probe, ProbeCriteria Criteria, string? Finding)
{
    public bool Passes => Probe.Passes(ProbeLevel.L2Body, Criteria.MinBytes);
}

/// <summary>
/// The full download of a page (L2, dpi-diagnostics §3) under a target's <see cref="ProbeCriteria"/>, and — while the
/// criterion is still being learned (a baseline, a confirmation without a bypass) — the two checks a plain download
/// misses: a shaper (§2.16: the page comes, on a flat shelf) and the 16 KB cut-off behind a small page (§2.8: only the
/// padded request crosses it). A finding tightens the criterion, and the page counts as blocked.
/// </summary>
public static class PageCheck
{
    /// <summary>The page from <paramref name="o"/> (address, name, local port) under <paramref name="c"/>.</summary>
    public static Task<PageCheckResult> RunAsync(HttpProbeOptions o, ProbeCriteria c, bool learn, CancellationToken ct) =>
        RunAsync(c, learn, LinkCapacity.Shared, (k, t) => HttpProbe.RunAsync(Apply(o, k), t), ct);

    /// <param name="probe">One download under the criterion it is given (<see cref="Apply"/>).</param>
    public static async Task<PageCheckResult> RunAsync(ProbeCriteria c, bool learn, LinkCapacity capacity,
        Func<ProbeCriteria, CancellationToken, Task<ProbeResult>> probe, CancellationToken ct)
    {
        var first = learn && c.MinRate <= 0 ? c with { RateBytes = Math.Max(c.RateBytes, ProbeCriteria.TrialRateBytes) } : c;
        double cap = capacity.Current();
        var r = await probe(first, ct).ConfigureAwait(false);
        bool shelf = capacity.Judge(r.Rate);
        if (!r.Passes(ProbeLevel.L2Body, c.MinBytes) || !learn)
            return new PageCheckResult(r, c, null);

        if (c.MinRate <= 0 && shelf && r.Rate is { } rate)
        {
            var learned = c with { MinRate = RateShelf.Threshold(rate.Rate, cap), RateBytes = ProbeCriteria.TrialRateBytes };
            var why = $"шейпер: ровно {RateShelf.Human(rate.Rate)} (разброс {rate.Cv:0.00}), канал {(cap > 0 ? "до " + RateShelf.Human(cap) : "не измерен")}";
            return new PageCheckResult(r with { Error = ProbeError.Throttled, ErrorDetail = why }, learned, why);
        }

        if (c.PadBytes <= 0 && r.Complete && r.BodyBytes < 128 * 1024)
        {
            var padded = await probe(c with { PadBytes = ProbeCriteria.VolumePad, MinBytes = 128 * 1024 }, ct).ConfigureAwait(false);
            if (!padded.Passes(ProbeLevel.L2Body, 128 * 1024) && Classifier.IsPaddedCutoff(padded))
            {
                var learned = c with { MinBytes = 128 * 1024, PadBytes = ProbeCriteria.VolumePad };
                return new PageCheckResult(padded, learned, $"обрыв на 16 КБ: раздутый запрос ({padded.BytesOut} B) обрывается");
            }
        }
        return new PageCheckResult(r, c, null);
    }

    /// <summary>The probe options with the criterion.</summary>
    public static HttpProbeOptions Apply(HttpProbeOptions o, ProbeCriteria c) => o with
    {
        MinBytes = c.MinBytes,
        PadBytes = c.PadBytes,
        MinRate = c.MinRate,
        RateBytes = c.RateBytes,
    };
}
