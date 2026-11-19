using System.Net;
using ZapretAutoTuner.Core.Diagnostics;

namespace ZapretAutoTuner.Tuning.Geneva;

/// <summary>
/// Opens the page in the program's own browser (BrowserProbe: a fresh isolated profile, never the user's browsers)
/// through whatever geneva applies now. <paramref name="address"/> pins the name to that address (the "Авто" mode
/// applies a strategy to the service's addresses only); null resolves it as usual. Returns null when the program has no
/// browser.
/// </summary>
public delegate Task<PageLoad?> GenevaOpenPage(string host, int port, IPAddress? address, CancellationToken ct);

/// <summary>
/// The final check of a geneva strategy in the browser (dpi-diagnostics §6.4, the wizard's final check for zapret2):
/// what passed the program's own download must open the page in a real browser too, the target's own part of it. The
/// page's other domains (a CDN) are not the target's strategy's business, as in <see cref="FinalCheck"/>.
/// </summary>
public static class GenevaBrowserCheck
{
    /// <summary>Found strategies of a manual search checked in the browser: the best ones.</summary>
    public const int MaxManual = 3;

    /// <summary>How long one page may take, with the browser's start; past it the strategy has failed.</summary>
    public static TimeSpan Timeout { get; } = TimeSpan.FromSeconds(60);

    /// <summary>The page's URL: plain HTTP on 80, HTTPS otherwise (another port is named).</summary>
    public static string Url(string host, int port) => port switch
    {
        80 => $"http://{host}/",
        443 => $"https://{host}/",
        _ => $"https://{host}:{port}/",
    };

    /// <summary>
    /// The verdict on one load: the document came and the target's own requests went through. A certificate from an
    /// authority the browser does not know says nothing about the strategy: the site's chain may end at a national root
    /// the system lacks (Минцифры), which the probes already allow when the name is right; that is no verdict (null).
    /// </summary>
    public static GenevaBrowserVerdict Judge(PageLoad load, string host)
    {
        var domains = SecondaryDomains.Analyze(load, host);
        if (FinalCheck.TargetPartLoads(load, domains))
            return new(true, "ok");
        if (load.Error is { Length: > 0 } error)
            return new(error.Contains("ERR_CERT_AUTHORITY_INVALID", StringComparison.Ordinal) ? null : false, error);
        var main = domains.FirstOrDefault(d => d.IsMain && d.Broken);
        return new(false, main is null ? "failed" : $"{main.Host}: {main.State}{(main.Error is null ? "" : " " + main.Error)}");
    }

    /// <summary>
    /// Opens the page and judges it, within <see cref="Timeout"/>. Null when there is no browser; a load that throws or
    /// runs out of time is a failure, a cancellation by <paramref name="ct"/> is passed on.
    /// </summary>
    public static async Task<GenevaBrowserVerdict?> RunAsync(GenevaOpenPage open, string host, int port, IPAddress? address, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(Timeout);
        PageLoad? load;
        try
        {
            load = await open(host, port, address, limit.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new(false, "timeout");
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return new(false, e.Message);
        }
        return load is null ? null : Judge(load, host);
    }
}

/// <summary>The browser's verdict: <see cref="Ok"/> true opened, false did not, null cannot say (an unknown root).</summary>
public sealed record GenevaBrowserVerdict(bool? Ok, string Detail);

/// <summary>The program's own browser: whether it is there now, and how a page is opened in it.</summary>
public sealed record GenevaBrowser(Func<bool> Available, GenevaOpenPage Open);
