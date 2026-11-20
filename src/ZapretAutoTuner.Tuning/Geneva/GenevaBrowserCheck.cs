using System.Net;
using ZapretAutoTuner.Core.Diagnostics;

namespace ZapretAutoTuner.Tuning.Geneva;

/// <summary>
/// Opens the page in the program's own browser (BrowserProbe: a fresh isolated profile, never the user's browsers)
/// through whatever geneva applies now. <paramref name="address"/> pins the name to that address (the "Авто" mode
/// applies a strategy to the service's addresses only); null resolves it as usual. Returns null when the program has no
/// browser.
/// </summary>
public delegate Task<PageLoad?> GenevaOpenPage(string host, int port, bool tls, IPAddress? address, CancellationToken ct);

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
    public static string Url(string host, int port) => Url(host, port, port != 80);

    /// <summary>The page's URL by the search's own scheme (<paramref name="tls"/>); a port other than the scheme's is named.</summary>
    public static string Url(string host, int port, bool tls) => (tls, port) switch
    {
        (false, 80) => $"http://{host}/",
        (true, 443) => $"https://{host}/",
        _ => $"{(tls ? "https" : "http")}://{host}:{port}/",
    };

    /// <summary>
    /// The verdict on one load: the document came and the target's own requests went through, and so did the page's
    /// other important domains that the tried strategy covers (<paramref name="covered"/>: YouTube's googlevideo.com and
    /// ytimg.com when the strategy reaches them). An important domain the strategy does not reach says nothing about it:
    /// it is named in <see cref="GenevaBrowserVerdict.Uncovered"/>, not failed. Noise (ads, counters) never counts
    /// (<see cref="SecondaryDomains"/>). A certificate from an authority the browser does not know says nothing about the
    /// strategy either: the site's chain may end at a national root the system lacks (Минцифры), which the probes already
    /// allow when the name is right; that is no verdict (null).
    /// </summary>
    public static GenevaBrowserVerdict Judge(PageLoad load, string host, Func<string, bool>? covered = null)
    {
        var domains = SecondaryDomains.Analyze(load, host);
        if (!FinalCheck.TargetPartLoads(load, domains))
        {
            if (load.Error is { Length: > 0 } error)
                return new(NationalZone.BrowserLacksRoot(load, host) ? null : false, error);
            var main = domains.FirstOrDefault(d => d.IsMain && d.Broken);
            return new(false, main is null ? "failed" : Describe(main));
        }
        var related = domains.Where(d => d.Important && !d.IsMain).ToList();
        var mine = related.Where(d => covered?.Invoke(d.Host) == true).ToList();
        var broken = mine.Where(Failed).ToList();
        var uncovered = related.Where(d => Failed(d) && covered?.Invoke(d.Host) != true).Select(d => d.Host).ToList();
        if (broken.Count > 0)
            return new(false, string.Join(", ", broken.Select(Describe)), [.. mine.Where(d => !Failed(d)).Select(d => d.Host)], uncovered) { SiteOpened = true };
        return new(true, "ok", [.. mine.Select(d => d.Host)], uncovered) { SiteOpened = true };
    }

    /// <summary>
    /// A related domain the network failed: requests ended in errors. A request still open when the page is read (a
    /// video streaming, a long poll) is not a failure: the stalled state of the page check does not count here.
    /// </summary>
    private static bool Failed(SecondaryDomain d) => d.State == DomainState.Failed || (d.State == DomainState.Partial && d.Error is not null);

    /// <summary>
    /// What the tried strategy reaches besides the site's own host: the site's other names (its registrable domain)
    /// and its family (<see cref="Core.Geneva.Auto.AutoFamilies"/>: YouTube's googlevideo.com, ytimg.com).
    /// </summary>
    public static IReadOnlyList<string> SiteAndFamily(string host)
    {
        var h = host.TrimEnd('.').ToLowerInvariant();
        // an address has no other names and no family
        if (IPAddress.TryParse(h.Trim('[', ']'), out _))
            return [];
        // the family by the host itself (youtubei.googleapis.com is YouTube's, while googleapis.com as a whole is not)
        if (Core.Geneva.Auto.AutoFamilies.Of(h) is { } family)
        {
            var domains = Core.Geneva.Auto.AutoFamilies.Domains(family);
            var site = Classifier.Registrable(h);
            // the registrable domain is the site's own only when the family claims it whole
            return domains.Any(d => Under(site, d)) ? [site, .. domains] : [h, .. domains];
        }
        return [Classifier.Registrable(h)];
    }

    /// <summary>
    /// A host the user's "не трогать" keeps out of geneva: by name, or by an excluded subnet it resolves into (geneva
    /// does not touch those addresses, so their failure says nothing about the strategy).
    /// </summary>
    public static async Task<bool> ExcludedAsync(Core.Geneva.Auto.AutoNameList excluded, string host, CancellationToken ct)
    {
        if (excluded.MatchesName(host))
            return true;
        if (!excluded.Subnets.Any())
            return false;
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host.TrimEnd('.'), limit.Token).ConfigureAwait(false);
            return addresses.Any(excluded.MatchesAddress);
        }
        catch (Exception e) when (e is System.Net.Sockets.SocketException or ArgumentException || e is OperationCanceledException && !ct.IsCancellationRequested)
        {
            return false;
        }
    }

    private static string Describe(SecondaryDomain d) => $"{d.Host}: {d.State}{(d.Error is null ? "" : " " + d.Error)}";

    /// <summary>
    /// A name and everything under it: <paramref name="host"/> is <paramref name="domain"/> or its subdomain
    /// (<c>rr1.googlevideo.com</c> under <c>googlevideo.com</c>).
    /// </summary>
    public static bool Under(string host, string domain)
    {
        host = host.TrimEnd('.');
        domain = domain.TrimEnd('.');
        return host.Equals(domain, StringComparison.OrdinalIgnoreCase)
            || (host.Length > domain.Length && host.EndsWith(domain, StringComparison.OrdinalIgnoreCase) && host[host.Length - domain.Length - 1] == '.');
    }

    /// <summary>
    /// Opens the page and judges it, within <see cref="Timeout"/>. Null when there is no browser; a load that throws or
    /// runs out of time is a failure, a cancellation by <paramref name="ct"/> is passed on.
    /// </summary>
    /// <param name="excluded">
    /// Asked of each covered domain that failed (only those, so a page of many domains costs no lookups): kept out of
    /// geneva (the user's "не трогать" by subnet), it is judged as not covered.
    /// </param>
    public static async Task<GenevaBrowserVerdict?> RunAsync(GenevaOpenPage open, string host, int port, bool tls, IPAddress? address, CancellationToken ct,
        Func<string, bool>? covered = null, Func<string, CancellationToken, Task<bool>>? excluded = null)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(Timeout);
        PageLoad? load;
        try
        {
            load = await open(host, port, tls, address, limit.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new(false, "timeout");
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return new(false, e.Message);
        }
        if (load is null)
            return null;
        var verdict = Judge(load, host, covered);
        if (excluded is null || covered is null || verdict.Ok != false || !verdict.SiteOpened)
            return verdict;
        var failed = SecondaryDomains.Analyze(load, host).Where(d => d.Important && !d.IsMain && Failed(d) && covered(d.Host)).Select(d => d.Host).ToList();
        var outside = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in failed)
        {
            if (await excluded(h, ct).ConfigureAwait(false))
                outside.Add(h);
        }
        return outside.Count == 0 ? verdict : Judge(load, host, h => covered(h) && !outside.Contains(h));
    }
}

/// <summary>
/// The browser's verdict: <see cref="Ok"/> true opened, false did not, null cannot say (an unknown root).
/// <see cref="Related"/>: the page's other important domains the strategy reaches that loaded with it;
/// <see cref="Uncovered"/>: important domains that failed but are not the strategy's (another service's business).
/// </summary>
public sealed record GenevaBrowserVerdict(bool? Ok, string Detail, IReadOnlyList<string>? Related = null, IReadOnlyList<string>? Uncovered = null)
{
    /// <summary>The site itself opened: a failure is its related resources'.</summary>
    public bool SiteOpened { get; init; }

    public IReadOnlyList<string> RelatedOk => Related ?? [];

    public IReadOnlyList<string> NotCovered => Uncovered ?? [];
}

/// <summary>The program's own browser: whether it is there now, and how a page is opened in it.</summary>
public sealed record GenevaBrowser(Func<bool> Available, GenevaOpenPage Open);
