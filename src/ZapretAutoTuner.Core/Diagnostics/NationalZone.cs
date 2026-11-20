namespace ZapretAutoTuner.Core.Diagnostics;

/// <summary>
/// Where Russia's national root (Минцифры) is trusted: Russian sites only. It is the state's CA, as is the DPI: a
/// certificate of it for a foreign site (youtube.com) is what an interception would show, and browsers that do take
/// this root (Yandex Browser) take it only for Russian sites too. A Russian service on a generic zone (.com) is not
/// covered.
/// </summary>
public static class NationalZone
{
    /// <summary>.ru, .su, .рф and the Russian geo and IDN zones (.рус, .москва, .дети, .moscow, .tatar).</summary>
    private static readonly string[] Zones = ["ru", "su", "xn--p1ai", "рф", "xn--p1acf", "рус", "xn--80adxhks", "москва", "xn--d1acj3b", "дети", "moscow", "tatar"];

    public static bool Covers(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
            return false;
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        int dot = h.LastIndexOf('.');
        var zone = dot < 0 ? h : h[(dot + 1)..];
        return Zones.Contains(zone, StringComparer.Ordinal);
    }

    /// <summary>
    /// The browser refused the page only for a root it lacks, on a site the national root covers: the program's own
    /// probes already checked that chain, so the load says nothing about a strategy (no verdict). Anywhere else the
    /// same error is what an interception shows.
    /// </summary>
    public static bool BrowserLacksRoot(PageLoad load, string host) =>
        load.Error?.Contains("ERR_CERT_AUTHORITY_INVALID", StringComparison.Ordinal) == true && Covers(host);
}
