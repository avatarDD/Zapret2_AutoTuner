using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Providers;
using ZapretAutoTuner.Probes.Http;

namespace ZapretAutoTuner.Probes.Providers;

/// <summary>One address of a provider to test, with the name its certificate proves.</summary>
public sealed record ProviderTarget
{
    public required string Provider { get; init; }

    public required string Host { get; init; }

    public required IPAddress Address { get; init; }

    public string Path { get; init; } = "/";

    public long MinBytes { get; init; } = 128 * 1024;

    /// <summary>Request padding for hosts without a large file, so a volume cut-off still shows (§4a step 3).</summary>
    public int PadBytes { get; init; }

    /// <summary>"endpoint" (from the catalog) or the network the sampled address came from.</summary>
    public required string Source { get; init; }

    public override string ToString() => $"{Provider} {Host} [{Address}] {Source}";
}

/// <summary>
/// Targets for the provider mode without a site (dpi-diagnostics §4a): the catalog's test endpoints plus addresses
/// sampled from distinct networks of the provider. A sampled address is asked for its certificate without SNI; a name
/// from it that the certificate then proves with SNI becomes the test's SNI. Addresses without a valid certificate are
/// skipped. Success is a large download (§4a: L2 ≥ 128 KB): hosts whose response is large come first; a host with a
/// small response is used only when there are not enough large ones, with a padded request and the whole response
/// required.
/// </summary>
public static class ProviderTargets
{
    /// <summary>L2 threshold for provider targets (the 16 KB cut-off, dpi-diagnostics §3).</summary>
    public const long LargeBytes = 128 * 1024;

    /// <summary>Request padding for a host with a small response (the CURL_PAD analogue, §3).</summary>
    public const int SmallPadBytes = 32 * 1024;

    /// <summary>A cut-off that stopped the download after this much proves the resource is larger than the cut.</summary>
    private const long CutoffEvidence = 8 * 1024;

    /// <summary>The provider's networks from its published lists, aggregated. A list that fails to load is skipped
    /// with a note; none loading at all is an error. Fallback sources are read only when no other source loaded, and
    /// their warning goes to the notes.</summary>
    public static async Task<(List<Cidr> Networks, List<string> Notes)> FetchRangesAsync(Provider p, HttpClient http, CancellationToken ct)
    {
        var cidrs = new List<string>();
        var notes = new List<string>();
        foreach (var fallback in new[] { false, true })
        {
            if (fallback && cidrs.Count > 0)
                break;
            foreach (var src in p.Ranges.Where(r => r.Fallback == fallback))
            {
                try
                {
                    var url = src.Url;
                    if (src.Link is { } pattern)
                    {
                        var page = await http.GetStringAsync(url, ct).ConfigureAwait(false);
                        var m = System.Text.RegularExpressions.Regex.Match(page, pattern, System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(2));
                        if (!m.Success)
                            throw new FormatException($"на странице нет ссылки на список / no list link on the page ({pattern})");
                        url = System.Net.WebUtility.HtmlDecode(m.Value);
                    }
                    var list = RangeParsers.Parse(src.Format, await http.GetStringAsync(url, ct).ConfigureAwait(false));
                    cidrs.AddRange(list);
                    if (src.Warning is { } w && list.Count > 0)
                        notes.Add($"{src.Url}: {w}");
                }
                catch (Exception e) when (e is HttpRequestException or System.Text.Json.JsonException or FormatException or TaskCanceledException && !ct.IsCancellationRequested)
                {
                    notes.Add($"{src.Url}: {e.Message}");
                }
            }
        }
        if (cidrs.Count == 0)
            throw new HttpRequestException($"{p.Name}: не удалось загрузить ни одного списка диапазонов / no range list loaded: {string.Join("; ", notes)}");
        return (CidrSet.Aggregate(cidrs), notes);
    }

    public static async Task<List<ProviderTarget>> FindAsync(Provider p, IReadOnlyList<Cidr> networks, int samples, Func<string, CancellationToken, Task<IPAddress[]>>? resolve = null,
        Func<HttpProbeOptions, CancellationToken, Task<ProbeResult>>? probe = null, CancellationToken ct = default)
    {
        resolve ??= static (string h, CancellationToken c) => System.Net.Dns.GetHostAddressesAsync(h, c);
        probe ??= HttpProbe.RunAsync;
        var targets = new List<ProviderTarget>();
        foreach (var e in p.TestEndpoints)
        {
            var uri = new Uri(e.Url);
            IPAddress[] addresses;
            try
            {
                addresses = await resolve(uri.Host, ct).ConfigureAwait(false);
            }
            catch (System.Net.Sockets.SocketException)
            {
                continue;
            }
            if ((addresses.FirstOrDefault(x => x.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) ?? addresses.FirstOrDefault()) is { } a)
                targets.Add(new ProviderTarget { Provider = p.Id, Host = uri.Host, Address = a, Path = uri.PathAndQuery, MinBytes = e.MinBytes, Source = "endpoint" });
        }

        // several candidates per wanted sample: many addresses answer nothing or carry no certificate
        int large = 0;
        var small = new List<ProviderTarget>();
        foreach (var address in CidrSet.Sample(networks, samples * 4))
        {
            if (large >= samples)
                break;
            ct.ThrowIfCancellationRequested();
            var bare = await probe(new HttpProbeOptions { Host = address.ToString(), Address = address, Sni = "", Level = ProbeLevel.L1Handshake, ConnectTimeout = TimeSpan.FromSeconds(3), MaxTime = TimeSpan.FromSeconds(6) }, ct).ConfigureAwait(false);
            foreach (var name in CandidateNames(bare.CertNames).Take(3))
            {
                // one GET proves the certificate for the name and shows how large the response is
                var check = await probe(new HttpProbeOptions { Host = name, Address = address, Level = ProbeLevel.L2Body, MinBytes = LargeBytes, ConnectTimeout = TimeSpan.FromSeconds(3), MaxTime = TimeSpan.FromSeconds(8) }, ct).ConfigureAwait(false);
                if (!check.CertValid)
                    continue;
                var t = new ProviderTarget
                {
                    Provider = p.Id,
                    Host = name,
                    Address = address,
                    MinBytes = LargeBytes,
                    Source = networks.First(n => n.Contains(address)).ToString(),
                };
                if (IsLarge(check))
                {
                    targets.Add(t);
                    large++;
                }
                else
                {
                    small.Add(t with { PadBytes = SmallPadBytes });
                }
                break;
            }
        }
        // not enough large responses: padded small ones fill up, and they must arrive whole (Passes: Complete)
        targets.AddRange(small.Take(Math.Max(0, samples - large)));
        return targets;
    }

    /// <summary>The response is large enough for the volume test: by Content-Length, by what arrived, or by a cut-off
    /// that stopped it (the resource is larger than the cut).</summary>
    internal static bool IsLarge(ProbeResult r) =>
        r.ContentLength >= LargeBytes || r.BodyBytes >= LargeBytes || (r.ContentLength is null && r.StalledAt >= CutoffEvidence);

    /// <summary>Names to try as SNI: exact names first; then each wildcard as <c>www.</c> (which it covers) and as its
    /// base (<c>*.x.com</c> → <c>www.x.com</c>, <c>x.com</c>), which the same server often serves too. No duplicates.</summary>
    internal static IEnumerable<string> CandidateNames(IEnumerable<string> san)
    {
        var names = san.Where(n => n.Length > 0 && !IPAddress.TryParse(n, out _)).ToList();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var n in names.Where(n => !n.StartsWith("*.", StringComparison.Ordinal)))
        {
            if (seen.Add(n))
                yield return n;
        }
        foreach (var n in names.Where(n => n.StartsWith("*.", StringComparison.Ordinal)))
        {
            foreach (var c in new[] { "www." + n[2..], n[2..] })
            {
                if (seen.Add(c))
                    yield return c;
            }
        }
    }
}
