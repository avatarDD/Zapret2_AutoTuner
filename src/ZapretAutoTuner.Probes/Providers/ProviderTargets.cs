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
/// skipped.
/// </summary>
public static class ProviderTargets
{
    /// <summary>The provider's networks from its published lists, aggregated. A list that fails to load is skipped
    /// with a note; none loading at all is an error.</summary>
    public static async Task<(List<Cidr> Networks, List<string> Notes)> FetchRangesAsync(Provider p, HttpClient http, CancellationToken ct)
    {
        var cidrs = new List<string>();
        var notes = new List<string>();
        foreach (var src in p.Ranges)
        {
            try
            {
                cidrs.AddRange(RangeParsers.Parse(src.Format, await http.GetStringAsync(src.Url, ct).ConfigureAwait(false)));
            }
            catch (Exception e) when (e is HttpRequestException or System.Text.Json.JsonException or FormatException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                notes.Add($"{src.Url}: {e.Message}");
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
        int found = 0;
        foreach (var address in CidrSet.Sample(networks, samples * 4))
        {
            if (found >= samples)
                break;
            ct.ThrowIfCancellationRequested();
            var bare = await probe(new HttpProbeOptions { Host = address.ToString(), Address = address, Sni = "", Level = ProbeLevel.L1Handshake, ConnectTimeout = TimeSpan.FromSeconds(3), MaxTime = TimeSpan.FromSeconds(6) }, ct).ConfigureAwait(false);
            foreach (var name in CandidateNames(bare.CertNames).Take(2))
            {
                var check = await probe(new HttpProbeOptions { Host = name, Address = address, Level = ProbeLevel.L1Handshake, ConnectTimeout = TimeSpan.FromSeconds(3), MaxTime = TimeSpan.FromSeconds(6) }, ct).ConfigureAwait(false);
                if (!check.CertValid)
                    continue;
                targets.Add(new ProviderTarget
                {
                    Provider = p.Id,
                    Host = name,
                    Address = address,
                    MinBytes = 1,
                    PadBytes = 32 * 1024,
                    Source = networks.First(n => n.Contains(address)).ToString(),
                });
                found++;
                break;
            }
        }
        return targets;
    }

    /// <summary>Names to try as SNI: exact names first; a wildcard becomes its base (<c>*.x.com</c> → <c>x.com</c>) or <c>www.</c>.</summary>
    internal static IEnumerable<string> CandidateNames(IEnumerable<string> san)
    {
        var names = san.Where(n => n.Length > 0 && !IPAddress.TryParse(n, out _)).ToList();
        foreach (var n in names.Where(n => !n.StartsWith("*.", StringComparison.Ordinal)))
            yield return n;
        foreach (var n in names.Where(n => n.StartsWith("*.", StringComparison.Ordinal)))
            yield return "www." + n[2..];
    }
}
