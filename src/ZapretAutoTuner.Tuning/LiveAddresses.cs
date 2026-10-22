using System.Net;
using System.Net.Sockets;

namespace ZapretAutoTuner.Tuning;

/// <summary>
/// The addresses a repair probes, picked like the classifier picks them (ClassifierRunner: IPv4 unless asked
/// otherwise, at most four, an address that does not connect is not tested further). Probing every A and AAAA record
/// of the system resolver would fail half of the attempts on a link without IPv6 and blame the strategy for it.
/// </summary>
public static class LiveAddresses
{
    /// <param name="resolve">The resolver; the system one by default.</param>
    /// <param name="connects">Whether TCP connects to the address; a 3 s connect to <paramref name="port"/> by default.</param>
    /// <returns>
    /// The addresses that connect; when none does, the candidates themselves, so the repair's reachability step
    /// finds the site down instead of an empty target.
    /// </returns>
    public static async Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken ct, int port = 443, int max = 4,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolve = null, Func<IPAddress, CancellationToken, Task<bool>>? connects = null)
    {
        resolve ??= Dns.GetHostAddressesAsync;
        connects ??= (a, c) => ConnectsAsync(a, port, TimeSpan.FromSeconds(3), c);
        var all = (await resolve(host, ct).ConfigureAwait(false)).Distinct().ToList();
        var v4 = all.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList();
        // IPv6 only for a site without IPv4: then the probe connect decides whether this link has IPv6 at all
        var candidates = (v4.Count > 0 ? v4 : all.Where(a => a.AddressFamily == AddressFamily.InterNetworkV6).ToList()).Take(max).ToList();
        if (candidates.Count == 0)
            return [];
        var ok = await Task.WhenAll(candidates.Select(a => connects(a, ct))).ConfigureAwait(false);
        var live = candidates.Where((_, i) => ok[i]).ToList();
        return live.Count > 0 ? live : candidates;
    }

    public static async Task<bool> ConnectsAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        using var s = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await s.ConnectAsync(address, port, cts.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return false;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
