using System.Net;

namespace ZapretAutoTuner.Probes.Dns;

/// <summary>
/// A resolver that only yields addresses. "Name does not exist" is reported as a <see cref="System.Net.Sockets.SocketException"/>
/// with <see cref="System.Net.Sockets.SocketError.HostNotFound"/> (or <c>NoData</c> when the name has no address records).
/// </summary>
public interface IAddressResolver
{
    string Name { get; }

    Task<IPAddress[]> ResolveAsync(string host, CancellationToken ct);
}

/// <summary>
/// The OS resolver (<see cref="System.Net.Dns.GetHostAddressesAsync(string, CancellationToken)"/>): the answer browsers
/// and programs get, including the hosts file, OS caches and whatever DNS the network handed out.
/// </summary>
public sealed class SystemDnsResolver : IAddressResolver
{
    public string Name => "Системный DNS / System DNS";

    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken ct) =>
        // WaitAsync: getaddrinfo is not cancellable on every platform
        System.Net.Dns.GetHostAddressesAsync(host, ct).WaitAsync(ct);
}
