using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Dns;

namespace ZapretAutoTuner.Probes.Dns;

/// <summary>
/// Plain DNS over UDP port 53 with one retry on timeout and a TCP fallback when the answer comes back truncated
/// (TC=1, RFC 7766). Datagrams with a foreign id are ignored, so a late answer to an earlier attempt is not mixed up.
/// Note: an on-path injector answers faster than the real server, so the first matching datagram wins — exactly
/// what an ordinary stub resolver sees.
/// </summary>
public sealed class UdpDnsTransport : DnsTransportBase
{
    private readonly int _retries;

    public UdpDnsTransport(IPEndPoint server, string? name = null, TimeSpan? timeout = null, int retries = 1)
        : base(name ?? server?.Address.ToString() ?? "", timeout ?? TimeSpan.FromSeconds(2))
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentOutOfRangeException.ThrowIfNegative(retries);
        Endpoint = server;
        _retries = retries;
    }

    public IPEndPoint Endpoint { get; }

    public override DnsResolverKind Kind => DnsResolverKind.Udp;

    public override string Server => Format(Endpoint);

    protected override async Task<byte[]> ExchangeAsync(byte[] query, ushort id, CancellationToken ct)
    {
        for (int attempt = 0; attempt <= _retries; attempt++)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(Timeout);
            byte[] resp;
            try
            {
                resp = await ExchangeUdpAsync(query, id, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                continue; // timeout: retry
            }
            if (DnsMessage.TryReadHeader(resp, out _, out ushort flags) && (flags & 0x0200) != 0)
                return await ExchangeTcpAsync(query, id, ct).ConfigureAwait(false);
            return resp;
        }
        throw new TimeoutException(string.Format(CultureInfo.InvariantCulture,
            "DNS-сервер {0} не ответил за {1} мс ({2} попытк.)", Server, (int)Timeout.TotalMilliseconds, _retries + 1));
    }

    private async Task<byte[]> ExchangeUdpAsync(byte[] query, ushort id, CancellationToken ct)
    {
        using var s = new Socket(Endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await s.ConnectAsync(Endpoint, ct).ConfigureAwait(false);
        await s.SendAsync(query, SocketFlags.None, ct).ConfigureAwait(false);
        var buf = new byte[65535];
        while (true)
        {
            int n = await s.ReceiveAsync(buf, SocketFlags.None, ct).ConfigureAwait(false);
            if (DnsMessage.TryReadHeader(buf.AsSpan(0, n), out ushort rid, out ushort flags) && rid == id && (flags & 0x8000) != 0)
                return buf.AsSpan(0, n).ToArray();
        }
    }

    /// <summary>DNS over TCP (RFC 1035 §4.2.2): two-byte length prefix in both directions.</summary>
    internal async Task<byte[]> ExchangeTcpAsync(byte[] query, ushort id, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        try
        {
            using var s = new Socket(Endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            await s.ConnectAsync(Endpoint, cts.Token).ConfigureAwait(false);
            await using var stream = new NetworkStream(s, ownsSocket: false);
            var framed = new byte[2 + query.Length];
            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
            query.CopyTo(framed, 2);
            await stream.WriteAsync(framed, cts.Token).ConfigureAwait(false);
            var len = new byte[2];
            await stream.ReadExactlyAsync(len, cts.Token).ConfigureAwait(false);
            var resp = new byte[BinaryPrimitives.ReadUInt16BigEndian(len)];
            await stream.ReadExactlyAsync(resp, cts.Token).ConfigureAwait(false);
            if (!DnsMessage.TryReadHeader(resp, out ushort rid, out _) || rid != id)
                throw new DnsTransportException($"{Name}: ответ по TCP не соответствует запросу");
            return resp;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException(string.Format(CultureInfo.InvariantCulture,
                "DNS-сервер {0} не ответил по TCP за {1} мс", Server, (int)Timeout.TotalMilliseconds));
        }
        catch (EndOfStreamException e)
        {
            throw new DnsTransportException($"{Name}: TCP-соединение закрыто до конца ответа", e);
        }
    }
}
