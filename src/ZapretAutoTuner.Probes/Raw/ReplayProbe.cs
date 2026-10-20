using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Probes.Raw;

public sealed record ReplayProbeOptions
{
    public required IPAddress Address { get; init; }

    public required int Port { get; init; }

    public bool Udp { get; init; } = true;

    /// <summary>What the program sent first (from the recording). For STUN a fresh binding request is sent instead.</summary>
    public IReadOnlyList<byte[]> Payloads { get; init; } = [];

    public AppProtocol App { get; init; }

    /// <summary>UDP: how many times the payloads are sent (the UDP detector wants at least 4 datagrams out).</summary>
    public int Rounds { get; init; } = 4;

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);
}

public sealed record ReplayProbeResult(bool Ok, int PacketsOut, int PacketsIn, long BytesIn, string? Error, TimeSpan Duration)
{
    public static ReplayProbeResult Fail(string error, int sent, TimeSpan d) => new(false, sent, 0, 0, error, d);
}

/// <summary>
/// A probe for protocols without a page (PLAN 6.3): replays the program's first datagrams (or segment) to its server
/// and waits for any answer. STUN gets a valid binding request with a new transaction id, so the server answers it.
/// Success for UDP is at least one datagram back; for TCP, data back with no reset.
/// </summary>
public static class ReplayProbe
{
    public static async Task<ReplayProbeResult> RunAsync(ReplayProbeOptions o, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var payloads = o.App == AppProtocol.Stun ? [StunBindingRequest()] : o.Payloads;
        if (payloads.Count == 0)
            return ReplayProbeResult.Fail("нечего отправить: в записи нет первых пакетов", 0, sw.Elapsed);
        return o.Udp ? await UdpAsync(o, payloads, sw, ct).ConfigureAwait(false) : await TcpAsync(o, payloads, sw, ct).ConfigureAwait(false);
    }

    private static async Task<ReplayProbeResult> UdpAsync(ReplayProbeOptions o, IReadOnlyList<byte[]> payloads, Stopwatch sw, CancellationToken ct)
    {
        using var s = new Socket(o.Address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await s.ConnectAsync(o.Address, o.Port, ct).ConfigureAwait(false);
        int sent = 0, received = 0;
        long bytes = 0;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(o.Timeout);
        var receive = Task.Run(async () =>
        {
            var buf = new byte[65536];
            try
            {
                while (true)
                {
                    int n = await s.ReceiveAsync(buf, SocketFlags.None, timeout.Token).ConfigureAwait(false);
                    Interlocked.Increment(ref received);
                    Interlocked.Add(ref bytes, n);
                    if (received >= 1)
                        await timeout.CancelAsync().ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (SocketException)
            {
                // ICMP port unreachable comes back as a reset on a connected UDP socket
            }
        }, CancellationToken.None);
        try
        {
            for (int round = 0; round < o.Rounds && received == 0; round++)
            {
                foreach (var p in payloads)
                {
                    await s.SendAsync(o.App == AppProtocol.Stun ? StunBindingRequest() : p, SocketFlags.None, timeout.Token).ConfigureAwait(false);
                    sent++;
                }
                await Task.Delay(TimeSpan.FromMilliseconds(250), timeout.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
        }
        catch (SocketException e)
        {
            await receive.ConfigureAwait(false);
            return new ReplayProbeResult(false, sent, received, bytes, e.SocketErrorCode.ToString(), sw.Elapsed);
        }
        await receive.ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        return received > 0
            ? new ReplayProbeResult(true, sent, received, bytes, null, sw.Elapsed)
            : new ReplayProbeResult(false, sent, 0, 0, "нет ответа", sw.Elapsed);
    }

    private static async Task<ReplayProbeResult> TcpAsync(ReplayProbeOptions o, IReadOnlyList<byte[]> payloads, Stopwatch sw, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(o.Timeout);
        using var s = new Socket(o.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await s.ConnectAsync(o.Address, o.Port, timeout.Token).ConfigureAwait(false);
            foreach (var p in payloads)
                await s.SendAsync(p, SocketFlags.None, timeout.Token).ConfigureAwait(false);
            var buf = new byte[65536];
            int n = await s.ReceiveAsync(buf, SocketFlags.None, timeout.Token).ConfigureAwait(false);
            return n > 0
                ? new ReplayProbeResult(true, payloads.Count, 1, n, null, sw.Elapsed)
                : new ReplayProbeResult(false, payloads.Count, 0, 0, "сервер закрыл соединение", sw.Elapsed);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return ReplayProbeResult.Fail(s.Connected ? "нет ответа" : "нет соединения", payloads.Count, sw.Elapsed);
        }
        catch (SocketException e)
        {
            return ReplayProbeResult.Fail(e.SocketErrorCode == SocketError.ConnectionReset ? "сброс (RST)" : e.SocketErrorCode.ToString(), payloads.Count, sw.Elapsed);
        }
    }

    /// <summary>A STUN binding request (RFC 5389) with a random transaction id and no attributes.</summary>
    public static byte[] StunBindingRequest()
    {
        var b = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(b, 0x0001);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), 0x2112A442);
        RandomNumberGenerator.Fill(b.AsSpan(8, 12));
        return b;
    }
}
