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

/// <summary>Why a replay failed.</summary>
public enum ReplayError
{
    None,

    /// <summary>The recording holds no first packets to send.</summary>
    NothingToSend,

    /// <summary>Sent, nothing came back in time.</summary>
    NoAnswer,

    /// <summary>TCP: the connection was not established.</summary>
    NoConnection,

    /// <summary>TCP: reset.</summary>
    Reset,

    /// <summary>TCP: the server closed the connection without data.</summary>
    ServerClosed,

    /// <summary>Another socket error (<see cref="ReplayProbeResult.Socket"/>).</summary>
    Socket,
}

public sealed record ReplayProbeResult(bool Ok, int PacketsOut, int PacketsIn, long BytesIn, ReplayError Error, TimeSpan Duration, SocketError? Socket = null)
{
    public static ReplayProbeResult Fail(ReplayError error, int sent, TimeSpan d, SocketError? socket = null) => new(false, sent, 0, 0, error, d, socket);

    public string? ErrorRu => Error switch
    {
        ReplayError.None => null,
        ReplayError.NothingToSend => "нечего отправить: в записи нет первых пакетов",
        ReplayError.NoAnswer => "нет ответа",
        ReplayError.NoConnection => "нет соединения",
        ReplayError.Reset => "сброс (RST)",
        ReplayError.ServerClosed => "сервер закрыл соединение",
        _ => $"ошибка сокета {Socket}",
    };

    public string? ErrorEn => Error switch
    {
        ReplayError.None => null,
        ReplayError.NothingToSend => "nothing to send: the recording has no first packets",
        ReplayError.NoAnswer => "no answer",
        ReplayError.NoConnection => "no connection",
        ReplayError.Reset => "reset (RST)",
        ReplayError.ServerClosed => "the server closed the connection",
        _ => $"socket error {Socket}",
    };
}

/// <summary>Why the program's first packets cannot tell whether a strategy works.</summary>
public enum ReplayRefusal
{
    None,

    /// <summary>Nothing was recorded before the server answered.</summary>
    NothingRecorded,

    /// <summary>The client sent more than was kept; a partial replay is not what the program sent.</summary>
    Truncated,

    /// <summary>WireGuard: a replayed handshake initiation is dropped by the peer's anti-replay (TAI64N timestamp).</summary>
    WireGuard,

    /// <summary>Discord voice: IP discovery is answered only for the SSRC of a live session.</summary>
    Discord,

    /// <summary>ICE connectivity checks: STUN with USERNAME/MESSAGE-INTEGRITY of the session; a peer ignores anything else.</summary>
    IceStun,
}

/// <summary>Whether a replay can judge a strategy for an endpoint; when not, only a rerun of the program can.</summary>
public sealed record ReplayCheck(ReplayRefusal Refusal)
{
    public bool CanReplay => Refusal == ReplayRefusal.None;

    public string? Ru => Refusal switch
    {
        ReplayRefusal.None => null,
        ReplayRefusal.NothingRecorded => "в записи нет первых пакетов программы",
        ReplayRefusal.Truncated => "программа отправила слишком много до ответа сервера",
        ReplayRefusal.WireGuard => "WireGuard отбрасывает повтор рукопожатия (защита от повторов)",
        ReplayRefusal.Discord => "Discord отвечает на IP discovery только в живой голосовой сессии",
        _ => "проверка связности ICE подписана ключами сессии",
    };

    public string? En => Refusal switch
    {
        ReplayRefusal.None => null,
        ReplayRefusal.NothingRecorded => "the recording has no first packets of the program",
        ReplayRefusal.Truncated => "the program sent too much before the server answered",
        ReplayRefusal.WireGuard => "WireGuard drops a replayed handshake (anti-replay)",
        ReplayRefusal.Discord => "Discord answers IP discovery only in a live voice session",
        _ => "the ICE connectivity check is signed with the session's keys",
    };
}

/// <summary>
/// A probe for protocols without a page (PLAN 6.3): replays the program's first datagrams (or segment) to its server
/// and waits for any answer. STUN gets a valid binding request with a new transaction id, so the server answers it.
/// Success for UDP is at least one datagram back; for TCP, data back with no reset.
/// </summary>
public static class ReplayProbe
{
    /// <summary>
    /// Whether a replay is meaningful (dpi-diagnostics §8): stateless first messages are answered by any server (QUIC
    /// Initial, a public STUN binding, the MTProto header, a DTLS ClientHello that does not follow ICE, a TLS
    /// ClientHello, unknown TCP or UDP); authenticated or session-bound ones are not (WireGuard, Discord IP discovery,
    /// ICE checks), and a strategy for them is verified by rerunning the program only.
    /// </summary>
    public static ReplayCheck CanReplay(AppProtocol app, IReadOnlyList<byte[]> payloads, bool truncated = false)
    {
        if (app == AppProtocol.WireGuard)
            return new(ReplayRefusal.WireGuard);
        if (app == AppProtocol.Discord)
            return new(ReplayRefusal.Discord);
        if (app == AppProtocol.Stun)
            return payloads.Count > 0 && IsIceCheck(payloads[0]) ? new(ReplayRefusal.IceStun) : new(ReplayRefusal.None);
        if (truncated)
            return new(ReplayRefusal.Truncated);
        return payloads.Count == 0 ? new(ReplayRefusal.NothingRecorded) : new(ReplayRefusal.None);
    }

    /// <summary>A STUN request carrying the session's USERNAME or MESSAGE-INTEGRITY (RFC 8445 connectivity check).</summary>
    public static bool IsIceCheck(ReadOnlySpan<byte> stun)
    {
        if (!ProtocolDetector.IsStun(stun))
            return false;
        int end = Math.Min(stun.Length, 20 + BinaryPrimitives.ReadUInt16BigEndian(stun[2..]));
        for (int pos = 20; pos + 4 <= end;)
        {
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(stun[pos..]);
            int len = BinaryPrimitives.ReadUInt16BigEndian(stun[(pos + 2)..]);
            if (type is 0x0006 or 0x0008 or 0x001C or 0x8029 or 0x802A) // USERNAME, MESSAGE-INTEGRITY(-SHA256), ICE-CONTROLLED/-CONTROLLING
                return true;
            pos += 4 + ((len + 3) & ~3);
        }
        return false;
    }

    public static async Task<ReplayProbeResult> RunAsync(ReplayProbeOptions o, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var payloads = o.App == AppProtocol.Stun ? [StunBindingRequest()] : o.Payloads;
        if (payloads.Count == 0)
            return ReplayProbeResult.Fail(ReplayError.NothingToSend, 0, sw.Elapsed);
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
            return new ReplayProbeResult(false, sent, received, bytes, ReplayError.Socket, sw.Elapsed, e.SocketErrorCode);
        }
        await receive.ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        return received > 0
            ? new ReplayProbeResult(true, sent, received, bytes, ReplayError.None, sw.Elapsed)
            : new ReplayProbeResult(false, sent, 0, 0, ReplayError.NoAnswer, sw.Elapsed);
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
                ? new ReplayProbeResult(true, payloads.Count, 1, n, ReplayError.None, sw.Elapsed)
                : new ReplayProbeResult(false, payloads.Count, 0, 0, ReplayError.ServerClosed, sw.Elapsed);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return ReplayProbeResult.Fail(s.Connected ? ReplayError.NoAnswer : ReplayError.NoConnection, payloads.Count, sw.Elapsed);
        }
        catch (SocketException e)
        {
            var error = e.SocketErrorCode switch
            {
                // Windows reports a reset that arrives during a send or receive as an aborted connection
                SocketError.ConnectionReset or SocketError.ConnectionAborted => ReplayError.Reset,
                SocketError.ConnectionRefused or SocketError.TimedOut or SocketError.NetworkUnreachable or SocketError.HostUnreachable => ReplayError.NoConnection,
                _ => ReplayError.Socket,
            };
            return ReplayProbeResult.Fail(error, payloads.Count, sw.Elapsed, e.SocketErrorCode);
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
