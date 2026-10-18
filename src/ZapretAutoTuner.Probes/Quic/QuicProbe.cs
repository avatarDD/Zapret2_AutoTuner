using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Probes.Quic;

public sealed record QuicProbeOptions
{
    public required IPAddress Address { get; init; }

    public int Port { get; init; } = 443;

    public string? Sni { get; init; }

    public ClientHelloSpec Spec { get; init; } = ClientHelloSpec.Get("chrome141");

    public bool Kyber { get; init; } = true;

    public uint Version { get; init; } = QuicInitial.Version1;

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);
}

/// <summary>
/// HTTP/3 reachability without a QUIC stack (dpi-diagnostics §2.7): sends client Initials with a browser-shaped
/// ClientHello and listens. The server's Initial is decrypted (its keys follow from our DCID) to see the ServerHello.
/// The handshake is never completed, so a volume-based UDP limit (the "4/1" detector) is not measured here; that needs
/// a full download.
/// </summary>
public static class QuicProbe
{
    public static async Task<QuicProbeResult> RunAsync(QuicProbeOptions o, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var dcid = RandomNumberGenerator.GetBytes(8);
        var scid = RandomNumberGenerator.GetBytes(8);
        var hello = ClientHelloBuilder.BuildHandshake(o.Spec, new ClientHelloOptions { Sni = o.Sni, Kyber = o.Kyber, Alpn = ["h3"], QuicScid = scid });
        var datagrams = QuicInitial.BuildInitials(hello, dcid, scid, o.Version);

        using var udp = new Socket(o.Address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await udp.ConnectAsync(new IPEndPoint(o.Address, o.Port), ct).ConfigureAwait(false);
        try
        {
            foreach (var d in datagrams)
                await udp.SendAsync(d, SocketFlags.None, ct).ConfigureAwait(false);
        }
        catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
        {
            // ICMP port unreachable for the first datagram surfaces on the next send
            return new QuicProbeResult { Address = o.Address.ToString(), Port = o.Port, Sni = o.Sni, Outcome = QuicOutcome.Unreachable, Sent = datagrams.Count, Duration = sw.Elapsed };
        }

        int received = 0;
        long bytes = 0;
        TimeSpan? first = null;
        var outcome = QuicOutcome.NoResponse;
        var versions = new List<uint>();
        var buf = new byte[65536];
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(o.Timeout);
        while (outcome != QuicOutcome.ServerHello)
        {
            int n;
            try
            {
                n = await udp.ReceiveAsync(buf, SocketFlags.None, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                break;
            }
            catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
            {
                if (received == 0)
                    outcome = QuicOutcome.Unreachable;
                break;
            }
            received++;
            bytes += n;
            first ??= sw.Elapsed;
            var d = buf.AsSpan(0, n);
            if (d.Length >= 5 && (d[0] & 0x80) != 0 && d[1] == 0 && d[2] == 0 && d[3] == 0 && d[4] == 0)
            {
                outcome = QuicOutcome.VersionNegotiation;
                versions.AddRange(ParseVersionNegotiation(d));
                break;
            }
            if (outcome == QuicOutcome.NoResponse)
                outcome = QuicOutcome.Responded;
            foreach (var p in QuicInitial.DecryptDatagram(d, dcid))
            {
                if (p.Crypto.Any(c => c.Offset == 0 && c.Data.Length > 0 && c.Data[0] == 2))
                    outcome = QuicOutcome.ServerHello;
            }
        }

        return new QuicProbeResult
        {
            Address = o.Address.ToString(),
            Port = o.Port,
            Sni = o.Sni,
            Outcome = outcome,
            Sent = datagrams.Count,
            Received = received,
            BytesReceived = bytes,
            FirstReply = first,
            Duration = sw.Elapsed,
            OfferedVersions = versions,
        };
    }

    private static List<uint> ParseVersionNegotiation(ReadOnlySpan<byte> d)
    {
        var list = new List<uint>();
        int p = 5;
        if (p >= d.Length)
            return list;
        p += 1 + d[p];
        if (p >= d.Length)
            return list;
        p += 1 + d[p];
        for (; p + 4 <= d.Length; p += 4)
            list.Add(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(d[p..]));
        return list;
    }
}
