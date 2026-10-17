using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Probes.Net;

namespace ZapretAutoTuner.Probes.Tls;

/// <summary>What came back for a crafted ClientHello.</summary>
public enum HelloOutcome
{
    ServerHello,
    HelloRetryRequest,

    /// <summary>A TLS alert from the server: the hello passed the DPI, the server did not like it.</summary>
    Alert,

    /// <summary>RST after the hello (typical SNI or fingerprint block).</summary>
    Reset,

    /// <summary>No answer (DPI drop).</summary>
    Timeout,

    /// <summary>FIN without a TLS answer.</summary>
    Closed,

    /// <summary>The answer is not TLS (a block page, a proxy).</summary>
    NotTls,

    /// <summary>TCP connect failed; see <see cref="HelloProbeResult.ConnectError"/>.</summary>
    ConnectFailed,
}

public sealed record HelloProbeResult
{
    public required string Address { get; init; }

    public int Port { get; init; }

    public string? Sni { get; init; }

    public required string Spec { get; init; }

    public HelloOutcome Outcome { get; init; }

    public ProbeError ConnectError { get; init; }

    /// <summary>TLS alert description when <see cref="Outcome"/> is Alert.</summary>
    public int? AlertCode { get; init; }

    /// <summary>Negotiated version (0x0304 from supported_versions, else the legacy version).</summary>
    public int? ServerVersion { get; init; }

    public int? CipherSuite { get; init; }

    /// <summary>Size of the ClientHello handshake message.</summary>
    public int HelloBytes { get; init; }

    public string? Ja4 { get; init; }

    public TimeSpan Duration { get; init; }

    public TimeSpan? Ttfb { get; init; }

    public bool RstSeen => Outcome == HelloOutcome.Reset || ConnectError == ProbeError.ConnectRefused;

    /// <summary>The server answered as TLS: whatever filters this flow let the hello through.</summary>
    public bool PassedDpi => Outcome is HelloOutcome.ServerHello or HelloOutcome.HelloRetryRequest or HelloOutcome.Alert;

    public override string ToString() => $"{Spec} {Sni ?? "(no SNI)"} @ {Address}:{Port} → {Outcome}{(AlertCode is { } a ? $" alert {a}" : "")}";
}

public sealed record HelloProbeOptions
{
    public required IPAddress Address { get; init; }

    public int Port { get; init; } = 443;

    public required ClientHelloSpec Spec { get; init; }

    public ClientHelloOptions Hello { get; init; } = new();

    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(5);

    public TimeSpan ReplyTimeout { get; init; } = TimeSpan.FromSeconds(5);
}

/// <summary>
/// The impersonating probe (PLAN 2.3, dpi-diagnostics §5): sends a ClientHello shaped like a given client and judges
/// the first answer — ServerHello or alert means the DPI let it through, RST or silence means a block. It never
/// completes the handshake, so it shows the reaction to the fingerprint itself (FINGERPRINT, KYBER_MULTIPKT, ECH).
/// </summary>
public static class HelloProbe
{
    /// <summary>SHA-256("HelloRetryRequest"), the ServerHello.random of a HelloRetryRequest (RFC 8446 §4.1.3).</summary>
    private static readonly byte[] HrrRandom = Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    public static async Task<HelloProbeResult> RunAsync(HelloProbeOptions o, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var record = ClientHelloBuilder.BuildRecord(o.Spec, o.Hello);
        TlsClientHello.TryParseRecords(record, out var ch);
        var r = new HelloProbeResult
        {
            Address = o.Address.ToString(),
            Port = o.Port,
            Sni = ch?.Sni,
            Spec = o.Spec.Id,
            HelloBytes = ch?.HandshakeLength ?? 0,
            Ja4 = ch?.Ja4(),
        };

        var conn = await TcpConnector.ConnectAsync(o.Address, o.Port, o.ConnectTimeout, ct).ConfigureAwait(false);
        if (!conn.Ok)
            return r with { Outcome = HelloOutcome.ConnectFailed, ConnectError = conn.Error, Duration = sw.Elapsed };
        using var socket = conn.Socket!;
        var sent = sw.Elapsed;
        try
        {
            await socket.SendAsync(record, SocketFlags.None, ct).ConfigureAwait(false);
            var (outcome, alert, version, cipher, first) = await ReadReplyAsync(socket, o.ReplyTimeout, sw, ct).ConfigureAwait(false);
            return r with
            {
                Outcome = outcome,
                AlertCode = alert,
                ServerVersion = version,
                CipherSuite = cipher,
                Ttfb = first is { } f ? f - sent : null,
                Duration = sw.Elapsed,
            };
        }
        catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted)
        {
            return r with { Outcome = HelloOutcome.Reset, Duration = sw.Elapsed };
        }
    }

    private static async Task<(HelloOutcome, int?, int?, int?, TimeSpan?)> ReadReplyAsync(Socket socket, TimeSpan timeout, Stopwatch sw, CancellationToken ct)
    {
        var buf = new byte[32 * 1024];
        int len = 0;
        TimeSpan? first = null;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        while (true)
        {
            int n;
            try
            {
                n = await socket.ReceiveAsync(buf.AsMemory(len), SocketFlags.None, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return (len == 0 ? HelloOutcome.Timeout : Judge(buf.AsSpan(0, len), partial: true).Item1, null, null, null, first);
            }
            catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted)
            {
                // a ServerHello that arrived before the reset still counts as an answer
                var j = len > 0 ? Judge(buf.AsSpan(0, len), partial: true) : default;
                return len > 0 && j.Item1 is HelloOutcome.ServerHello or HelloOutcome.HelloRetryRequest or HelloOutcome.Alert
                    ? (j.Item1, j.Item2, j.Item3, j.Item4, first)
                    : (HelloOutcome.Reset, null, null, null, first);
            }
            if (n == 0)
            {
                if (len == 0)
                    return (HelloOutcome.Closed, null, null, null, first);
                var j = Judge(buf.AsSpan(0, len), partial: true);
                return (j.Item1 == HelloOutcome.Timeout ? HelloOutcome.Closed : j.Item1, j.Item2, j.Item3, j.Item4, first);
            }
            first ??= sw.Elapsed;
            len += n;
            var (outcome, alert, version, cipher) = Judge(buf.AsSpan(0, len), partial: false);
            if (outcome != HelloOutcome.Timeout || len == buf.Length)
                return (outcome == HelloOutcome.Timeout ? HelloOutcome.NotTls : outcome, alert, version, cipher, first);
        }
    }

    /// <summary>
    /// Judges the first server record. Returns Timeout while more bytes are needed (unless <paramref name="partial"/>,
    /// when a cut ServerHello header still counts).
    /// </summary>
    internal static (HelloOutcome, int?, int?, int?) Judge(ReadOnlySpan<byte> d, bool partial)
    {
        if (d.Length >= 1 && d[0] is not (0x15 or 0x16))
            return (HelloOutcome.NotTls, null, null, null);
        if (d.Length >= 3 && d[1] != 3)
            return (HelloOutcome.NotTls, null, null, null);
        if (d.Length < 5)
            return (partial && d.Length > 0 ? HelloOutcome.NotTls : HelloOutcome.Timeout, null, null, null);
        int rlen = BinaryPrimitives.ReadUInt16BigEndian(d[3..]);
        var body = d[5..Math.Min(d.Length, 5 + rlen)];
        if (d[0] == 0x15)
            return body.Length >= 2 ? (HelloOutcome.Alert, body[1], null, null) : (partial ? HelloOutcome.Alert : HelloOutcome.Timeout, null, null, null);

        // handshake: ServerHello = type 2, len(3), version(2), random(32), sid len, sid, cipher(2), comp(1), exts
        if (body.Length >= 1 && body[0] != 2)
            return (HelloOutcome.NotTls, null, null, null);
        if (body.Length < 4 + 2 + 32 + 1)
            return (partial && body.Length > 0 ? HelloOutcome.ServerHello : HelloOutcome.Timeout, null, null, null);
        int version = BinaryPrimitives.ReadUInt16BigEndian(body[4..]);
        bool hrr = body.Slice(6, 32).SequenceEqual(HrrRandom);
        int p = 38;
        int sidLen = body[p++];
        p += sidLen;
        if (body.Length < p + 3)
            return (partial ? (hrr ? HelloOutcome.HelloRetryRequest : HelloOutcome.ServerHello) : HelloOutcome.Timeout, null, version, null);
        int cipher = BinaryPrimitives.ReadUInt16BigEndian(body[p..]);
        p += 3;
        if (body.Length >= p + 2)
        {
            int end = Math.Min(body.Length, p + 2 + BinaryPrimitives.ReadUInt16BigEndian(body[p..]));
            for (p += 2; p + 4 <= end;)
            {
                int type = BinaryPrimitives.ReadUInt16BigEndian(body[p..]);
                int elen = BinaryPrimitives.ReadUInt16BigEndian(body[(p + 2)..]);
                if (type == TlsClientHello.ExtSupportedVersions && elen == 2 && p + 6 <= end)
                    version = BinaryPrimitives.ReadUInt16BigEndian(body[(p + 4)..]);
                p += 4 + elen;
            }
        }
        return (hrr ? HelloOutcome.HelloRetryRequest : HelloOutcome.ServerHello, null, version, cipher);
    }
}
