using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Diagnostics;

namespace ZapretAutoTuner.Probes.Net;

/// <summary>Result of a TCP connect: the socket, or why there is none (port test of dpi-diagnostics §2.2–2.3).</summary>
public sealed record TcpConnectResult(Socket? Socket, ProbeError Error, string? Detail, TimeSpan Elapsed)
{
    public bool Ok => Socket is not null;

    /// <summary>The SYN got a RST back.</summary>
    public bool Rst => Error == ProbeError.ConnectRefused;
}

public static class TcpConnector
{
    /// <summary>Connects with a timeout; never throws for network errors. The caller owns the socket.</summary>
    /// <param name="localPort">Bind to this local port first (0: any).</param>
    public static async Task<TcpConnectResult> ConnectAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken ct, int localPort = 0)
    {
        var started = DateTime.UtcNow;
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            if (localPort != 0)
            {
                // the port may linger in TIME_WAIT from the previous probe of the block
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                try
                {
                    socket.Bind(new IPEndPoint(address.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, localPort));
                }
                catch (SocketException e)
                {
                    // not the network's answer: the caller picks another port (the message is localized, the code is not)
                    socket.Dispose();
                    return new TcpConnectResult(null, ProbeError.Other, $"{ProbeDetail.LocalPortPrefix}{localPort} {e.SocketErrorCode}", DateTime.UtcNow - started);
                }
            }
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await socket.ConnectAsync(new IPEndPoint(address, port), cts.Token).ConfigureAwait(false);
            return new TcpConnectResult(socket, ProbeError.None, null, DateTime.UtcNow - started);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            socket.Dispose();
            return new TcpConnectResult(null, ProbeError.ConnectTimeout, "SYN без ответа", DateTime.UtcNow - started);
        }
        catch (SocketException e)
        {
            socket.Dispose();
            var (err, detail) = e.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => (ProbeError.ConnectRefused, "RST в ответ на SYN"),
                SocketError.TimedOut => (ProbeError.ConnectTimeout, "SYN без ответа"),
                SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.HostDown or SocketError.AddressNotAvailable
                    => (ProbeError.Unreachable, e.Message),
                _ => (ProbeError.Other, e.Message),
            };
            return new TcpConnectResult(null, err, detail, DateTime.UtcNow - started);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
