using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Probes.Raw;

namespace ZapretAutoTuner.Probes.Tests;

/// <summary>The replay probe for protocols without a page (PLAN 6.3), against loopback servers.</summary>
public sealed class ReplayProbeTests
{
    /// <summary>A UDP server on loopback that records datagrams and answers them unless silent.</summary>
    private sealed class UdpServer : IAsyncDisposable
    {
        private readonly Socket _s = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _loop;

        public UdpServer(bool answer)
        {
            _s.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _loop = Task.Run(async () =>
            {
                var buf = new byte[65536];
                try
                {
                    while (true)
                    {
                        var r = await _s.ReceiveFromAsync(buf, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), _cts.Token);
                        Received.Enqueue(buf.AsSpan(0, r.ReceivedBytes).ToArray());
                        if (answer)
                            await _s.SendToAsync(buf.AsMemory(0, r.ReceivedBytes), SocketFlags.None, r.RemoteEndPoint, _cts.Token);
                    }
                }
                catch (OperationCanceledException)
                {
                }
                catch (SocketException)
                {
                }
            });
        }

        public int Port => ((IPEndPoint)_s.LocalEndPoint!).Port;

        public ConcurrentQueue<byte[]> Received { get; } = new();

        public async ValueTask DisposeAsync()
        {
            await _cts.CancelAsync();
            await _loop;
            _s.Dispose();
            _cts.Dispose();
        }
    }

    private static ReplayProbeOptions Udp(int port, AppProtocol app = AppProtocol.Unknown, params byte[][] payloads) => new()
    {
        Address = IPAddress.Loopback,
        Port = port,
        Udp = true,
        App = app,
        Payloads = payloads,
        Timeout = TimeSpan.FromMilliseconds(1500),
    };

    [Fact]
    public async Task Udp_answer_is_success()
    {
        await using var server = new UdpServer(answer: true);
        var r = await ReplayProbe.RunAsync(Udp(server.Port, AppProtocol.WireGuard, new byte[148], new byte[32]));
        Assert.True(r.Ok, r.Error);
        Assert.Null(r.Error);
        Assert.True(r.PacketsIn >= 1);
        Assert.True(r.BytesIn >= 32);
        Assert.True(r.PacketsOut >= 1);
        Assert.Equal(148, server.Received.First().Length);
    }

    [Fact]
    public async Task Silent_udp_server_is_no_reply()
    {
        await using var server = new UdpServer(answer: false);
        var r = await ReplayProbe.RunAsync(Udp(server.Port, AppProtocol.Unknown, [1, 2, 3]) with { Timeout = TimeSpan.FromMilliseconds(600) });
        Assert.False(r.Ok);
        Assert.Equal("нет ответа", r.Error);
        Assert.Equal(0, r.PacketsIn);
        Assert.True(r.PacketsOut >= 2, $"sent {r.PacketsOut}");
        Assert.True(r.Duration < TimeSpan.FromSeconds(3));
    }

    [Fact]
    public async Task Udp_sends_all_rounds_to_a_silent_server_within_the_timeout()
    {
        await using var server = new UdpServer(answer: false);
        var r = await ReplayProbe.RunAsync(Udp(server.Port, AppProtocol.Unknown, [1], [2]) with { Rounds = 2, Timeout = TimeSpan.FromMilliseconds(900) });
        Assert.False(r.Ok);
        Assert.Equal(4, r.PacketsOut); // two payloads, two rounds
    }

    [Fact]
    public async Task Stun_sends_a_fresh_binding_request()
    {
        await using var server = new UdpServer(answer: true);
        var stale = new byte[20];
        var r = await ReplayProbe.RunAsync(Udp(server.Port, AppProtocol.Stun, stale));
        Assert.True(r.Ok, r.Error);
        var sent = server.Received.First();
        Assert.Equal(20, sent.Length);
        Assert.Equal(0x0001, BinaryPrimitives.ReadUInt16BigEndian(sent));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(sent.AsSpan(2)));
        Assert.Equal(0x2112A442u, BinaryPrimitives.ReadUInt32BigEndian(sent.AsSpan(4, 4)));
        Assert.True(ProtocolDetector.IsStun(sent));
        // STUN works without a recording too
        Assert.True((await ReplayProbe.RunAsync(Udp(server.Port, AppProtocol.Stun))).Ok);
    }

    [Fact]
    public void Binding_requests_get_new_transaction_ids()
    {
        var a = ReplayProbe.StunBindingRequest();
        var b = ReplayProbe.StunBindingRequest();
        Assert.True(ProtocolDetector.IsStun(a));
        Assert.NotEqual(a.AsSpan(8).ToArray(), b.AsSpan(8).ToArray());
    }

    [Fact]
    public async Task Nothing_recorded_is_nothing_to_send()
    {
        var r = await ReplayProbe.RunAsync(Udp(9, AppProtocol.WireGuard));
        Assert.False(r.Ok);
        Assert.StartsWith("нечего отправить", r.Error, StringComparison.Ordinal);
        Assert.Equal(0, r.PacketsOut);
    }

    private static ReplayProbeOptions Tcp(int port, params byte[][] payloads) => new()
    {
        Address = IPAddress.Loopback,
        Port = port,
        Udp = false,
        App = AppProtocol.Mtproto,
        Payloads = payloads,
        Timeout = TimeSpan.FromMilliseconds(1500),
    };

    [Fact]
    public async Task Tcp_echo_is_success()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var server = Task.Run(async () =>
        {
            using var c = await l.AcceptSocketAsync();
            var buf = new byte[1024];
            int n = await c.ReceiveAsync(buf, SocketFlags.None);
            await c.SendAsync(buf.AsMemory(0, n), SocketFlags.None);
            await Task.Delay(200);
        });
        var r = await ReplayProbe.RunAsync(Tcp(((IPEndPoint)l.LocalEndpoint).Port, new byte[64]));
        await server;
        Assert.True(r.Ok, r.Error);
        Assert.True(r.BytesIn > 0);
        Assert.Equal(1, r.PacketsOut);
    }

    [Fact]
    public async Task Tcp_server_closing_at_once_fails()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var server = Task.Run(async () =>
        {
            using var c = await l.AcceptSocketAsync();
            c.Close();
        });
        var r = await ReplayProbe.RunAsync(Tcp(((IPEndPoint)l.LocalEndpoint).Port, new byte[64]));
        await server;
        Assert.False(r.Ok);
        Assert.Contains(r.Error, new[] { "сервер закрыл соединение", "сброс (RST)" });
    }

    [Fact]
    public async Task Tcp_silent_server_is_no_reply_and_closed_port_does_not_connect()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        var r = await ReplayProbe.RunAsync(Tcp(port, new byte[64]) with { Timeout = TimeSpan.FromMilliseconds(400) });
        Assert.False(r.Ok);
        Assert.Equal("нет ответа", r.Error);
        l.Stop();

        var refused = await ReplayProbe.RunAsync(Tcp(port, new byte[64]));
        Assert.False(refused.Ok);
        Assert.Equal(nameof(SocketError.ConnectionRefused), refused.Error);
    }
}
