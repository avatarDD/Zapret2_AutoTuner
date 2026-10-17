using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Probes.Quic;

namespace ZapretAutoTuner.Probes.Tests;

public class QuicProbeTests
{
    public enum Mode
    {
        ServerHello,
        Garbage,
        VersionNegotiation,
        Silent,
    }

    /// <summary>A UDP "QUIC server" that opens the client Initials and answers with a server Initial.</summary>
    private sealed class FakeQuicServer : IAsyncDisposable
    {
        private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _loop;

        public FakeQuicServer(Mode mode) => _loop = Task.Run(() => LoopAsync(mode));

        public int Port => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;

        public List<byte[]> Received { get; } = [];

        private async Task LoopAsync(Mode mode)
        {
            while (!_cts.IsCancellationRequested)
            {
                UdpReceiveResult r;
                try
                {
                    r = await _udp.ReceiveAsync(_cts.Token);
                }
                catch (Exception)
                {
                    return;
                }
                lock (Received)
                    Received.Add(r.Buffer);
                var pkts = QuicInitial.DecryptDatagram(r.Buffer);
                if (pkts.Count == 0 || mode == Mode.Silent)
                    continue;
                // answer once, after the last datagram of the hello
                var st = QuicInitial.TryParseClientHello(Received.Select(b => (ReadOnlyMemory<byte>)b), out _, out var first);
                if (st != TlsParseStatus.Ok)
                    continue;
                byte[] reply = mode switch
                {
                    Mode.ServerHello => QuicInitial.BuildInitials([2, 0, 0, 4, 3, 3, 0, 0], first!.Scid, [7, 7, 7, 7], server: true, keyDcid: first.Dcid)[0],
                    Mode.VersionNegotiation => [0x80, 0, 0, 0, 0, 8, .. first!.Scid, 8, .. first.Dcid, 0, 0, 0, 1, 0x6B, 0x33, 0x43, 0xCF],
                    _ => [0x40, 1, 2, 3, 4, 5, 6, 7, 8],
                };
                await _udp.SendAsync(reply, r.RemoteEndPoint, _cts.Token);
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _cts.CancelAsync();
            _udp.Dispose();
            try
            {
                await _loop;
            }
            catch (Exception)
            {
                // closed
            }
            _cts.Dispose();
        }
    }

    [Theory]
    [InlineData(Mode.ServerHello, QuicOutcome.ServerHello)]
    [InlineData(Mode.Garbage, QuicOutcome.Responded)]
    [InlineData(Mode.VersionNegotiation, QuicOutcome.VersionNegotiation)]
    [InlineData(Mode.Silent, QuicOutcome.NoResponse)]
    public async Task Outcomes(Mode mode, QuicOutcome expected)
    {
        await using var s = new FakeQuicServer(mode);
        var r = await QuicProbe.RunAsync(new QuicProbeOptions { Address = IPAddress.Loopback, Port = s.Port, Sni = "quic.example", Timeout = TimeSpan.FromSeconds(1) });
        Assert.Equal(expected, r.Outcome);
        Assert.Equal(2, r.Sent); // kyber hello in two datagrams, like Chrome
        Assert.Equal(expected != QuicOutcome.NoResponse, r.PassedDpi);
        if (expected == QuicOutcome.VersionNegotiation)
            Assert.Equal([1u, QuicInitial.Version2], r.OfferedVersions);
    }

    [Fact]
    public async Task Closed_port_is_unreachable()
    {
        int port;
        using (var u = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
            port = ((IPEndPoint)u.Client.LocalEndPoint!).Port;
        var r = await QuicProbe.RunAsync(new QuicProbeOptions { Address = IPAddress.Loopback, Port = port, Timeout = TimeSpan.FromSeconds(1) });
        Assert.Equal(QuicOutcome.Unreachable, r.Outcome);
    }
}
