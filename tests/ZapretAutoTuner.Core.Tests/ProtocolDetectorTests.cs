using System.Buffers.Binary;
using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>ProtocolDetector, FlowVerdict and what FlowAnalyzer keeps for a replay (PLAN 6.3, dpi-diagnostics §8).</summary>
public sealed class ProtocolDetectorTests
{
    private static readonly IPAddress Somewhere = IPAddress.Parse("198.51.100.7");

    private static byte[] WireGuard(byte type, int length)
    {
        var b = new byte[length];
        b[0] = type;
        b[5] = 0xAA; // sender index, not reserved
        return b;
    }

    private static byte[] Discord()
    {
        var b = new byte[74];
        BinaryPrimitives.WriteUInt16BigEndian(b, 1);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2), 70);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), 0x01020304); // SSRC
        return b;
    }

    [Fact]
    public void Stun_needs_the_magic_cookie_and_a_matching_length()
    {
        Assert.True(ProtocolDetector.IsStun(TestPackets.Stun()));
        Assert.True(ProtocolDetector.IsStun(TestPackets.Stun(8)));
        Assert.Equal(AppProtocol.Stun, ProtocolDetector.DetectUdp(TestPackets.Stun(), 3478));

        var noCookie = TestPackets.Stun();
        noCookie[4] = 0;
        Assert.False(ProtocolDetector.IsStun(noCookie));
        var badLength = TestPackets.Stun(8).AsSpan(0, 24);
        Assert.False(ProtocolDetector.IsStun(badLength));
        var highBits = TestPackets.Stun();
        highBits[0] = 0x40;
        Assert.False(ProtocolDetector.IsStun(highBits));
        Assert.False(ProtocolDetector.IsStun(TestPackets.Stun().AsSpan(0, 19)));
    }

    [Fact]
    public void Discord_ip_discovery_is_exactly_74_bytes_of_type_1_length_70()
    {
        Assert.True(ProtocolDetector.IsDiscordIpDiscovery(Discord()));
        Assert.Equal(AppProtocol.Discord, ProtocolDetector.DetectUdp(Discord(), 50001));
        Assert.False(ProtocolDetector.IsDiscordIpDiscovery(Discord().AsSpan(0, 73)));
        var wrongType = Discord();
        wrongType[1] = 2;
        Assert.False(ProtocolDetector.IsDiscordIpDiscovery(wrongType));
        var wrongLength = Discord();
        wrongLength[3] = 71;
        Assert.False(ProtocolDetector.IsDiscordIpDiscovery(wrongLength));
    }

    [Theory]
    [InlineData(1, 148, true)]
    [InlineData(2, 92, true)]
    [InlineData(3, 64, true)]
    [InlineData(4, 32, true)]
    [InlineData(4, 96, true)]
    [InlineData(1, 147, false)]
    [InlineData(1, 92, false)]
    [InlineData(2, 148, false)]
    [InlineData(3, 92, false)]
    [InlineData(4, 50, false)]
    [InlineData(5, 64, false)]
    [InlineData(0, 148, false)]
    public void WireGuard_type_byte_goes_with_its_size(byte type, int length, bool expected)
    {
        Assert.Equal(expected, ProtocolDetector.IsWireGuard(WireGuard(type, length)));
        if (expected)
            Assert.Equal(AppProtocol.WireGuard, ProtocolDetector.DetectUdp(WireGuard(type, length), 51820));
    }

    [Fact]
    public void WireGuard_reserved_bytes_must_be_zero()
    {
        var b = WireGuard(1, 148);
        b[2] = 1;
        Assert.False(ProtocolDetector.IsWireGuard(b));
    }

    [Fact]
    public void Dtls_record_is_recognised_and_dns_goes_by_port()
    {
        var dtls = new byte[100];
        dtls[0] = 0x16;
        dtls[1] = 0xFE;
        dtls[2] = 0xFD;
        Assert.Equal(AppProtocol.Dtls, ProtocolDetector.DetectUdp(dtls, 443));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectUdp(dtls.AsSpan(0, 12), 443));
        dtls[0] = 0x18;
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectUdp(dtls, 443));

        var junk = new byte[40];
        junk[0] = 0x55;
        Assert.Equal(AppProtocol.Dns, ProtocolDetector.DetectUdp(junk, 53));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectUdp(junk, 5353));
    }

    [Fact]
    public void Tcp_tls_http_and_mtproto_transports()
    {
        Assert.Equal(AppProtocol.Tls, ProtocolDetector.DetectTcp(new byte[] { 0x16, 0x03, 0x01, 0, 5 }, Somewhere));
        Assert.Equal(AppProtocol.Http, ProtocolDetector.DetectTcp("GET / HTTP/1.1\r\n"u8, Somewhere));
        Assert.Equal(AppProtocol.Http, ProtocolDetector.DetectTcp("POST /x HTTP/1.1\r\n"u8, Somewhere));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp("GETX"u8, Somewhere));
        // abridged and intermediate/padded tags
        Assert.Equal(AppProtocol.Mtproto, ProtocolDetector.DetectTcp(new byte[] { 0xef, 1, 2 }, Somewhere));
        Assert.Equal(AppProtocol.Mtproto, ProtocolDetector.DetectTcp(new byte[] { 0xee, 0xee, 0xee, 0xee, 0 }, Somewhere));
        Assert.Equal(AppProtocol.Mtproto, ProtocolDetector.DetectTcp(new byte[] { 0xdd, 0xdd, 0xdd, 0xdd }, Somewhere));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp(new byte[] { 0xee, 0xee, 0xee, 0x00 }, Somewhere));
    }

    [Fact]
    public void Obfuscated2_is_told_by_telegram_networks_and_length()
    {
        var random = new byte[64];
        new Random(5).NextBytes(random);
        random[0] = 0x42;
        var telegram = IPAddress.Parse("149.154.167.51");
        Assert.Equal(AppProtocol.Mtproto, ProtocolDetector.DetectTcp(random, telegram));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp(random, Somewhere));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp(random.AsSpan(0, 63), telegram));
    }

    [Theory]
    [InlineData("149.154.160.1", true)]
    [InlineData("149.154.175.255", true)]
    [InlineData("149.154.176.0", false)]
    [InlineData("91.108.4.10", true)]
    [InlineData("91.105.193.1", true)]
    [InlineData("91.105.194.1", false)]
    [InlineData("::ffff:91.108.56.3", true)]
    [InlineData("2001:67c:4e8:f004::a", true)]
    [InlineData("2001:b28:f23d::1", true)]
    [InlineData("2001:b28:f240::1", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("2a00:1450::1", false)]
    public void Telegram_networks(string address, bool expected) =>
        Assert.Equal(expected, ProtocolDetector.InTelegram(IPAddress.Parse(address)));

    [Fact]
    public void L7_names_are_the_engine_filter_names()
    {
        var engineL7 = new[] { "tls", "http", "quic", "stun", "wireguard", "discord", "dtls", "dns", "mtproto" };
        var names = Enum.GetValues<AppProtocol>().Where(p => p != AppProtocol.Unknown).Select(ProtocolDetector.L7Name).ToList();
        Assert.All(names, n => Assert.Contains(n, engineL7));
        Assert.Equal(names.Count, names.Distinct().Count());
        Assert.Null(ProtocolDetector.L7Name(AppProtocol.Unknown));
    }

    private static Flow F(string proto, int outPackets, int inPackets, long bytesOut = 0, long bytesIn = 0) => new()
    {
        Protocol = proto,
        Client = new IPEndPoint(IPAddress.Parse("192.168.1.2"), 50000),
        Server = new IPEndPoint(Somewhere, 443),
        PacketsOut = outPackets,
        PacketsIn = inPackets,
        BytesOut = bytesOut,
        BytesIn = bytesIn,
    };

    [Theory]
    [InlineData(4, 0, FlowHealth.NoReply)]
    [InlineData(10, 1, FlowHealth.NoReply)]
    [InlineData(3, 0, FlowHealth.Unknown)]
    [InlineData(4, 2, FlowHealth.Ok)]
    [InlineData(1, 5, FlowHealth.Ok)]
    public void Udp_out_four_in_at_most_one_is_no_reply(int outPackets, int inPackets, FlowHealth expected) =>
        Assert.Equal(expected, FlowVerdict.Judge(F("udp", outPackets, inPackets)));

    [Fact]
    public void Tcp_verdicts()
    {
        var injected = F("tcp", 3, 2, 500, 900);
        injected.Rsts.Add(new RstInfo(DateTime.UtcNow, 50, 1, true, Packets.RstOrigin.Injected, ["TTL"]));
        Assert.Equal(FlowHealth.Reset, FlowVerdict.Judge(injected)); // data came, still a DPI reset

        var serverRstAfterData = F("tcp", 3, 2, 500, 900);
        serverRstAfterData.Rsts.Add(new RstInfo(DateTime.UtcNow, 50, 1, true, Packets.RstOrigin.Server, []));
        Assert.Equal(FlowHealth.Ok, FlowVerdict.Judge(serverRstAfterData));

        var rstNoData = F("tcp", 3, 1, 500, 0);
        rstNoData.Rsts.Add(new RstInfo(DateTime.UtcNow, 50, 1, true, Packets.RstOrigin.Unknown, []));
        Assert.Equal(FlowHealth.Reset, FlowVerdict.Judge(rstNoData));

        Assert.Equal(FlowHealth.Ok, FlowVerdict.Judge(F("tcp", 3, 3, 500, 2000)));

        var stalled = F("tcp", 3, 1, 500, 0);
        stalled.SynAckTime = DateTime.UtcNow;
        Assert.Equal(FlowHealth.Stalled, FlowVerdict.Judge(stalled));
        Assert.Equal(FlowHealth.Unknown, FlowVerdict.Judge(F("tcp", 1, 0, 500, 0)));
    }

    [Fact]
    public void Analyzer_keeps_first_udp_payloads_and_the_protocol()
    {
        const string me = "192.168.1.2", srv = "198.51.100.7";
        var packets = TestPackets.Capture(
            TestPackets.Udp(me, 50000, srv, 3478, TestPackets.Stun()),
            TestPackets.Udp(me, 50000, srv, 3478, TestPackets.Stun(4)),
            TestPackets.Udp(me, 50000, srv, 3478, TestPackets.Stun()),
            TestPackets.Udp(me, 50000, srv, 3478, TestPackets.Stun()),
            TestPackets.Udp(me, 50000, srv, 3478, TestPackets.Stun()),
            TestPackets.Udp(me, 50001, srv, 51820, WireGuard(1, 148)),
            TestPackets.Udp(srv, 51820, me, 50001, WireGuard(2, 92)),
            TestPackets.Udp(me, 50001, srv, 51820, WireGuard(4, 32)));

        var flows = FlowAnalyzer.Analyze(packets);
        Assert.Equal(2, flows.Count);
        var stun = flows[0];
        Assert.Equal(AppProtocol.Stun, stun.AppProtocol);
        Assert.Equal(4, stun.InitialPayloadsOut.Count); // at most 4
        Assert.Equal(24, stun.InitialPayloadsOut[1].Length);
        Assert.Equal(5, stun.PacketsOut);
        Assert.Equal(FlowHealth.NoReply, FlowVerdict.Judge(stun));

        var wg = flows[1];
        Assert.Equal(AppProtocol.WireGuard, wg.AppProtocol);
        // only what the client sent before the server answered
        var only = Assert.Single(wg.InitialPayloadsOut);
        Assert.Equal(148, only.Length);
    }

    [Fact]
    public void Analyzer_detects_tcp_protocol_from_the_first_data_segment()
    {
        const string me = "192.168.1.2", tg = "149.154.167.51";
        var obf = new byte[64];
        new Random(1).NextBytes(obf);
        obf[0] = 0x11;
        var packets = TestPackets.Capture(
            TestPackets.Tcp(me, 40000, tg, 443, TcpFlags.Syn, 100, 0),
            TestPackets.Tcp(tg, 443, me, 40000, TcpFlags.Syn | TcpFlags.Ack, 500, 101),
            TestPackets.Tcp(me, 40000, tg, 443, TcpFlags.Ack, 101, 501),
            TestPackets.Tcp(me, 40000, tg, 443, TcpFlags.Ack | TcpFlags.Psh, 101, 501, obf),
            TestPackets.Tcp(tg, 443, me, 40000, TcpFlags.Ack | TcpFlags.Psh, 501, 165, new byte[100]),
            TestPackets.Tcp(me, 40000, tg, 443, TcpFlags.Ack | TcpFlags.Psh, 165, 601, new byte[10]));

        var f = Assert.Single(FlowAnalyzer.Analyze(packets));
        Assert.Equal(AppProtocol.Mtproto, f.AppProtocol);
        var first = Assert.Single(f.InitialPayloadsOut);
        Assert.Equal(obf, first);
        Assert.Equal(FlowHealth.Ok, FlowVerdict.Judge(f));
    }

    [Fact]
    public void Analyzer_cuts_initial_payloads_at_1500_bytes()
    {
        var big = new byte[1600];
        var f = Assert.Single(FlowAnalyzer.Analyze(TestPackets.Capture(TestPackets.Udp("10.0.0.2", 5000, "198.51.100.7", 9000, big))));
        Assert.Equal(1500, Assert.Single(f.InitialPayloadsOut).Length);
        Assert.Equal(AppProtocol.Unknown, f.AppProtocol);
    }
}
