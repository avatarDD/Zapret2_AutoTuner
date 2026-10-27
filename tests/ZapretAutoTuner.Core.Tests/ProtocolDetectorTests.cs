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

    /// <summary>A real obfuscated2 header: random, with bytes 56..60 set so that they decrypt to the given tag.</summary>
    internal static byte[] Obfuscated2(int seed, uint tag = 0xEFEFEFEF, int length = 64)
    {
        var b = new byte[length];
        new Random(seed).NextBytes(b);
        Span<byte> ks = stackalloc byte[16];
        ProtocolDetector.Obfuscated2Keystream(b, ks);
        Span<byte> t = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(t, tag);
        for (int i = 0; i < 4; i++)
            b[56 + i] = (byte)(ks[8 + i] ^ t[i]);
        return b;
    }

    [Fact]
    public void Stun_like_the_engine_length_fits_and_is_a_multiple_of_four()
    {
        Assert.True(ProtocolDetector.IsStun(TestPackets.Stun()));
        Assert.True(ProtocolDetector.IsStun(TestPackets.Stun(8)));
        Assert.Equal(AppProtocol.Stun, ProtocolDetector.DetectUdp(TestPackets.Stun()));

        var noCookie = TestPackets.Stun();
        noCookie[4] = 0;
        Assert.False(ProtocolDetector.IsStun(noCookie));
        // the length may be shorter than the datagram (protocol.c: len field <= len-20), not longer
        Assert.True(ProtocolDetector.IsStun(TestPackets.Stun(4).Concat(new byte[8]).ToArray()));
        Assert.False(ProtocolDetector.IsStun(TestPackets.Stun(8).AsSpan(0, 24)));
        var notMultipleOf4 = TestPackets.Stun(8);
        notMultipleOf4[3] = 6;
        Assert.False(ProtocolDetector.IsStun(notMultipleOf4));
        var highBits = TestPackets.Stun();
        highBits[0] = 0x40;
        Assert.False(ProtocolDetector.IsStun(highBits));
        Assert.False(ProtocolDetector.IsStun(TestPackets.Stun().AsSpan(0, 19)));
    }

    [Fact]
    public void Discord_ip_discovery_is_74_bytes_of_type_1_length_70_with_an_empty_address()
    {
        Assert.True(ProtocolDetector.IsDiscordIpDiscovery(Discord()));
        Assert.Equal(AppProtocol.Discord, ProtocolDetector.DetectUdp(Discord()));
        Assert.False(ProtocolDetector.IsDiscordIpDiscovery(Discord().AsSpan(0, 73)));
        var wrongType = Discord();
        wrongType[1] = 2;
        Assert.False(ProtocolDetector.IsDiscordIpDiscovery(wrongType));
        var wrongLength = Discord();
        wrongLength[3] = 71;
        Assert.False(ProtocolDetector.IsDiscordIpDiscovery(wrongLength));
        // the response carries the address: not a request
        var withAddress = Discord();
        withAddress[8] = (byte)'1';
        Assert.False(ProtocolDetector.IsDiscordIpDiscovery(withAddress));
        var lastAddressByte = Discord();
        lastAddressByte[71] = 1;
        Assert.False(ProtocolDetector.IsDiscordIpDiscovery(lastAddressByte));
        var port = Discord();
        port[72] = 0xC3; // the port after the address is not checked
        Assert.True(ProtocolDetector.IsDiscordIpDiscovery(port));
    }

    [Theory]
    [InlineData(1, 148, true)]
    [InlineData(2, 92, true)]
    [InlineData(3, 64, true)]
    [InlineData(4, 32, true)]
    [InlineData(4, 96, false)]  // data: only in a flow already known as WireGuard
    [InlineData(4, 52, false)]
    [InlineData(1, 147, false)]
    [InlineData(1, 92, false)]
    [InlineData(2, 148, false)]
    [InlineData(3, 92, false)]
    [InlineData(4, 50, false)]
    [InlineData(5, 64, false)]
    [InlineData(0, 148, false)]
    public void WireGuard_type_goes_with_its_size(byte type, int length, bool expected)
    {
        Assert.Equal(expected, ProtocolDetector.IsWireGuard(WireGuard(type, length)));
        Assert.Equal(expected ? AppProtocol.WireGuard : AppProtocol.Unknown, ProtocolDetector.DetectUdp(WireGuard(type, length)));
    }

    [Theory]
    [InlineData(52, true)]
    [InlineData(96, true)]
    [InlineData(51, false)]
    [InlineData(40, false)]
    public void WireGuard_data_is_type_4_of_at_least_52_bytes_in_a_wireguard_flow(int length, bool expected)
    {
        Assert.Equal(expected, ProtocolDetector.IsWireGuardData(WireGuard(4, length)));
        Assert.Equal(expected ? AppProtocol.WireGuard : AppProtocol.Unknown, ProtocolDetector.DetectUdp(WireGuard(4, length), knownWireGuard: true));
    }

    [Fact]
    public void WireGuard_reserved_bytes_must_be_zero()
    {
        var b = WireGuard(1, 148);
        b[2] = 1;
        Assert.False(ProtocolDetector.IsWireGuard(b));
    }

    private static byte[] DtlsRecord(byte type, byte v1, byte v2, int recordLength, int total, byte handshake = 1)
    {
        var b = new byte[total];
        b[0] = type;
        b[1] = v1;
        b[2] = v2;
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(11), (ushort)recordLength);
        if (total > 13)
            b[13] = handshake;
        return b;
    }

    [Theory]
    [InlineData(0xFE, 0xFF, true)]
    [InlineData(0xFE, 0xFD, true)]
    [InlineData(0xFE, 0xFC, true)]
    [InlineData(0x01, 0x00, true)]
    [InlineData(0xFE, 0xFE, false)]
    [InlineData(0x03, 0x03, false)]
    public void Dtls_versions_are_those_of_the_engine(byte v1, byte v2, bool expected)
    {
        Assert.Equal(expected, ProtocolDetector.IsDtls(DtlsRecord(0x16, v1, v2, 80, 100)));
        Assert.Equal(expected ? AppProtocol.Dtls : AppProtocol.Unknown, ProtocolDetector.DetectUdp(DtlsRecord(0x16, v1, v2, 80, 100)));
    }

    [Fact]
    public void Dtls_record_length_must_fit_and_only_hellos_name_the_flow()
    {
        Assert.True(ProtocolDetector.IsDtls(DtlsRecord(0x16, 0xFE, 0xFD, 87, 100)));
        Assert.False(ProtocolDetector.IsDtls(DtlsRecord(0x16, 0xFE, 0xFD, 88, 100)));
        Assert.False(ProtocolDetector.IsDtls(DtlsRecord(0x16, 0xFE, 0xFD, 0, 13)));
        Assert.False(ProtocolDetector.IsDtls(DtlsRecord(0x18, 0xFE, 0xFD, 10, 100)));
        // a ServerHello is dtls too; application data or a ChangeCipherSpec is a DTLS record but the engine names
        // the payload only for hellos
        Assert.Equal(AppProtocol.Dtls, ProtocolDetector.DetectUdp(DtlsRecord(0x16, 0xFE, 0xFD, 80, 100, handshake: 2)));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectUdp(DtlsRecord(0x16, 0xFE, 0xFD, 80, 100, handshake: 11)));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectUdp(DtlsRecord(0x17, 0xFE, 0xFD, 80, 100)));
    }

    [Fact]
    public void Dns_goes_by_the_header_not_the_port()
    {
        var query = TestPackets.DnsQuery("example.com");
        Assert.True(ProtocolDetector.IsDnsQuery(query));
        Assert.Equal(AppProtocol.Dns, ProtocolDetector.DetectUdp(query));
        var junk = new byte[40];
        junk[0] = 0x55;
        junk[5] = 7;
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectUdp(junk));
    }

    [Fact]
    public void Tcp_tls_and_http_like_the_engine()
    {
        Assert.Equal(AppProtocol.Tls, ProtocolDetector.DetectTcp(new byte[] { 0x16, 0x03, 0x01, 0, 5, 0x01, 0, 0, 0x50, 0x03, 0x03 }));
        // a record header alone, a TLS 1.4 record or a ServerHello is not a ClientHello
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp(new byte[] { 0x16, 0x03, 0x01, 0, 5 }));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp(new byte[] { 0x16, 0x03, 0x04, 0, 5, 0x01, 0, 0, 0x50, 0x03, 0x03 }));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp(new byte[] { 0x16, 0x03, 0x03, 0, 5, 0x02, 0, 0, 0x50, 0x03, 0x03 }));
        Assert.Equal(AppProtocol.Http, ProtocolDetector.DetectTcp("GET / HTTP/1.1\r\n"u8));
        Assert.Equal(AppProtocol.Http, ProtocolDetector.DetectTcp("POST /x HTTP/1.1\r\nHost: a\r\n"u8));
        Assert.Equal(AppProtocol.Http, ProtocolDetector.DetectTcp("TRACE  /x\tHTTP/1.0\r\n"u8));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp("GET /\r\n"u8));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp("GET / HTTP/2\r\n"u8));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp("GETX"u8));
    }

    [Fact]
    public void Mtproto_is_the_obfuscated2_header_that_decrypts_to_ef_ef_ef_ef()
    {
        for (int seed = 1; seed < 20; seed++)
        {
            Assert.True(ProtocolDetector.IsMtproto(Obfuscated2(seed)));
            Assert.Equal(AppProtocol.Mtproto, ProtocolDetector.DetectTcp(Obfuscated2(seed)));
            Assert.Equal(AppProtocol.Mtproto, ProtocolDetector.DetectTcp(Obfuscated2(seed, length: 200))); // more data after the header
        }
        // the engine accepts only the abridged tag: intermediate (ee) and padded (dd) are unknown to it
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp(Obfuscated2(3, 0xEEEEEEEE)));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp(Obfuscated2(3, 0xDDDDDDDD)));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp(Obfuscated2(3).AsSpan(0, 63)));
        // no plain transport tags and no guessing by address
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp(new byte[] { 0xef, 1, 2 }));
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp(new byte[] { 0xee, 0xee, 0xee, 0xee, 0 }));
        var random = new byte[64];
        new Random(5).NextBytes(random);
        Assert.Equal(AppProtocol.Unknown, ProtocolDetector.DetectTcp(random));
    }

    [Fact]
    public void Mtproto_counter_carries_into_the_high_half()
    {
        // IV low half ff..fd: +3 overflows; the engine's ctr_add carries into the high 64 bits
        var b = Obfuscated2(7);
        for (int i = 48; i < 56; i++)
            b[i] = 0xFF;
        b[55] = 0xFD;
        Span<byte> ks = stackalloc byte[16];
        ProtocolDetector.Obfuscated2Keystream(b, ks);
        var counter = b.AsSpan(40, 16).ToArray();
        for (int i = 8; i < 16; i++)
            counter[i] = 0;
        BinaryPrimitives.WriteUInt64BigEndian(counter, BinaryPrimitives.ReadUInt64BigEndian(counter) + 1);
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = b.AsSpan(8, 32).ToArray();
        Assert.Equal(aes.EncryptEcb(counter, System.Security.Cryptography.PaddingMode.None), ks.ToArray());
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
        var obf = Obfuscated2(1);
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
    public void Analyzer_keeps_whole_datagrams_and_segments()
    {
        var big = new byte[1600];
        var f = Assert.Single(FlowAnalyzer.Analyze(TestPackets.Capture(TestPackets.Udp("10.0.0.2", 5000, "198.51.100.7", 9000, big))));
        Assert.Equal(1600, Assert.Single(f.InitialPayloadsOut).Length);
        Assert.False(f.InitialPayloadsTruncated);
        Assert.Equal(AppProtocol.Unknown, f.AppProtocol);

        // a pre-LSO segment of 20 KB (WinDivert sees them before segmentation) is kept whole
        const string me = "192.168.1.2", srv = "198.51.100.7";
        var seg = new byte[20_000];
        seg[0] = 0x42;
        var tcp = Assert.Single(FlowAnalyzer.Analyze(TestPackets.Capture(
            TestPackets.Tcp(me, 40000, srv, 9000, TcpFlags.Syn, 100, 0),
            TestPackets.Tcp(srv, 9000, me, 40000, TcpFlags.Syn | TcpFlags.Ack, 500, 101),
            TestPackets.Tcp(me, 40000, srv, 9000, TcpFlags.Ack | TcpFlags.Psh, 101, 501, seg))));
        Assert.Equal(20_000, Assert.Single(tcp.InitialPayloadsOut).Length);
        Assert.False(tcp.InitialPayloadsTruncated);
    }

    [Fact]
    public void Analyzer_leaves_retransmissions_out_of_the_replay()
    {
        const string me = "192.168.1.2", srv = "198.51.100.7";
        var data = new byte[300];
        data[0] = 0x42;
        var f = Assert.Single(FlowAnalyzer.Analyze(TestPackets.Capture(
            TestPackets.Tcp(me, 40000, srv, 9000, TcpFlags.Syn, 100, 0),
            TestPackets.Tcp(srv, 9000, me, 40000, TcpFlags.Syn | TcpFlags.Ack, 500, 101),
            TestPackets.Tcp(me, 40000, srv, 9000, TcpFlags.Ack | TcpFlags.Psh, 101, 501, data),
            TestPackets.Tcp(me, 40000, srv, 9000, TcpFlags.Ack | TcpFlags.Psh, 101, 501, data),
            TestPackets.Tcp(me, 40000, srv, 9000, TcpFlags.Ack | TcpFlags.Psh, 101, 501, data),
            TestPackets.Tcp(me, 40000, srv, 9000, TcpFlags.Ack | TcpFlags.Psh, 401, 501, new byte[10]))));
        Assert.Equal([300, 10], f.InitialPayloadsOut.Select(p => p.Length));
        Assert.Equal(2, f.Retransmissions);
    }

    [Fact]
    public void Analyzer_marks_a_replay_that_does_not_fit()
    {
        const string me = "192.168.1.2", srv = "198.51.100.7";
        var packets = new List<byte[]>
        {
            TestPackets.Tcp(me, 40000, srv, 9000, TcpFlags.Syn, 100, 0),
            TestPackets.Tcp(srv, 9000, me, 40000, TcpFlags.Syn | TcpFlags.Ack, 500, 101),
        };
        uint seq = 101;
        for (int i = 0; i < 5; i++)
        {
            var seg = new byte[15_000];
            seg[0] = (byte)(i + 1);
            packets.Add(TestPackets.Tcp(me, 40000, srv, 9000, TcpFlags.Ack, seq, 501, seg));
            seq += 15_000;
        }
        var f = Assert.Single(FlowAnalyzer.Analyze(TestPackets.Capture([.. packets])));
        Assert.True(f.InitialPayloadsTruncated);
        Assert.True(f.InitialPayloadsOut.Sum(p => p.Length) <= FlowAnalyzer.MaxInitialBytes);

        var e = Assert.Single(Programs.ProgramEndpoints.FromRecording([new Programs.ObservedSocket(Model.L4Kind.Tcp, new IPEndPoint(IPAddress.Parse(me), 40000), null)], [f]));
        Assert.True(e.InitialPayloadsTruncated);
        Assert.Empty(e.InitialPayloads);
    }

    [Theory]
    [InlineData("203.0.113.9", 3478, "192.168.1.2", 50000, false)] // the server spoke first: the private end is the client
    [InlineData("192.168.1.2", 50000, "203.0.113.9", 3478, true)]
    [InlineData("203.0.113.9", 53, "198.51.100.7", 40000, false)]   // both public: the well-known port is the server
    [InlineData("198.51.100.7", 3478, "203.0.113.9", 60000, false)] // the ephemeral port is the client
    [InlineData("198.51.100.7", 27015, "203.0.113.9", 27016, true)] // nothing to tell: first sender
    [InlineData("192.168.1.2", 5353, "224.0.0.251", 5353, true)]    // multicast is never the client
    [InlineData("224.0.0.251", 5353, "192.168.1.2", 5353, false)]
    public void Udp_orientation_does_not_trust_the_first_datagram(string src, int sport, string dst, int dport, bool srcIsClient)
    {
        Assert.Equal(srcIsClient, FlowAnalyzer.UdpSourceIsClient(new IPEndPoint(IPAddress.Parse(src), sport), new IPEndPoint(IPAddress.Parse(dst), dport)));
    }

    [Fact]
    public void Udp_flow_whose_server_spoke_first_is_oriented_to_the_local_client()
    {
        const string me = "192.168.1.2", srv = "203.0.113.9";
        var f = Assert.Single(FlowAnalyzer.Analyze(TestPackets.Capture(
            TestPackets.Udp(srv, 3478, me, 50000, TestPackets.Stun()),
            TestPackets.Udp(me, 50000, srv, 3478, TestPackets.Stun()),
            TestPackets.Udp(me, 50000, srv, 3478, TestPackets.Stun()))));
        Assert.Equal(new IPEndPoint(IPAddress.Parse(me), 50000), f.Client);
        Assert.Equal(2, f.PacketsOut);
        Assert.Equal(1, f.PacketsIn);
    }

    // ---- FlowVerdict over time ----

    private static readonly DateTime T0 = new(2026, 10, 1, 12, 0, 0, DateTimeKind.Utc);

    private static Flow Tcp(double lastSeen, long bytesIn = 0, double? lastDataIn = null, int retrans = 0, AppProtocol app = AppProtocol.Unknown) => new()
    {
        Protocol = "tcp",
        Client = new IPEndPoint(IPAddress.Parse("192.168.1.2"), 50000),
        Server = new IPEndPoint(Somewhere, 443),
        FirstSeen = T0,
        LastSeen = T0.AddSeconds(lastSeen),
        SynTime = T0,
        SynAckTime = T0.AddMilliseconds(20),
        PacketsOut = 5,
        PacketsIn = bytesIn > 0 ? 10 : 1,
        BytesOut = 500,
        BytesIn = bytesIn,
        LastDataIn = lastDataIn is { } d ? T0.AddSeconds(d) : null,
        Retransmissions = retrans,
        AppProtocol = app,
    };

    [Fact]
    public void Data_that_stopped_at_16_kb_while_the_client_retransmits_is_a_cutoff_not_ok()
    {
        Assert.Equal(FlowHealth.Cutoff, FlowVerdict.Judge(Tcp(lastSeen: 10, bytesIn: 16_000, lastDataIn: 1, retrans: 3), T0.AddSeconds(30)));
        Assert.Equal(FlowHealth.Ok, FlowVerdict.Judge(Tcp(lastSeen: 10, bytesIn: 16_000, lastDataIn: 1, retrans: 0), T0.AddSeconds(30)));
        Assert.Equal(FlowHealth.Ok, FlowVerdict.Judge(Tcp(lastSeen: 10, bytesIn: 500_000, lastDataIn: 1, retrans: 3), T0.AddSeconds(30)));
    }

    [Fact]
    public void A_flow_opened_at_the_end_of_the_capture_is_not_judged()
    {
        var young = Tcp(lastSeen: 1, retrans: 2, app: AppProtocol.Tls);
        Assert.Equal(FlowHealth.Unknown, FlowVerdict.Judge(young, T0.AddSeconds(1.5)));
        // by default the flow's own last packet is the end
        Assert.Equal(FlowHealth.Unknown, FlowVerdict.Judge(young));
        Assert.Equal(FlowHealth.Stalled, FlowVerdict.Judge(Tcp(lastSeen: 6, retrans: 2, app: AppProtocol.Tls), T0.AddSeconds(6)));
    }

    [Fact]
    public void A_quiet_server_that_acknowledged_is_a_long_poll_not_a_stall()
    {
        // unknown protocol, no retransmissions: the request was acknowledged and the server is holding the answer
        Assert.Equal(FlowHealth.Unknown, FlowVerdict.Judge(Tcp(lastSeen: 20), T0.AddSeconds(30)));
        Assert.Equal(FlowHealth.Stalled, FlowVerdict.Judge(Tcp(lastSeen: 20, retrans: 3), T0.AddSeconds(30)));
        // a ClientHello or a request is answered at once: silence there is a stall
        Assert.Equal(FlowHealth.Stalled, FlowVerdict.Judge(Tcp(lastSeen: 20, app: AppProtocol.Tls), T0.AddSeconds(30)));
        Assert.Equal(FlowHealth.Stalled, FlowVerdict.Judge(Tcp(lastSeen: 20, app: AppProtocol.Mtproto), T0.AddSeconds(30)));
    }
}
