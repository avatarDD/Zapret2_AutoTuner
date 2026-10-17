using System.Net;
using System.Text.Json;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>Packet parsing against the tshark reference in tests/pcaps/expected.json (PLAN 1.4).</summary>
public class PacketTests
{
    private static readonly JsonElement Expected = JsonDocument.Parse(File.ReadAllText(RepoPaths.Pcaps("expected.json"))).RootElement;

    public static TheoryData<string> CorpusFiles()
    {
        var d = new TheoryData<string>();
        foreach (var p in Expected.EnumerateObject())
            d.Add(p.Name);
        return d;
    }

    private static List<Flow> Flows(string file) => FlowAnalyzer.Analyze(PcapReader.Read(File.ReadAllBytes(RepoPaths.Pcaps(file))));

    [Theory]
    [MemberData(nameof(CorpusFiles))]
    public void ClientHello_matches_tshark(string file)
    {
        var expected = Expected.GetProperty(file).GetProperty("client_hellos").EnumerateArray().ToList();
        var hellos = Flows(file).Where(f => f.ClientHello is not null).ToList();
        Assert.Equal(expected.Count, hellos.Count);
        for (int i = 0; i < expected.Count; i++)
        {
            var e = expected[i];
            var f = hellos[i];
            var ch = f.ClientHello!;
            bool quic = f.Protocol == "udp";
            Assert.Equal(e.GetProperty("sni").GetString(), ch.Sni);
            // Wireshark 4.2 still writes "u" for QUIC; the JA4 spec uses "q"
            var ja4 = e.GetProperty("ja4").GetString()!;
            var ja4r = e.GetProperty("ja4_r").GetString()!;
            if (quic)
            {
                ja4 = "q" + ja4[1..];
                ja4r = "q" + ja4r[1..];
            }
            Assert.Equal(ja4r, ch.Ja4Raw(quic));
            Assert.Equal(ja4, ch.Ja4(quic));
            Assert.Equal(e.GetProperty("ja3_full").GetString(), ch.Ja3String());
            Assert.Equal(e.GetProperty("ja3").GetString(), ch.Ja3());
            Assert.Equal(e.GetProperty("alpn").EnumerateArray().Select(x => x.GetString()), ch.Alpn);
            Assert.Equal(e.GetProperty("key_share_groups").EnumerateArray().Select(x => (ushort)x.GetInt32()), ch.KeyShareGroups);
        }
    }

    [Theory]
    [MemberData(nameof(CorpusFiles))]
    public void Rst_ttl_and_ipid_match_tshark(string file)
    {
        var expected = Expected.GetProperty(file).GetProperty("rsts").EnumerateArray().ToList();
        var rsts = Flows(file).SelectMany(f => f.Rsts).ToList();
        Assert.Equal(expected.Count, rsts.Count);
        for (int i = 0; i < expected.Count; i++)
        {
            Assert.Equal(expected[i].GetProperty("ttl").GetInt32(), rsts[i].Ttl);
            Assert.Equal(expected[i].GetProperty("ip_id").GetInt32(), rsts[i].IpId);
        }
    }

    [Fact]
    public void Kyber_hello_spans_two_segments_and_rst_is_injected()
    {
        var f = Assert.Single(Flows("tls13_kyber_rst.pcap"));
        Assert.True(f.ClientHello!.HasPostQuantumKeyShare);
        Assert.True(f.ClientHello.HandshakeLength > 1400);
        Assert.Equal(2, f.ClientHelloSegments);
        var rst = Assert.Single(f.Rsts);
        Assert.Equal(RstOrigin.Injected, rst.Origin);
        Assert.Contains(rst.Reasons, r => r.Contains("TTL", StringComparison.Ordinal));
        Assert.Contains(rst.Reasons, r => r.Contains("IPID", StringComparison.Ordinal));
        Assert.Contains(rst.Reasons, r => r.Contains("RTT", StringComparison.Ordinal));
    }

    [Fact]
    public void Server_rst_with_matching_ttl_is_not_injected()
    {
        var f = Assert.Single(Flows("tls13_ech_server_rst.pcap"));
        Assert.True(f.ClientHello!.HasEch);
        Assert.False(f.ClientHello.OffersPostQuantum);
        Assert.Equal(RstOrigin.Server, Assert.Single(f.Rsts).Origin);
    }

    [Fact]
    public void Quic_kyber_hello_is_reassembled_from_two_initials()
    {
        var f = Assert.Single(Flows("quic_kyber_two_initials.pcap"));
        Assert.Equal("udp", f.Protocol);
        Assert.Equal(2, f.ClientHelloSegments);
        Assert.True(f.ClientHello!.HasPostQuantumKeyShare);
        Assert.Equal(["h3"], f.ClientHello.Alpn);
    }

    [Fact]
    public void Quic_keys_match_rfc9001_appendix_a()
    {
        var (key, iv, hp) = QuicInitial.ClientKeys(Convert.FromHexString("8394c8f03e515708"), QuicInitial.Version1);
        Assert.Equal("1f369613dd76d5467730efcbe3b1a22d", Convert.ToHexStringLower(key));
        Assert.Equal("fa044b2f42a3fd3b46fb255c", Convert.ToHexStringLower(iv));
        Assert.Equal("9f50449e04a0e810283a1e9933adedd2", Convert.ToHexStringLower(hp));
    }

    [Fact]
    public void Quic_v2_keys_match_rfc9369_appendix_a()
    {
        var (key, iv, hp) = QuicInitial.ClientKeys(Convert.FromHexString("8394c8f03e515708"), QuicInitial.Version2);
        Assert.Equal("8b1a0bc121284290a29e0971b5cd045d", Convert.ToHexStringLower(key));
        Assert.Equal("91f73e2351d8fa91660e909f", Convert.ToHexStringLower(iv));
        Assert.Equal("45b95e15235d6f45a6b19cbcb0294ba9", Convert.ToHexStringLower(hp));
    }

    [Fact]
    public void Quic_garbage_and_server_packets_are_ignored()
    {
        Assert.Empty(QuicInitial.DecryptDatagram(new byte[50]));
        var bytes = new byte[1200];
        bytes[0] = 0xC0;
        bytes[4] = 1;
        bytes[5] = 8;
        Assert.Empty(QuicInitial.DecryptDatagram(bytes));
    }

    [Fact]
    public void Pcapng_roundtrip_keeps_packets_time_and_direction()
    {
        var src = PcapReader.Read(File.ReadAllBytes(RepoPaths.Pcaps("tls13_kyber_rst.pcap")));
        var dirs = src.Select((p, i) => p with { Direction = i % 2 == 0 ? PacketDirection.Outbound : PacketDirection.Inbound }).ToList();
        var back = PcapReader.Read(PcapNgWriter.ToBytes(dirs));
        Assert.Equal(dirs.Count, back.Count);
        for (int i = 0; i < dirs.Count; i++)
        {
            Assert.Equal(dirs[i].Data.ToArray(), back[i].Data.ToArray());
            Assert.Equal(dirs[i].Direction, back[i].Direction);
            Assert.True(Math.Abs((dirs[i].TimestampUtc - back[i].TimestampUtc).TotalMilliseconds) < 0.01);
        }
    }

    [Fact]
    public void Pcapng_written_by_us_is_read_by_tshark_identically()
    {
        if (!TryFind("tshark", out var tshark))
            return; // tshark is optional; the corpus test above covers parsing
        var src = PcapReader.Read(File.ReadAllBytes(RepoPaths.Pcaps("tls13_single.pcap")));
        var file = Path.Combine(Path.GetTempPath(), $"zt-{Guid.NewGuid():N}.pcapng");
        File.WriteAllBytes(file, PcapNgWriter.ToBytes(src));
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo(tshark, ["-r", file, "-T", "fields", "-e", "tls.handshake.extensions_server_name"])
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = System.Diagnostics.Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            Assert.Equal(0, p.ExitCode);
            Assert.Contains("example.org", output, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(file);
        }
    }

    private static bool TryFind(string exe, out string path)
    {
        foreach (var d in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            path = Path.Combine(d, exe);
            if (File.Exists(path))
                return true;
        }
        path = "";
        return false;
    }

    [Fact]
    public void Ipv4_tcp_fields()
    {
        var p = PcapReader.Read(File.ReadAllBytes(RepoPaths.Pcaps("tls13_single.pcap")))[1].Parse()!;
        Assert.Equal(IPAddress.Parse("203.0.113.10"), p.Source);
        Assert.Equal(443, p.SourcePort);
        Assert.True(p.Has(TcpFlags.Syn | TcpFlags.Ack));
        Assert.Equal(52, p.Ttl);
        Assert.Equal(0, p.IpId);
    }

    [Fact]
    public void Ipv6_with_extension_header()
    {
        // IPv6, hop-by-hop (8 bytes) → UDP 1234 → 53, payload "hi"
        var pkt = new List<byte>
        {
            0x60, 0, 0, 0, 0, 18, 0, 64,
        };
        pkt.AddRange(IPAddress.Parse("2001:db8::1").GetAddressBytes());
        pkt.AddRange(IPAddress.Parse("2001:db8::2").GetAddressBytes());
        pkt.AddRange(new byte[] { 17, 0, 1, 4, 0, 0, 0, 0 });
        pkt.AddRange(new byte[] { 0x04, 0xD2, 0, 53, 0, 10, 0, 0, (byte)'h', (byte)'i' });
        var p = IpPacket.Parse(pkt.ToArray())!;
        Assert.True(p.IsUdp);
        Assert.Equal(1234, p.SourcePort);
        Assert.Equal(53, p.DestinationPort);
        Assert.Equal("hi", System.Text.Encoding.ASCII.GetString(p.Payload.Span));
        Assert.Null(p.IpId);
    }

    [Theory]
    [InlineData(new byte[] { })]
    [InlineData(new byte[] { 0x45, 0, 0 })]
    [InlineData(new byte[] { 0x16, 3, 1, 0, 5, 1, 0, 0 })]
    public void Truncated_input_does_not_throw(byte[] data)
    {
        _ = IpPacket.Parse(data);
        _ = TlsClientHello.TryParseRecords(data, out _);
        _ = QuicInitial.DecryptDatagram(data);
    }

    [Fact]
    public void Cut_client_hello_needs_more()
    {
        var src = PcapReader.Read(File.ReadAllBytes(RepoPaths.Pcaps("tls13_kyber_rst.pcap")));
        var first = src.Select(p => p.Parse()!).First(p => p.Payload.Length > 0);
        Assert.Equal(TlsParseStatus.NeedMore, TlsClientHello.TryParseRecords(first.Payload.Span, out _));
        Assert.Equal(TlsParseStatus.NotTls, TlsClientHello.TryParseRecords("GET / HTTP/1.1\r\n"u8, out _));
    }
}
