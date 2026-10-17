using System.Text.Json;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Core.Tests;

public sealed class ClientHelloBuilderTests
{
    private static TlsClientHello Parse(byte[] record)
    {
        Assert.Equal(TlsParseStatus.Ok, TlsClientHello.TryParseRecords(record, out var ch));
        return ch!;
    }

    private static TlsClientHello Build(string id, ClientHelloOptions? o = null) =>
        Parse(ClientHelloBuilder.BuildRecord(ClientHelloSpec.Get(id), o ?? new ClientHelloOptions { Sni = "www.example.com" }));

    // Published JA4 of the real clients (FoxIO ja4 database), so the specs are checked against the clients, not themselves.
    [Theory]
    [InlineData("chrome141", "t13d1516h2_8daaf6152771_e15453cad77d")]
    [InlineData("chrome_legacy", "t13d1516h2_8daaf6152771_e5627efa2ab1")]
    [InlineData("firefox", "t13d1717h2_5b57614c22b0_3cbfd9057e0d")]
    [InlineData("safari", "t13d2014h2_a09f3c656075_14788d8d241b")]
    public void Ja4_matches_the_real_client(string id, string ja4)
    {
        Assert.Equal(ja4, Build(id).Ja4());
    }

    // A server validates the NIST key share it picks (Schannel answered a random point with an alert), so the share
    // must import as a real public key; the OS crypto checks that the point is on the curve.
    [Theory]
    [InlineData(32)]
    [InlineData(48)]
    [InlineData(66)]
    public void Nist_key_share_is_a_point_on_the_curve(int size)
    {
        var (curve, named) = size switch
        {
            32 => (WeierstrassCurve.P256, System.Security.Cryptography.ECCurve.NamedCurves.nistP256),
            48 => (WeierstrassCurve.P384, System.Security.Cryptography.ECCurve.NamedCurves.nistP384),
            _ => (WeierstrassCurve.P521, System.Security.Cryptography.ECCurve.NamedCurves.nistP521),
        };
        for (int seed = 0; seed < 4; seed++)
        {
            var point = ClientHelloBuilder.EcPoint(curve, new Random(seed));
            Assert.Equal(1 + 2 * size, point.Length);
            Assert.Equal(4, point[0]);
            Assert.Equal(point, ClientHelloBuilder.EcPoint(curve, new Random(seed)));
            Import(point);
            var bad = (byte[])point.Clone();
            bad[^1] ^= 1;
            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => Import(bad));
        }

        void Import(byte[] p)
        {
            using var ec = System.Security.Cryptography.ECDiffieHellman.Create();
            ec.ImportParameters(new System.Security.Cryptography.ECParameters
            {
                Curve = named,
                Q = new System.Security.Cryptography.ECPoint { X = p[1..(1 + size)], Y = p[(1 + size)..] },
            });
        }
    }

    [Fact]
    public void Chrome_spec_equals_the_captured_chromium_hello()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(RepoPaths.Pcaps(), "expected.json")));
        var captured = doc.RootElement.GetProperty("live_chromium141.pcap").GetProperty("client_hellos")[0];
        var ch = Build("chrome141", new ClientHelloOptions { Sni = "chrome.test" });
        Assert.Equal(captured.GetProperty("ja4_r").GetString(), ch.Ja4Raw());
        Assert.Equal(captured.GetProperty("ja4").GetString(), ch.Ja4());

        var real = PcapReader.Read(File.ReadAllBytes(Path.Combine(RepoPaths.Pcaps(), "live_chromium141.pcap")));
        var flows = FlowAnalyzer.Analyze(real);
        var realCh = flows.First(f => f.ClientHellos.Count > 0).ClientHellos[^1];
        Assert.Equal(realCh.HandshakeLength, ch.HandshakeLength);
        Assert.Equal(realCh.KeyShareGroups.Where(g => !TlsClientHello.IsGrease(g)), ch.KeyShareGroups.Where(g => !TlsClientHello.IsGrease(g)));
    }

    [Fact]
    public void Kyber_share_has_the_real_size_and_can_be_turned_off()
    {
        var spec = ClientHelloSpec.Get("chrome141");
        var hs = ClientHelloBuilder.BuildHandshake(spec, new ClientHelloOptions { Sni = "a.example" });
        var ch = Parse(ClientHelloBuilder.BuildRecord(spec, new ClientHelloOptions { Sni = "a.example" }));
        Assert.True(ch.HasPostQuantumKeyShare);
        Assert.True(hs.Length > 1400); // more than one MSS: the multi-packet hello of §2.12

        var plain = Build("chrome141", new ClientHelloOptions { Sni = "a.example", Kyber = false });
        Assert.False(plain.OffersPostQuantum);
        Assert.False(plain.HasPostQuantumKeyShare);
        Assert.Contains((ushort)0x001D, plain.KeyShareGroups);
        Assert.True(plain.HandshakeLength < 600);
    }

    [Fact]
    public void MlKem_key_passes_the_modulus_check()
    {
        var key = ClientHelloBuilder.MlKem768PublicKey(new Random(5));
        Assert.Equal(1184, key.Length);
        for (int i = 0; i < 384; i++)
        {
            int a = key[3 * i] | ((key[(3 * i) + 1] & 0x0F) << 8);
            int b = (key[(3 * i) + 1] >> 4) | (key[(3 * i) + 2] << 4);
            Assert.True(a < 3329 && b < 3329);
        }
    }

    [Fact]
    public void Ech_grease_can_be_added_or_removed()
    {
        Assert.False(Build("chrome141").HasEch);
        Assert.True(Build("chrome141", new ClientHelloOptions { Sni = "a.example", Ech = true }).HasEch);
        Assert.True(Build("firefox").HasEch);
        Assert.False(Build("firefox", new ClientHelloOptions { Sni = "a.example", Ech = false }).HasEch);
    }

    [Fact]
    public void No_sni_for_ip_or_empty()
    {
        Assert.Null(Build("chrome141", new ClientHelloOptions { Sni = "203.0.113.5" }).Sni);
        Assert.Null(Build("chrome141", new ClientHelloOptions()).Sni);
        Assert.StartsWith("t13i", Build("chrome141", new ClientHelloOptions()).Ja4(), StringComparison.Ordinal);
    }

    [Fact]
    public void Chrome_permutes_extensions_but_keeps_grease_at_the_ends()
    {
        var orders = Enumerable.Range(0, 8)
            .Select(i => Build("chrome141", new ClientHelloOptions { Sni = "a.example", Seed = i }).Extensions)
            .ToList();
        Assert.True(orders.Select(o => string.Join(',', o)).Distinct().Count() > 1);
        Assert.All(orders, o =>
        {
            Assert.True(TlsClientHello.IsGrease(o[0]));
            Assert.True(TlsClientHello.IsGrease(o[^1]));
            Assert.NotEqual(o[0], o[^1]);
        });
        // fixed order for a non-permuting client
        var ff = Enumerable.Range(0, 3).Select(i => string.Join(',', Build("firefox", new ClientHelloOptions { Sni = "a.example", Seed = i }).Extensions)).Distinct();
        Assert.Single(ff);
    }

    [Fact]
    public void Seeded_hello_is_reproducible()
    {
        var o = new ClientHelloOptions { Sni = "a.example", Seed = 42 };
        var spec = ClientHelloSpec.Get("safari");
        Assert.Equal(ClientHelloBuilder.BuildRecord(spec, o), ClientHelloBuilder.BuildRecord(spec, o));
    }

    [Fact]
    public void Boringssl_padding_rounds_to_512()
    {
        var ch = Build("chrome_legacy", new ClientHelloOptions { Sni = "a.example" });
        Assert.Equal(512, ch.HandshakeLength);
        Assert.Contains(TlsClientHello.ExtPadding, ch.Extensions);
        // a long SNI pushes the hello past 512: no padding then
        var big = Build("chrome_legacy", new ClientHelloOptions { Sni = string.Join('.', Enumerable.Repeat(new string('a', 60), 4)) + ".com" });
        Assert.True(big.HandshakeLength > 512);
        Assert.DoesNotContain(TlsClientHello.ExtPadding, big.Extensions);
    }

    [Fact]
    public void Tls12_only_client_has_no_tls13_extensions()
    {
        var ch = Build("tv_tls12");
        Assert.Equal(0x0303, ch.MaxVersion);
        Assert.Empty(ch.SupportedVersions);
        Assert.Empty(ch.KeyShareGroups);
        Assert.Empty(ch.SessionId);
        Assert.Equal(["http/1.1"], ch.Alpn);
    }

    [Fact]
    public void Quic_hello_has_transport_parameters_and_only_tls13()
    {
        var hs = ClientHelloBuilder.BuildHandshake(ClientHelloSpec.Get("chrome141"),
            new ClientHelloOptions { Sni = "a.example", Alpn = ["h3"], QuicScid = [1, 2, 3, 4] });
        Assert.Equal(TlsParseStatus.Ok, TlsClientHello.TryParseHandshake(hs, out var ch));
        Assert.Contains((ushort)0x0039, ch!.Extensions);
        Assert.Equal(["h3"], ch.Alpn);
        Assert.All(ch.CipherSuites.Where(c => !TlsClientHello.IsGrease(c)), c => Assert.Equal(0x13, c >> 8));
        Assert.DoesNotContain((ushort)0xFF01, ch.Extensions);
        Assert.Empty(ch.SessionId);
        Assert.StartsWith("q13d", ch.Ja4(quic: true), StringComparison.Ordinal);
    }

    [Fact]
    public void Every_spec_builds_and_parses()
    {
        foreach (var s in ClientHelloSpec.All)
        {
            var ch = Build(s.Id);
            Assert.Equal("www.example.com", ch.Sni);
            Assert.NotEmpty(ch.CipherSuites);
        }
    }
}

public sealed class ClientProfileHelloTests
{
    [Fact]
    public void Profiles_point_to_specs_that_agree_with_their_flags()
    {
        foreach (var p in ZapretAutoTuner.Core.Model.ClientProfile.BuiltIn.Where(p => p.HelloSpec is not null))
        {
            var spec = ClientHelloSpec.Get(p.HelloSpec!);
            var hs = ClientHelloBuilder.BuildHandshake(spec, new ClientHelloOptions { Sni = "a.example", Kyber = p.Kyber });
            Assert.Equal(TlsParseStatus.Ok, TlsClientHello.TryParseHandshake(hs, out var ch));
            Assert.Equal(p.Kyber, ch!.HasPostQuantumKeyShare);
            Assert.Equal(p.Tls12Only, ch.MaxVersion == 0x0303);
        }
    }
}
