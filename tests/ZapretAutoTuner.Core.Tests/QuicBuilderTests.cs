using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Core.Tests;

public sealed class QuicBuilderTests
{
    private static readonly byte[] Dcid = Convert.FromHexString("8394c8f03e515708");
    private static readonly byte[] Scid = Convert.FromHexString("0102030405060708");

    private static byte[] Hello(bool kyber) => ClientHelloBuilder.BuildHandshake(ClientHelloSpec.Get("chrome141"),
        new ClientHelloOptions { Sni = "quic.example", Kyber = kyber, Alpn = ["h3"], QuicScid = Scid, Seed = 1 });

    [Theory]
    [InlineData(false, QuicInitial.Version1, 1)]
    [InlineData(true, QuicInitial.Version1, 2)]
    [InlineData(true, QuicInitial.Version2, 2)]
    public void Initials_roundtrip_through_the_decryptor(bool kyber, uint version, int expectedDatagrams)
    {
        var hs = Hello(kyber);
        var dgrams = QuicInitial.BuildInitials(hs, Dcid, Scid, version);
        Assert.Equal(expectedDatagrams, dgrams.Count);
        Assert.All(dgrams, d => Assert.Equal(1200, d.Length));
        Assert.All(dgrams, d => Assert.True(QuicInitial.IsInitial(d)));
        var st = QuicInitial.TryParseClientHello(dgrams.Select(d => (ReadOnlyMemory<byte>)d), out var ch, out var first);
        Assert.Equal(TlsParseStatus.Ok, st);
        Assert.Equal("quic.example", ch!.Sni);
        Assert.Equal(version, first!.Version);
        Assert.Equal(Dcid, first.Dcid);
        Assert.Equal(kyber, ch.HasPostQuantumKeyShare);
        Assert.Equal(hs.Length, ch.HandshakeLength);
    }

    [Fact]
    public void Server_initial_opens_only_with_server_keys()
    {
        byte[] serverHello = [2, 0, 0, 4, 3, 3, 0, 0];
        var d = QuicInitial.BuildInitials(serverHello, Scid, [9, 9, 9, 9], server: true, keyDcid: Dcid)[0];
        Assert.Empty(QuicInitial.DecryptDatagram(d)); // client keys of its own DCID do not open it
        var p = Assert.Single(QuicInitial.DecryptDatagram(d, Dcid));
        Assert.Equal(serverHello, p.Crypto[0].Data);
    }

    [Fact]
    public void Tampered_datagram_does_not_decrypt()
    {
        var d = QuicInitial.BuildInitials(Hello(false), Dcid, Scid)[0];
        d[^20] ^= 1;
        Assert.Empty(QuicInitial.DecryptDatagram(d));
    }
}
