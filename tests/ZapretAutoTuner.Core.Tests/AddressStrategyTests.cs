using ZapretAutoTuner.Core.Validation;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Unify;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>Strategies for program protocols and address profiles (PLAN 6.3–6.4).</summary>
public sealed class AddressStrategyTests
{
    [Theory]
    [InlineData(TargetProtocol.Stun, "stun")]
    [InlineData(TargetProtocol.WireGuard, "wireguard_initiation")]
    [InlineData(TargetProtocol.Discord, "discord_ip_discovery")]
    [InlineData(TargetProtocol.Dtls, "dtls_client_hello")]
    [InlineData(TargetProtocol.Udp, "unknown")]
    public void Udp_program_protocols_get_the_udp_fake_family_with_their_payload(TargetProtocol protocol, string payload)
    {
        Assert.Equal(payload, StrategyGenerator.AutoPayload(protocol));
        var set = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Standard, Protocol = protocol, Platform = EnginePlatform.Linux });
        Assert.Empty(set.Rejected);
        Assert.NotEmpty(set.OfFamily("udp_fake"));
        Assert.All(set.Candidates, c =>
        {
            Assert.Equal("udp_fake", c.Family);
            Assert.Equal(L4Kind.Udp, c.L4);
            Assert.StartsWith($"--payload={payload} ", c.Key, StringComparison.Ordinal);
            // a known payload passes the functions' default payload=known; unknown needs it on every instance
            foreach (var call in c.Strategy.Calls)
                Assert.Equal(payload == "unknown" ? "unknown" : null, call["payload"]);
            if (payload == "unknown")
                Assert.StartsWith("--payload=unknown --out-range=-d2 ", c.Key, StringComparison.Ordinal);
            else
                Assert.DoesNotContain("--out-range", c.Key, StringComparison.Ordinal);
        });
        Assert.Contains(set.Candidates, c => c.Key.Contains("udplen", StringComparison.Ordinal) && c.Key.Contains("increment=", StringComparison.Ordinal));
    }

    [Fact]
    public void Unknown_tcp_gets_a_generic_family_with_payload_unknown_not_tls()
    {
        var set = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Standard, Protocol = TargetProtocol.Tcp, Platform = EnginePlatform.Linux });
        Assert.Empty(set.Rejected);
        Assert.NotEmpty(set.OfFamily("tcp_generic"));
        Assert.All(set.Candidates, c =>
        {
            Assert.Equal("tcp_generic", c.Family);
            Assert.Equal(L4Kind.Tcp, c.L4);
            Assert.StartsWith("--payload=unknown --out-range=-d2 ", c.Key, StringComparison.Ordinal);
            Assert.All(c.Strategy.Calls, call => Assert.Equal("unknown", call["payload"]));
            Assert.DoesNotContain("tls", c.Key, StringComparison.Ordinal);
            Assert.DoesNotContain("sld", c.Key, StringComparison.Ordinal);
        });
        Assert.Empty(StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Full, Protocol = TargetProtocol.Tls }).OfFamily("tcp_generic"));
    }

    [Fact]
    public void Mtproto_gets_offset_splits_and_fakes_over_tcp()
    {
        var set = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Standard, Protocol = TargetProtocol.Mtproto, Platform = EnginePlatform.Windows });
        Assert.Empty(set.Rejected);
        Assert.NotEmpty(set.OfFamily("mtproto"));
        Assert.All(set.Candidates, c =>
        {
            Assert.Equal("mtproto", c.Family);
            Assert.Equal(L4Kind.Tcp, c.L4);
            Assert.StartsWith("--payload=mtproto_initial ", c.Key, StringComparison.Ordinal);
            // no SNI or host in obfuscated2: positions are plain offsets
            Assert.DoesNotContain("sld", c.Key, StringComparison.Ordinal);
        });
        Assert.Contains(set.Candidates, c => c.Key.Contains("multisplit:pos=1", StringComparison.Ordinal));
        Assert.Contains(set.Candidates, c => c.Key.Contains("multidisorder:pos=", StringComparison.Ordinal));
    }

    [Fact]
    public void Program_protocols_do_not_leak_into_site_searches()
    {
        foreach (var p in new[] { TargetProtocol.Tls, TargetProtocol.Http, TargetProtocol.Quic })
        {
            var set = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Full, Protocol = p });
            Assert.Empty(set.OfFamily("udp_fake"));
            Assert.Empty(set.OfFamily("mtproto"));
            Assert.Empty(set.OfFamily("tcp_generic"));
        }
        Assert.Equal("tls_client_hello", StrategyGenerator.AutoPayload(TargetProtocol.Tls));
        Assert.Equal("http_req", StrategyGenerator.AutoPayload(TargetProtocol.Http));
        Assert.Equal("quic_initial", StrategyGenerator.AutoPayload(TargetProtocol.Quic));
        Assert.Equal("mtproto_initial", StrategyGenerator.AutoPayload(TargetProtocol.Mtproto));
    }

    [Theory]
    [InlineData(AppProtocol.Tls, false, TargetProtocol.Tls)]
    [InlineData(AppProtocol.Http, false, TargetProtocol.Http)]
    [InlineData(AppProtocol.Quic, true, TargetProtocol.Quic)]
    [InlineData(AppProtocol.Stun, true, TargetProtocol.Stun)]
    [InlineData(AppProtocol.WireGuard, true, TargetProtocol.WireGuard)]
    [InlineData(AppProtocol.Discord, true, TargetProtocol.Discord)]
    [InlineData(AppProtocol.Dtls, true, TargetProtocol.Dtls)]
    [InlineData(AppProtocol.Mtproto, false, TargetProtocol.Mtproto)]
    [InlineData(AppProtocol.Unknown, true, TargetProtocol.Udp)]
    [InlineData(AppProtocol.Dns, true, TargetProtocol.Udp)]
    [InlineData(AppProtocol.Unknown, false, TargetProtocol.Tcp)]
    [InlineData(AppProtocol.Dns, false, TargetProtocol.Tcp)]
    public void Detected_protocol_maps_to_the_search_protocol(AppProtocol app, bool udp, TargetProtocol expected) =>
        Assert.Equal(expected, StrategyGenerator.FromApp(app, udp));

    [Fact]
    public void Every_program_protocol_has_a_payload_the_engine_knows()
    {
        // protocol.c l7proto payload names of the bundled zapret2
        var known = new[] { "tls_client_hello", "http_req", "quic_initial", "stun", "wireguard_initiation", "discord_ip_discovery", "dtls_client_hello", "mtproto_initial", "unknown" };
        Assert.All(Enum.GetValues<TargetProtocol>(), p => Assert.Contains(StrategyGenerator.AutoPayload(p), known));
    }

    // ---- Unifier.AddIpProfiles ----

    private const string Split1 = "--payload=tls_client_hello --lua-desync=multisplit:pos=1";
    private const string UdpFake = "--payload=stun --lua-desync=fake:blob=0x00000000000000000000000000000000:repeats=6";

    [Fact]
    public void Ip_profiles_come_after_the_hostlist_profiles_with_aggregated_ipsets()
    {
        var plan = Unifier.Plan([new DomainResult("a.com", L4Kind.Tcp, Strategy.Parse(Split1), new Efficiency(5, 5), 1)]);
        var s = Unifier.ToSolution(plan);
        Assert.Single(s.Profiles);

        Unifier.AddIpProfiles(s,
        [
            new IpResult("hetzner", ["5.9.0.0/17", "5.9.128.0/17", "5.9.1.0/24", "2a01:4f8::/32", "junk"], L4Kind.Tcp, "443", ["tls"], Strategy.Parse(Split1)),
            new IpResult("discord", ["66.22.196.10", "66.22.196.11"], L4Kind.Udp, "50000-50100", ["stun", "discord"], Strategy.Parse(UdpFake)),
        ]);

        Assert.Equal(3, s.Profiles.Count);
        Assert.Equal("tcp1", s.Profiles[0].Name);
        var h = s.Profiles[1];
        Assert.Equal("hetzner", h.Name);
        Assert.Equal("443", h.TcpPorts);
        Assert.Null(h.UdpPorts);
        Assert.Equal(["tls"], h.L7);
        Assert.Equal([new ListRef("hetzner")], h.Ipsets);
        Assert.Empty(h.Hostlists);
        Assert.Equal(["5.9.0.0/16", "2a01:4f8::/32"], s.Ipsets["hetzner"]);

        var d = s.Profiles[2];
        Assert.Null(d.TcpPorts);
        Assert.Equal("50000-50100", d.UdpPorts);
        Assert.Equal(["stun", "discord"], d.L7);
        Assert.Equal(["66.22.196.10/31"], s.Ipsets["discord"]);
        Assert.Equal(UdpFake, d.Strategy.ToString());

        Assert.Equal(["a.com", "hetzner", "discord"], s.Meta.Targets);
        Assert.Equal("443,50000-50100", s.TcpPorts + "," + s.UdpPorts);
    }

    [Fact]
    public void Ip_profile_names_that_collide_get_a_suffix_instead_of_overwriting()
    {
        var plan = Unifier.Plan([new DomainResult("a.com", L4Kind.Tcp, Strategy.Parse(Split1), new Efficiency(5, 5), 1)]);
        var s = Unifier.ToSolution(plan);
        var hostlist = s.Hostlists.Keys.First();
        Unifier.AddIpProfiles(s,
        [
            new IpResult("discord", ["66.22.196.10"], L4Kind.Udp, "50000-50100", ["discord"], Strategy.Parse(UdpFake)),
            new IpResult("discord", ["66.22.197.10"], L4Kind.Tcp, "443", ["tls"], Strategy.Parse(Split1)),
            new IpResult(hostlist, ["198.51.100.1"], L4Kind.Tcp, "443", [], Strategy.Parse(Split1)),
        ]);
        Assert.Equal(["discord", "discord-2", hostlist + "-2"], s.Profiles.Skip(1).Select(p => p.Name));
        Assert.Equal(s.Profiles.Count, s.Profiles.Select(p => p.Name).Distinct().Count());
        Assert.Equal(["66.22.196.10/32"], s.Ipsets["discord"]);
        Assert.Equal(["66.22.197.10/32"], s.Ipsets["discord-2"]);
        Assert.Equal([new ListRef("discord-2")], s.Profiles[2].Ipsets);
        Assert.Equal(["198.51.100.1/32"], s.Ipsets[hostlist + "-2"]);
    }
}
