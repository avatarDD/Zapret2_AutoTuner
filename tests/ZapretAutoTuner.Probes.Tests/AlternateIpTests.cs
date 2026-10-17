using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Dns;
using ZapretAutoTuner.Probes.Diagnostics;
using ZapretAutoTuner.Probes.Dns;

namespace ZapretAutoTuner.Probes.Tests;

public class AlternateIpTests
{
    private sealed class FixedSource(params AltIpCandidate[] c) : IAltIpCandidateSource
    {
        public Task<IReadOnlyList<AltIpCandidate>> GetAsync(string host, CancellationToken ct) => Task.FromResult<IReadOnlyList<AltIpCandidate>>(c);
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    [Fact]
    public async Task Only_addresses_with_a_valid_certificate_are_accepted_and_full_download_ranks_first()
    {
        if (!OperatingSystem.IsLinux())
            return; // 127.0.0.2+ are loopback addresses on Linux only
        int port = FreePort();
        var host = "blocked.test";
        await using var full = new TestServer(ServerMode.Ok, TestCerts.Leaf(host), bodyBytes: 200_000, bind: IPAddress.Parse("127.0.0.2"), port: port);
        await using var cut = new TestServer(ServerMode.StallAfter, TestCerts.Leaf(host), bodyBytes: 200_000, bind: IPAddress.Parse("127.0.0.3"), port: port);
        await using var foreign = new TestServer(ServerMode.Ok, TestCerts.Leaf("other.test"), bind: IPAddress.Parse("127.0.0.4"), port: port);
        // 127.0.0.5: nothing listens (connection refused)

        var r = await AlternateIpSearch.RunAsync(host, dns: null, new AlternateIpOptions
        {
            Port = port,
            Subnets = [],
            Exclude = [IPAddress.Parse("127.0.0.9")],
            AddressFilter = _ => true,
            Sources = [new FixedSource(
                new AltIpCandidate(IPAddress.Parse("127.0.0.5"), "test"),
                new AltIpCandidate(IPAddress.Parse("127.0.0.4"), "test"),
                new AltIpCandidate(IPAddress.Parse("127.0.0.3"), "test"),
                new AltIpCandidate(IPAddress.Parse("127.0.0.2"), "test"),
                new AltIpCandidate(IPAddress.Parse("127.0.0.9"), "test"))],
            TweakHttp = o => o with { TrustedRoots = TestCerts.Roots, StallTimeout = TimeSpan.FromSeconds(1) },
        });

        Assert.Equal(4, r.Checked.Count); // the excluded one is not checked
        Assert.True(r.Found);
        Assert.Equal(["127.0.0.2", "127.0.0.3"], r.Best.Select(b => b.Candidate.Address.ToString()));
        Assert.True(r.Best[0].OpensFully);
        Assert.False(r.Best[1].OpensFully); // accepted: a strategy is tuned for it next
        Assert.Contains("сертификат", r.Checked.Single(c => c.Candidate.Address.ToString() == "127.0.0.4").RejectReason, StringComparison.Ordinal);
        Assert.Contains("заблокирован", r.Checked.Single(c => c.Candidate.Address.ToString() == "127.0.0.5").RejectReason, StringComparison.Ordinal);
        Assert.Contains("127.0.0.2", r.SummaryRu, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Nothing_found_means_vpn()
    {
        var r = await AlternateIpSearch.RunAsync("blocked.test", null, new AlternateIpOptions { Subnets = [] });
        Assert.False(r.Found);
        Assert.Contains("VPN", r.SummaryRu, StringComparison.Ordinal);
    }

    [Fact]
    public void Gather_orders_doh_first_dedups_and_drops_stubs()
    {
        var dns = new DnsReport
        {
            Host = "x.example",
            Answers =
            [
                new DnsResolverAnswer { Resolver = "system", Kind = DnsResolverKind.System, Status = DnsAnswerStatus.Ok, Addresses = [IPAddress.Parse("10.10.10.10"), IPAddress.Parse("203.0.113.1")] },
                new DnsResolverAnswer { Resolver = "Google DoH", Kind = DnsResolverKind.Doh, Status = DnsAnswerStatus.Ok, Addresses = [IPAddress.Parse("203.0.113.2"), IPAddress.Parse("203.0.113.1")] },
            ],
            Verdict = new DnsVerdict { Kind = DnsVerdictKind.Clean },
        };
        var ecs = new[] { new DnsSubnetAnswer(DnsClientSubnet.Parse("80.128.0.0/24"), [IPAddress.Parse("198.51.100.7"), IPAddress.Parse("2001:db8::7")], 24, null) };
        var list = AlternateIpSearch.Gather(dns, ecs, [], new AlternateIpOptions { Exclude = [IPAddress.Parse("203.0.113.2")], Ipv6 = false });
        Assert.Equal(["203.0.113.1", "198.51.100.7"], list.Select(c => c.Address.ToString()));
        Assert.Equal("Google DoH", list[0].Source);
        Assert.StartsWith("ECS", list[1].Source, StringComparison.Ordinal);
    }

    [Fact]
    public void Default_subnets_load()
    {
        Assert.True(AlternateIpSearch.DefaultSubnets().Count >= 5);
    }
}
