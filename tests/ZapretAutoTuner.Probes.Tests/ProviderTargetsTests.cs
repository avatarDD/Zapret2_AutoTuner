using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Providers;
using ZapretAutoTuner.Probes.Http;
using ZapretAutoTuner.Probes.Providers;

namespace ZapretAutoTuner.Probes.Tests;

/// <summary>Provider targets without a site (dpi-diagnostics §4a): catalog endpoints plus sampled, certified addresses.</summary>
public sealed class ProviderTargetsTests
{
    [Fact]
    public void Candidate_names_put_exact_names_first_and_turn_wildcards_into_www_and_the_base()
    {
        var names = ProviderTargets.CandidateNames(["*.cdn.test", "1.2.3.4", "", "edge.test", "2001:db8::1", "*.x.test", "y.test", "x.test"]).ToList();
        Assert.Equal(["edge.test", "y.test", "x.test", "www.cdn.test", "cdn.test", "www.x.test"], names);
        Assert.Empty(ProviderTargets.CandidateNames([]));
    }

    private static Provider TestProvider() => new()
    {
        Id = "hoster",
        Name = "Hoster",
        TestEndpoints =
        [
            new ProviderEndpoint { Url = "https://speed.hoster.test/100MB.bin?x=1", San = "speed.hoster.test", MinBytes = 4096 },
            new ProviderEndpoint { Url = "https://gone.hoster.test/f", San = "gone.hoster.test" },
            new ProviderEndpoint { Url = "https://empty.hoster.test/f", San = "empty.hoster.test" },
        ],
    };

    private static List<Cidr> Networks(params string[] cidrs) => CidrSet.Aggregate(cidrs);

    private static Task<IPAddress[]> Resolve(string host, CancellationToken ct) => host switch
    {
        "speed.hoster.test" => Task.FromResult(new[] { IPAddress.Parse("2001:db8::10"), IPAddress.Parse("192.0.2.10") }),
        "empty.hoster.test" => Task.FromResult(Array.Empty<IPAddress>()),
        _ => throw new SocketException((int)SocketError.HostNotFound),
    };

    /// <summary>192.0.2.x: a wildcard certificate, a large response; 198.51.100.x: nothing; 203.0.113.x: three names,
    /// the second valid, a small (2 KB) response.</summary>
    private sealed class FakeTls
    {
        public ConcurrentQueue<HttpProbeOptions> Calls { get; } = new();

        public Task<ProbeResult> Probe(HttpProbeOptions o, CancellationToken ct)
        {
            Calls.Enqueue(o);
            var b = o.Address.GetAddressBytes();
            var r = new ProbeResult { Host = o.Host, Address = o.Address.ToString(), ConnectOk = true, TlsOk = true };
            if (o.Sni == "")
            {
                return Task.FromResult(r with
                {
                    CertNames = b[0] switch
                    {
                        192 => ["*.cdn.test", "192.0.2.1"],
                        203 => ["a.test", "b.test", "c.test"],
                        _ => [],
                    },
                });
            }
            return Task.FromResult(r with
            {
                CertValid = o.Host is "www.cdn.test" or "b.test",
                HttpStatus = 200,
                ContentLength = o.Host == "www.cdn.test" ? 10_000_000 : 2048,
                BodyBytes = o.Host == "www.cdn.test" ? 128 * 1024 : 2048,
                Complete = o.Host != "www.cdn.test",
            });
        }
    }

    [Fact]
    public async Task Finds_endpoints_and_one_certified_address_per_network()
    {
        var tls = new FakeTls();
        var nets = Networks("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24");

        var targets = await ProviderTargets.FindAsync(TestProvider(), nets, 2, Resolve, tls.Probe);

        // only one large response among the networks: the small one fills up, padded
        Assert.Equal(3, targets.Count);
        var ep = targets[0];
        Assert.Equal("endpoint", ep.Source);
        Assert.Equal("speed.hoster.test", ep.Host);
        Assert.Equal(IPAddress.Parse("192.0.2.10"), ep.Address); // IPv4 preferred
        Assert.Equal("/100MB.bin?x=1", ep.Path);
        Assert.Equal(4096, ep.MinBytes);
        Assert.Equal("hoster", ep.Provider);

        var cdn = targets[1];
        Assert.Equal("www.cdn.test", cdn.Host);
        Assert.Equal("192.0.2.0/24", cdn.Source);
        Assert.True(nets[0].Contains(cdn.Address));
        Assert.Equal(ProviderTargets.LargeBytes, cdn.MinBytes);
        Assert.Equal(0, cdn.PadBytes); // a large response needs no padding

        var b = targets[2];
        Assert.Equal("b.test", b.Host);
        Assert.Equal("203.0.113.0/24", b.Source);
        // a small response: padded request, and only the whole response passes (a 2 KB 403 is not 1 byte of success)
        Assert.Equal(ProviderTargets.LargeBytes, b.MinBytes);
        Assert.Equal(ProviderTargets.SmallPadBytes, b.PadBytes);
        var half = new ProbeResult { Host = "b.test", Address = "203.0.113.1", ConnectOk = true, TlsOk = true, CertValid = true, HttpStatus = 403, BodyBytes = 1000 };
        Assert.False(half.Passes(ProbeLevel.L2Body, b.MinBytes));
        Assert.True((half with { Complete = true }).Passes(ProbeLevel.L2Body, b.MinBytes));
        // the name check is a GET that shows the size
        Assert.All(tls.Calls.Where(c => c.Sni != ""), c => Assert.Equal(ProbeLevel.L2Body, c.Level));

        // the bare probe asks without SNI, at L1; only two names of a certificate are tried
        Assert.All(tls.Calls.Where(c => c.Sni == ""), c =>
        {
            Assert.Equal(ProbeLevel.L1Handshake, c.Level);
            Assert.Equal(c.Address.ToString(), c.Host);
        });
        Assert.DoesNotContain(tls.Calls, c => c.Host == "c.test");
        Assert.Contains(tls.Calls, c => c.Host == "a.test" && c.Sni is null && c.Address.Equals(b.Address));
    }

    [Fact]
    public async Task Large_responses_are_preferred_over_small_ones()
    {
        var tls = new FakeTls();
        // the small-response network comes first in the sample, the large one later
        var targets = await ProviderTargets.FindAsync(new Provider { Id = "p", Name = "P" }, Networks("203.0.113.0/24", "192.0.2.0/24"), 1, Resolve, tls.Probe);
        var t = Assert.Single(targets);
        Assert.Equal("www.cdn.test", t.Host);
        Assert.Equal(0, t.PadBytes);
    }

    [Theory]
    [InlineData(200_000L, 16_000L, null, true)]       // Content-Length says large, the cut-off stopped it
    [InlineData(null, 16_000L, 16_000L, true)]        // chunked, cut at 16 KB: larger than the cut
    [InlineData(null, 140_000L, null, true)]
    [InlineData(2048L, 2048L, null, false)]           // a small error page
    [InlineData(null, 3000L, 3000L, false)]
    public void Large_means_by_length_by_bytes_or_by_a_cutoff(long? contentLength, long body, long? stalledAt, bool expected)
    {
        var r = new ProbeResult { Host = "h", Address = "192.0.2.1", ContentLength = contentLength, BodyBytes = body, StalledAt = stalledAt };
        Assert.Equal(expected, ProviderTargets.IsLarge(r));
    }

    [Fact]
    public async Task Stops_once_enough_samples_are_found()
    {
        var tls = new FakeTls();
        var nets = Networks("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24");
        var targets = await ProviderTargets.FindAsync(new Provider { Id = "p", Name = "P" }, nets, 1, Resolve, tls.Probe);
        var t = Assert.Single(targets);
        Assert.Equal("www.cdn.test", t.Host);
        Assert.All(tls.Calls, c => Assert.Equal(192, c.Address.GetAddressBytes()[0]));
    }

    [Fact]
    public async Task Addresses_without_a_valid_certificate_give_nothing()
    {
        var tls = new FakeTls();
        var targets = await ProviderTargets.FindAsync(new Provider { Id = "p", Name = "P" }, Networks("198.51.100.0/24"), 3, Resolve, tls.Probe);
        Assert.Empty(targets);
        Assert.Single(tls.Calls);
    }

    [Fact]
    public async Task Cancellation_stops_the_sampling()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ProviderTargets.FindAsync(new Provider { Id = "p", Name = "P" }, Networks("192.0.2.0/24"), 1, Resolve, new FakeTls().Probe, cts.Token));
    }

    private sealed class StubHandler(Func<Uri, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request.RequestUri!));
    }

    [Fact]
    public async Task Ranges_are_aggregated_and_a_failing_list_is_a_note()
    {
        var p = new Provider
        {
            Id = "p",
            Name = "P",
            Ranges =
            [
                new ProviderRangeSource { Url = "https://ok.test/v4", Format = "text" },
                new ProviderRangeSource { Url = "https://bad.test/json", Format = "aws" },
                new ProviderRangeSource { Url = "https://down.test/x", Format = "text" },
            ],
        };
        using var http = new HttpClient(new StubHandler(u => u.Host switch
        {
            "ok.test" => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("10.0.0.0/25\n10.0.0.128/25\n") },
            "bad.test" => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{not json") },
            _ => new HttpResponseMessage(HttpStatusCode.NotFound),
        }));

        var (nets, notes) = await ProviderTargets.FetchRangesAsync(p, http, CancellationToken.None);
        Assert.Equal(["10.0.0.0/24"], nets.Select(n => n.ToString()));
        Assert.Equal(2, notes.Count);

        p.Ranges.RemoveAt(0);
        await Assert.ThrowsAsync<HttpRequestException>(() => ProviderTargets.FetchRangesAsync(p, http, CancellationToken.None));
    }
}
