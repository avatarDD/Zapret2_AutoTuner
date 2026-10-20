using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Providers;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>The provider catalog, range list parsers and CIDR aggregation (PLAN 6.4, dpi-diagnostics §4a).</summary>
public sealed class ProvidersTests
{
    /// <summary>A small sample of each published format, and the CIDRs it holds.</summary>
    private static readonly Dictionary<string, (string Text, string[] Expected)> Samples = new()
    {
        ["text"] = ("# Cloudflare\n173.245.48.0/20\r\n\n103.21.244.0/22\n2400:cb00::/32\n", ["173.245.48.0/20", "103.21.244.0/22", "2400:cb00::/32"]),
        ["geofeed"] = ("# prefix,country,region,city\n5.101.96.0/21,NL,NL-NH,Amsterdam,\n2a03:b0c0::/32,US,,,\nbad-line,US\n", ["5.101.96.0/21", "2a03:b0c0::/32"]),
        ["aws"] = ("""{"syncToken":"1","prefixes":[{"ip_prefix":"3.5.140.0/22","region":"ap-northeast-2"},{"ip_prefix":"3.5.140.0/22","service":"S3"}],"ipv6_prefixes":[{"ipv6_prefix":"2600:1f14::/35"}]}""", ["3.5.140.0/22", "2600:1f14::/35"]),
        ["google"] = ("""{"prefixes":[{"ipv4Prefix":"34.1.208.0/20","scope":"africa-south1"},{"ipv6Prefix":"2600:1900:8000::/44"}]}""", ["34.1.208.0/20", "2600:1900:8000::/44"]),
        ["fastly"] = ("""{"addresses":["23.235.32.0/20","43.249.72.0/22"],"ipv6_addresses":["2a04:4e40::/32"]}""", ["23.235.32.0/20", "43.249.72.0/22", "2a04:4e40::/32"]),
        ["oracle"] = ("""{"regions":[{"region":"us-phoenix-1","cidrs":[{"cidr":"129.146.0.0/21","tags":["OCI"]}]},{"region":"eu-frankfurt-1","cidrs":[{"cidr":"130.61.0.0/16"}]}]}""", ["129.146.0.0/21", "130.61.0.0/16"]),
        ["ripestat"] = ("""{"status":"ok","data":{"prefixes":[{"prefix":"5.9.0.0/16","timelines":[]},{"prefix":"2a01:4f8::/32"}]}}""", ["5.9.0.0/16", "2a01:4f8::/32"]),
        ["azure"] = ("""{"values":[{"name":"AzureCloud","properties":{"addressPrefixes":["4.144.0.0/17","2603:1000::/40"]}}]}""", ["4.144.0.0/17", "2603:1000::/40"]),
    };

    public static TheoryData<string> Formats()
    {
        var d = new TheoryData<string>();
        foreach (var f in Samples.Keys)
            d.Add(f);
        return d;
    }

    [Theory]
    [MemberData(nameof(Formats))]
    public void Range_formats_parse_their_sample(string format)
    {
        var (text, expected) = Samples[format];
        var cidrs = RangeParsers.Parse(format, text);
        Assert.Equal(expected, cidrs);
        Assert.All(cidrs, c => Assert.True(Cidr.TryParse(c, out _), c));
    }

    [Fact]
    public void Unknown_format_and_empty_json_lists()
    {
        Assert.Throws<FormatException>(() => RangeParsers.Parse("csv", "1.2.3.0/24"));
        Assert.Empty(RangeParsers.Parse("aws", "{}"));
        Assert.Empty(RangeParsers.Parse("oracle", """{"regions":[{"cidrs":[{"x":1}]}]}"""));
        Assert.Empty(RangeParsers.Parse("text", "# nothing\n"));
    }

    [Fact]
    public void Default_catalog_loads_with_unique_ids_and_known_formats()
    {
        var c = ProviderCatalog.Default;
        Assert.True(c.Providers.Count >= 10);
        Assert.Equal(c.Providers.Count, c.Providers.Select(p => p.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.NotEmpty(c.Major);
        foreach (var p in c.Providers)
        {
            Assert.Matches("^[a-z0-9-]+$", p.Id);
            Assert.False(string.IsNullOrWhiteSpace(p.Name));
            Assert.NotEmpty(p.Asn);
            Assert.NotEmpty(p.Ranges);
            Assert.Equal(p.Id + "-ipset", p.IpsetName);
            foreach (var r in p.Ranges)
            {
                Assert.True(Samples.ContainsKey(r.Format), $"{p.Id}: unknown range format {r.Format}");
                Assert.StartsWith("https://", r.Url, StringComparison.Ordinal);
            }
            foreach (var e in p.TestEndpoints)
            {
                var uri = new Uri(e.Url);
                Assert.Equal("https", uri.Scheme);
                Assert.Equal(uri.Host, e.San);
                Assert.True(e.MinBytes > 0);
            }
        }
        var cf = c.Find("cloudflare");
        Assert.NotNull(cf);
        Assert.Equal("Cloudflare", cf.Name);
        Assert.Contains(13335, cf.Asn);
        Assert.Null(c.Find("nope"));
    }

    [Fact]
    public void Catalog_parses_snake_case_with_comments()
    {
        using var s = new MemoryStream("""
            // a comment
            {"providers": [{"id": "x", "name": "X", "major": true, "asn": [1],
              "ranges": [{"url": "https://x/r", "format": "ripestat"}],
              "test_endpoints": [{"url": "https://x/f", "san": "x", "min_bytes": 5}],}]}
            """u8.ToArray());
        var p = Assert.Single(ProviderCatalog.Parse(s).Providers);
        Assert.True(p.Major);
        Assert.Equal("ripestat", p.Ranges[0].Format);
        Assert.Equal(5, p.TestEndpoints[0].MinBytes);
    }

    // ---- Cidr ----

    [Theory]
    [InlineData("10.0.0.5/8", "10.0.0.0/8")]
    [InlineData(" 192.0.2.77 ", "192.0.2.77/32")]
    [InlineData("192.0.2.77/0", "0.0.0.0/0")]
    [InlineData("2001:db8:1:2::5/32", "2001:db8::/32")]
    [InlineData("2001:db8::1", "2001:db8::1/128")]
    [InlineData("::ffff:198.51.100.1/32", "198.51.100.1/32")]
    public void Cidr_parses_and_masks_the_host_bits(string text, string expected)
    {
        Assert.True(Cidr.TryParse(text, out var c));
        Assert.Equal(expected, c.ToString());
    }

    [Theory]
    [InlineData("10.0.0.0/33")]
    [InlineData("2001:db8::/129")]
    [InlineData("10.0.0.0/-1")]
    [InlineData("10.0.0.0/8/9")]
    [InlineData("10.0.0.0/x")]
    [InlineData("example.com")]
    [InlineData("")]
    public void Cidr_rejects_garbage(string text) => Assert.False(Cidr.TryParse(text, out _));

    [Fact]
    public void Cidr_contains_and_bounds()
    {
        Assert.True(Cidr.TryParse("10.1.0.0/16", out var c));
        Assert.Equal(AddressFamily.InterNetwork, c.Family);
        Assert.True(c.Contains(IPAddress.Parse("10.1.255.255")));
        Assert.True(c.Contains(IPAddress.Parse("::ffff:10.1.0.1")));
        Assert.False(c.Contains(IPAddress.Parse("10.2.0.0")));
        Assert.False(c.Contains(IPAddress.Parse("2001:db8::1")));
        Assert.Equal((UInt128)65536, c.Size);
        Assert.Equal(IPAddress.Parse("10.1.0.5"), c.At(5));

        Assert.True(Cidr.TryParse("0.0.0.0/0", out var all4));
        Assert.True(all4.Contains(IPAddress.Parse("255.255.255.255")));
        Assert.True(Cidr.TryParse("::/0", out var all6));
        Assert.Equal(UInt128.MaxValue, all6.Last);
        Assert.True(all6.Contains(IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
    }

    // ---- CidrSet ----

    private static List<string> Agg(params string[] cidrs) => CidrSet.Aggregate(cidrs).Select(c => c.ToString()).ToList();

    [Fact]
    public void Aggregate_merges_adjacent_halves_and_contained_networks()
    {
        Assert.Equal(["10.0.0.0/24"], Agg("10.0.0.128/25", "10.0.0.0/25"));
        Assert.Equal(["10.0.0.0/8"], Agg("10.1.0.0/16", "10.0.0.0/8", "10.200.3.4"));
        Assert.Equal(["10.0.0.0/24", "10.0.2.0/24"], Agg("10.0.0.0/24", "10.0.2.0/24"));
        // adjacent but not one aligned block
        Assert.Equal(["10.0.1.0/24", "10.0.2.0/24"], Agg("10.0.1.0/24", "10.0.2.0/24"));
        Assert.Equal(["10.0.0.0/22"], Agg("10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/23"));
        // overlapping ranges cut back into aligned blocks
        Assert.Equal(["192.0.2.0/24", "192.0.3.0/25"], Agg("192.0.2.0/24", "192.0.2.128/25", "192.0.3.0/25"));
        Assert.Equal(["0.0.0.0/0"], Agg("0.0.0.0/1", "128.0.0.0/1"));
    }

    [Fact]
    public void Aggregate_keeps_families_apart_v4_first_and_skips_junk()
    {
        Assert.Equal(["198.51.100.0/24", "2001:db8::/32"], Agg("2001:db8:8000::/33", "not a cidr", "198.51.100.0/24", "2001:db8::/33", "# comment"));
        Assert.Equal(["::/0"], Agg("::/0"));
        Assert.Equal(["::/0"], Agg("2001:db8::/32", "::/0", "ffff::/16"));
        Assert.Equal(["::/0"], Agg("8000::/1", "::/1"));
        Assert.Empty(Agg());
    }

    [Fact]
    public void Sample_picks_hosts_of_distinct_networks_half_v4()
    {
        var nets = CidrSet.Aggregate(
        [
            "10.0.0.0/16", "10.2.0.0/16", "10.4.0.0/24", "10.5.0.0/24", "10.6.0.0/30", "10.7.0.1/32",
            "2001:db8::/48", "2001:db9::/48", "2001:dba::/64",
        ]);
        var picks = CidrSet.Sample(nets, 6);
        Assert.Equal(6, picks.Count);
        Assert.Equal(3, picks.Count(p => p.AddressFamily == AddressFamily.InterNetwork));
        var owners = picks.Select(p => nets.Single(n => n.Contains(p))).ToList();
        Assert.Equal(owners.Count, owners.Distinct().Count());
        foreach (var (p, n) in picks.Zip(owners))
        {
            if (n.Size > 2)
            {
                Assert.NotEqual(n.At(0), p); // never the network address
                Assert.NotEqual(n.At(n.Size - 1), p); // nor the broadcast one
            }
        }
        // the same input gives the same picks; another seed may move them inside the networks
        Assert.Equal(picks, CidrSet.Sample(nets, 6));
        Assert.All(CidrSet.Sample(nets, 6, seed: 7), p => Assert.Contains(nets, n => n.Contains(p)));
    }

    [Fact]
    public void Sample_is_bounded_by_the_networks()
    {
        var v4 = CidrSet.Aggregate(["192.0.2.0/24", "198.51.100.7/32"]);
        var picks = CidrSet.Sample(v4, 10);
        Assert.Equal(2, picks.Count);
        Assert.Contains(IPAddress.Parse("198.51.100.7"), picks);
        Assert.Empty(CidrSet.Sample([], 5));
        Assert.Empty(CidrSet.Sample(v4, 0));

        var v6Only = CidrSet.Aggregate(["2001:db8::/32", "2001:db9::/32"]);
        Assert.All(CidrSet.Sample(v6Only, 2), p => Assert.Equal(AddressFamily.InterNetworkV6, p.AddressFamily));
        Assert.True(Cidr.TryParse("::/0", out var all6));
        Assert.Single(CidrSet.Sample([all6], 1));
    }
}
