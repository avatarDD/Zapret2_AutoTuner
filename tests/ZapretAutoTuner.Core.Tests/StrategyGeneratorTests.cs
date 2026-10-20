using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Tests;

public sealed class StrategyGeneratorTests
{
    public static TheoryData<SearchMode, TargetProtocol, EnginePlatform> AllCombos()
    {
        var d = new TheoryData<SearchMode, TargetProtocol, EnginePlatform>();
        foreach (var m in Enum.GetValues<SearchMode>())
        {
            foreach (var p in Enum.GetValues<TargetProtocol>())
            {
                foreach (var pl in new[] { EnginePlatform.Linux, EnginePlatform.Windows })
                    d.Add(m, p, pl);
            }
        }
        return d;
    }

    [Theory]
    [MemberData(nameof(AllCombos))]
    public void Every_generated_strategy_passes_the_validator(SearchMode mode, TargetProtocol protocol, EnginePlatform platform)
    {
        var set = StrategyGenerator.Generate(new GeneratorOptions { Mode = mode, Protocol = protocol, Platform = platform, TcpTimestamps = platform == EnginePlatform.Linux });
        Assert.True(set.Rejected.Count == 0, string.Join("\n", set.Rejected.Select(r => $"{r.Family}: {r.Strategy}\n  {string.Join("\n  ", r.Issues)}")));
        Assert.NotEmpty(set.Candidates);
        Assert.Equal(set.Candidates.Count, set.Candidates.Select(c => c.Key).Distinct().Count());
        // nfqws2 syntax only (AGENTS.md rule 1)
        Assert.DoesNotContain(set.Candidates, c => c.Key.Contains("--dpi-desync", StringComparison.Ordinal));
        if (platform == EnginePlatform.Windows)
            Assert.DoesNotContain(set.Candidates, c => c.Key.Contains("tcp_ts=", StringComparison.Ordinal));
    }

    [Fact]
    public void Modes_grow_and_quick_is_a_subset_of_standard()
    {
        int Count(SearchMode m) => StrategyGenerator.Generate(new GeneratorOptions { Mode = m }).Candidates.Count;
        int quick = Count(SearchMode.Quick), standard = Count(SearchMode.Standard), full = Count(SearchMode.Full);
        Assert.InRange(quick, 15, 120);
        Assert.InRange(standard, quick + 1, 1500);
        Assert.True(full > standard, $"{quick} {standard} {full}");

        var std = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Standard }).Candidates.Select(c => c.Key).ToHashSet();
        var q = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Quick }).Candidates.Select(c => c.Key);
        Assert.All(q, k => Assert.Contains(k, std));
    }

    [Fact]
    public void Families_come_in_blockcheck_order_and_labels_move_them()
    {
        var plain = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Standard });
        var order = plain.Candidates.Select(c => c.Family).Distinct().ToList();
        Assert.Equal("multisplit", order[0]);
        Assert.True(order.IndexOf("seqovl") < order.IndexOf("fake"));
        Assert.True(order.IndexOf("fake") < order.IndexOf("fake_multi"));
        Assert.Equal("wssize", order[^1]); // last resort
        Assert.DoesNotContain("oob", order); // full mode only
        Assert.DoesNotContain("quic", order);
        Assert.DoesNotContain("http_basic", order);

        // a volume cut-off: strategies that look like the white domain first
        var cut = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Standard, Labels = [BlockLabel.Cutoff16K] });
        Assert.Contains(StrategyGenerator.WhiteBlob, cut.Candidates[0].Key, StringComparison.Ordinal);

        var http = StrategyGenerator.Generate(new GeneratorOptions { Protocol = TargetProtocol.Http, Labels = [BlockLabel.HttpBlock] });
        Assert.Equal("http_basic", http.Candidates[0].Family);
        Assert.All(http.Candidates.Where(c => c.Key.Contains("--payload", StringComparison.Ordinal)), c => Assert.Contains("--payload=http_req", c.Key, StringComparison.Ordinal));
        Assert.Contains(http.Candidates, c => c.Key.Contains("pos=method+2", StringComparison.Ordinal));

        var quic = StrategyGenerator.Generate(new GeneratorOptions { Protocol = TargetProtocol.Quic, Labels = [BlockLabel.QuicBlock] });
        Assert.All(quic.Candidates, c => Assert.Equal(L4Kind.Udp, c.L4));
        Assert.All(quic.Candidates, c => Assert.StartsWith("--payload=quic_initial", c.Key, StringComparison.Ordinal));
    }

    [Fact]
    public void Templates_expand_with_fooling_white_sni_and_payload()
    {
        var set = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Standard, WhiteSni = "vk.com" });
        Assert.Contains(set.Candidates, c => c.Key == "--payload=tls_client_hello --lua-desync=multisplit:pos=midsld");
        Assert.Contains(set.Candidates, c => c.Key == "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=1");
        Assert.Contains(set.Candidates, c => c.Key == "--payload=tls_client_hello --lua-desync=fake:blob=tls_white:tcp_ack=-66000:tcp_ts_up:tls_mod=rnd,dupsid,sni=vk.com:repeats=6");
        Assert.Contains(set.Candidates, c => c.Key.StartsWith("--payload=tls_client_hello --lua-desync=hostfakesplit:host=vk.com:", StringComparison.Ordinal));
        Assert.Contains(set.Candidates, c => c.Key == "--lua-desync=wssize:wsize=1:scale=6");
        Assert.DoesNotContain(set.Candidates, c => c.Key.Contains("::", StringComparison.Ordinal) || c.Key.Contains('{', StringComparison.Ordinal));

        var full = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Full });
        Assert.Contains(full.Candidates, c => c.Key == "--in-range=-s1 --lua-desync=oob");
    }

    [Fact]
    public void Excluded_and_pointless_families_are_cut()
    {
        var set = StrategyGenerator.Generate(new GeneratorOptions { ExcludeFamilies = ["wssize", "syndata"] });
        Assert.DoesNotContain(set.Candidates, c => c.Family is "wssize" or "syndata");
    }

    [Fact]
    public void White_hello_is_a_real_single_record_client_hello()
    {
        var set = StrategyGenerator.Generate(new GeneratorOptions { WhiteSni = "max.ru" });
        var hex = set.Blobs[StrategyGenerator.WhiteBlob];
        var bytes = Convert.FromHexString(hex[2..]);
        Assert.InRange(bytes.Length, 300, 1400); // fits one segment
        Assert.Equal(TlsParseStatus.Ok, TlsClientHello.TryParseRecords(bytes, out var ch));
        Assert.Equal("max.ru", ch!.Sni);
        Assert.Equal($"--blob=tls_white:{hex}", Assert.Single(StrategyGenerator.BlobArgs(set)));
        // deterministic: the same hello every time, so the strategy hash is stable
        Assert.Equal(hex, StrategyGenerator.Generate(new GeneratorOptions { WhiteSni = "max.ru" }).Blobs[StrategyGenerator.WhiteBlob]);
    }

    [Fact]
    public void Axis_maps_inherit_from_the_previous_mode_and_sets_resolve()
    {
        const string yaml = """
            sets:
              f: {quick: [a], full: [a, b]}
              pos_tls: [x, y]
            families:
              - id: t
                order: 1
                l4: tcp
                protocols: [tls]
                payload: none
                templates: ["--lua-desync=multisplit:pos={p}:{f}"]
                axes:
                  p: "@pos"
                  f: "@f"
            """;
        var cat = FamilyCatalog.Parse(yaml);
        var std = StrategyGenerator.Expand(cat["t"], new GeneratorOptions { Mode = SearchMode.Standard }, cat).ToList();
        Assert.Equal(["--lua-desync=multisplit:pos=x:a", "--lua-desync=multisplit:pos=y:a"], std);
        var full = StrategyGenerator.Expand(cat["t"], new GeneratorOptions { Mode = SearchMode.Full }, cat).ToList();
        Assert.Equal(4, full.Count);
    }
}
