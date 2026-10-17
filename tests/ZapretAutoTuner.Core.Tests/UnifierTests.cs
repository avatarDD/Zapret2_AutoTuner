using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Unify;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Tests;

public sealed class UnifierTests
{
    private const string Split1 = "--payload=tls_client_hello --lua-desync=multisplit:pos=1";
    private const string Midsld = "--payload=tls_client_hello --lua-desync=multisplit:pos=midsld";
    private const string Fake = "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5 --lua-desync=multisplit:pos=1";
    private const string Quic = "--payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6";

    private static DomainResult R(string domain, string s, bool ok, double score = 1, L4Kind l4 = L4Kind.Tcp) =>
        new(domain, l4, Strategy.Parse(s), ok ? new Efficiency(5, 5) : new Efficiency(0, 2), score);

    [Fact]
    public void Same_strategy_written_two_ways_is_one_candidate()
    {
        var a = Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:tcp_md5:blob=fake_default_tls");
        var b = Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5");
        Assert.Equal(StrategyNormalizer.Key(a), StrategyNormalizer.Key(b));
        // the order of instances matters and is kept
        var c = Strategy.Parse("--payload=tls_client_hello --lua-desync=multisplit:pos=1 --lua-desync=fake:blob=fake_default_tls:tcp_md5");
        Assert.NotEqual(StrategyNormalizer.Key(c), StrategyNormalizer.Key(Strategy.Parse(Fake)));
    }

    [Fact]
    public void Intersection_gives_one_common_strategy_the_best_by_score()
    {
        var plan = Unifier.Plan(
        [
            R("a.com", Split1, true, 1), R("b.com", Split1, true, 1), R("c.com", Split1, true, 1),
            R("a.com", Fake, true, 4), R("b.com", Fake, true, 4), R("c.com", Fake, true, 4),
            R("a.com", Midsld, true, 1),
        ]);
        var p = Assert.Single(plan.Profiles);
        Assert.Equal(Split1, p.Strategy.ToString());
        Assert.Equal(["a.com", "b.com", "c.com"], p.Domains);
        Assert.True(plan.Common);
        Assert.Empty(plan.Adaptive);
        Assert.Empty(plan.Uncovered);
    }

    [Fact]
    public void Set_cover_takes_few_cheap_profiles_and_puts_narrow_ones_first()
    {
        // YouTube + Discord + 3 sites: one strategy covers four domains, the fifth needs its own
        var plan = Unifier.Plan(
        [
            R("youtube.com", Fake, true, 4), R("site1.ru", Fake, true, 4), R("site2.ru", Fake, true, 4), R("site3.ru", Fake, true, 4),
            R("discord.com", Midsld, true, 1), R("site1.ru", Midsld, true, 1),
            R("youtube.com", Split1, false), R("discord.com", Split1, false),
            R("youtube.com", Quic, true, 2, L4Kind.Udp), R("discord.com", Quic, true, 2, L4Kind.Udp),
            R("nothing.org", Split1, false),
        ]);
        Assert.Equal(2, plan.TcpProfiles);
        Assert.Equal(1, plan.UdpProfiles);
        Assert.Equal(Midsld, plan.Profiles[0].Strategy.ToString());
        // the cheaper split per covered domain goes first and takes site1 too; the fake covers the rest
        Assert.Equal(["site1.ru", "discord.com"], plan.Profiles[0].Domains);
        Assert.Equal(["youtube.com", "site2.ru", "site3.ru"], plan.Profiles[1].Domains);
        Assert.Equal(L4Kind.Udp, plan.Profiles[2].L4);
        Assert.Equal([("nothing.org", L4Kind.Tcp)], plan.Uncovered);
        Assert.False(plan.Common);
        var adaptive = Assert.Single(plan.Adaptive);
        Assert.True(adaptive.Adaptive);
        Assert.Equal(5, adaptive.Domains.Count);
    }

    [Fact]
    public void Cross_check_result_overrides_history()
    {
        // history says Split1 works on b, the cross-check (later row) says it does not
        var plan = Unifier.Plan([R("a.com", Split1, true), R("b.com", Split1, true), R("b.com", Split1, false), R("b.com", Midsld, true), R("a.com", Midsld, true, 2)]);
        var p = Assert.Single(plan.Profiles);
        Assert.Equal(Midsld, p.Strategy.ToString());
    }

    [Fact]
    public void Circular_variant_tags_strategies_and_passes_the_validator()
    {
        var c = Unifier.Circular([Strategy.Parse(Fake), Strategy.Parse(Midsld)]);
        var text = c.ToString();
        Assert.StartsWith("--out-range=-s34228 --in-range=-s5556 --lua-desync=circular --in-range=x --out-range=a", text, StringComparison.Ordinal);
        Assert.Contains("--lua-desync=fake:blob=fake_default_tls:tcp_md5:strategy=1:final", text, StringComparison.Ordinal);
        Assert.Contains("--lua-desync=multisplit:pos=1:strategy=1:final", text, StringComparison.Ordinal);
        Assert.Contains("--lua-desync=multisplit:pos=midsld:strategy=2", text, StringComparison.Ordinal);
        Assert.DoesNotContain("strategy=2:final", text, StringComparison.Ordinal);
        var v = new StrategyValidator(new ValidationContext()).ValidateStrategy(c);
        Assert.True(v.Ok, string.Join("\n", v.Errors));
        // the orchestrator needs incoming packets (Windows: --wf-tcp-in)
        Assert.True(EngineArgsBuilder.NeedsIncoming(new Profile { Strategy = c }));
    }

    [Fact]
    public void Solution_has_a_hostlist_per_profile_and_validates()
    {
        var plan = Unifier.Plan(
        [
            R("youtube.com", Fake, true, 4), R("site1.ru", Fake, true, 4), R("discord.com", Midsld, true, 1),
            R("youtube.com", Quic, true, 2, L4Kind.Udp),
        ]);
        var s = Unifier.ToSolution(plan);
        Assert.Equal(["tcp1", "tcp2", "quic1"], s.Profiles.Select(p => p.Name));
        Assert.Equal(["discord.com"], s.Hostlists["tcp1"]); // narrow first
        Assert.Equal("443", s.Profiles[2].UdpPorts);
        Assert.Equal(["quic"], s.Profiles[2].L7);
        var validator = new StrategyValidator(new ValidationContext());
        foreach (var p in s.Profiles)
            Assert.True(validator.ValidateProfile(p).Ok, string.Join("\n", validator.ValidateProfile(p).Errors));
        var adaptive = Unifier.ToSolution(plan, adaptive: true);
        Assert.Equal(["tcp1", "quic1"], adaptive.Profiles.Select(p => p.Name));
        Assert.Contains("circular", adaptive.Profiles[0].Strategy.ToString(), StringComparison.Ordinal);
    }
}
