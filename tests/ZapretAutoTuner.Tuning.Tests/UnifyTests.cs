using System.Net;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Unify;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Tuning.Tests;

public sealed class UnifyTests
{
    private const string Midsld = "--payload=tls_client_hello --lua-desync=multisplit:pos=midsld";
    private const string Quic = "--payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6";
    private const string Midsld1 = "--payload=tls_client_hello --lua-desync=multisplit:pos=midsld+1";

    /// <summary>The stand's truth: which strategy opens which domain.</summary>
    private sealed class Truth(Func<string, string, bool> works) : ICrossChecker
    {
        public List<(string Strategy, string Domain)> Checked { get; } = [];

        public Task<Efficiency> CheckAsync(Strategy strategy, string domain, L4Kind l4, CancellationToken ct)
        {
            Checked.Add((strategy.ToString(), domain));
            return Task.FromResult(works(strategy.ToString(), domain) ? new Efficiency(3, 3) : new Efficiency(0, 1));
        }
    }

    private static DomainResult R(string d, string s, bool ok, double score = 1, L4Kind l4 = L4Kind.Tcp) => new(d, l4, Strategy.Parse(s), ok ? new Efficiency(5, 5) : new Efficiency(0, 2), score);

    [Fact]
    public async Task Cross_check_finds_the_common_strategy_history_did_not_show()
    {
        // the searches found midsld for sni and drop, midsld+1 for flaky; midsld+1 really works on all three
        var history = new[] { R("sni.test", Midsld, true), R("drop.test", Midsld, true), R("flaky.test", Midsld1, true, 1.1) };
        var truth = new Truth((s, d) => s == Midsld1 || d != "flaky.test");
        var plan = await UnifyRunner.RunAsync(history, ["sni.test", "drop.test", "flaky.test"], truth);

        var p = Assert.Single(plan.Profiles);
        Assert.True(plan.Common);
        Assert.Equal(["sni.test", "drop.test", "flaky.test"], p.Domains);
        // midsld (better score, two domains) is checked everywhere first and fails on flaky; midsld+1 is common
        Assert.Contains((Midsld, "flaky.test"), truth.Checked);
        Assert.Equal(Midsld1, p.Strategy.ToString());
    }

    [Fact]
    public async Task Stale_history_does_not_survive_the_cross_check()
    {
        // history says midsld works on both, but now it opens only one; the cover needs two profiles
        var history = new[] { R("a.test", Midsld, true), R("b.test", Midsld, true), R("b.test", Midsld1, true, 2) };
        var truth = new Truth((s, d) => s == Midsld ? d == "a.test" : d == "b.test");
        var plan = await UnifyRunner.RunAsync(history, ["a.test", "b.test"], truth);
        Assert.Equal(2, plan.TcpProfiles);
        Assert.Single(plan.Adaptive);
    }

    [Fact]
    public async Task Budget_limits_the_cross_checks()
    {
        var history = Enumerable.Range(1, 8).SelectMany(i => new[] { R($"d{i}.test", $"--payload=tls_client_hello --lua-desync=multisplit:pos={i}", true) }).ToArray();
        var truth = new Truth((_, _) => false);
        await UnifyRunner.RunAsync(history, [.. history.Select(h => h.Domain)], truth, new UnifyOptions { MaxChecks = 10 });
        Assert.Equal(10, truth.Checked.Count);
    }

    [Fact]
    public void Combined_launch_has_every_profile_with_inline_hostlists()
    {
        var plan = Unifier.Plan([R("a.test", Midsld, true), R("b.test", Midsld1, true), new("a.test", L4Kind.Udp, Strategy.Parse("--payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6"), new(5, 5), 1)]);
        var solution = Unifier.ToSolution(plan);
        var targets = new[]
        {
            new TrialTarget { Host = "a.test", Addresses = [IPAddress.Parse("10.0.0.1")] },
            new TrialTarget { Host = "b.test", Addresses = [IPAddress.Parse("10.0.0.2")] },
        };
        var (argv, queue) = ConfigCheck.BuildLaunch(solution, targets, new AgentTrialOptions { LuaDir = "/lua", Platform = EnginePlatform.Linux });

        Assert.Equal(2, argv.Count(a => a == "--new"));
        Assert.Contains("--hostlist-domains=a.test", argv);
        Assert.Contains("--hostlist-domains=b.test", argv);
        Assert.DoesNotContain(argv, a => a.StartsWith("--hostlist=", StringComparison.Ordinal));
        Assert.NotNull(queue);
        Assert.Equal("443", queue.TcpPorts);
        Assert.Equal("443", queue.UdpPorts);
        Assert.Equal(["10.0.0.1", "10.0.0.2"], queue.Targets);
        var v = new StrategyValidator(new ValidationContext()).ValidateArgv(argv);
        Assert.True(v.Ok, string.Join("\n", v.Errors));
    }

    [Fact]
    public async Task Budget_is_shared_between_tcp_and_quic_and_skips_do_not_count()
    {
        var tcp = Enumerable.Range(1, 8).Select(i => R($"d{i}.test", $"--payload=tls_client_hello --lua-desync=multisplit:pos={i}", true));
        var quic = new[] { R("d1.test", Quic, true, 1, L4Kind.Udp), R("d2.test", Quic, true, 1, L4Kind.Udp) };
        var history = tcp.Concat(quic).ToArray();
        var truth = new Truth((_, _) => false);
        await UnifyRunner.RunAsync(history, [.. history.Select(h => h.Domain).Distinct()], truth, new UnifyOptions { MaxChecks = 10 });
        // QUIC needs two checks, TCP takes the rest of the budget
        Assert.Equal(10, truth.Checked.Count);
        Assert.Equal(2, truth.Checked.Count(c => c.Strategy == Quic));

        // the first candidate works everywhere: the worse ones are skipped and the budget is not spent on them
        var h2 = new[] { R("a.test", Midsld, true), R("b.test", Midsld, true), R("b.test", Midsld1, true, 2), R("a.test", Midsld1, true, 2) };
        var t2 = new Truth((_, _) => true);
        var plan = await UnifyRunner.RunAsync(h2, ["a.test", "b.test"], t2, new UnifyOptions { MaxChecks = 3 });
        Assert.Equal(2, t2.Checked.Count);
        Assert.Equal(Midsld, Assert.Single(plan.Profiles).Strategy.ToString());
    }

    [Fact]
    public void Combined_launch_with_a_phase0_hostlist_profile_uses_ipcache_hostname()
    {
        var plan = Unifier.Plan([R("a.test", "--lua-desync=wssize:wsize=1:scale=6", true), R("b.test", Midsld, true)]);
        var solution = Unifier.ToSolution(plan);
        var targets = new[] { new TrialTarget { Host = "a.test", Addresses = [IPAddress.Parse("10.0.0.1")] } };
        var (argv, _) = ConfigCheck.BuildLaunch(solution, targets, new AgentTrialOptions { LuaDir = "/lua", Platform = EnginePlatform.Linux });
        Assert.Contains(argv, a => a.StartsWith("--ipcache-hostname", StringComparison.Ordinal));
        var v = new StrategyValidator(new ValidationContext()).ValidateArgv(argv);
        Assert.True(v.Ok, string.Join("\n", v.Errors));
    }
}
