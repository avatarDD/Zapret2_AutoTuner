using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>zapret2 1.0.7 on the tuning side: test instances outrank protection, hostlist prefixes, the site check.</summary>
public sealed class Zapret2v107TuningTests
{
    private static Solution Video()
    {
        var s = new Solution();
        s.Hostlists["video"] = ["com", "!vk.com", "^youtube.com"];
        s.Profiles.Add(new Profile { Name = "video", TcpPorts = "443", Hostlists = [new ListRef("video")], Strategy = Strategy.Parse("--lua-desync=multisplit:pos=1") });
        return s;
    }

    [Fact]
    public void Test_instances_outrank_protection_on_windows()
    {
        var s = Video();
        var trial = new AgentTrialOptions { LuaDir = "C:/zt/lua", Platform = EnginePlatform.Windows };
        var (argv, _) = ConfigCheck.BuildLaunch(s, [], trial);
        Assert.Contains("--wf-priority=2000", argv);
        var (protection, _) = ConfigCheck.BuildLaunch(s, [], trial with { WinDivertPriority = null });
        Assert.DoesNotContain(protection, a => a.StartsWith("--wf-priority", StringComparison.Ordinal));
        // Linux has no WinDivert
        var (linux, _) = ConfigCheck.BuildLaunch(s, [], trial with { Platform = EnginePlatform.Linux });
        Assert.DoesNotContain(linux, a => a.StartsWith("--wf-", StringComparison.Ordinal));
    }

    [Fact]
    public void Protection_reads_hostlist_prefixes_like_the_engine()
    {
        var s = Video();
        Assert.NotNull(Protection.CurrentOf(s, "mail.com"));
        Assert.Null(Protection.CurrentOf(s, "vk.com"));
        Assert.Null(Protection.CurrentOf(s, "m.vk.com"));
        // ^youtube.com is under "com" anyway; the strict entry only decides for the full name
        Assert.NotNull(Protection.CurrentOf(s, "www.youtube.com"));
        Assert.Equal(["com", "youtube.com"], Protection.Domains(s));

        // replacing a strict entry removes it, the exemption stays
        var fix = new StrategyCandidate(Strategy.Parse("--lua-desync=fakedsplit:pos=1"), "f", 0, [], L4Kind.Tcp);
        var next = Protection.ReplaceDomain(s, "youtube.com", fix);
        Assert.Equal(["com", "!vk.com"], next.Hostlists["video"]);
        Assert.Equal("fix-youtube-com", next.Profiles[0].Name);
    }

    private sealed class Executor(Func<int, TrialOutcome> attempt) : ITrialExecutor
    {
        public List<StrategyCandidate> Ran { get; } = [];

        public Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
        {
            Ran.Add(candidate);
            return Task.FromResult<IReadOnlyList<TrialOutcome>>([.. Enumerable.Range(0, attempts).Select(attempt)]);
        }

        public Task<bool> TargetReachableAsync(CancellationToken ct) => Task.FromResult(true);
    }

    private static Func<int, CancellationToken, Task<IReadOnlyList<TrialOutcome>>> Baseline(bool ok) =>
        (n, _) => Task.FromResult<IReadOnlyList<TrialOutcome>>([.. Enumerable.Range(0, n).Select(_ => ok ? TrialOutcome.Success() : TrialOutcome.Fail(TrialFailure.Reset))]);

    private static readonly Strategy Split = Strategy.Parse("--lua-desync=multisplit:pos=1");

    [Fact]
    public async Task Site_check_needs_a_blocked_site()
    {
        var ex = new Executor(_ => TrialOutcome.Success());
        var r = await StrategySiteCheck.RunAsync(ex, Baseline(true), Split, CancellationToken.None);
        Assert.Equal(SiteCheckVerdict.NotBlocked, r.Verdict);
        // the engine never starts on an open site
        Assert.Empty(ex.Ran);
    }

    [Theory]
    [InlineData(5, SiteCheckVerdict.Works)]
    [InlineData(2, SiteCheckVerdict.Unstable)]
    [InlineData(0, SiteCheckVerdict.Fails)]
    public async Task Site_check_counts_full_loads(int ok, SiteCheckVerdict verdict)
    {
        var ex = new Executor(i => i < ok ? TrialOutcome.Success() : TrialOutcome.Fail(TrialFailure.Stalled));
        var r = await StrategySiteCheck.RunAsync(ex, Baseline(false), Split, CancellationToken.None);
        Assert.Equal(verdict, r.Verdict);
        Assert.Equal(ok, r.Ok);
        Assert.Equal(StrategySiteCheck.Attempts, r.Outcomes.Count);
        Assert.Equal(ok == StrategySiteCheck.Attempts ? TrialFailure.None : TrialFailure.Stalled, r.MainFailure);
        var ran = Assert.Single(ex.Ran);
        Assert.Equal(L4Kind.Tcp, ran.L4);
        Assert.Equal(Split.ToString(), ran.Strategy.ToString());
    }

    [Fact]
    public void Site_solution_is_one_profile_for_the_site_and_valid()
    {
        var s = StrategySiteCheck.SolutionFor(Split, "youtube.com");
        var p = Assert.Single(s.Profiles);
        Assert.Equal(["youtube.com"], p.HostlistDomains);
        Assert.Equal("443", p.TcpPorts);   // what the HTTPS probe checked
        Assert.Equal(["youtube.com"], Protection.Domains(s));
        var v = new StrategyValidator(new ValidationContext { Platform = EnginePlatform.Linux }).ValidateProfile(p, p.Name);
        Assert.True(v.Ok, v.ToString());
        Assert.Contains("--hostlist-domains=youtube.com", Core.Export.ArgvExporter.Build(s).Text, StringComparison.Ordinal);
    }
}
