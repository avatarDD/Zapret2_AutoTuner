using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Delivery;

namespace ZapretAutoTuner.Tuning.Tests;

public sealed class RouterTrialExecutorTests
{
    private static StrategyCandidate Tcp(string s) => ProgramFixtures.Candidate(s, L4Kind.Tcp);

    private static RouterTrialOptions Options(Func<RouterTrialOptions, RouterTrialOptions>? tweak = null)
    {
        var o = new RouterTrialOptions
        {
            Targets = ["rutracker.org", "example.com"],
            CurrentProfiles = [("YouTube QUIC", "--filter-udp=443 --hostlist=lists/youtube.txt --lua-desync=fake:blob=fake_default_quic:repeats=6")],
            Blobs = new Dictionary<string, string> { ["tls_wl"] = "0x160301", ["unused"] = "0xdeadbeef", ["filed"] = "@bin/filed.bin" },
            Poll = TimeSpan.FromMilliseconds(1),
        };
        return tweak?.Invoke(o) ?? o;
    }

    private static ExperimentProbe Probe(string target, int okCount, string code = "tls_rst") =>
        new(target, okCount == 3, okCount == 3 ? "ok" : code, code, 150, okCount > 0 ? 65536 : 0, 3, okCount);

    private static ExperimentVariantResult Variant(string label, params ExperimentProbe[] probes) =>
        new(label, true, false, "", null, probes, 0, 0, [], [], []);

    private static ExperimentReport Report(IReadOnlyList<ExperimentVariantResult> variants, IReadOnlyList<string>? open = null, string error = "") =>
        new("r", "finished", variants, open ?? [], "", false, false, "true", "", "", error);

    [Fact]
    public void Candidate_profile_comes_first_limited_to_the_targets_with_its_blobs_inlined()
    {
        var x = new RouterTrialExecutor(new RouterGui().Experiments(), Options());
        var p = x.Profiles(Tcp("--payload=tls_client_hello --lua-desync=fake:blob=tls_wl:tcp_md5 --lua-desync=multisplit:pos=1"));
        Assert.Equal(2, p.Count);
        Assert.Equal("AutoTuner", p[0].Name);
        var args = p[0].Args;
        Assert.StartsWith("--blob=tls_wl:0x160301 ", args, StringComparison.Ordinal);
        Assert.Contains("--filter-tcp=443,80", args, StringComparison.Ordinal);
        Assert.Contains("--hostlist-domains=rutracker.org,example.com", args, StringComparison.Ordinal);
        Assert.Contains("--payload=tls_client_hello --lua-desync=fake:blob=tls_wl:tcp_md5 --lua-desync=multisplit:pos=1", args, StringComparison.Ordinal);
        // only blobs the candidate uses, and only inline ones: the router has no files of ours
        Assert.DoesNotContain("unused", args, StringComparison.Ordinal);
        Assert.DoesNotContain("filed", args, StringComparison.Ordinal);
        Assert.DoesNotContain("--dpi-desync", args, StringComparison.Ordinal);
        Assert.Equal(Options().CurrentProfiles[0], p[1]);
    }

    [Fact]
    public void Udp_candidate_filters_udp_443_and_skips_file_blobs()
    {
        var x = new RouterTrialExecutor(new RouterGui().Experiments(), Options(o => o with { CurrentProfiles = [] }));
        var p = Assert.Single(x.Profiles(ProgramFixtures.Candidate("--payload=quic_initial --lua-desync=fake:blob=filed:repeats=6", L4Kind.Udp)));
        Assert.Contains("--filter-udp=443 ", p.Args, StringComparison.Ordinal);
        Assert.DoesNotContain("--filter-tcp", p.Args, StringComparison.Ordinal);
        Assert.DoesNotContain("--blob=", p.Args, StringComparison.Ordinal);
    }

    [Fact]
    public void Outcomes_expand_ok_count_of_attempts_and_leave_out_targets_open_without_bypass()
    {
        var v = Variant("zt0", Probe("rutracker.org", 2, "tls_rst"), Probe("example.com", 3), Probe("open.org", 0, "tcp_reset"));
        var o = RouterTrialExecutor.Outcomes(v, Report([v], ["OPEN.org"]));
        Assert.Equal(6, o.Count);
        Assert.Equal(5, o.Count(x => x.Ok));
        var fail = Assert.Single(o, x => !x.Ok);
        Assert.Equal(TrialFailure.Reset, fail.Failure);
        Assert.Contains("rutracker.org", fail.Detail, StringComparison.Ordinal);
        Assert.Contains("tls_rst", fail.Detail, StringComparison.Ordinal);
        Assert.All(o.Where(x => x.Ok), x => Assert.Equal(65536, x.BytesIn));
        Assert.All(o, x => Assert.Equal(TimeSpan.FromMilliseconds(150), x.Duration));
    }

    [Fact]
    public void A_probe_with_no_attempts_counts_once()
    {
        var v = Variant("zt0", new ExperimentProbe("rutracker.org", false, "tcp_timeout", "TCP таймаут", 5000, 0, 0, 0));
        var o = Assert.Single(RouterTrialExecutor.Outcomes(v, Report([v])));
        Assert.False(o.Ok);
        Assert.Equal(TrialFailure.Timeout, o.Failure);
    }

    [Fact]
    public void Every_target_open_without_bypass_gives_a_single_other_failure()
    {
        var v = Variant("zt0", Probe("example.com", 3));
        var o = Assert.Single(RouterTrialExecutor.Outcomes(v, Report([v], ["example.com"])));
        Assert.False(o.Ok);
        Assert.Equal(TrialFailure.Other, o.Failure);
    }

    [Fact]
    public void Skipped_or_not_started_variant_is_one_other_failure_with_the_reason()
    {
        var invalid = new ExperimentVariantResult("zt0", false, true, "аргументы не прошли валидацию nfqws2", null, [], 0, 0, [], [],
            ["lua: attempt to call a nil value (global 'fakee')", "nfqws2: lua init failed"]);
        var o = Assert.Single(RouterTrialExecutor.Outcomes(invalid, Report([invalid])));
        Assert.Equal(TrialFailure.Other, o.Failure);
        Assert.Contains("global 'fakee'", o.Detail, StringComparison.Ordinal);
        Assert.Contains("lua init failed", o.Detail, StringComparison.Ordinal);

        var dead = new ExperimentVariantResult("zt0", false, false, "", "nfqws2: queue 200 bind failed", [Probe("rutracker.org", 0)], 0, 0, [], [], []);
        o = Assert.Single(RouterTrialExecutor.Outcomes(dead, Report([dead])));
        Assert.Equal(TrialFailure.Other, o.Failure);
        Assert.Contains("queue 200 bind failed", o.Detail, StringComparison.Ordinal);

        var skipped = new ExperimentVariantResult("zt0", false, true, "прогон остановлен", null, [], 0, 0, [], [], []);
        Assert.Contains("прогон остановлен", Assert.Single(RouterTrialExecutor.Outcomes(skipped, Report([skipped]))).Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_variant_is_an_other_failure_with_the_report_error()
    {
        var o = Assert.Single(RouterTrialExecutor.Outcomes(null, Report([], error: "движок занят")));
        Assert.Equal(TrialFailure.Other, o.Failure);
        Assert.Equal("движок занят", o.Detail);
        Assert.NotEmpty(Assert.Single(RouterTrialExecutor.Outcomes(null, Report([]))).Detail!);
    }

    // every code of zapret-gui core/testers/probe.py PROBE_CODES
    [Theory]
    [InlineData("ok", TrialFailure.Other)]
    [InlineData("dns_block", TrialFailure.Other)]
    [InlineData("dns_hijack", TrialFailure.Other)]
    [InlineData("tcp_refused", TrialFailure.NoConnect)]
    [InlineData("tcp_reset", TrialFailure.Reset)]
    [InlineData("tcp_timeout", TrialFailure.Timeout)]
    [InlineData("tls_rst", TrialFailure.Reset)]
    [InlineData("tls_mitm", TrialFailure.BadCertificate)]
    [InlineData("tls_timeout", TrialFailure.Timeout)]
    [InlineData("tls_garbage", TrialFailure.Other)]
    [InlineData("isp_page", TrialFailure.Other)]
    [InlineData("tcp_16_20", TrialFailure.Stalled)]
    [InlineData("http_cutoff", TrialFailure.Stalled)]
    [InlineData("http_timeout", TrialFailure.Timeout)]
    [InlineData("throttled", TrialFailure.Stalled)]
    [InlineData("rate_limited", TrialFailure.Other)]
    [InlineData("unknown", TrialFailure.Other)]
    [InlineData("", TrialFailure.Other)]
    public void Probe_codes_map_to_trial_failures(string code, TrialFailure expected)
    {
        Assert.Equal(expected, RouterTrialExecutor.Failure(code));
    }

    [Fact]
    public async Task Batch_runs_experiments_of_batch_size_and_returns_outcomes_in_input_order()
    {
        var gui = new RouterGui { Probe = (args, _) => args.Contains("pos=3", StringComparison.Ordinal) ? (true, "ok", 3) : (false, "tls_rst", 0) };
        var x = new RouterTrialExecutor(gui.Experiments(), Options(o => o with { BatchSize = 2, TtlSec = 240 }));
        var candidates = Enumerable.Range(1, 5).Select(i => Tcp($"--payload=tls_client_hello --lua-desync=multisplit:pos={i}")).ToList();
        var r = await x.RunBatchAsync(candidates, 3, CancellationToken.None);

        Assert.Equal(3, gui.Starts);
        Assert.Equal([2, 2, 1], gui.StartArgs.Select(a => ((JsonArray)a["variants"]!).Count));
        Assert.Equal(["zt0", "zt1"], ((JsonArray)gui.StartArgs[0]["variants"]!).Select(v => (string)v!["label"]!));
        var first = gui.StartArgs[0];
        Assert.Equal(["rutracker.org", "example.com"], ((JsonArray)first["targets"]!).Select(t => (string)t!));
        Assert.Equal(3, (int)first["repeats"]!);
        Assert.Equal(240, (int)first["ttl_sec"]!);
        Assert.True((bool)first["baseline"]!);
        Assert.False((bool)first["keep_best"]!);
        Assert.Equal(2, ((JsonArray)first["variants"]![0]!["profiles"]!).Count);

        Assert.Equal(5, r.Count);
        for (int i = 0; i < 5; i++)
            Assert.Equal(i == 2, r[i].All(o => o.Ok));
        Assert.All(r, o => Assert.Equal(6, o.Count));
        Assert.NotNull(x.LastReport);
        Assert.DoesNotContain(gui.Calls, c => c.Tool is "strategy_experiment_commit" or "strategy_experiment_rollback");
    }

    [Fact]
    public async Task Single_run_goes_through_one_experiment_and_skips_open_targets()
    {
        var gui = new RouterGui { OpenWithoutBypass = ["example.com"], Probe = (_, _) => (false, "tcp_16_20", 1) };
        var x = new RouterTrialExecutor(gui.Experiments(), Options(o => o with { Targets = [.. Enumerable.Range(0, 12).Select(i => $"s{i}.org"), "example.com"] }));
        var o = await x.RunAsync(Tcp("--lua-desync=multisplit:pos=1"), 9, _ => false, CancellationToken.None);
        var start = Assert.Single(gui.StartArgs);
        Assert.Equal(10, ((JsonArray)start["targets"]!).Count);   // the GUI allows 10
        Assert.Equal(5, (int)start["repeats"]!);                  // and 5 repeats
        Assert.Equal(30, o.Count);
        Assert.Equal(10, o.Count(t => t.Ok));
        Assert.All(o.Where(t => !t.Ok), t => Assert.Equal(TrialFailure.Stalled, t.Failure));
        Assert.True(await x.TargetReachableAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Cancelled_run_asks_the_router_to_roll_back_at_once()
    {
        var gui = new RouterGui { States = ["running"] };
        var x = new RouterTrialExecutor(gui.Experiments(), Options(o => o with { Poll = TimeSpan.FromMilliseconds(5) }));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => x.RunBatchAsync([Tcp("--lua-desync=multisplit:pos=1")], 3, cts.Token));
        Assert.Equal("strategy_experiment_rollback", gui.Calls[^1].Tool);
        Assert.Contains(gui.Calls, c => c.Tool == "strategy_experiment_status");
        Assert.DoesNotContain(gui.Calls, c => c.Tool == "strategy_experiment_result");
        Assert.Null(x.LastReport);
    }
}
