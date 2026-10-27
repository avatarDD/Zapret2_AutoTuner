using System.Net;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Delivery;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>The closed loop on the router (PLAN 7.6, R1–R5) over zapret-gui's experiments in memory.</summary>
public sealed class RouterTuningTests
{
    private static ClassifierVerdict Blocked(string host) => new()
    {
        Host = host,
        Primary = BlockLabel.SniBlock,
        Next = NextStep.SearchStrategy,
        LiveAddresses = ["203.0.113.5"],
        Findings = [new LabelFinding(BlockLabel.SniBlock, "203.0.113.5", ["reset"])],
    };

    [Fact]
    public async Task Connect_names_the_missing_tools_and_reads_the_enabled_active_profiles()
    {
        var gui = new RouterGui { Tools = ["strategy_experiment_status", "strategy_get"] };
        var (missing, _, current) = await RouterTuning.ConnectAsync(gui.Experiments(), CancellationToken.None);
        Assert.Contains("strategy_experiment_start", missing);
        Assert.Empty(current);
        Assert.DoesNotContain(gui.Calls, c => c.Tool == "strategy_get");

        gui = new RouterGui { Active = ("yt_quic", [("QUIC", "--filter-udp=443 --lua-desync=fake:blob=fake_default_quic", true), ("old", "--filter-tcp=80 --lua-desync=multisplit", false)]) };
        var (none, id, profiles) = await RouterTuning.ConnectAsync(gui.Experiments(), CancellationToken.None);
        Assert.Empty(none);
        Assert.Equal("yt_quic", id);
        Assert.Equal([("QUIC", "--filter-udp=443 --lua-desync=fake:blob=fake_default_quic")], profiles);

        // nothing selected on the router: no profiles to keep, not an error
        var (_, empty, nothing) = await RouterTuning.ConnectAsync(new RouterGui().Experiments(), CancellationToken.None);
        Assert.Equal("", empty);
        Assert.Empty(nothing);
    }

    [Fact]
    public async Task The_pipeline_searches_on_the_router_and_its_trials_feed_the_learned_order_as_router()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        long network = kb.Network(new NetworkInfo(12389, null));
        var set = StrategyGenerator.Generate(new GeneratorOptions { Mode = SearchMode.Quick });
        var winner = set.Candidates[2];
        var gui = new RouterGui { Probe = (args, _) => args.Contains(winner.Strategy.ToString(), StringComparison.Ordinal) ? (true, "ok", 3) : (false, "tls_rst", 0) };
        var current = new List<(string, string)> { ("QUIC", "--filter-udp=443 --lua-desync=fake:blob=fake_default_quic") };
        var services = new RouterPipelineServices(gui.Experiments(), new RouterTrialOptions { Targets = ["rutracker.org"], CurrentProfiles = current, Poll = TimeSpan.FromMilliseconds(1) },
            (h, _, _) => Task.FromResult(Blocked(h)), kb, network, 12389, "Quick");
        var learning = RouterTuning.ForRouter(TuningSession.Learning(kb, new LearningContext(12389)))!;
        Assert.Equal(RouterTuning.ClientProfile, learning.Context.ClientProfile);
        var options = new PipelineOptions
        {
            Unify = false,
            Search = new SearchOptions { Generator = new GeneratorOptions { Mode = SearchMode.Quick }, StopAfterFound = 1, Learning = learning, PunishPause = TimeSpan.FromMilliseconds(1) },
        };

        var r = await new TuningPipeline(services, options).RunAsync(["rutracker.org"]);

        Assert.Equal(winner.Key, r.Targets[0].Best?.Candidate.Key);
        Assert.NotNull(r.Solution);
        var first = gui.StartArgs[0];
        Assert.True((bool)first["baseline"]!);                       // rule 5: the router's own baseline first
        Assert.All(gui.StartArgs.Skip(1), a => Assert.False((bool)a["baseline"]!));
        Assert.Equal(["rutracker.org"], ((JsonArray)first["targets"]!).Select(t => (string)t!));
        var profiles = (JsonArray)first["variants"]![0]!["profiles"]!;
        Assert.Equal(2, profiles.Count);                               // the router's current profile stays after the candidate
        Assert.Equal("QUIC", (string)profiles[1]!["name"]!);
        Assert.DoesNotContain(gui.Calls, c => c.Tool == "strategy_experiment_commit");

        // the router's trials: source router, client profile router, so the bandit has its own level for them
        var history = kb.LearningHistory(DateTimeOffset.UtcNow.AddDays(-1));
        Assert.NotEmpty(history);
        Assert.All(history, h => Assert.Equal(CandidateSource.Router, h.Source));
        Assert.All(history, h => Assert.Equal(RouterTuning.ClientProfile, h.ClientProfile));
        Assert.Contains(history, h => h.Strategy == winner.Strategy.ToString() && h.Successes > 0);
        Assert.Contains(kb.Results("rutracker.org"), x => x.ClientProfile == RouterTuning.ClientProfile && x.Status == "working");

        // the next search on the router starts from the router's winner
        var next = new ThompsonOrder(RouterTuning.ForRouter(TuningSession.Learning(kb, new LearningContext(12389, "SniBlock")))! with { Seed = 1 });
        Assert.True(next.Strategy(winner.Key).Mean > next.Pool.Mean);
    }

    [Fact]
    public void A_solution_becomes_inline_router_profiles()
    {
        var s = new Solution
        {
            Profiles =
            [
                new Profile { Name = "yt", TcpPorts = "443", Hostlists = [new ListRef("zt-yt")], Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=zt_tls:tcp_md5") },
                new Profile { Name = "cf", TcpPorts = "443", Ipsets = [new ListRef("zt-cf-ipset")], Strategy = Strategy.Parse("--lua-desync=multisplit:pos=1") },
            ],
        };
        s.Hostlists["zt-yt"] = ["youtube.com", "googlevideo.com"];
        s.Ipsets["zt-cf-ipset"] = ["104.16.0.0/13"];
        s.Blobs["zt_tls"] = [0x16, 0x03, 0x01];
        var (profiles, problems) = RouterTuning.ProfilesOf(s);
        Assert.Empty(problems);
        Assert.Equal(["yt", "cf"], profiles.Select(p => p.Name));
        Assert.StartsWith("--blob=zt_tls:0x160301 ", profiles[0].Args, StringComparison.Ordinal);
        Assert.Contains("--hostlist-domains=youtube.com,googlevideo.com", profiles[0].Args, StringComparison.Ordinal);
        Assert.Contains("--ipset-ip=104.16.0.0/13", profiles[1].Args, StringComparison.Ordinal);
        Assert.All(profiles, p => Assert.DoesNotContain("--hostlist=", p.Args, StringComparison.Ordinal));
        Assert.All(profiles, p => Assert.DoesNotContain("--ipset=", p.Args, StringComparison.Ordinal));
        Assert.All(profiles, p => Assert.DoesNotContain("--dpi-desync", p.Args, StringComparison.Ordinal));

        s.Profiles[0].HostlistExcludes = [new ListRef("netrogat")];
        s.Hostlists["zt-yt"] = [.. Enumerable.Range(0, 200).Select(i => $"site{i}.example.com")];
        var (_, more) = RouterTuning.ProfilesOf(s);
        Assert.Contains(more, p => p.Contains("исключения", StringComparison.Ordinal));
        Assert.Contains(more, p => p.Contains("2000", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Keep_applies_the_only_variant_with_keep_best_and_commit_saves_it_after_the_yes()
    {
        var gui = new RouterGui { Probe = (_, _) => (true, "ok", 3) };
        var x = gui.Experiments();
        var (report, kept, problem) = await RouterTuning.KeepAsync(x, [("yt", "--filter-tcp=443 --lua-desync=multisplit")], ["rutracker.org"], 300, TimeSpan.FromMilliseconds(1), CancellationToken.None);
        Assert.True(kept, problem);
        Assert.True(report!.AwaitingCommit);
        var start = Assert.Single(gui.StartArgs);
        Assert.True((bool)start["keep_best"]!);
        Assert.False((bool)start["baseline"]!);
        Assert.Equal(RouterTuning.KeepLabel, (string)start["variants"]![0]!["label"]!);
        Assert.DoesNotContain(gui.Calls, c => c.Tool is "strategy_experiment_commit" or "strategy_experiment_rollback");

        // committing is impossible without the user's yes
        await Assert.ThrowsAsync<InvalidOperationException>(() => RouterTuning.CommitAsync(x, confirmedByUser: false, "zt_router_x", null, CancellationToken.None));
        var (saved, note) = await RouterTuning.CommitAsync(x, confirmedByUser: true, "zt_router_x", "AutoTuner", CancellationToken.None);
        Assert.True(saved);
        Assert.Equal("", note);
        var commit = gui.Calls.Single(c => c.Tool == "strategy_experiment_commit").Args;
        Assert.Equal(RouterTuning.KeepLabel, (string)commit["label"]!);
        Assert.Equal("zt_router_x", (string)commit["save_as"]!);
        Assert.True((bool)commit["make_active"]!);
    }

    [Fact]
    public async Task Without_strategies_write_the_commit_is_kept_unsaved_and_says_so()
    {
        var gui = new RouterGui { Probe = (_, _) => (true, "ok", 3), DenySave = true };
        var (saved, note) = await RouterTuning.CommitAsync(gui.Experiments(), confirmedByUser: true, "zt_router_x", null, CancellationToken.None);
        Assert.False(saved);
        Assert.Contains("strategies_write", note, StringComparison.Ordinal);
        var commits = gui.Calls.Where(c => c.Tool == "strategy_experiment_commit").Select(c => c.Args).ToList();
        Assert.Equal(2, commits.Count);
        Assert.Null(commits[1]["save_as"]);
    }

    [Fact]
    public async Task Keep_reverts_at_once_when_nothing_opens()
    {
        var gui = new RouterGui { Probe = (_, _) => (false, "tls_rst", 0) };
        var (_, kept, problem) = await RouterTuning.KeepAsync(gui.Experiments(), [("yt", "--filter-tcp=443 --lua-desync=multisplit")], ["rutracker.org"], 300, TimeSpan.FromMilliseconds(1), CancellationToken.None);
        Assert.False(kept);
        Assert.NotEmpty(problem);
        Assert.Equal("strategy_experiment_rollback", gui.Calls[^1].Tool);
    }

    [Fact]
    public void Record_stores_the_routers_measurements_without_open_targets_or_unstarted_variants()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        var s = Strategy.Parse("--lua-desync=multisplit:pos=1");
        var started = new ExperimentVariantResult("A", true, false, "", null,
            [new ExperimentProbe("blocked.example", false, "tls_rst", "", 100, 0, 3, 2), new ExperimentProbe("open.example", true, "ok", "", 100, 65536, 3, 3)], 0, 0, [], [], []);
        var skipped = new ExperimentVariantResult("B", false, true, "validation", null, [], 0, 0, [], [], []);
        var report = new ExperimentReport("r", "finished", [started, skipped], ["open.example"], "A", false, false, null, "", "", "");
        int n = RouterTuning.Record(kb, report, new Dictionary<string, (Strategy, L4Kind)> { ["A"] = (s, L4Kind.Tcp), ["B"] = (Strategy.Parse("--lua-desync=fake"), L4Kind.Tcp) });
        Assert.Equal(3, n);
        var r = Assert.Single(kb.Results("blocked.example"));
        Assert.Equal(new Efficiency(2, 3), r.Efficiency);
        Assert.Equal(RouterTuning.ClientProfile, r.ClientProfile);
        Assert.Empty(kb.Results("open.example"));
        Assert.All(kb.LearningHistory(DateTimeOffset.UtcNow.AddDays(-1)), h => Assert.Equal(CandidateSource.Router, h.Source));
    }

    /// <summary>Review L3: an unexpected error of one read does not end the watch silently; it is kept and retried.</summary>
    [Fact]
    public async Task The_feedback_watcher_survives_an_unexpected_error()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        int reads = 0;
        using var cts = new CancellationTokenSource();
        var watcher = new RouterFeedbackWatcher(kb, (_, _) =>
        {
            if (++reads >= 3)
                cts.Cancel();
            throw new InvalidOperationException("bad answer");
        }, ["rutracker.org"]);
        await watcher.RunAsync(TimeSpan.FromMilliseconds(1), cts.Token).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(reads >= 3);
        Assert.Equal("bad answer", watcher.LastError);
    }

    [Fact]
    public async Task The_feedback_watcher_journals_failing_new_and_recovered_hosts_once()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        var gui = new RouterGui
        {
            LogLines =
            [
                "20.10.2026 10:00:01 : rutracker.org : profile 1 (noname) : client 192.168.1.33:51234 : proto tls : incoming RST",
                "20.10.2026 10:00:05 : rutracker.org : profile 1 (noname) : client 192.168.1.33:51240 : proto tls : retrans threshold reached",
                "20.10.2026 10:00:06 : cdn.new.example : profile 1 (noname) : client 192.168.1.33:51241 : proto tls : incoming RST",
            ],
        };
        var mcp = new ZapretGuiMcp(new HttpClient(gui) { BaseAddress = new Uri("http://192.168.1.1:8080/") }, "tok");
        var watcher = new RouterFeedbackWatcher(kb, (since, ct) => RouterFeedback.FromZapretGuiAsync(mcp, since, ct), ["rutracker.org"]);
        int changed = 0;
        watcher.Changed += () => changed++;

        Assert.Equal(2, await watcher.PollOnceAsync(CancellationToken.None));
        var rows = kb.Changes();
        Assert.Contains(rows, c => c.Domain == "rutracker.org" && c.Kind == "router_failing");
        Assert.Contains(rows, c => c.Domain == "cdn.new.example" && c.Kind == "router_new_host");
        // the same failure again is not journalled twice; the second read asks only for newer lines
        Assert.Equal(0, await watcher.PollOnceAsync(CancellationToken.None));
        Assert.NotNull(gui.Calls.Last(c => c.Tool == "logs_tail").Args["since"]);

        gui.LogLines = ["20.10.2026 10:10:00 : rutracker.org : profile 1 (noname) : client 192.168.1.33:51300 : proto tls : fail counter reset. website is working."];
        Assert.Equal(1, await watcher.PollOnceAsync(CancellationToken.None));
        Assert.Contains(kb.Changes(), c => c.Domain == "rutracker.org" && c.Kind == "router_recovered");
        Assert.Equal(2, changed);
        // it only reads
        Assert.All(gui.Calls, c => Assert.Equal("logs_tail", c.Tool));
    }
}
