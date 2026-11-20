using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Protocol;
using ZapretAutoTuner.Tuning.Geneva;
using static ZapretAutoTuner.Tuning.Tests.ProgramFixtures;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>geneva's "Авто" mode end to end with fakes: a blocked resolver is found, confirmed, bypassed, saved.</summary>
public sealed class GenevaAutoTests
{
    private const string Me = "192.168.1.2";

    /// <summary>The probe: blocked until the strategy that "works" is applied.</summary>
    private sealed class FakeProbes(FakeGenevaAgent agent, string works) : IAutoProbes
    {
        public List<(string Key, string? Applied)> Checks { get; } = [];

        /// <summary>Called on each check with the strategy applied to the service (null: none); a value replaces the answer.</summary>
        public Func<AutoService, string?, AutoConfirm?>? Answer { get; set; }

        public Task<AutoConfirm> CheckAsync(AutoService s, CancellationToken ct)
        {
            GenevaAutoApplyRequest? last;
            lock (agent.AutoApplied)
                last = agent.AutoApplied.LastOrDefault();
            var on = last?.Groups.FirstOrDefault(g => g.Targets.Any(t => t.Addresses.Contains(s.Address?.ToString() ?? "-")))?.Strategy;
            lock (Checks)
                Checks.Add((s.Key, on));
            if (Answer?.Invoke(s, on) is { } given)
                return Task.FromResult(given);
            return Task.FromResult(on == works ? AutoConfirm.NotBlocked : AutoConfirm.Blocked);
        }

        public GenevaJudge? Judge(AutoService s) => null;
    }

    private static async Task Until(Func<bool> done, int seconds = 20)
    {
        for (int i = 0; i < seconds * 40 && !done(); i++)
            await Task.Delay(25);
        Assert.True(done());
    }

    private static (GenevaController Controller, GenevaAuto Auto, FakeGenevaAgent Agent, FakeProbes Probes, MemoryGenevaStore Store) Make(
        Action<GenevaController, FakeGenevaAgent>? before = null, string? works = null, Func<CancellationToken, Task<IReadOnlyList<string>>>? library = null,
        GenevaState? saved = null)
    {
        // a resolver that never answers: every slice holds the same unanswered query
        var monitor = new FakeMonitor(Capture(
            Udp(Me, 50003, "8.8.8.8", 53, DnsQuery("example.com")),
            Udp(Me, 50003, "8.8.8.8", 53, DnsQuery("example.com"))), new Dictionary<int, ObservedSocket[]>());
        var agent = new FakeGenevaAgent();
        var store = new MemoryGenevaStore { Json = saved?.Serialize() };
        var controller = new GenevaController(_ => Task.FromResult<IGenevaAgent>(agent), store, (h, p, t, l, _, ct) => Task.FromResult(new ProbeResult { Host = h, Address = "" }));
        before?.Invoke(controller, agent);
        var probes = new FakeProbes(agent, works ?? AutoCandidates.Dns[1]);
        var auto = new GenevaAuto(controller, _ => Task.FromResult<IGenevaAgent>(agent), monitor, probes,
            () => new DateTime(2026, 1, 1, 0, 0, 30, DateTimeKind.Utc))
        {
            Slice = TimeSpan.FromMilliseconds(30),
            Library = library,
        };
        return (controller, auto, agent, probes, store);
    }

    [Fact]
    public async Task A_blocked_resolver_is_confirmed_bypassed_with_its_own_strategy_and_saved()
    {
        var (controller, auto, agent, probes, store) = Make();
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);
        Assert.True(auto.Running);
        Assert.True(controller.State.Auto.Enabled);

        await Until(() => auto.View.Services.Any(s => s.Key == "dns:8.8.8.8" && s.Status == AutoStatus.Applied));
        var s = auto.View.Services.Single(x => x.Key == "dns:8.8.8.8");
        Assert.Equal(AutoCandidates.Dns[1], s.Strategy);

        // the baseline came first, without a bypass (AGENTS.md rule 5)
        Assert.Equal(("dns:8.8.8.8", (string?)null), probes.Checks[0]);
        // the strategy is applied to the resolver alone
        GenevaAutoApplyRequest last;
        lock (agent.AutoApplied)
            last = agent.AutoApplied[^1];
        var g = Assert.Single(last.Groups);
        Assert.Equal(AutoCandidates.Dns[1], g.Strategy);
        var t = Assert.Single(g.Targets);
        Assert.Equal(["8.8.8.8"], t.Addresses);
        Assert.Equal("53", t.UdpPorts);

        Assert.Contains("dns:8.8.8.8", store.Json, StringComparison.Ordinal);
        var saved = GenevaState.Parse(store.Json);
        Assert.True(saved.Auto.Enabled);
        Assert.Equal(AutoStatus.Applied, saved.Auto.Services.Single(x => x.Key == "dns:8.8.8.8").Status);
    }

    [Fact]
    public async Task With_geneva_2_an_applied_site_also_goes_by_name_with_its_family()
    {
        var (controller, auto, agent, _, _) = Make((c, a) =>
        {
            a.AutoByName = true;
            c.SaveAuto(new GenevaAutoState
            {
                Services =
                [
                    new AutoService
                    {
                        Key = "web:youtube.com", Kind = AutoKind.Web, Transport = Core.Model.L4Kind.Tcp, Name = "youtube.com", App = "tls",
                        Addresses = [new AutoAddress("203.0.113.5", new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc))],
                        Ports = [443], Status = AutoStatus.Applied, Strategy = AutoCandidates.Tcp[0],
                    },
                ],
            });
        });
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);
        await Until(() => auto.View.ByName && auto.View.Groups.Any(g => g.ByName));
        GenevaAutoApplyRequest last;
        lock (agent.AutoApplied)
            last = agent.AutoApplied[^1];
        var h = Assert.Single(last.Hosts);
        Assert.Equal(AutoCandidates.Tcp[0], h.Strategy);
        Assert.Contains("youtube.com", h.Domains);
        Assert.Contains("googlevideo.com", h.Domains);
        Assert.Contains(auto.View.Groups.Single(g => g.ByName).Services, n => n.StartsWith("googlevideo.com", StringComparison.Ordinal));

        // a VPN server the user excludes: the name-based process is told
        controller.Lists = new AutoLists { Excluded = ["192.0.2.10", "vpn.example.org"] };
        await Until(() => { lock (agent.AutoApplied) return agent.AutoApplied[^1].ExcludeDomains.Contains("vpn.example.org"); });
        lock (agent.AutoApplied)
            Assert.Contains("192.0.2.10/32", agent.AutoApplied[^1].ExcludeSubnets);
    }

    [Fact]
    public async Task The_users_own_strategy_is_tried_like_a_found_one_and_pinned_when_it_works()
    {
        var (controller, auto, _, probes, _) = Make();
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);
        await Until(() => auto.View.Services.Any(s => s.Key == "dns:8.8.8.8" && s.Status == AutoStatus.Applied) && auto.View.Current is null);

        Assert.False(await auto.TryStrategyAsync("dns:8.8.8.8", AutoCandidates.Udp[0], default));
        Assert.Equal(AutoCandidates.Dns[1], auto.View.Services.Single(x => x.Key == "dns:8.8.8.8").Strategy);
        await Assert.ThrowsAsync<GenevaRefusedException>(() => auto.TryStrategyAsync("dns:8.8.8.8", AutoCandidates.Tcp[0], default));

        Assert.True(await auto.TryStrategyAsync("dns:8.8.8.8", AutoCandidates.Dns[1], default));
        var s = auto.View.Services.Single(x => x.Key == "dns:8.8.8.8");
        Assert.True(s.Pinned);
        // a trial asks the probe twice in a row
        lock (probes.Checks)
            Assert.True(probes.Checks.Count(c => c.Applied == AutoCandidates.Dns[1]) >= 2);
    }

    [Fact]
    public async Task The_users_own_strategy_needs_a_confirmed_block()
    {
        // a site the probe without a bypass found open: any strategy would "work" there (AGENTS.md rule 5)
        var open = new AutoService
        {
            Key = "web:open.example", Kind = AutoKind.Web, Transport = ZapretAutoTuner.Core.Model.L4Kind.Tcp, Name = "open.example", Host = "open.example", App = "tls",
            Ports = [443], Status = AutoStatus.NotBlocked,
        };
        var (controller, auto, _, probes, _) = Make(saved: new GenevaState { Auto = new GenevaAutoState { Services = [open] } });
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);
        await Assert.ThrowsAsync<GenevaRefusedException>(() => auto.TryStrategyAsync("web:open.example", AutoCandidates.Tcp[0], default));
        lock (probes.Checks)
            Assert.DoesNotContain(probes.Checks, c => c.Key == "web:open.example");
        Assert.False(auto.View.Services.Single(x => x.Key == "web:open.example").Pinned);
    }

    [Fact]
    public async Task A_trial_whose_group_did_not_start_is_not_taken_for_a_working_strategy()
    {
        // a site's group runs; the group of the strategy that would "work" for the resolver never starts
        var (controller, auto, agent, probes, _) = Make((c, a) =>
        {
            a.AutoRefused.Add(AutoCandidates.Dns[1]);
            c.SaveAuto(new GenevaAutoState
            {
                Services =
                [
                    new AutoService
                    {
                        Key = "web:a.com", Kind = AutoKind.Web, Transport = Core.Model.L4Kind.Tcp, Name = "a.com", App = "tls",
                        Addresses = [new AutoAddress("203.0.113.5", new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc))],
                        Ports = [443], Status = AutoStatus.Applied, Strategy = AutoCandidates.Tcp[0],
                    },
                ],
            });
        });
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);

        // the quick check went past the refused strategy without a probe and never applied it
        await Until(() => { lock (probes.Checks) return probes.Checks.Any(c => c.Applied == AutoCandidates.Udp[0]); });
        lock (probes.Checks)
            Assert.DoesNotContain(probes.Checks, c => c.Applied == AutoCandidates.Dns[1]);
        Assert.NotEqual(AutoCandidates.Dns[1], auto.View.Services.Single(x => x.Key == "dns:8.8.8.8").Strategy);
    }

    [Fact]
    public async Task After_two_empty_searches_the_wider_round_tries_the_library_and_a_bigger_search()
    {
        const string fromLibrary = @"[UDP:dport:53]-fragment{ip:-1:True}-| \/";
        var t0 = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var saved = new GenevaState
        {
            Auto = new GenevaAutoState
            {
                Services =
                [
                    new AutoService
                    {
                        Key = "dns:8.8.8.8", Kind = AutoKind.Dns, Transport = Core.Model.L4Kind.Udp, Name = "DNS 8.8.8.8", App = "dns",
                        Addresses = [new AutoAddress("8.8.8.8", t0)], Ports = [53], Replay = Convert.ToBase64String([1, 2, 3]),
                        Status = AutoStatus.Blocked, Attempts = AutoRules.WideAfter,
                    },
                ],
            },
        }.WithProgress(new GenevaSearchProgress
        {
            // the two searches before ran to their end and found nothing
            Host = "8.8.8.8", Port = 53, Population = AutoRules.Population, Generation = 14, Generations = 15, Finished = true, Protos = "UDP,IP,DNS,DNSQR",
        });
        var (controller, auto, agent, probes, _) = Make(works: "nothing works", library: _ => Task.FromResult<IReadOnlyList<string>>([fromLibrary]), saved: saved);
        await using var _c = controller;
        await using var _a = auto;
        await auto.EnableAsync(default);

        await Until(() => { lock (agent.Started) return agent.Started.Any(r => r.Mode == "evolve"); });
        // the library's strategy was tried on the resolver's own traffic first
        lock (probes.Checks)
            Assert.Contains(probes.Checks, c => c.Applied == fromLibrary);
        GenevaStartRequest evolve;
        lock (agent.Started)
            evolve = agent.Started.First(r => r.Mode == "evolve");
        Assert.False(evolve.Resume);
        Assert.Equal(AutoRules.WidePopulation, evolve.Population);
        Assert.Equal(AutoRules.WideGenerations, evolve.Generations);
        Assert.Equal("UDP,IP,DNS,DNSQR", evolve.Protos);
        Assert.Contains(fromLibrary, evolve.Seeds);
    }

    [Fact]
    public async Task Turning_it_off_stops_every_group_and_the_single_bypass_waits_while_it_runs()
    {
        var (controller, auto, agent, _, store) = Make();
        await using var c = controller;
        await using var a = auto;
        await auto.EnableAsync(default);
        await Assert.ThrowsAsync<GenevaRefusedException>(() => controller.StartRunAsync(AutoCandidates.Tcp[0], "443", false, default));

        await auto.DisableAsync();
        Assert.False(auto.Running);
        Assert.False(controller.State.Auto.Enabled);
        lock (agent.AutoApplied)
            Assert.Empty(agent.AutoApplied[^1].Groups);
        Assert.False(GenevaState.Parse(store.Json).Auto.Enabled);
    }

    [Fact]
    public async Task It_does_not_start_while_something_else_bypasses()
    {
        var (controller, auto, _, _, _) = Make();
        await using var c = controller;
        await using var a = auto;
        auto.Busy = () => "работает защита";
        await Assert.ThrowsAsync<GenevaRefusedException>(() => auto.EnableAsync(default));
        Assert.False(auto.Running);
        Assert.False(await auto.RestoreAsync(default));
    }

    [Fact]
    public async Task A_strategy_being_tried_is_not_listed_as_a_working_one()
    {
        var (controller, auto, _, probes, _) = Make(works: "nothing works");
        await using var _c = controller;
        await using var _a = auto;
        var seen = new List<AutoGroupView>();
        probes.Answer = (s, on) =>
        {
            if (on is not null)
            {
                lock (seen)
                    seen.AddRange(auto.View.Groups);
            }
            return null;
        };
        await auto.EnableAsync(default);
        await Until(() => { lock (seen) return seen.Count > 0; });
        lock (seen)
        {
            // the group runs (the trial needs it), but it serves nobody yet: the page leaves it out
            Assert.All(seen, g => Assert.True(g.Trial));
            Assert.All(seen, g => Assert.Empty(g.Services));
        }
    }

    [Fact]
    public async Task A_search_long_after_the_block_was_seen_looks_again_and_a_site_that_opens_is_not_searched()
    {
        var t0 = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var saved = new GenevaState
        {
            Auto = new GenevaAutoState
            {
                Services =
                [
                    new AutoService
                    {
                        Key = "dns:8.8.8.8", Kind = AutoKind.Dns, Transport = Core.Model.L4Kind.Udp, Name = "DNS 8.8.8.8", App = "dns",
                        Addresses = [new AutoAddress("8.8.8.8", t0)], Ports = [53], Replay = Convert.ToBase64String([1, 2, 3]),
                        Status = AutoStatus.Blocked, BaselineAt = t0.AddHours(-3),
                    },
                ],
            },
        };
        var (controller, auto, agent, probes, _) = Make(saved: saved);
        await using var _c = controller;
        await using var _a = auto;
        // the resolver answers by now without a bypass
        probes.Answer = (_, on) => on is null ? AutoConfirm.NotBlocked : null;
        await auto.EnableAsync(default);
        await Until(() => auto.View.Services.Single(x => x.Key == "dns:8.8.8.8").Status == AutoStatus.NotBlocked);
        lock (probes.Checks)
            Assert.DoesNotContain(probes.Checks, c => c.Applied is not null);
        lock (agent.Started)
            Assert.DoesNotContain(agent.Started, r => r.Mode == "evolve");
    }

    [Fact]
    public async Task A_service_on_the_do_not_search_list_leaves_and_is_never_searched()
    {
        var (controller, auto, agent, probes, _) = Make(works: "nothing works");
        await using var _c = controller;
        await using var _a = auto;
        controller.Lists = new AutoLists { NoSearch = ["8.8.8.0/24"] };
        await auto.EnableAsync(default);
        await Task.Delay(600);
        Assert.DoesNotContain(auto.View.Services, x => x.Key == "dns:8.8.8.8");
        lock (probes.Checks)
            Assert.Empty(probes.Checks);
        lock (agent.Started)
            Assert.DoesNotContain(agent.Started, r => r.Mode == "evolve");
    }

    [Fact]
    public async Task Taking_the_searched_service_out_of_the_search_stops_its_search()
    {
        var (controller, auto, _, probes, _) = Make(works: "nothing works");
        await using var _c = controller;
        await using var _a = auto;
        await auto.EnableAsync(default);
        await Until(() => { lock (probes.Checks) return probes.Checks.Any(c => c.Applied is not null); });
        controller.Lists = new AutoLists { NoSearch = ["AS15169"], AsnPrefixes = new Dictionary<string, IReadOnlyList<string>> { ["15169"] = ["8.8.8.0/24"] } };
        await Until(() => auto.View.Services.All(x => x.Key != "dns:8.8.8.8") && auto.View.Current is null);
    }

    private static GenevaState TwoBlockedResolvers()
    {
        var t0 = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        AutoService Resolver(string ip) => new()
        {
            Key = "dns:" + ip, Kind = AutoKind.Dns, Transport = Core.Model.L4Kind.Udp, Name = "DNS " + ip, App = "dns",
            Addresses = [new AutoAddress(ip, t0)], Ports = [53], Replay = Convert.ToBase64String([1, 2, 3]),
            Status = AutoStatus.Blocked, BaselineAt = t0, LastSeen = t0,
        };
        return new GenevaState { Workers = 8, Auto = new GenevaAutoState { Services = [Resolver("8.8.8.8"), Resolver("1.1.1.1")] } };
    }

    [Fact]
    public async Task With_split_threads_two_blocked_services_are_searched_at_once()
    {
        var (controller, auto, agent, _, _) = Make(works: "nothing works", saved: TwoBlockedResolvers() with { AutoSplit = true });
        agent.Hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var _c = controller;
        await using var _a = auto;
        await auto.EnableAsync(default);

        await Until(() => controller.Searches.Count == 2, seconds: 60);
        Assert.Equal(new HashSet<string> { "8.8.8.8", "1.1.1.1" }, controller.Searches.Select(x => x.Host).ToHashSet());
        lock (agent.Started)
            Assert.All(agent.Started.Where(r => r.Mode == "evolve"), r => Assert.Equal(2, r.Workers));
        Assert.Equal(2, auto.View.Searches.Count);
        // 8 threads split: up to 4 side by side, nothing holds the groups; each service names its geneva search
        Assert.Equal(4, auto.View.SearchSlots);
        await Until(() => auto.View.Searches.All(x => x.SearchId is not null), seconds: 10);
        Assert.Equal(controller.Searches.Select(x => x.Id).ToHashSet(), auto.View.Searches.Select(x => x.SearchId!).ToHashSet());
        Assert.Contains("8.8.8.8", auto.CurrentPhase.En, StringComparison.Ordinal);
        Assert.Contains("1.1.1.1", auto.CurrentPhase.En, StringComparison.Ordinal);
        agent.Hold.SetResult();
    }

    [Fact]
    public async Task With_all_threads_on_one_service_the_services_wait_their_turn()
    {
        var (controller, auto, agent, _, _) = Make(works: "nothing works", saved: TwoBlockedResolvers());
        agent.Hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var _c = controller;
        await using var _a = auto;
        await auto.EnableAsync(default);

        await Until(() => controller.Searches.Count == 1, seconds: 60);
        await Task.Delay(1500);
        Assert.Single(controller.Searches);
        Assert.Single(auto.View.Searches);
        Assert.Equal(8, Assert.Single(agent.Started, r => r.Mode == "evolve").Workers);
        agent.Hold.SetResult();
    }

    /// <summary>The resolver of <see cref="Make"/> opens: only the saved site is searched.</summary>
    private static AutoConfirm? OnlyTheSite(AutoService s, string? applied) => s.Key.StartsWith("dns:", StringComparison.Ordinal) ? AutoConfirm.NotBlocked : null;

    private static GenevaState BlockedSite() => new()
    {
        Auto = new GenevaAutoState
        {
            Services =
            [
                new AutoService
                {
                    Key = "web:blocked.example", Kind = AutoKind.Web, Transport = Core.Model.L4Kind.Tcp, Name = "blocked.example", Host = "blocked.example", App = "tls",
                    Addresses = [new AutoAddress("203.0.113.7", new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc))],
                    Ports = [443], Status = AutoStatus.Blocked,
                    FirstSeen = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), LastSeen = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                },
            ],
        },
    };

    [Fact]
    public async Task A_sites_strategy_is_applied_only_after_it_opens_the_site_in_the_programs_browser()
    {
        var opened = new List<(string Host, int Port, string? Address)>();
        var (controller, auto, _, probes, _) = Make((c, _) => c.Browser = new GenevaBrowser(() => true, (host, port, _, address, ct) =>
        {
            lock (opened)
                opened.Add((host, port, address?.ToString()));
            return Task.FromResult<PageLoad?>(new PageLoad { Url = GenevaBrowserCheck.Url(host, port), LoadFired = true });
        }), works: AutoCandidates.Tcp[0], saved: BlockedSite());
        probes.Answer = OnlyTheSite;
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);
        await Until(() => auto.View.Services.Any(s => s.Key == "web:blocked.example" && s.Status == AutoStatus.Applied));
        Assert.Equal(AutoCandidates.Tcp[0], auto.View.Services.Single(x => x.Key == "web:blocked.example").Strategy);
        // the name pinned to the address the strategy is applied to
        lock (opened)
            Assert.Contains(("blocked.example", 443, (string?)"203.0.113.7"), opened);
    }

    [Fact]
    public async Task A_strategy_that_does_not_open_the_site_in_the_browser_is_not_applied()
    {
        int opens = 0;
        var (controller, auto, _, probes, _) = Make((c, _) => c.Browser = new GenevaBrowser(() => true, (host, port, _, address, ct) =>
        {
            Interlocked.Increment(ref opens);
            return Task.FromResult<PageLoad?>(new PageLoad { Url = GenevaBrowserCheck.Url(host, port), Error = "net::ERR_CONNECTION_RESET" });
        }), works: AutoCandidates.Tcp[0], saved: BlockedSite());
        probes.Answer = OnlyTheSite;
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);
        await Until(() => auto.Log.Any(l => l.Contains("не открылся во встроенном браузере", StringComparison.Ordinal)));
        Assert.True(Volatile.Read(ref opens) > 0);
        Assert.NotEqual(AutoStatus.Applied, auto.View.Services.Single(x => x.Key == "web:blocked.example").Status);
    }

    [Fact]
    public async Task With_the_browser_check_off_a_site_is_judged_by_the_probes_alone()
    {
        int opens = 0;
        var (controller, auto, _, probes, _) = Make((c, _) =>
        {
            c.BrowserCheck = false;
            c.Browser = new GenevaBrowser(() => true, (host, port, _, address, ct) =>
            {
                Interlocked.Increment(ref opens);
                return Task.FromResult<PageLoad?>(new PageLoad { Url = "", Error = "failed" });
            });
        }, works: AutoCandidates.Tcp[0], saved: BlockedSite());
        probes.Answer = OnlyTheSite;
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);
        await Until(() => auto.View.Services.Any(s => s.Key == "web:blocked.example" && s.Status == AutoStatus.Applied));
        Assert.Equal(0, Volatile.Read(ref opens));
    }

    [Fact]
    public async Task During_the_browser_check_the_tried_strategy_also_reaches_the_sites_family_by_name()
    {
        var site = new AutoService
        {
            Key = "web:youtube.com", Kind = AutoKind.Web, Transport = Core.Model.L4Kind.Tcp, Name = "youtube.com", Host = "www.youtube.com", App = "tls",
            Addresses = [new AutoAddress("203.0.113.7", new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc))],
            Ports = [443], Status = AutoStatus.Blocked,
            FirstSeen = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), LastSeen = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        };
        var seen = new List<IReadOnlyList<string>>();
        FakeGenevaAgent? fake = null;
        var (controller, auto, agent, probes, _) = Make((c, a) =>
        {
            fake = a;
            a.AutoByName = true;
            c.Browser = new GenevaBrowser(() => true, (host, port, _, address, ct) =>
            {
                // what the name-based process was given while the page opens
                lock (a.AutoApplied)
                    seen.Add([.. a.AutoApplied[^1].Hosts.Where(h => h.Strategy == AutoCandidates.Tcp[0]).SelectMany(h => h.Domains)]);
                return Task.FromResult<PageLoad?>(new PageLoad
                {
                    Url = GenevaBrowserCheck.Url(host, port),
                    LoadFired = true,
                    Requests =
                    [
                        new PageRequest { Url = "https://www.youtube.com/", ResourceType = "document", Status = 200, Duration = TimeSpan.FromSeconds(1) },
                        new PageRequest { Url = "https://i.ytimg.com/a.jpg", ResourceType = "image", Error = "net::ERR_CONNECTION_RESET" },
                    ],
                });
            });
        }, works: AutoCandidates.Tcp[0], saved: new GenevaState { Auto = new GenevaAutoState { Services = [site] } });
        probes.Answer = OnlyTheSite;
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);
        // ytimg.com went through the strategy under test and did not load: the strategy is not taken
        await Until(() => auto.Log.Any(l => l.Contains("не загрузились связанные ресурсы", StringComparison.Ordinal) && l.Contains("ytimg.com", StringComparison.Ordinal)));
        lock (seen)
            Assert.Contains(seen, d => d.Contains("ytimg.com") && d.Contains("googlevideo.com"));
        Assert.NotEqual(AutoStatus.Applied, auto.View.Services.Single(x => x.Key == "web:youtube.com").Status);
        // the trial's names are gone once the check is over
        await Until(() => { lock (agent.AutoApplied) return !agent.AutoApplied[^1].Hosts.Any(h => h.Domains.Contains("ytimg.com") && h.Strategy == AutoCandidates.Tcp[0]); });
    }

    [Fact]
    public async Task An_applied_strategy_that_no_longer_opens_the_site_is_found_by_the_routine_check()
    {
        // applied an hour ago and in use, but the DPI learned it: its flows show nothing the slices could judge
        var t0 = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var site = new AutoService
        {
            Key = "web:weak.example", Kind = AutoKind.Web, Transport = Core.Model.L4Kind.Tcp, Name = "weak.example", Host = "weak.example", App = "tls",
            Addresses = [new AutoAddress("203.0.113.8", t0)], Ports = [443],
            Status = AutoStatus.Applied, Strategy = AutoCandidates.Tcp[1], AppliedAt = t0.AddHours(-1),
            FirstSeen = t0.AddHours(-2), LastSeen = t0,
        };
        var (controller, auto, _, probes, _) = Make(works: AutoCandidates.Tcp[0], saved: new GenevaState { Auto = new GenevaAutoState { Services = [site] } });
        probes.Answer = OnlyTheSite;
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);
        await Until(() => auto.Log.Any(l => l.Contains("плановая проверка с обходом не прошла", StringComparison.Ordinal)));
        // a second probe with the bypass agrees: a new strategy is searched
        await Until(() => auto.Log.Any(l => l.Contains("weak.example: стратегия больше не работает, ищу новую", StringComparison.Ordinal)));
        // the probes judged the strategy that was applied
        lock (probes.Checks)
            Assert.Contains(("web:weak.example", (string?)AutoCandidates.Tcp[1]), probes.Checks);
    }

    [Fact]
    public async Task An_important_service_failing_with_its_bypass_is_checked_before_a_less_important_suspicion()
    {
        // YouTube's strategy is on and most flows pass, but three stalled since: not "weakened", and the half-hour check
        // is far; a resolver waits for its probe meanwhile
        var t0 = new DateTime(2026, 1, 1, 0, 0, 30, DateTimeKind.Utc);
        var yt = new AutoService
        {
            Key = "web:youtube.com", Kind = AutoKind.Web, Transport = Core.Model.L4Kind.Tcp, Name = "youtube.com", Host = "www.youtube.com", App = "tls",
            Addresses = [new AutoAddress("203.0.113.8", t0)], Ports = [443],
            Status = AutoStatus.Applied, Strategy = AutoCandidates.Tcp[1], AppliedAt = t0.AddMinutes(-8),
            FirstSeen = t0.AddHours(-2), LastSeen = t0, Priority = AutoPriority.Important, Why = "соединение есть, данных нет",
            Fails = [t0.AddMinutes(-3), t0.AddMinutes(-2), t0.AddMinutes(-1)],
            Oks = [.. Enumerable.Range(1, 8).Select(i => t0.AddSeconds(-10 * i))],
        };
        var dns = new AutoService
        {
            Key = "dns:8.8.8.8", Kind = AutoKind.Dns, Transport = Core.Model.L4Kind.Udp, Name = "8.8.8.8", App = "dns",
            Addresses = [new AutoAddress("8.8.8.8", t0)], Ports = [53],
            Status = AutoStatus.Suspected, Suspicions = 1, FirstSeen = t0.AddMinutes(-5), LastSeen = t0,
            NoConnections = [t0.AddMinutes(-1)], Fails = [t0.AddMinutes(-1), t0.AddSeconds(-30)],
        };
        var (controller, auto, _, probes, _) = Make(saved: new GenevaState { Auto = new GenevaAutoState { Services = [yt, dns] } });
        probes.Answer = (s, _) => s.Key == "web:youtube.com" ? AutoConfirm.NotBlocked : null;
        await using var _ = controller;
        await using var __ = auto;
        await auto.EnableAsync(default);
        await Until(() => { lock (probes.Checks) return probes.Checks.Any(c => c.Key == "dns:8.8.8.8"); });
        Assert.Contains(auto.Log, l => l.Contains("youtube.com: важный сервис, с обходом не прошли 3 из 11", StringComparison.Ordinal));
        lock (probes.Checks)
        {
            Assert.Equal("web:youtube.com", probes.Checks[0].Key);
            Assert.Equal(AutoCandidates.Tcp[1], probes.Checks[0].Applied);
        }
        // passed: the row says so instead of the old failure, and the same failures do not call for another check
        var row = auto.View.Services.Single(x => x.Key == "web:youtube.com");
        Assert.Equal(AutoStatus.Applied, row.Status);
        Assert.NotNull(row.CheckedAt);
        Assert.Equal((0, 0), AutoBook.SinceChecked(row, t0));
        lock (probes.Checks)
            Assert.Single(probes.Checks, c => c.Key == "web:youtube.com");
    }

    [Fact]
    public void The_programs_own_page_loads_are_not_the_users_traffic()
    {
        var t0 = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        AutoSample Flow(string host, DateTime time) => new()
        {
            Key = "web:" + host, Kind = AutoKind.Web, Transport = Core.Model.L4Kind.Tcp, Name = host, Host = host, App = "tls",
            Server = new System.Net.IPEndPoint(System.Net.IPAddress.Parse("203.0.113.9"), 443), Time = time, Health = AutoHealth.Failed,
        };
        var done = new GenevaAuto.OwnLoad(t0, "www.site.example", "ads.tracker.example") { To = t0.AddSeconds(10) };
        // a check still running when the slice ends: open-ended
        var running = new GenevaAuto.OwnLoad(t0.AddSeconds(20), "running.example");
        List<GenevaAuto.OwnLoad> loads = [done, running];
        var kept = GenevaAuto.WithoutOwnLoads(
        [
            Flow("ads.tracker.example", t0.AddSeconds(3)),     // fetched by the check, while it ran
            Flow("WWW.site.example", t0.AddSeconds(5)),         // the same name, another case
            Flow("ads.tracker.example", t0.AddSeconds(30)),    // the user's own visit later
            Flow("other.example", t0.AddSeconds(4)),            // the user's own traffic meanwhile
            Flow("", t0.AddSeconds(4)) with { Host = null },    // an address only
            Flow("running.example", t0.AddSeconds(25)),         // fetched by the check still under way
        ], loads);
        Assert.Equal(3, kept.Count);
        Assert.DoesNotContain(kept, x => x.Host == "running.example");
        Assert.DoesNotContain(kept, x => x.Time == t0.AddSeconds(3) || x.Time == t0.AddSeconds(5));
    }
}
