using System.Net;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>
/// The "Авто" mode with geneva_c 2.0 (issue 28): what matters first, peers that cannot crowd out a site, the user's word
/// (important, pinned, check now, never touch), families of domains and strategies applied by name.
/// </summary>
public class AutoPriorityTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static AutoSample Site(string site, AutoHealth health, DateTime time, string ip = "203.0.113.5", string? host = null) => new()
    {
        Key = "web:" + site,
        Kind = AutoKind.Web,
        Transport = L4Kind.Tcp,
        Name = site,
        Host = host ?? "www." + site,
        App = "tls",
        Server = new IPEndPoint(IPAddress.Parse(ip), 443),
        Time = time,
        Health = health,
        Why = health == AutoHealth.Ok ? "" : "сброс",
    };

    private static AutoSample Peer(int n, AutoHealth health, DateTime time) => new()
    {
        Key = $"ep:tcp:tcp:198.51.{n / 250}.{n % 250 + 1}:51413",
        Kind = AutoKind.Endpoint,
        Transport = L4Kind.Tcp,
        Name = $"TCP 198.51.{n / 250}.{n % 250 + 1}:51413",
        App = "tcp",
        Server = new IPEndPoint(IPAddress.Parse($"198.51.{n / 250}.{n % 250 + 1}"), 51413),
        Time = time,
        Health = health,
        Why = "нет ответа",
    };

    private static AutoBook Blocked(params AutoSample[] samples)
    {
        var book = new AutoBook();
        book.Feed(samples, T0.AddSeconds(3));
        book.Evaluate(T0.AddSeconds(3));
        foreach (var s in book.Services.ToList())
            book.Confirmed(s.Key, AutoConfirm.Blocked, T0.AddSeconds(4));
        return book;
    }

    private static IEnumerable<AutoSample> Fails(Func<int, AutoHealth, DateTime, AutoSample> make, int n) =>
        Enumerable.Range(0, 3).Select(i => make(n, AutoHealth.Failed, T0.AddSeconds(i)));

    // ---- priority

    [Theory]
    [InlineData("youtube.com", AutoPriority.Important)]
    [InlineData("googlevideo.com", AutoPriority.Important)]
    [InlineData("discordapp.net", AutoPriority.Important)]
    [InlineData("example.com", AutoPriority.Normal)]
    public void Sites_are_normal_and_the_well_known_services_important(string site, AutoPriority expected)
    {
        var book = new AutoBook();
        book.Feed([Site(site, AutoHealth.Ok, T0)], T0);
        Assert.Equal(expected, book.Find("web:" + site)!.Priority);
    }

    [Fact]
    public void A_bare_peer_is_background_and_a_named_server_low()
    {
        var book = new AutoBook();
        book.Feed([Peer(1, AutoHealth.Ok, T0), Peer(1, AutoHealth.Ok, T0) with
        {
            Key = "ep:wireguard:udp:203.0.113.9:51820", Kind = AutoKind.Endpoint, Transport = L4Kind.Udp, App = "wireguard",
            Server = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 51820),
        }], T0);
        Assert.Equal(AutoPriority.Background, book.Find(Peer(1, AutoHealth.Ok, T0).Key)!.Priority);
        Assert.Equal(AutoPriority.Low, book.Find("ep:wireguard:udp:203.0.113.9:51820")!.Priority);
    }

    [Fact]
    public void The_users_lists_and_word_override_the_computed_priority()
    {
        var book = new AutoBook();
        book.Feed([Site("example.com", AutoHealth.Ok, T0), Site("youtube.com", AutoHealth.Ok, T0), Peer(7, AutoHealth.Ok, T0)], T0);
        book.SetLists(new AutoLists { Important = ["198.51.0.0/24"], Unimportant = ["example.com"], KnownImportant = false });
        Assert.Equal(AutoPriority.Background, book.Find("web:example.com")!.Priority);
        Assert.Equal(AutoPriority.Normal, book.Find("web:youtube.com")!.Priority);
        Assert.Equal(AutoPriority.Important, book.Find(Peer(7, AutoHealth.Ok, T0).Key)!.Priority);
        Assert.True(book.SetUserPriority("web:example.com", AutoUserPriority.Important));
        Assert.Equal(AutoPriority.Important, book.Find("web:example.com")!.Priority);
    }

    // ---- order

    [Fact]
    public void Two_hundred_failing_peers_do_not_go_before_youtube()
    {
        var samples = Enumerable.Range(0, 200).SelectMany(n => Fails(Peer, n).Concat(Fails(Peer, n)))
            .Concat(Fails((_, h, t) => Site("youtube.com", h, t), 0)).ToArray();
        var book = Blocked(samples);
        Assert.Equal("web:youtube.com", book.NextToSearch(T0.AddSeconds(5))!.Key);
    }

    [Fact]
    public void A_site_interrupts_a_peers_search_and_a_peer_never_interrupts()
    {
        var book = Blocked([.. Fails(Peer, 1), .. Fails((_, h, t) => Site("example.com", h, t), 0)]);
        book.Searching(Peer(1, AutoHealth.Ok, T0).Key, T0.AddSeconds(5));
        Assert.Equal("web:example.com", book.Preempting(Peer(1, AutoHealth.Ok, T0).Key, T0.AddSeconds(6))?.Key);

        var other = Blocked([.. Fails(Peer, 1), .. Fails((_, h, t) => Site("example.com", h, t), 0)]);
        other.Searching("web:example.com", T0.AddSeconds(5));
        Assert.Null(other.Preempting("web:example.com", T0.AddHours(3)));
    }

    [Fact]
    public void A_waiting_peer_rises_but_never_above_low()
    {
        var book = Blocked([.. Fails(Peer, 1)]);
        var peer = book.Find(Peer(1, AutoHealth.Ok, T0).Key)!;
        Assert.Equal(AutoPriority.Background, AutoPriorities.Effective(peer, T0.AddMinutes(10)));
        Assert.Equal(AutoPriority.Low, AutoPriorities.Effective(peer, T0.AddHours(5)));
    }

    [Fact]
    public void Peers_cannot_take_the_places_kept_for_sites()
    {
        var book = new AutoBook();
        // a torrent client's peers, each failing (suspected and blocked keep them in the book)
        for (int n = 0; n < AutoRules.MaxServices + 50; n++)
            book.Feed(Fails(Peer, n), T0.AddSeconds(3));
        Assert.True(book.Services.Count <= AutoRules.MaxServices - AutoRules.ReservedPlaces);
        book.Feed([Site("example.com", AutoHealth.Failed, T0)], T0.AddSeconds(3));
        Assert.NotNull(book.Find("web:example.com"));
    }

    // ---- the user's word

    [Fact]
    public void A_pinned_strategy_stays_when_its_service_fails()
    {
        var book = Blocked([.. Fails((_, h, t) => Site("example.com", h, t), 0)]);
        book.Applied("web:example.com", AutoCandidates.Tcp[0], 400, T0.AddSeconds(10));
        Assert.True(book.Pin("web:example.com", true));
        book.Feed(Enumerable.Range(20, 3).Select(i => Site("example.com", AutoHealth.Failed, T0.AddSeconds(i))), T0.AddSeconds(30));
        book.Evaluate(T0.AddSeconds(30));
        var s = book.Find("web:example.com")!;
        Assert.Equal(AutoStatus.Applied, s.Status);
        Assert.Equal(AutoCandidates.Tcp[0], s.Strategy);
        // a check the user asked for that fails does not drop it either
        book.CheckNow("web:example.com", T0.AddSeconds(40));
        Assert.Equal(AutoStatus.Degraded, s.Status);
        book.Confirmed("web:example.com", AutoConfirm.Blocked, T0.AddSeconds(41));
        Assert.Equal(AutoStatus.Applied, s.Status);
        Assert.Equal(AutoCandidates.Tcp[0], s.Strategy);
    }

    [Fact]
    public void Check_now_probes_at_once_whatever_the_pause()
    {
        var book = new AutoBook();
        book.Feed(Fails((_, h, t) => Site("example.com", h, t), 0), T0.AddSeconds(3));
        book.Evaluate(T0.AddSeconds(3));
        book.Confirmed("web:example.com", AutoConfirm.NotBlocked, T0.AddSeconds(4));
        Assert.Null(book.NextToConfirm(T0.AddMinutes(5)));
        book.CheckNow("web:example.com", T0.AddMinutes(5));
        Assert.Equal("web:example.com", book.NextToConfirm(T0.AddMinutes(5))!.Key);

        book.Confirmed("web:example.com", AutoConfirm.Blocked, T0.AddMinutes(6));
        book.NotFound("web:example.com", T0.AddMinutes(7));
        book.CheckNow("web:example.com", T0.AddMinutes(8));
        Assert.Equal("web:example.com", book.NextToSearch(T0.AddMinutes(8))!.Key);
    }

    [Fact]
    public void Excluded_traffic_never_enters_the_book_and_leaves_it()
    {
        var book = new AutoBook();
        book.Feed([Site("example.com", AutoHealth.Ok, T0), Site("vpn.example.org", AutoHealth.Ok, T0, ip: "192.0.2.10")], T0);
        Assert.Equal(["vpn.example.org"], book.SetLists(new AutoLists { Excluded = ["192.0.2.0/28"] }));
        Assert.Null(book.Find("web:vpn.example.org"));
        book.Feed([Site("vpn.example.org", AutoHealth.Failed, T0.AddSeconds(1), ip: "192.0.2.10")], T0.AddSeconds(1));
        Assert.Null(book.Find("web:vpn.example.org"));
        Assert.NotNull(book.Find("web:example.com"));
    }

    [Fact]
    public void A_failure_on_a_new_cdn_address_does_not_count_against_the_applied_strategy()
    {
        var book = Blocked([.. Fails((_, h, t) => Site("youtube.com", h, t), 0)]);
        book.Applied("web:youtube.com", AutoCandidates.Tcp[0], 400, T0.AddSeconds(10));
        // three new addresses, each failing once before the rules took it in
        book.Feed(Enumerable.Range(1, 3).Select(i => Site("youtube.com", AutoHealth.Failed, T0.AddSeconds(20 + i), ip: $"203.0.113.{100 + i}")), T0.AddSeconds(30));
        book.Evaluate(T0.AddSeconds(30));
        var s = book.Find("web:youtube.com")!;
        Assert.Equal(AutoStatus.Applied, s.Status);
        Assert.Equal(4, s.Addresses.Count);
    }

    // ---- families and names

    [Fact]
    public void A_family_shares_its_strategy_and_its_domains_get_it_by_name()
    {
        var book = Blocked([.. Fails((_, h, t) => Site("youtube.com", h, t), 0), .. Fails((_, h, t) => Site("googlevideo.com", h, t, ip: "203.0.113.50", host: "rr1---sn-abc.googlevideo.com"), 0)]);
        book.Applied("web:youtube.com", AutoCandidates.XTcp[0], 400, T0.AddSeconds(10));
        var video = book.Find("web:googlevideo.com")!;
        Assert.Equal(AutoCandidates.XTcp[0], book.FamilyStrategy(video));
        Assert.Equal(AutoCandidates.XTcp[0], AutoCandidates.For(video, [], [], family: book.FamilyStrategy(video), ext: true)[0]);

        // googlevideo.com waits for its own search: not given the site's strategy by name meanwhile
        var hosts = AutoPlan.HostProfiles(book.Services);
        var p = Assert.Single(hosts);
        Assert.Equal(AutoCandidates.XTcp[0], p.Strategy);
        Assert.Contains("youtube.com", p.Domains);
        Assert.Contains("ytimg.com", p.Domains);
        Assert.DoesNotContain("googlevideo.com", p.Domains);
        Assert.False(p.Udp);

        // once it is applied too, both are named
        book.Applied("web:googlevideo.com", AutoCandidates.XTcp[0], 400, T0.AddSeconds(20));
        Assert.Contains("googlevideo.com", Assert.Single(AutoPlan.HostProfiles(book.Services)).Domains);
        // the service on trial is left to its address group
        Assert.DoesNotContain("youtube.com", Assert.Single(AutoPlan.HostProfiles(book.Services, "web:youtube.com")).Domains);
    }

    [Fact]
    public void Sites_behind_one_address_with_different_strategies_are_left_to_their_names()
    {
        var book = Blocked([.. Fails((_, h, t) => Site("a.com", h, t, ip: "203.0.113.7"), 0), .. Fails((_, h, t) => Site("b.com", h, t, ip: "203.0.113.7"), 0)]);
        book.Feed([Site("b.com", AutoHealth.Ok, T0.AddSeconds(5), ip: "203.0.113.8")], T0.AddSeconds(5));
        book.Applied("web:a.com", AutoCandidates.Tcp[0], 400, T0.AddSeconds(10));
        book.Applied("web:b.com", AutoCandidates.Tcp[1], 400, T0.AddSeconds(10));
        var byAddress = AutoPlan.Groups(book.Services);
        Assert.Contains(byAddress, g => g.Targets.Any(t => t.Addresses.Contains(IPAddress.Parse("203.0.113.7"))));
        var covered = AutoPlan.ByNameCovers(book.Services, AutoPlan.HostProfiles(book.Services));
        Assert.Equal(["web:a.com", "web:b.com"], covered.Order(StringComparer.Ordinal));
        var byName = AutoPlan.Groups(book.Services, byName: covered);
        Assert.DoesNotContain(byName, g => g.Targets.Any(t => t.Addresses.Contains(IPAddress.Parse("203.0.113.7"))));
        Assert.Contains(byName, g => g.Targets.Any(t => t.Addresses.Contains(IPAddress.Parse("203.0.113.8"))));
        Assert.Equal(2, AutoPlan.HostProfiles(book.Services).Count);
        // a site the names do not cover (no process for it) keeps the address: dropping it would leave it without bypass
        var half = AutoPlan.Groups(book.Services, byName: new HashSet<string>(StringComparer.Ordinal) { "web:a.com" });
        Assert.Contains(half, g => g.Targets.Any(t => t.Addresses.Contains(IPAddress.Parse("203.0.113.7"))));
        Assert.Contains(AutoPlan.Groups(book.Services, byName: new HashSet<string>()), g => g.Targets.Any(t => t.Addresses.Contains(IPAddress.Parse("203.0.113.7"))));
    }

    [Fact]
    public void A_site_keeps_two_browsers_handshakes()
    {
        var book = new AutoBook();
        byte[] small = new byte[300], big1 = new byte[1400], big2 = new byte[400];
        book.Feed([Site("example.com", AutoHealth.Ok, T0) with { Replay = [small] }], T0);
        book.Feed([Site("example.com", AutoHealth.Ok, T0.AddSeconds(1)) with { Replay = [big1, big2] }], T0.AddSeconds(1));
        var s = book.Find("web:example.com")!;
        Assert.Equal(2, s.Replays.Count);
        book.Feed([Site("example.com", AutoHealth.Ok, T0.AddSeconds(2)) with { Replay = [big1, big2] }], T0.AddSeconds(2));
        Assert.Equal(2, s.Replays.Count);
    }

    // ---- zapret2's methods

    [Fact]
    public void Zapret2s_methods_follow_the_classics_only_when_geneva_knows_them()
    {
        var site = Blocked([.. Fails((_, h, t) => Site("example.com", h, t), 0)]).Find("web:example.com")!;
        var plain = AutoCandidates.For(site, [], []);
        Assert.DoesNotContain(plain, GenevaStrategyText.NeedsExt);
        var ext = AutoCandidates.For(site, [], [], ext: true);
        Assert.Equal(plain, ext.Take(plain.Count));
        Assert.Equal(AutoCandidates.XTcp, ext.Skip(plain.Count));
        Assert.All(AutoCandidates.XTcp.Concat(AutoCandidates.XQuic), x => Assert.True(GenevaStrategyText.NeedsExt(x)));
        Assert.All(AutoCandidates.Tcp.Concat(AutoCandidates.Udp).Concat(AutoCandidates.Dns), x => Assert.False(GenevaStrategyText.NeedsExt(x)));
        Assert.True(GenevaStrategyText.NeedsExt(@"[FLOW:n:a]-xwhen{iff=L7:payload:tls_client_hello}(xsplit{pos=2},)-| \/"));
    }

    [Fact]
    public void The_bypass_leaves_the_excluded_alone_with_geneva_2()
    {
        var s = new GenevaRunSettings { Strategy = AutoCandidates.Tcp[0], ExcludeSubnets = ["192.0.2.10/32", "2001:db8::/32"], ExcludeDomains = ["vpn.example.org"] };
        Assert.Empty(s.Problems());
        var argv = GenevaArgv.Run(s, 5000, lists: true);
        Assert.Equal("--ext", argv[1]);
        Assert.Equal("192.0.2.10/32,2001:db8::/32", argv[argv.IndexOf("--ipset-exclude-ip") + 1]);
        Assert.Equal("vpn.example.org", argv[argv.IndexOf("--hostlist-exclude-domains") + 1]);
        // an older geneva: as before, without the extensions
        var old = GenevaArgv.Run(s, 5000);
        Assert.DoesNotContain("--ext", old);
        Assert.DoesNotContain("--ipset-exclude-ip", old);
        Assert.NotEmpty(new GenevaRunSettings { Strategy = AutoCandidates.Tcp[0], ExcludeDomains = ["not a domain"] }.Problems());
        Assert.Contains("--ext", GenevaArgv.Run(new GenevaRunSettings { Strategy = AutoCandidates.XTcp[0] }, 5000));
    }

    [Fact]
    public void A_search_with_zapret2s_methods_runs_with_the_extensions()
    {
        var with = new GenevaSearchSettings { Host = "example.com", Seeds = [AutoCandidates.Tcp[0], AutoCandidates.XTcp[0]] };
        Assert.Equal(["evolve", "--ext"], GenevaArgv.Evolve(with, "c", "d", "s").Take(2));
        Assert.DoesNotContain("--ext", GenevaArgv.Evolve(with with { Seeds = [AutoCandidates.Tcp[0]] }, "c", "d", "s"));
        Assert.Contains("--ext", GenevaArgv.Evolve(with with { Seeds = [], Resume = true, ResumeExt = true }, "c", "d", null));
    }

    [Theory]
    [InlineData("203.0.113.0/24", "203.0.113.77", true)]
    [InlineData("203.0.113.0/25", "203.0.113.200", false)]
    [InlineData("2001:db8::/32", "2001:db8:1::5", true)]
    [InlineData("192.0.2.1", "192.0.2.1", true)]
    public void Name_lists_match_subnets(string entry, string address, bool match) =>
        Assert.Equal(match, new AutoNameList([entry]).MatchesAddress(IPAddress.Parse(address)));

    [Fact]
    public void Name_lists_match_subdomains_and_refuse_garbage()
    {
        var l = new AutoNameList(["example.com", "# comment", ""]);
        Assert.True(l.MatchesName("www.example.com"));
        Assert.True(l.MatchesName("example.com."));
        Assert.False(l.MatchesName("badexample.com"));
        Assert.NotNull(AutoNameList.Problem("not a domain"));
        Assert.NotNull(AutoNameList.Problem("10.0.0.0/33"));
        Assert.Null(AutoNameList.Problem("*.example.com"));
        Assert.Equal("YouTube", AutoFamilies.Of("rr3---sn-4g5e6nsz.googlevideo.com"));
        Assert.Null(AutoFamilies.Of("notyoutube.com"));
    }
}
