using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>
/// The exchange file of geneva strategies, the same as zapret-gui's (<c>core/geneva_share.py</c>): golden and round-trip
/// tests (AGENTS.md rule 8), the starting set, and how shared strategies become the "Авто" mode's candidates.
/// </summary>
public sealed class GenevaShareTests
{
    private const string Fragment = @"[TCP:flags:PA]-fragment{tcp:-1:False}-| \/";
    private const string Corrupt = @"[UDP:sport:*]-duplicate(tamper{UDP:load:corrupt},)-| \/";

    /// <summary>The screenshot's strategy that bypassed most sites (zapret-gui's "Авто", November 2026).</summary>
    private const string Overlap = @"[TCP:flags:PA]-fragment{tcp:34:True:17}-| \/ [TCP:seq:2285867905:4]-tamper{TCP:options-altchksumopt:replace:}-|";

    private static string TestData(string name) => Path.Combine(RepoPaths.Root, "tests", "testdata", "geneva-share", name);

    [Fact]
    public void A_file_exported_by_zapret_gui_is_read_as_it_is()
    {
        // written by zapret-gui's build_export (core/geneva_share.py) itself
        var (items, errors) = GenevaShare.Parse(File.ReadAllText(TestData("zapret-gui-export.json")));
        Assert.Empty(errors);
        Assert.Equal(2, items.Count);
        Assert.Equal(Overlap, items[0].Strategy);
        Assert.Equal(["youtube.com", "googlevideo.com"], items[0].Services);
        Assert.Equal(389, items[0].Fitness);
        Assert.Equal(Corrupt, items[1].Strategy);
        Assert.Equal(["ytimg.com"], items[1].Services);
    }

    [Fact]
    public void The_export_has_zapret_guis_shape_and_merges_services_by_strategy()
    {
        var json = GenevaShare.Build(
        [
            new GenevaSharedStrategy { Strategy = Overlap, Services = ["youtube.com"], Fitness = 380 },
            new GenevaSharedStrategy { Strategy = Corrupt, Services = ["ytimg.com"] },
            new GenevaSharedStrategy { Strategy = Overlap, Services = ["googlevideo.com", "YouTube.com"], Fitness = 389 },
        ], new DateTimeOffset(2026, 11, 4, 9, 40, 0, TimeSpan.Zero));
        var doc = JsonNode.Parse(json)!.AsObject();
        Assert.Equal(["format", "version", "exported_at", "items"], doc.Select(kv => kv.Key));
        Assert.Equal("zapret-gui/geneva-strategies", (string?)doc["format"]);
        Assert.Equal(1, (int)doc["version"]!);
        Assert.Equal("2026-11-04T09:40:00Z", (string?)doc["exported_at"]);
        var items = doc["items"]!.AsArray();
        Assert.Equal(2, items.Count);
        var first = items[0]!.AsObject();
        Assert.Equal(["strategy", "transport", "services", "fitness"], first.Select(kv => kv.Key));
        Assert.Equal(Overlap, (string?)first["strategy"]);
        Assert.Equal("tcp", (string?)first["transport"]);
        Assert.Equal(["youtube.com", "googlevideo.com"], first["services"]!.AsArray().Select(x => (string?)x));
        Assert.Equal(389, (double)first["fitness"]!);
        Assert.Equal("udp", (string?)items[1]!["transport"]);
        Assert.Null(items[1]!["fitness"]);

        // round trip
        var (back, errors) = GenevaShare.Parse(json);
        Assert.Empty(errors);
        Assert.Equal([Overlap, Corrupt], back.Select(x => x.Strategy));
        Assert.Equal(["youtube.com", "googlevideo.com"], back[0].Services);
    }

    [Fact]
    public void Plain_text_one_strategy_per_line_is_taken_and_bad_lines_are_reported()
    {
        var (items, errors) = GenevaShare.Parse("# from a friend\r\n" + Fragment + "\r\n\r\n" + Fragment + "\nnot a strategy\n" + Corrupt + "\n");
        Assert.Equal([Fragment, Corrupt], items.Select(x => x.Strategy));
        Assert.Single(errors);
        Assert.StartsWith("3:", errors[0], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{"format":"other/thing","items":[]}""", "чужой формат")]
    [InlineData("""{"format":"zapret-gui/geneva-strategies"}""", "нет списка items")]
    [InlineData("""{"items":""", "не JSON")]
    [InlineData("""{"format":7,"items":[]}""", "чужой формат")]
    public void A_wrong_document_is_refused(string text, string why)
    {
        var (items, errors) = GenevaShare.Parse(text);
        Assert.Empty(items);
        Assert.Contains(why, Assert.Single(errors), StringComparison.Ordinal);
    }

    [Fact]
    public void A_fitness_out_of_range_is_dropped_not_thrown()
    {
        var (items, errors) = GenevaShare.Parse("{\"format\":\"zapret-gui/geneva-strategies\",\"items\":[{\"strategy\":\"" + Fragment.Replace("\\", "\\\\", StringComparison.Ordinal) + "\",\"fitness\":1e999}]}");
        Assert.Empty(errors);
        Assert.Null(Assert.Single(items).Fitness);
    }

    [Fact]
    public void Every_workers_ports_are_the_searchs_not_the_users()
    {
        Assert.True(AutoObserver.IsProbePort(GenevaArgv.LocalPortsBase));
        Assert.True(AutoObserver.IsProbePort(GenevaArgv.LocalPortsBase + GenevaArgv.LocalPortsCount * 7 + 63));
        Assert.False(AutoObserver.IsProbePort(GenevaArgv.LocalPortsBase + GenevaArgv.LocalPortsCount * 8));
        Assert.False(AutoObserver.IsProbePort(GenevaArgv.LocalPortsBase - 1));
    }

    [Fact]
    public void Limits_hold_items_services_and_size()
    {
        var many = new JsonArray([.. Enumerable.Range(0, GenevaShare.MaxItems + 5).Select(i => (JsonNode)new JsonObject
        {
            ["strategy"] = $"[TCP:flags:PA]-fragment{{tcp:{i + 1}:True}}-| \\/",
            ["services"] = new JsonArray([.. Enumerable.Range(0, 30).Select(n => (JsonNode)$"s{n}.example")]),
        })]);
        var (items, errors) = GenevaShare.Parse(new JsonObject { ["format"] = GenevaShare.Format, ["items"] = many }.ToJsonString());
        Assert.Equal(GenevaShare.MaxItems, items.Count);
        Assert.All(items, i => Assert.Equal(GenevaShare.MaxServices, i.Services.Count));
        Assert.Contains(errors, e => e.Contains("взяты первые", StringComparison.Ordinal));
        Assert.Contains("КБ", Assert.Single(GenevaShare.Parse(new string('#', GenevaShare.MaxBytes + 1)).Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void The_starting_set_holds_the_screenshots_strategies()
    {
        var preset = GenevaShare.Preset;
        Assert.Equal(4, preset.Count);
        Assert.All(preset, p => Assert.Null(GenevaStrategyText.Problem(p.Strategy)));
        var overlap = Assert.Single(preset, p => p.Strategy == Overlap);
        foreach (var site in new[] { "youtube.com", "googlevideo.com", "discord.com", "x.com", "google.com" })
            Assert.Contains(site, overlap.Services);
        Assert.Contains(preset, p => p.Strategy == Fragment && p.Services.Contains("rutor.info"));
        Assert.Contains(preset, p => p.Strategy == Corrupt && p.Services.Contains("facebook.com"));
        // no addresses of the user's network go out with it
        Assert.DoesNotContain(preset.SelectMany(p => p.Services), n => System.Net.IPAddress.TryParse(n, out _));
    }

    [Theory]
    [InlineData("youtube.com", "", true)]
    [InlineData("youtube.com", "www.youtube.com", true)]
    [InlineData("ytimg.com (QUIC)", "i.ytimg.com", true)]
    [InlineData("STUN stun.l.google.com (74.125.250.129:19302)", "stun.l.google.com", true)]
    [InlineData("notyoutube.com", "", false)]
    [InlineData("google.com", "", false)]
    public void A_shared_strategy_names_its_services_and_their_subdomains(string name, string host, bool expected)
    {
        var shared = new GenevaSharedStrategy { Strategy = Fragment, Services = ["youtube.com", "ytimg.com", "stun.l.google.com"] };
        Assert.Equal(expected, GenevaShare.Names(shared, name, host));
    }

    private static AutoService Site(string name) => new() { Key = "web:" + name, Kind = AutoKind.Web, Transport = L4Kind.Tcp, Name = name };

    [Fact]
    public void The_strategy_shared_for_the_service_is_tried_first_then_the_running_ones()
    {
        var shared = new[]
        {
            new GenevaSharedStrategy { Strategy = Corrupt, Services = ["youtube.com"] }, // UDP: not for TCP
            new GenevaSharedStrategy { Strategy = Overlap, Services = ["youtube.com"] },
            new GenevaSharedStrategy { Strategy = Fragment, Services = ["rutor.info"] },
        };
        var c = AutoCandidates.For(Site("youtube.com"), [AutoCandidates.Tcp[1]], [], shared);
        Assert.Equal([Overlap, AutoCandidates.Tcp[1], Fragment], c.Take(3));
        Assert.DoesNotContain(Corrupt, c);
        Assert.InRange(c.Count, 3, AutoRules.MaxQuickCandidates);
        // without shared ones the order is the one before
        Assert.Equal(AutoCandidates.For(Site("a.com"), [], []), AutoCandidates.For(Site("a.com"), [], [], []));
        Assert.Equal(AutoCandidates.Tcp[0], AutoCandidates.For(Site("a.com"), [], [])[0]);
    }

    [Fact]
    public void A_resolver_tries_its_classics_before_the_strategies_shared_for_sites()
    {
        var dns = new AutoService { Key = "dns:8.8.8.8", Kind = AutoKind.Dns, Transport = L4Kind.Udp, Name = "DNS 8.8.8.8" };
        var c = AutoCandidates.For(dns, [], [], GenevaShare.Preset);
        Assert.Equal(AutoCandidates.Dns, c.Take(AutoCandidates.Dns.Count));
    }

    [Fact]
    public void The_wider_round_adds_the_library_and_tries_more()
    {
        var library = Enumerable.Range(1, 60).Select(i => $"[TCP:flags:PA]-fragment{{tcp:{i}:False}}-| \\/").ToList();
        var c = AutoCandidates.For(Site("a.com"), [], [], GenevaShare.Preset, library, AutoRules.MaxWideCandidates);
        Assert.Equal(AutoRules.MaxWideCandidates, c.Count);
        Assert.Contains(library[0], c);
        Assert.Equal(c.Count, c.Distinct().Count());
        Assert.Equal("TCP,IP", AutoCandidates.Protos(Site("a.com"), wide: true));
        Assert.Equal("TCP", AutoCandidates.Protos(Site("a.com")));
    }

    [Fact]
    public void Workers_go_to_geneva_and_stay_in_range()
    {
        var s = new GenevaSearchSettings { Host = "blocked.example", Workers = 4 };
        var argv = GenevaArgv.Evolve(s, "/x/c", "/x/d", null);
        Assert.Equal("4", argv[argv.IndexOf("--workers") + 1]);
        Assert.Empty(s.Problems());
        Assert.NotEmpty((s with { Workers = 0 }).Problems());
        Assert.NotEmpty((s with { Workers = 9 }).Problems());
        Assert.Equal("1", GenevaArgv.Evolve(new GenevaSearchSettings { Host = "blocked.example" }, "c", "d", null) is var a ? a[a.IndexOf("--workers") + 1] : "");
    }
}
