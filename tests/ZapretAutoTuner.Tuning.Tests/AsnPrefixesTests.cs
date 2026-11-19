using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Tuning.Geneva;

namespace ZapretAutoTuner.Tuning.Tests;

public sealed class AsnPrefixesTests
{
    private static readonly DateTime Now = new(2026, 11, 18, 12, 0, 0, DateTimeKind.Utc);

    private const string Ripe = """{"data":{"prefixes":[{"prefix":"95.165.0.0/16"},{"prefix":"2a02:2698::/32"},{"prefix":"bad"}]}}""";

    [Fact]
    public async Task The_networks_of_a_named_AS_are_fetched_kept_and_dropped_when_it_goes()
    {
        var asked = new List<string>();
        Task<string> Get(string url, CancellationToken ct)
        {
            asked.Add(url);
            return Task.FromResult(Ripe);
        }
        var (lists, problems) = await AsnPrefixes.RefreshAsync(new AutoLists { NoSearch = ["*.ru", "AS12389"] }, Get, Now, default);
        Assert.Empty(problems);
        Assert.Equal(["https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS12389"], asked);
        Assert.Equal(["95.165.0.0/16", "2a02:2698::/32"], lists.AsnPrefixes["12389"]);
        Assert.False(AsnPrefixes.Stale(lists, Now.AddDays(6)));
        Assert.True(AsnPrefixes.Stale(lists, Now.AddDays(7)));
        Assert.Equal(Now, lists.AsnFetched["12389"]);

        // fresh: not asked again; a week later: asked again
        await AsnPrefixes.RefreshAsync(lists, Get, Now.AddDays(1), default);
        Assert.Single(asked);
        await AsnPrefixes.RefreshAsync(lists, Get, Now.AddDays(8), default);
        Assert.Equal(2, asked.Count);

        // the AS left the lists: its networks go
        var (gone, _) = await AsnPrefixes.RefreshAsync(lists with { NoSearch = ["*.ru"] }, Get, Now, default);
        Assert.Empty(gone.AsnPrefixes);
        // "не трогать" never takes an AS: nothing is fetched for it
        Assert.Empty(AsnPrefixes.Named(new AutoLists { Excluded = ["AS1"] }));
    }

    [Fact]
    public async Task An_AS_that_cannot_be_fetched_keeps_what_it_had_and_says_so()
    {
        var old = new AutoLists
        {
            Important = ["AS12389"],
            AsnPrefixes = new Dictionary<string, IReadOnlyList<string>> { ["12389"] = ["95.165.0.0/16"] },
            AsnFetched = new Dictionary<string, DateTime> { ["12389"] = Now.AddDays(-30) },
        };
        var (lists, problems) = await AsnPrefixes.RefreshAsync(old, (_, _) => throw new HttpRequestException("offline"), Now, default);
        Assert.Contains(problems, p => p.Contains("AS12389", StringComparison.Ordinal));
        Assert.Equal(["95.165.0.0/16"], lists.AsnPrefixes["12389"]);
    }

    [Fact]
    public void The_lists_with_their_networks_survive_a_save()
    {
        var state = new GenevaState
        {
            Lists = new AutoLists
            {
                NoSearch = ["*.ru", "AS12389"],
                AsnPrefixes = new Dictionary<string, IReadOnlyList<string>> { ["12389"] = ["95.165.0.0/16"] },
                AsnFetched = new Dictionary<string, DateTime> { ["12389"] = Now },
            },
            Auto = new GenevaAutoState { Services = [new AutoService { Key = "web:a.com", BaselineAt = Now }] },
        };
        var back = GenevaState.Parse(state.Serialize());
        Assert.Equal(["*.ru", "AS12389"], back.Lists.NoSearch);
        Assert.Equal(["95.165.0.0/16"], back.Lists.AsnPrefixes["12389"]);
        Assert.Equal(Now, back.Lists.AsnFetched["12389"]);
        Assert.Equal(Now, back.Auto.Services.Single().BaselineAt);
        // a state saved by the previous version (no such fields) still loads
        Assert.Empty(GenevaState.Parse("""{"lists":{"important":["a.com"]}}""").Lists.NoSearch);
    }

    [Fact]
    public void A_save_keeps_what_was_added_elsewhere_while_the_networks_loaded()
    {
        var before = new AutoLists { NoSearch = ["*.ru"], Important = ["a.com"] };
        var edited = before with { NoSearch = ["*.ru", "AS12389"], Important = [] };
        // meanwhile a row's "Не подбирать" added a site
        var now = before with { NoSearch = ["*.ru", "bank.example"] };
        var merged = AsnPrefixes.Merge(edited, before, now);
        Assert.Equal(["*.ru", "AS12389", "bank.example"], merged.NoSearch);
        // what the user removed stays removed
        Assert.Empty(merged.Important);
    }
}
