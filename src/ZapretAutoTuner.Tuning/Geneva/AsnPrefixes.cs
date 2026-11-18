using System.Globalization;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Core.Providers;

namespace ZapretAutoTuner.Tuning.Geneva;

/// <summary>
/// The networks of the AS numbers in the "Авто" lists (<c>AS12389</c>): their announced prefixes from RIPEstat, the
/// same source the provider catalog reads. Only the number the user typed goes out; the answer is kept in the lists
/// and fetched again after <see cref="MaxAge"/>.
/// </summary>
public static class AsnPrefixes
{
    public static TimeSpan MaxAge { get; } = TimeSpan.FromDays(7);

    /// <summary>
    /// The most networks kept for one AS after merging (the biggest carriers announce a few thousand prefixes, far fewer
    /// once adjacent ones are joined): they are saved with the lists on every change of geneva's state.
    /// </summary>
    public const int MaxPrefixes = 5000;

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    /// <summary>Reads a URL as text, straight (nothing but the AS number goes out).</summary>
    public static Func<string, CancellationToken, Task<string>> DefaultGet { get; } = (url, ct) => Http.GetStringAsync(url, ct);

    /// <summary>Some AS in the lists has no networks yet, or they are older than <see cref="MaxAge"/>.</summary>
    public static bool Stale(AutoLists l, DateTime now) => Named(l).Any(a =>
    {
        var key = a.ToString(CultureInfo.InvariantCulture);
        return !l.AsnPrefixes.ContainsKey(key) || !l.AsnFetched.TryGetValue(key, out var at) || now - at >= MaxAge;
    });

    /// <summary>
    /// The user's edit of the lists made on <paramref name="before"/>, laid over <paramref name="now"/>: entries added
    /// meanwhile elsewhere ("Не подбирать" in a row's menu, MCP) are kept, the networks are those of <paramref name="edited"/>.
    /// </summary>
    public static AutoLists Merge(AutoLists edited, AutoLists before, AutoLists now)
    {
        static List<string> M(IReadOnlyList<string> mine, IReadOnlyList<string> was, IReadOnlyList<string> cur) =>
            [.. mine, .. cur.Where(x => !was.Contains(x, StringComparer.OrdinalIgnoreCase) && !mine.Contains(x, StringComparer.OrdinalIgnoreCase))];
        return edited with
        {
            Important = M(edited.Important, before.Important, now.Important),
            Unimportant = M(edited.Unimportant, before.Unimportant, now.Unimportant),
            Excluded = M(edited.Excluded, before.Excluded, now.Excluded),
            NoSearch = M(edited.NoSearch, before.NoSearch, now.NoSearch),
        };
    }

    public static string Url(int asn) => "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + asn.ToString(CultureInfo.InvariantCulture);

    /// <summary>The AS numbers the lists name that the mode matches by address (all but "не трогать").</summary>
    public static List<int> Named(AutoLists l) => AutoNameList.AsnsOf(l.Important.Concat(l.Unimportant).Concat(l.NoSearch));

    /// <summary>
    /// The lists with the prefixes of every AS they name: missing or older than <see cref="MaxAge"/> are fetched, the
    /// ones no longer named are dropped. An AS that cannot be fetched keeps what it had and is named in the problems.
    /// </summary>
    public static async Task<(AutoLists Lists, List<string> Problems)> RefreshAsync(AutoLists lists, Func<string, CancellationToken, Task<string>> get,
        DateTime now, CancellationToken ct)
    {
        var named = Named(lists);
        var prefixes = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        var fetched = new Dictionary<string, DateTime>(StringComparer.Ordinal);
        var problems = new List<string>();
        var due = new List<(string Key, bool Have, IReadOnlyList<string>? Old)>();
        foreach (var asn in named)
        {
            var key = asn.ToString(CultureInfo.InvariantCulture);
            bool have = lists.AsnPrefixes.TryGetValue(key, out var old);
            if (have && lists.AsnFetched.TryGetValue(key, out var at) && now - at < MaxAge)
            {
                prefixes[key] = old!;
                fetched[key] = at;
                continue;
            }
            due.Add((key, have, old));
        }
        // side by side: one slow answer does not hold the others
        var results = await Task.WhenAll(due.Select(async d =>
        {
            try
            {
                var text = await get(Url(int.Parse(d.Key, CultureInfo.InvariantCulture)), ct).ConfigureAwait(false);
                var list = CidrSet.Aggregate(RangeParsers.Parse("ripestat", text)).Take(MaxPrefixes).Select(c => c.ToString()).ToList();
                if (list.Count == 0)
                    throw new FormatException("пустой список / an empty list");
                return (d.Key, d.Have, d.Old, List: (List<string>?)list, Error: (string?)null);
            }
            catch (Exception e) when (e is HttpRequestException or System.Text.Json.JsonException or FormatException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                return (d.Key, d.Have, d.Old, List: null, Error: e.Message);
            }
        })).ConfigureAwait(false);
        foreach (var r in results)
        {
            if (r.List is { } list)
            {
                prefixes[r.Key] = list;
                fetched[r.Key] = now;
                continue;
            }
            problems.Add($"AS{r.Key}: сети не получены / no networks: {r.Error}");
            if (r.Have)
            {
                prefixes[r.Key] = r.Old!;
                if (lists.AsnFetched.TryGetValue(r.Key, out var at2))
                    fetched[r.Key] = at2;
            }
        }
        return (lists with { AsnPrefixes = prefixes, AsnFetched = fetched }, problems);
    }
}
