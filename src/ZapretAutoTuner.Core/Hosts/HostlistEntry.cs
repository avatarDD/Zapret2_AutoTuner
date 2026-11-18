namespace ZapretAutoTuner.Core.Hosts;

/// <summary>
/// One hostlist line as nfqws2 reads it (nfq2/hostlist.c, zapret2 1.0.7): any mix of the prefixes <c>^</c> (no
/// subdomains) and <c>!</c> (local exemption: the name and its subdomains are not part of this list), then the domain.
/// </summary>
public readonly record struct HostlistEntry(string Domain, bool Strict, bool Exempt)
{
    /// <summary>Splits the prefixes off; the domain is lower-cased like the engine does.</summary>
    public static HostlistEntry Parse(string line)
    {
        bool strict = false, exempt = false;
        int i = 0;
        for (; i < line.Length && line[i] is '^' or '!'; i++)
        {
            if (line[i] == '^')
                strict = true;
            else
                exempt = true;
        }
        return new HostlistEntry(line[i..].ToLowerInvariant(), strict, exempt);
    }

    /// <summary>The canonical form: <c>!</c> before <c>^</c>, as zapret-gui writes it.</summary>
    public override string ToString() => (Exempt ? "!" : "") + (Strict ? "^" : "") + Domain;

    /// <summary>
    /// Does one list match <paramref name="host"/>? The engine's <c>SearchHostList</c>: walk from the full name to
    /// the top-level domain; the first entry for a suffix wins (a duplicate later in the list is ignored), a strict
    /// entry counts only for the full name, an exemption ends the search with no match. One pass over the list and
    /// no copy of it: only entries for the host's own suffixes are looked at.
    /// </summary>
    public static bool Matches(IEnumerable<string> list, string host)
    {
        var name = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (name.Length == 0)
            return false;
        // the host's suffixes, full name first: www.youtube.com, youtube.com, com
        var suffixes = new List<string> { name };
        for (int dot = name.IndexOf('.', StringComparison.Ordinal); dot >= 0; dot = name.IndexOf('.', dot + 1))
            suffixes.Add(name[(dot + 1)..]);
        var found = new HostlistEntry?[suffixes.Count];
        foreach (var line in list)
        {
            var t = line.AsSpan().Trim();
            int i = 0;
            while (i < t.Length && t[i] is '^' or '!')
                i++;
            var domain = t[i..];
            for (int k = 0; k < suffixes.Count; k++)
            {
                if (found[k] is null && domain.Equals(suffixes[k], StringComparison.OrdinalIgnoreCase))
                {
                    found[k] = Parse(t.ToString());
                    break;
                }
            }
        }
        for (int k = 0; k < suffixes.Count; k++)
        {
            if (found[k] is { } e && !(e.Strict && k > 0))
                return !e.Exempt;
        }
        return false;
    }

    /// <summary>
    /// Several lists of one profile as one static list (<c>--hostlist-domains</c>) that matches what the lists match
    /// together. A list matches by itself (an exemption is local to it), so an exemption that another list
    /// covers whole — the name and, for a non-strict one, the names under it — is dropped, and one whose names under
    /// it another list covers keeps only the name (<c>!^</c>); of two includes for one name the
    /// one without <c>^</c> stays, since it matches more. Without exemptions this is a plain ordered union.
    /// </summary>
    public static List<string> Merge(IReadOnlyList<IReadOnlyList<string>> lists)
    {
        var order = new List<string>();
        var merged = new Dictionary<string, HostlistEntry>(StringComparer.Ordinal);
        for (int i = 0; i < lists.Count; i++)
        {
            var own = new HashSet<string>(StringComparer.Ordinal);
            foreach (var line in lists[i])
            {
                var e = Parse(line.Trim());
                // the engine keeps the first entry of a name within one list
                if (e.Domain.Length == 0 || !own.Add(e.Domain))
                    continue;
                if (e.Exempt)
                {
                    // what the exemption leaves out, another list may take: the name, and for a non-strict one the
                    // names under it. All of it: the exemption goes. Only the names under it: it keeps the name alone
                    // (strict). Only the name or nothing: it stays, else a wider include would bring the names under
                    // it back (a list that takes only the name itself loses it then: one entry per name). "*." is no
                    // name a list can hold: it stands for any name below.
                    int self = i;
                    var others = lists.Where((_, j) => j != self).ToList();
                    bool name = others.Any(l => Matches(l, e.Domain));
                    bool below = !e.Strict && others.Any(l => Matches(l, "*." + e.Domain));
                    if (name && (e.Strict || below))
                        continue;
                    if (below)
                        e = new HostlistEntry(e.Domain, Strict: true, Exempt: true);
                }
                if (!merged.TryGetValue(e.Domain, out var cur))
                {
                    merged[e.Domain] = e;
                    order.Add(e.Domain);
                }
                else if (!e.Exempt && !cur.Exempt && cur.Strict && !e.Strict)
                    merged[e.Domain] = e;
                else if (e.Exempt && cur.Exempt && cur.Strict && !e.Strict)
                    merged[e.Domain] = e;
            }
        }
        return [.. order.Select(d => merged[d].ToString())];
    }

    /// <summary>Domains the list includes (exemptions and prefixes dropped), for display and target lists.</summary>
    public static IEnumerable<string> Included(IEnumerable<string> list) =>
        list.Select(l => Parse(l.Trim())).Where(e => !e.Exempt && e.Domain.Length > 0).Select(e => e.Domain);
}
