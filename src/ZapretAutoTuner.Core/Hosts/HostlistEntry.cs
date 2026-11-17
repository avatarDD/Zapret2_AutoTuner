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
    /// entry counts only for the full name, an exemption ends the search with no match.
    /// </summary>
    public static bool Matches(IEnumerable<string> list, string host)
    {
        var map = new Dictionary<string, HostlistEntry>(StringComparer.Ordinal);
        foreach (var line in list)
        {
            var e = Parse(line.Trim());
            if (e.Domain.Length > 0)
                map.TryAdd(e.Domain, e);
        }
        var p = host.Trim().TrimEnd('.').ToLowerInvariant();
        bool full = true;
        while (p.Length > 0)
        {
            if (map.TryGetValue(p, out var e) && !(e.Strict && !full))
                return !e.Exempt;
            int dot = p.IndexOf('.', StringComparison.Ordinal);
            if (dot < 0)
                break;
            p = p[(dot + 1)..];
            full = false;
        }
        return false;
    }

    /// <summary>Domains the list includes (exemptions and prefixes dropped), for display and target lists.</summary>
    public static IEnumerable<string> Included(IEnumerable<string> list) =>
        list.Select(l => Parse(l.Trim())).Where(e => !e.Exempt && e.Domain.Length > 0).Select(e => e.Domain);
}
