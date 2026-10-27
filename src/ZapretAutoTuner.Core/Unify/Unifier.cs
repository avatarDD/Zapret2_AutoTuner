using System.Globalization;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Core.Unify;

/// <summary>A strategy for addresses rather than names: a provider (its ranges) or a program's servers.</summary>
/// <param name="Name">The profile and ipset name: a provider id or a program endpoint name.</param>
public sealed record IpResult(string Name, IReadOnlyList<string> Cidrs, L4Kind L4, string Ports, IReadOnlyList<string> L7, Strategy Strategy);

/// <summary>What is known about one strategy on one domain: from the search, the knowledge base or a cross-check.</summary>
public sealed record DomainResult(string Domain, L4Kind L4, Strategy Strategy, Efficiency Efficiency, double Score);

/// <summary>One profile of the unified config: a strategy and the domains it serves.</summary>
public sealed record UnifiedProfile(Strategy Strategy, IReadOnlyList<string> Domains, L4Kind L4, double Score, bool Adaptive = false)
{
    public override string ToString() => $"{L4.ToString().ToLowerInvariant()} [{string.Join(',', Domains)}] {Strategy}";
}

/// <summary>
/// The result of unification (dpi-diagnostics §7): the fewest profiles that cover the domains, narrow ones first, a
/// separate QUIC profile, and the domains nothing works for. <see cref="Adaptive"/> is the <c>circular</c> variant
/// offered when one domain group needs several strategies.
/// </summary>
public sealed record UnifyPlan(IReadOnlyList<UnifiedProfile> Profiles, IReadOnlyList<(string Domain, L4Kind L4)> Uncovered, IReadOnlyList<UnifiedProfile> Adaptive)
{
    /// <summary>One strategy serves every domain of each protocol (blockcheck2 COMMON).</summary>
    public bool Common => Profiles.GroupBy(p => p.L4).All(g => g.Count() == 1);

    public int TcpProfiles => Profiles.Count(p => p.L4 == L4Kind.Tcp);

    public int UdpProfiles => Profiles.Count(p => p.L4 == L4Kind.Udp);
}

/// <summary>Normalisation so that the same strategy written two ways is one candidate (§7.1).</summary>
public static class StrategyNormalizer
{
    /// <summary>
    /// Arguments of each instance in name order (Lua reads them as a table, the order means nothing), duplicates
    /// dropped; the order of the instances and of the filters is kept, it does matter.
    /// </summary>
    public static Strategy Canonical(Strategy s) => new(s.Actions.Select(a => a is LuaDesync { Call: var c }
        ? new LuaDesync(new LuaCall(c.Function, c.Args.DistinctBy(x => x.Name).OrderBy(x => x.Name, StringComparer.Ordinal)))
        : a));

    public static string Key(Strategy s) => Canonical(s).ToString();
}

/// <summary>
/// Unification (PLAN 4.1, dpi-diagnostics §7): normalisation, the intersection first (one strategy for everything),
/// otherwise a greedy weighted set cover where a strategy costs 1 + its score and the cheapest per newly covered
/// domain wins. Pure: cross-checks are done by the caller before the plan (Tuning.UnifyRunner).
/// </summary>
public static class Unifier
{
    public static UnifyPlan Plan(IEnumerable<DomainResult> results, IReadOnlyCollection<string>? domains = null)
    {
        var all = results.ToList();
        var profiles = new List<UnifiedProfile>();
        var uncovered = new List<(string, L4Kind)>();
        var adaptive = new List<UnifiedProfile>();
        foreach (var l4 in new[] { L4Kind.Tcp, L4Kind.Udp })
        {
            var rows = all.Where(r => r.L4 == l4).ToList();
            var targets = (domains is null ? rows.Select(r => r.Domain) : domains.Where(d => rows.Any(r => r.Domain == d)))
                .Select(Norm).Distinct(StringComparer.Ordinal).ToList();
            if (targets.Count == 0)
                continue;
            var cells = Matrix(rows);
            var (chosen, left) = Cover(cells, targets);
            profiles.AddRange(NarrowFirst(chosen).Select(p => new UnifiedProfile(p.Strategy, p.Domains, l4, p.Score)));
            uncovered.AddRange(left.Select(d => (d, l4)));
            if (chosen.Count > 1)
            {
                var group = chosen.SelectMany(p => p.Domains).OrderBy(d => d, StringComparer.Ordinal).ToList();
                var ordered = chosen.OrderByDescending(p => p.Domains.Count).ThenBy(p => p.Score).Select(p => p.Strategy).ToList();
                adaptive.Add(new UnifiedProfile(Circular(ordered), group, l4, chosen.Sum(p => p.Score), Adaptive: true));
            }
        }
        return new UnifyPlan(profiles, uncovered, adaptive);
    }

    private sealed record Candidate(Strategy Strategy, double Score, HashSet<string> Works);

    private sealed record Chosen(Strategy Strategy, double Score, List<string> Domains);

    private static Dictionary<string, Candidate> Matrix(List<DomainResult> rows)
    {
        var d = new Dictionary<string, Candidate>(StringComparer.Ordinal);
        // the latest row for a cell wins: a cross-check overrides history
        var latest = new Dictionary<(string, string), DomainResult>();
        foreach (var r in rows)
            latest[(StrategyNormalizer.Key(r.Strategy), Norm(r.Domain))] = r;
        foreach (var ((key, domain), r) in latest)
        {
            if (!d.TryGetValue(key, out var c))
                d[key] = c = new Candidate(StrategyNormalizer.Canonical(r.Strategy), r.Score, new HashSet<string>(StringComparer.Ordinal));
            if (r.Efficiency.Working)
                c.Works.Add(domain);
        }
        return d;
    }

    /// <summary>
    /// Narrow hostlists first (§7.6): a hostlist matches subdomains too, so a profile holding a subdomain of another
    /// profile's domain must come before it or it is never reached; the rest go by domain count, then score.
    /// </summary>
    private static List<Chosen> NarrowFirst(List<Chosen> chosen)
    {
        var left = chosen.OrderBy(p => p.Domains.Count).ThenBy(p => p.Score).ToList();
        var result = new List<Chosen>();
        while (left.Count > 0)
        {
            // the first profile no other remaining profile must precede
            var next = left.FirstOrDefault(p => !left.Any(o => o != p && Shadows(p, o))) ?? left[0];
            result.Add(next);
            left.Remove(next);
        }
        return result;
    }

    /// <summary>Whether <paramref name="wide"/> would catch a domain of <paramref name="narrow"/> if it came first.</summary>
    private static bool Shadows(Chosen wide, Chosen narrow) =>
        narrow.Domains.Any(n => wide.Domains.Any(w => n.EndsWith("." + w, StringComparison.Ordinal)));

    private static (List<Chosen> Chosen, List<string> Left) Cover(Dictionary<string, Candidate> cells, List<string> targets)
    {
        var candidates = cells.Values.Where(c => c.Works.Count > 0).ToList();
        // §7.2: one strategy that works everywhere, the best by score
        var common = candidates.Where(c => targets.All(c.Works.Contains)).OrderBy(c => c.Score).ThenBy(c => c.Strategy.ToString(), StringComparer.Ordinal).FirstOrDefault();
        if (common is not null)
            return ([new Chosen(common.Strategy, common.Score, [.. targets])], []);

        // §7.3: greedy weighted set cover
        var left = new HashSet<string>(targets, StringComparer.Ordinal);
        var chosen = new List<Chosen>();
        while (left.Count > 0)
        {
            var best = candidates
                .Select(c => (C: c, New: c.Works.Count(left.Contains)))
                .Where(x => x.New > 0)
                .OrderBy(x => (1 + x.C.Score) / x.New)
                .ThenByDescending(x => x.New)
                .ThenBy(x => x.C.Strategy.ToString(), StringComparer.Ordinal)
                .Select(x => x.C)
                .FirstOrDefault();
            if (best is null)
                break;
            var covered = targets.Where(d => left.Contains(d) && best.Works.Contains(d)).ToList();
            left.ExceptWith(covered);
            chosen.Add(new Chosen(best.Strategy, best.Score, covered));
        }
        return (chosen, [.. targets.Where(left.Contains)]);
    }

    /// <summary>
    /// The <c>circular</c> variant (§7.5, nfqws2-lua §5.1): the orchestrator sees the first 34228 bytes out and 5556
    /// in to count failures, and every strategy's instances carry <c>strategy=N</c> from 1 without gaps. Rotation
    /// starts on strategy 1, so the best goes first; there is no <c>final</c>, which would stop the rotation for good
    /// on a strategy that may stop working. Each strategy after the first starts from the engine defaults
    /// (<c>--payload=all --in-range=x --out-range=a</c>) so it does not inherit the previous one's filters.
    /// </summary>
    public static Strategy Circular(IReadOnlyList<Strategy> strategies, int fails = 3)
    {
        if (strategies.Count < 2)
            throw new ArgumentException("circular needs two strategies or more", nameof(strategies));
        var actions = new List<ProfileAction>
        {
            new OutRange("-s34228"),
            new InRange("-s5556"),
            new LuaDesync(new LuaCall("circular", fails == 3 ? [] : [new LuaArg("fails", fails.ToString(CultureInfo.InvariantCulture))])),
            new InRange("x"),
            new OutRange("a"),
        };
        for (int i = 0; i < strategies.Count; i++)
        {
            var n = (i + 1).ToString(CultureInfo.InvariantCulture);
            if (i > 0 && strategies[i - 1].Actions.Any(a => a is not LuaDesync))
                actions.AddRange([new PayloadFilter(["all"]), new InRange("x"), new OutRange("a")]);
            foreach (var a in strategies[i].Actions)
                actions.Add(a is LuaDesync { Call: var c } ? new LuaDesync(c.With("strategy", n)) : a);
        }
        return new Strategy(actions);
    }

    /// <summary>
    /// Whether the config needs <c>--ipcache-hostname</c>: a hostlist profile with a phase-0 technique (oob, syndata,
    /// wssize...) acts before the hostname is known, so it fires only when the name is taken from the ipcache
    /// (nfqws2-lua §10.7). Without it the Validator refuses the config.
    /// </summary>
    public static bool NeedsIpcacheHostname(Solution solution) => solution.Profiles.Any(p =>
        p.HasHostFilter && !p.HasIpFilter && p.Strategy.Calls.Any(c => Catalog.LuaCatalog.Default.Find(c.Function) is { Phase0: true }));

    /// <summary>
    /// The plan as an exportable config: one profile per unified profile with its own hostlist (named after the
    /// profile), ports of the protocol, and the pinned addresses. The "everything else" profile is the exporter's
    /// choice (§7.6, MODE_LIST/ALL/AUTO).
    /// </summary>
    public static Solution ToSolution(UnifyPlan plan, int port = 443, bool adaptive = false)
    {
        var s = new Solution();
        var list = adaptive
            ? [.. plan.Profiles.Where(p => !plan.Adaptive.Any(a => a.L4 == p.L4)), .. plan.Adaptive]
            : plan.Profiles;
        int tcp = 0, udp = 0;
        foreach (var p in list.OrderBy(p => p.L4))
        {
            var name = p.L4 == L4Kind.Udp ? $"quic{++udp}" : $"tcp{++tcp}";
            s.Hostlists[name] = [.. p.Domains];
            var portStr = port.ToString(CultureInfo.InvariantCulture);
            s.Profiles.Add(new Profile
            {
                Name = name,
                TcpPorts = p.L4 == L4Kind.Tcp ? portStr : null,
                UdpPorts = p.L4 == L4Kind.Udp ? portStr : null,
                L7 = [p.L4 == L4Kind.Udp ? "quic" : port == 80 ? "http" : "tls"],
                Hostlists = [new ListRef(name)],
                Strategy = p.Strategy,
            });
        }
        s.Meta.Targets = [.. plan.Profiles.SelectMany(p => p.Domains).Distinct(StringComparer.Ordinal)];
        return s;
    }

    /// <summary>
    /// Appends address-based profiles (PLAN 6.3–6.4): a provider's ranges or a program's servers, each with its own
    /// ipset (aggregated, dpi-diagnostics §4a). They go after the hostlist profiles: a site's own strategy is more
    /// specific than its hoster's. A name already taken by a profile, a hostlist or an ipset gets a suffix
    /// (<c>name-2</c>, <c>name-3</c>…), so nothing in the solution is overwritten.
    /// </summary>
    public static void AddIpProfiles(Solution s, IEnumerable<IpResult> results)
    {
        foreach (var r in results)
        {
            var name = r.Name;
            for (int i = 2; s.Profiles.Any(p => p.Name == name) || s.Ipsets.ContainsKey(name) || s.Hostlists.ContainsKey(name); i++)
                name = $"{r.Name}-{i.ToString(System.Globalization.CultureInfo.InvariantCulture)}";
            s.Ipsets[name] = [.. Providers.CidrSet.Aggregate(r.Cidrs).Select(c => c.ToString())];
            s.Profiles.Add(new Profile
            {
                Name = name,
                TcpPorts = r.L4 == L4Kind.Tcp ? r.Ports : null,
                UdpPorts = r.L4 == L4Kind.Udp ? r.Ports : null,
                L7 = [.. r.L7],
                Ipsets = [new ListRef(name)],
                Strategy = r.Strategy,
            });
            s.Meta.Targets.Add(name);
        }
    }

    private static string Norm(string domain) => domain.Trim().TrimEnd('.').ToLowerInvariant();
}
