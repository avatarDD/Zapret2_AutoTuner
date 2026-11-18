using ZapretAutoTuner.Core.Hosts;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning;

/// <summary>
/// "Защита активна" (PLAN 7.1): the final solution run as one long-lived engine instance, and the edits the repair
/// makes to it (7.3). The solution itself is never changed in place: each edit returns a copy, which the caller
/// hot-swaps in (<see cref="HotSwap"/>).
/// </summary>
public static class Protection
{
    /// <summary>The protection's own queue, apart from the trials' (300), so a repair can probe while it runs.</summary>
    public const int QueueNum = 310;

    /// <summary>
    /// The second protection queue. A hot swap starts the new instance while the old one still holds its queue, and
    /// the Agent refuses a busy queue, so the instances take 310 and 311 in turn.
    /// </summary>
    public const int AltQueueNum = 311;

    /// <summary>The monitor's repair trials: apart from the wizard's (300), so both can run at once.</summary>
    public const int RepairQueueNum = 320;

    /// <summary>The queue the next instance takes after one on <paramref name="current"/>.</summary>
    public static int NextQueue(int current) => current == QueueNum ? AltQueueNum : QueueNum;

    /// <summary>argv and queue for the whole solution; hostlists inline, all addresses (the filter is the hostlist).</summary>
    /// <param name="userLua">Approved user Lua (function → script file, ResourceStore.ApprovedLuaPaths): the scripts the solution calls are loaded.</param>
    public static (List<string> Argv, QueueRule? Queue) Launch(Solution s, string luaDir, int queueNum = QueueNum, IReadOnlyDictionary<string, string>? userLua = null) =>
        ConfigCheck.BuildLaunch(s, [], new AgentTrialOptions
        {
            LuaDir = luaDir,
            QueueNum = queueNum,
            Blobs = s.Blobs.ToDictionary(b => b.Key, b => "0x" + Convert.ToHexString(b.Value), StringComparer.Ordinal),
            UserLua = userLua ?? new Dictionary<string, string>(),
            // the long-lived instance keeps the default priority, so test instances (2000) see packets first
            WinDivertPriority = null,
        });

    /// <summary>Every domain the solution filters by name.</summary>
    public static IReadOnlyList<string> Domains(Solution s) =>
        [.. s.Profiles.SelectMany(p => DomainsOf(s, p)).Distinct(StringComparer.OrdinalIgnoreCase)];

    /// <summary>The strategy that serves a domain: the first profile whose hostlist has it or a parent of it.</summary>
    public static StrategyCandidate? CurrentOf(Solution s, string domain)
    {
        foreach (var p in s.Profiles)
        {
            if (Serves(s, p, domain))
                return new StrategyCandidate(p.Strategy, "current", 0, [], p.L4Kinds.FirstOrDefault());
        }
        return null;
    }

    /// <summary>
    /// The domain taken out of every hostlist; with a strategy, it gets its own profile in front of the others (the
    /// engine takes the first matching profile). A profile left with no hosts is dropped, so it does not start to
    /// catch everything.
    /// </summary>
    public static Solution ReplaceDomain(Solution s, string domain, StrategyCandidate? strategy)
    {
        var copy = Copy(s);
        var ports = s.Profiles.FirstOrDefault(p => Serves(s, p, domain));
        foreach (var list in copy.Hostlists.Values)
            list.RemoveAll(d => IsEntryFor(d, domain));
        foreach (var p in copy.Profiles)
            p.HostlistDomains.RemoveAll(d => IsEntryFor(d, domain));
        copy.Profiles.RemoveAll(p => WasByName(s, p.Name) && !DomainsOf(copy, p).Any());
        if (strategy is not null)
        {
            var udp = strategy.L4 == L4Kind.Udp;
            copy.Profiles.Insert(0, new Profile
            {
                Name = "fix-" + domain.Replace('.', '-'),
                TcpPorts = udp ? null : ports?.TcpPorts ?? "80,443",
                UdpPorts = udp ? ports?.UdpPorts ?? "443" : null,
                L7 = [.. ports?.L7 ?? []],
                HostlistDomains = [domain],
                Strategy = strategy.Strategy,
            });
        }
        copy.Meta.Targets = [.. Domains(copy)];
        return copy;
    }

    /// <summary>The profile filtered only by names we hold (no external list files, no autohostlist).</summary>
    private static bool WasByName(Solution s, string name) =>
        s.Profiles.FirstOrDefault(o => o.Name == name) is { } p && DomainsOf(s, p).Any() && p.HostlistAuto is null
        && p.Hostlists.All(l => s.Hostlists.ContainsKey(l.Name));

    /// <summary>Included domains of the profile's lists; <c>^</c>/<c>!</c> prefixes dropped, exemptions left out.</summary>
    private static IEnumerable<string> DomainsOf(Solution s, Profile p) => ListsOf(s, p).SelectMany(HostlistEntry.Included);

    /// <summary>The profile's include lists, each matched on its own like the engine does.</summary>
    private static IEnumerable<IReadOnlyList<string>> ListsOf(Solution s, Profile p) =>
        new[] { (IReadOnlyList<string>)p.HostlistDomains }.Concat(p.Hostlists.Select(l => s.Hostlists.TryGetValue(l.Name, out var d) ? (IReadOnlyList<string>)d : []));

    /// <summary>Does the profile's hostlist filter take <paramref name="domain"/> (nfqws2 1.0.7 rules, <c>^</c> and <c>!</c>)?</summary>
    private static bool Serves(Solution s, Profile p, string domain) => ListsOf(s, p).Any(l => HostlistEntry.Matches(l, domain));

    /// <summary>An include entry (plain or <c>^</c>) for exactly this domain; exemptions stay.</summary>
    private static bool IsEntryFor(string entry, string domain) =>
        HostlistEntry.Parse(entry.Trim()) is { Exempt: false } e && string.Equals(e.Domain, domain, StringComparison.OrdinalIgnoreCase);

    private static Solution Copy(Solution s) => new()
    {
        Profiles = [.. s.Profiles.Select(p => p.Clone())],
        Hostlists = new(s.Hostlists.ToDictionary(kv => kv.Key, kv => kv.Value.ToList()), StringComparer.Ordinal),
        Ipsets = new(s.Ipsets.ToDictionary(kv => kv.Key, kv => kv.Value.ToList()), StringComparer.Ordinal),
        Blobs = new(s.Blobs, StringComparer.Ordinal),
        LuaFiles = new(s.LuaFiles, StringComparer.Ordinal),
        HostPins = [.. s.HostPins],
        Meta = new()
        {
            Created = s.Meta.Created,
            TestedProfiles = [.. s.Meta.TestedProfiles],
            Targets = [.. s.Meta.Targets],
            ReportRef = s.Meta.ReportRef,
            Title = s.Meta.Title,
        },
    };
}
