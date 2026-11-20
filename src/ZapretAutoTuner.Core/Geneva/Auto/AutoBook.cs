using System.Globalization;
using System.Net;
using System.Text.Json.Serialization;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Geneva.Auto;

/// <summary>An address a service was seen at, and when (old ones leave the firewall set).</summary>
public sealed record AutoAddress(string Ip, DateTime Seen);

/// <summary>One service of the "Авто" mode with what is known about it; saved as it changes.</summary>
public sealed class AutoService
{
    public string Key { get; set; } = "";

    public AutoKind Kind { get; set; }

    public L4Kind Transport { get; set; }

    public string Name { get; set; } = "";

    /// <summary>The last full name seen (www.example.com for the site example.com): what the probe loads.</summary>
    public string Host { get; set; } = "";

    public string App { get; set; } = "";

    public List<AutoAddress> Addresses { get; set; } = [];

    /// <summary>Server ports seen (at most 8).</summary>
    public List<int> Ports { get; set; } = [];

    /// <summary><see cref="AutoKind.LocalPort"/>: the program's port.</summary>
    public int LocalPort { get; set; }

    /// <summary>The client's first packets (base64, comma-separated) for a replay probe; empty when it cannot judge.</summary>
    public string Replay { get; set; } = "";

    /// <summary>
    /// A site's success criterion learned without a bypass (<c>PageCheck</c>): the speed behind a shaper, 128 KB with
    /// padding behind the 16 KB cut-off. Null: the plain full download.
    /// </summary>
    public Diagnostics.ProbeCriteria? Criteria { get; set; }

    public AutoStatus Status { get; set; }

    public DateTime Since { get; set; }

    /// <summary>The last reason shown in the list, in Russian.</summary>
    public string Why { get; set; } = "";

    public string? Strategy { get; set; }

    public double Fitness { get; set; }

    public DateTime? AppliedAt { get; set; }

    public DateTime FirstSeen { get; set; }

    public DateTime LastSeen { get; set; }

    public List<DateTime> Fails { get; set; } = [];

    public List<DateTime> Oks { get; set; } = [];

    public List<DateTime> NoConnections { get; set; } = [];

    /// <summary>
    /// When geneva's detector (<c>--ext-auto observe</c>) held the service's name or address impaired with a class the
    /// slices cannot see (a shaper, a freeze): enough to suspect it even though its flows look fine.
    /// </summary>
    public List<DateTime> Detected { get; set; } = [];

    /// <summary>The detector's class of the last <see cref="Detected"/>, in words.</summary>
    public string DetectedWhy { get; set; } = "";

    /// <summary>When a paused service is looked at again (not blocked, address block, nothing found).</summary>
    public DateTime? NextCheck { get; set; }

    /// <summary>
    /// When the probe without a bypass last said "blocked". A search that starts long after it looks again first: a
    /// site that opens by now is not searched (a known strategy would pass on it and be applied for nothing).
    /// </summary>
    public DateTime? BaselineAt { get; set; }

    /// <summary>Searches that found nothing in a row: the pause before the next one doubles.</summary>
    public int Attempts { get; set; }

    /// <summary>Slices in a row that found it suspicious: a service no probe can judge is blocked after two.</summary>
    public int Suspicions { get; set; }

    [JsonIgnore]
    public bool CanReplay => Replay.Length > 0;

    /// <summary>The probe without a bypass can judge it: a page load (web) or a replay; else only its own traffic can.</summary>
    [JsonIgnore]
    public bool Probeable => Kind == AutoKind.Web || CanReplay;

    /// <summary>The site's own browser handshakes: what a trial replays besides the page load.</summary>
    [JsonIgnore]
    public IReadOnlyList<string> Replays => Kind == AutoKind.Web
        ? [.. new[] { Replay, ReplayAlt }.Where(r => r.Length > 0).Distinct(StringComparer.Ordinal)]
        : [];

    [JsonIgnore]
    public int Port => Ports.Count > 0 ? Ports[0] : Kind switch
    {
        AutoKind.Web or AutoKind.Quic => 443,
        AutoKind.Dns => 53,
        _ => 0,
    };

    /// <summary>
    /// A browser's ClientHello of the site seen before <see cref="Replay"/> (another browser, another size): a strategy
    /// must get both through, else it works for one browser and breaks the other.
    /// </summary>
    public string ReplayAlt { get; set; } = "";

    /// <summary>The user's word: important or not important; none — the program decides.</summary>
    public AutoUserPriority UserPriority { get; set; }

    /// <summary>The user pinned the strategy: failures never make the mode look for another one.</summary>
    public bool Pinned { get; set; }

    /// <summary>The log already said that the pinned strategy fails (once per pin and run of the program).</summary>
    [JsonIgnore]
    public bool PinnedWarned { get; set; }

    /// <summary>The importance as last computed (<see cref="AutoPriorities"/>): shown on the page and in MCP.</summary>
    public AutoPriority Priority { get; set; } = AutoPriority.Normal;

    /// <summary>The newest address: where the probes go.</summary>
    [JsonIgnore]
    public IPAddress? Address => Addresses.OrderByDescending(a => a.Seen).Select(a => IPAddress.TryParse(a.Ip, out var ip) ? ip : null).FirstOrDefault(a => a is not null);

    /// <summary>
    /// Its strategy is on. Not while it is searched: the search's probes go to the same addresses, and two strategies
    /// on one packet would judge neither.
    /// </summary>
    [JsonIgnore]
    public bool IsActive => Status is AutoStatus.Applied or AutoStatus.Degraded && Strategy is not null;

    public AutoService Clone()
    {
        var c = (AutoService)MemberwiseClone();
        c.Addresses = [.. Addresses];
        c.Ports = [.. Ports];
        c.Fails = [.. Fails];
        c.Oks = [.. Oks];
        c.NoConnections = [.. NoConnections];
        c.Detected = [.. Detected];
        return c;
    }
}

/// <summary>What the probe without a bypass said about a suspected service.</summary>
public enum AutoConfirm
{
    Blocked,
    NotBlocked,
    IpBlocked,

    /// <summary>No probe can judge it (WireGuard, DHT): its own traffic decides.</summary>
    Unknown,
}

/// <summary>
/// The services of the "Авто" mode and their transitions (skill <c>geneva</c>, §9). Pure: the time comes from the
/// caller, so the rules are tested without waiting. Not thread-safe; the owner locks.
/// </summary>
public sealed class AutoBook
{
    private readonly Dictionary<string, AutoService> _services = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTime> _dnsPoisoned = new(StringComparer.Ordinal);

    /// <summary>
    /// The sites the running name-based process covers (<see cref="AutoPlan.ByNameCovers"/>, set after each apply): its
    /// strategy reaches them on any address, so a failure on a new one counts against the strategy.
    /// </summary>
    public IReadOnlySet<string> ByName { get; set; } = new HashSet<string>();
    private AutoLists _lists = new();
    private AutoNameList _important = AutoNameList.Empty;
    private AutoNameList _unimportant = AutoNameList.Empty;
    private AutoNameList _excluded = AutoNameList.Empty;
    private AutoNameList _noSearch = AutoNameList.Empty;

    public AutoBook(IEnumerable<AutoService>? saved = null)
    {
        // copies: the saved ones belong to the controller's state, which serializes them under its own lock
        foreach (var s in (saved ?? []).Select(x => x.Clone()))
        {
            if (s.Key.Length == 0)
                continue;
            // a book saved by an older version may hold the first packets of a protocol that is no longer replayed
            if (!AutoObserver.ReplayableApps.Contains(s.App))
                s.Replay = "";
            // a search does not survive the process: saved as searching means the power went off or the program was
            // killed in the middle of it. Nothing picks a searching service up (NextToSearch takes blocked ones), so it
            // would stay "в подборе" for good; it waits for its search again, as after Interrupted.
            if (s.Status == AutoStatus.Searching)
            {
                s.Status = AutoStatus.Blocked;
                s.Why = "подбор прерван, продолжу";
            }
            _services[s.Key] = s;
        }
    }

    public IReadOnlyCollection<AutoService> Services => _services.Values;

    /// <summary>The user's lists (important, unimportant, never touched).</summary>
    public AutoLists Lists => _lists;

    /// <summary>The traffic no bypass may touch: a VPN or proxy server, whatever the user named.</summary>
    public AutoNameList Excluded => _excluded;

    /// <summary>
    /// Takes the user's lists: priorities are computed again, and services the exclusions now name leave the book (their
    /// strategies are no longer applied). Returns the names that left.
    /// </summary>
    public List<string> SetLists(AutoLists lists) => SetLists(lists, out _);

    /// <summary>
    /// <see cref="SetLists(AutoLists)"/>; <paramref name="skipped"/> gets the services that left because they are not to
    /// be searched for (a service with a strategy applied stays: it already works).
    /// </summary>
    public List<string> SetLists(AutoLists lists, out List<string> skipped)
    {
        _lists = lists;
        _important = new AutoNameList(lists.Important, lists.AsnPrefixes);
        _unimportant = new AutoNameList(lists.Unimportant, lists.AsnPrefixes);
        _excluded = AutoNameList.Exclusions(lists.Excluded);
        _noSearch = new AutoNameList(lists.NoSearch, lists.AsnPrefixes);
        var gone = new List<string>();
        skipped = [];
        foreach (var s in _services.Values.ToList())
        {
            if (_excluded.Matches(s))
            {
                _services.Remove(s.Key);
                gone.Add(s.Name);
                continue;
            }
            if (!s.IsActive && s.Status != AutoStatus.Searching && _noSearch.Matches(s))
            {
                _services.Remove(s.Key);
                skipped.Add(s.Name);
                continue;
            }
            s.Priority = AutoPriorities.Base(s, _important, _unimportant, _lists.KnownImportant);
        }
        return gone;
    }

    /// <summary>The user does not want a bypass searched for this service (<see cref="AutoLists.NoSearch"/>).</summary>
    public bool NotSearched(AutoService s) => _noSearch.Matches(s);

    public AutoService? Find(string key) => _services.GetValueOrDefault(key);

    public List<AutoService> Snapshot() => [.. _services.Values.Select(s => s.Clone()).OrderBy(s => Order(s.Status)).ThenBy(s => s.Name, StringComparer.Ordinal)];

    private static int Order(AutoStatus s) => s switch
    {
        AutoStatus.Searching => 0,
        AutoStatus.Degraded => 1,
        AutoStatus.Applied => 2,
        AutoStatus.Blocked => 3,
        AutoStatus.Suspected => 4,
        AutoStatus.NotFound => 5,
        AutoStatus.IpBlocked => 6,
        AutoStatus.Fallback => 7,
        AutoStatus.NotBlocked => 8,
        _ => 9,
    };

    /// <summary>Adds a slice's samples. A service seen for the first time starts as <see cref="AutoStatus.Watching"/>.</summary>
    public void Feed(IEnumerable<AutoSample> samples, DateTime now)
    {
        foreach (var x in samples)
        {
            if (_excluded.Matches(x))
                continue;
            if (!_services.TryGetValue(x.Key, out var s))
            {
                // not to be searched for: it does not even become a problem on the page
                if (_noSearch.Matches(x))
                    continue;
                var fresh = new AutoService { Key = x.Key, Kind = x.Kind, Transport = x.Transport, Name = x.Name, App = x.App, Host = x.Host ?? "" };
                fresh.Ports.Add(x.Server.Port);
                var priority = AutoPriorities.Base(fresh, _important, _unimportant, _lists.KnownImportant);
                if (!MakeRoom(priority))
                    continue;
                s = new AutoService
                {
                    Key = x.Key,
                    Kind = x.Kind,
                    Transport = x.Transport,
                    Name = x.Name,
                    App = x.App,
                    Status = AutoStatus.Watching,
                    Since = now,
                    FirstSeen = x.Time,
                    LocalPort = x.Kind == AutoKind.LocalPort ? x.LocalPort : 0,
                    Priority = priority,
                };
                _services[x.Key] = s;
            }
            // an address the applied strategy did not cover yet (a new CDN host): this flow went without the bypass,
            // and its failure says nothing about the strategy; the address joins the set now
            bool uncovered = s.IsActive && x.Kind != AutoKind.LocalPort && !ByName.Contains(s.Key)
                && !s.Addresses.Any(a => a.Ip == Norm(x.Server.Address));
            s.LastSeen = x.Time > s.LastSeen ? x.Time : s.LastSeen;
            if (!string.IsNullOrEmpty(x.Host))
                s.Host = x.Host;
            if (x.Kind != AutoKind.LocalPort)
            {
                AddAddress(s, x.Server.Address, x.Time);
                if (!s.Ports.Contains(x.Server.Port) && s.Ports.Count < 8)
                    s.Ports.Add(x.Server.Port);
            }
            if (x.Replay.Count > 0)
                KeepReplay(s, AutoObserver.ToBase64(x.Replay));
            if (uncovered && x.Health != AutoHealth.Ok)
            {
                Trim(s, now);
                continue;
            }
            switch (x.Health)
            {
                case AutoHealth.Ok:
                    s.Oks.Add(x.Time);
                    break;
                case AutoHealth.Failed:
                    s.Fails.Add(x.Time);
                    s.Why = x.Why;
                    break;
                case AutoHealth.NoConnection:
                    s.NoConnections.Add(x.Time);
                    s.Why = x.Why;
                    break;
            }
            Trim(s, now);
        }
    }

    private static string Norm(IPAddress a) => (a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a).ToString();

    /// <summary>
    /// The site's handshake for the trial's replay. A site keeps two: the newest and one of another size (another
    /// browser: Chrome's ClientHello with ML-KEM takes two packets, an older client's one); both must get through.
    /// </summary>
    private static void KeepReplay(AutoService s, string replay)
    {
        if (s.Kind != AutoKind.Web || s.Replay.Length == 0 || s.Replay == replay)
        {
            s.Replay = replay;
            return;
        }
        if (Size(s.Replay) != Size(replay) || Count(s.Replay) != Count(replay))
            s.ReplayAlt = s.Replay;
        s.Replay = replay;
        if (s.ReplayAlt.Length > 0 && Size(s.ReplayAlt) == Size(s.Replay) && Count(s.ReplayAlt) == Count(s.Replay))
            s.ReplayAlt = "";

        static int Count(string r) => r.Split(',').Length;
        static int Size(string r) => AutoObserver.FromBase64(r).Sum(p => p.Length) / 64;
    }

    private static void AddAddress(AutoService s, IPAddress a, DateTime seen)
    {
        var ip = Norm(a);
        int i = s.Addresses.FindIndex(x => x.Ip == ip);
        if (i >= 0)
            s.Addresses[i] = s.Addresses[i] with { Seen = seen > s.Addresses[i].Seen ? seen : s.Addresses[i].Seen };
        else
            s.Addresses.Add(new AutoAddress(ip, seen));
        if (s.Addresses.Count > AutoRules.MaxAddresses)
            s.Addresses = [.. s.Addresses.OrderByDescending(x => x.Seen).Take(AutoRules.MaxAddresses)];
    }

    private static void Trim(AutoService s, DateTime now)
    {
        var from = now - AutoRules.Window;
        foreach (var list in new[] { s.Fails, s.Oks, s.NoConnections, s.Detected })
        {
            list.RemoveAll(t => t < from);
            if (list.Count > 200)
                list.RemoveRange(0, list.Count - 200);
        }
    }

    /// <summary>
    /// Makes a place for a new service of <paramref name="priority"/>: a full book drops the least important service it
    /// may drop (background first, then the oldest), and peers never take the places kept for sites
    /// (<see cref="AutoRules.ReservedPlaces"/>). False when there is no place.
    /// </summary>
    private bool MakeRoom(AutoPriority priority)
    {
        bool minor = priority >= AutoPriority.Low;
        int minors = _services.Values.Count(s => s.Priority >= AutoPriority.Low);
        bool full = _services.Count >= AutoRules.MaxServices;
        bool minorsFull = minor && minors >= AutoRules.MaxServices - AutoRules.ReservedPlaces;
        if (!full && !minorsFull)
            return true;
        // a peer makes room among peers only; a site may push out anything that is not worked on
        var victim = _services.Values
            .Where(s => Evictable(s) && (!minorsFull || s.Priority >= AutoPriority.Low) && s.Priority >= priority)
            .OrderByDescending(s => s.Priority)
            .ThenBy(s => s.LastSeen)
            .FirstOrDefault();
        return victim is not null && _services.Remove(victim.Key);
    }

    /// <summary>
    /// Nothing is done for it: watched, open, behind an address block, a QUIC fallback. A background service waiting
    /// for its probe or search may go too: a peer that comes back is seen again.
    /// </summary>
    private static bool Evictable(AutoService s) =>
        s.Status is AutoStatus.Watching or AutoStatus.NotBlocked or AutoStatus.Fallback or AutoStatus.IpBlocked
        || (s.Priority == AutoPriority.Background && s.Status is AutoStatus.Suspected or AutoStatus.Blocked or AutoStatus.NotFound);

    /// <summary>
    /// Moves services by what the window holds: suspicion, a QUIC fallback, a pause that ended, an applied strategy that
    /// stopped working. Returns the lines for the log.
    /// </summary>
    public List<string> Evaluate(DateTime now)
    {
        var log = new List<string>();
        foreach (var s in _services.Values.ToList())
        {
            Trim(s, now);
            if (s.Status != AutoStatus.Applied && s.Status != AutoStatus.Degraded && now - s.LastSeen > AutoRules.Forget)
            {
                _services.Remove(s.Key);
                continue;
            }
            s.Addresses.RemoveAll(a => now - a.Seen > AutoRules.AddressLife && s.Addresses.Count > 1);
            s.Priority = AutoPriorities.Base(s, _important, _unimportant, _lists.KnownImportant);
            bool suspicious = Suspicious(s, out var why);
            switch (s.Status)
            {
                case AutoStatus.Watching:
                case AutoStatus.Fallback:
                case AutoStatus.NotBlocked when s.NextCheck is null || now >= s.NextCheck:
                case AutoStatus.IpBlocked when s.NextCheck is null || now >= s.NextCheck:
                    if (!suspicious)
                    {
                        if (s.Status is AutoStatus.NotBlocked or AutoStatus.IpBlocked)
                            Move(s, AutoStatus.Watching, now, "");
                        s.Suspicions = 0;
                        break;
                    }
                    if (s.Kind == AutoKind.Quic && TcpWorks(s))
                    {
                        if (s.Status != AutoStatus.Fallback)
                            log.Add($"{s.Name}: QUIC не проходит, браузер открывает сайт по TCP");
                        Move(s, AutoStatus.Fallback, now, "QUIC не проходит, работает TCP");
                        break;
                    }
                    s.Suspicions = 1;
                    Move(s, AutoStatus.Suspected, now, why);
                    log.Add($"{s.Name}: похоже на блокировку ({why})");
                    break;
                case AutoStatus.Suspected:
                    s.Suspicions = suspicious ? s.Suspicions + 1 : 0;
                    if (!suspicious)
                        Move(s, AutoStatus.Watching, now, "");
                    break;
                case AutoStatus.Applied when s.AppliedAt is { } at:
                {
                    // only what happened with the strategy on counts
                    int fails = s.Fails.Count(t => t > at) + s.NoConnections.Count(t => t > at);
                    int oks = s.Oks.Count(t => t > at);
                    if (oks == 0 && fails >= Threshold(s) && s.Pinned)
                    {
                        // the user pinned it: no new search; failures only show
                        if (!s.PinnedWarned)
                            log.Add($"{s.Name}: закреплённая стратегия даёт ошибки, оставляю её (сбросьте закрепление для нового подбора)");
                        s.PinnedWarned = true;
                        if (!s.Why.StartsWith("закреплена", StringComparison.Ordinal))
                            s.Why = "закреплена; есть ошибки: " + s.Why;
                        s.AppliedAt = now;
                    }
                    else if (oks == 0 && fails >= Threshold(s))
                    {
                        Move(s, AutoStatus.Degraded, now, "обход перестал работать: " + s.Why);
                        s.NextCheck = null;
                        log.Add($"{s.Name}: обход перестал работать, проверяю");
                    }
                    break;
                }
                case AutoStatus.NotFound when s.NextCheck is { } next && now >= next:
                    Move(s, AutoStatus.Blocked, now, "повторный подбор");
                    break;
            }
        }
        return log;
    }

    /// <summary>Whether the window looks like DPI: failures and not one success.</summary>
    public static bool Suspicious(AutoService s, out string why)
    {
        why = s.Why;
        // geneva's detector saw a shaper or a freeze: its flows look fine to the slices, the probe decides
        if (s.Detected.Count > 0)
        {
            why = s.DetectedWhy;
            return true;
        }
        if (s.Oks.Count > 0)
            return false;
        int fails = s.Fails.Count + s.NoConnections.Count;
        if (s.NoConnections.Count > 0 && s.Fails.Count == 0)
            why = "соединение не устанавливается";
        return fails >= Threshold(s);
    }

    private static int Threshold(AutoService s) => s.Kind == AutoKind.LocalPort ? AutoRules.PeerFailsToSuspect
        : s.Transport == L4Kind.Udp ? AutoRules.UdpFailsToSuspect
        : AutoRules.FailsToSuspect;

    /// <summary>The site's TCP is fine (the browser's fallback from QUIC works).</summary>
    private bool TcpWorks(AutoService quic)
    {
        var web = Find("web:" + quic.Key["quic:".Length..]);
        return web is not null && web.Oks.Count > 0;
    }

    private static void Move(AutoService s, AutoStatus to, DateTime now, string why)
    {
        if (s.Status != to)
        {
            s.Status = to;
            s.Since = now;
        }
        if (why.Length > 0)
            s.Why = why;
    }

    /// <summary>
    /// geneva's detector saw a forged DNS answer for a name (<c>DNS_POISON</c>: a stub address, or an injected answer
    /// that came before the resolver's). No packet strategy helps here (geneva_c docs/EXT.md): the user is told to use
    /// DoH. True when the name is new or was last reported more than an hour ago.
    /// </summary>
    public bool DnsPoisoned(string name, DateTime now)
    {
        name = name.TrimEnd('.').ToLowerInvariant();
        if (name.Length == 0 || _dnsPoisoned.TryGetValue(name, out var at) && now - at < TimeSpan.FromHours(1))
            return false;
        if (_dnsPoisoned.Count > 256)
            _dnsPoisoned.Clear();
        _dnsPoisoned[name] = now;
        return true;
    }

    /// <summary>
    /// A key geneva's detector holds impaired (<c>ext_status</c>, <c>impaired</c>): a name (<paramref name="level"/>
    /// <c>host</c>) or an address (<c>ip</c>) with a class of <see cref="AutoRules.DetectorClasses"/>. The services it
    /// names — a site by its name or a subdomain of it, any service by an address it was seen at — are suspected unless
    /// they are already handled (applied, searched, paused after a probe). Returns the names of the newly suspected.
    /// </summary>
    public List<string> Detect(string level, string key, string cls, DateTime now)
    {
        var hit = new List<string>();
        if (!AutoRules.DetectorClasses.Contains(cls) || key.Length == 0)
            return hit;
        key = key.TrimEnd('.').ToLowerInvariant();
        foreach (var s in _services.Values)
        {
            bool match = level switch
            {
                // the detector's classes are TCP ones: a site's QUIC or a UDP service at the address is not judged by them
                "host" => s.Kind == AutoKind.Web && (key == s.Host.ToLowerInvariant() || AutoFamilies.SiteOf(s) is var site && (key == site || key.EndsWith("." + site, StringComparison.Ordinal))),
                "ip" => s.Transport == L4Kind.Tcp && s.Addresses.Any(a => string.Equals(a.Ip, key, StringComparison.OrdinalIgnoreCase)),
                _ => false,
            };
            if (!match || s.Status is not (AutoStatus.Watching or AutoStatus.Fallback or AutoStatus.Suspected)
                && !(s.Status is AutoStatus.NotBlocked && (s.NextCheck is null || now >= s.NextCheck)))
                continue;
            // one mark a minute keeps the suspicion alive; only a new one is reported
            bool fresh = s.Detected.Count == 0;
            if (fresh || now - s.Detected[^1] >= TimeSpan.FromMinutes(1))
                s.Detected.Add(now);
            s.DetectedWhy = cls == "THROTTLE" ? "детектор geneva: замедление (шейпер)" : "детектор geneva: заморозка на 8–64 КБ";
            if (fresh)
                hit.Add(s.Name);
        }
        return hit;
    }

    /// <summary>
    /// A suspected or degraded service whose probe is due: the most important first (issue 28), within a level a
    /// broken bypass before a new suspicion, then the one used most recently and most.
    /// </summary>
    public AutoService? NextToConfirm(DateTime now) => Queue(_services.Values
        .Where(s => s.Status is AutoStatus.Suspected or AutoStatus.Degraded && (s.NextCheck is null || now >= s.NextCheck)
            && (s.Status == AutoStatus.Degraded || !_noSearch.Matches(s))), now)
        .FirstOrDefault();

    /// <summary>
    /// The blocked service to search next: the most important first; within a level sites, DNS, QUIC, servers,
    /// peers, then the one used most recently and most. The number of failures does not decide: a torrent client's peers
    /// fail by the hundred.
    /// </summary>
    public AutoService? NextToSearch(DateTime now) => NextToSearch(now, _ => true);

    /// <summary>The blocked services whose search is due now: what <see cref="NextToSearch(DateTime)"/> picks from.</summary>
    public int Waiting(DateTime now) => _services.Values.Count(s => Due(s, now));

    private bool Due(AutoService s, DateTime now) =>
        s.Status == AutoStatus.Blocked && (s.NextCheck is null || now >= s.NextCheck) && !_noSearch.Matches(s);

    /// <summary>The next service to search among those <paramref name="allowed"/> lets through (searches side by side).</summary>
    public AutoService? NextToSearch(DateTime now, Func<AutoService, bool> allowed) => Queue(_services.Values
        .Where(s => Due(s, now) && allowed(s)), now)
        .FirstOrDefault();

    /// <summary>
    /// Two services whose searches must not run side by side: they share a server address (a strategy tried on one
    /// would meet the other's packets, and one address goes to one group) or are the same site.
    /// </summary>
    public static bool Overlap(AutoService a, AutoService b) =>
        a.Key == b.Key
        || AutoFamilies.SiteOf(a) == AutoFamilies.SiteOf(b)
        || a.Addresses.Any(x => b.Addresses.Any(y => y.Ip == x.Ip))
        || a.Kind == AutoKind.LocalPort && b.Kind == AutoKind.LocalPort && a.LocalPort == b.LocalPort;

    private static IEnumerable<AutoService> Queue(IEnumerable<AutoService> list, DateTime now) => list
        .OrderBy(s => AutoPriorities.Effective(s, now))
        .ThenByDescending(s => s.Status == AutoStatus.Degraded)
        .ThenBy(s => s.Kind switch { AutoKind.Web => 0, AutoKind.Dns => 1, AutoKind.Quic => 2, AutoKind.Endpoint => 3, _ => 4 })
        .ThenByDescending(s => s.LastSeen)
        .ThenByDescending(s => s.Oks.Count + s.Fails.Count + s.NoConnections.Count)
        .ThenBy(s => s.Key, StringComparer.Ordinal);

    /// <summary>
    /// A blocked service important enough to interrupt the search for <paramref name="searching"/>: more important
    /// than it now, and not a background one itself (a peer that waited long rises, but never interrupts).
    /// </summary>
    public AutoService? Preempting(string searching, DateTime now)
    {
        if (Find(searching) is not { } cur)
            return null;
        var current = AutoPriorities.Effective(cur, now);
        var next = NextToSearch(now);
        return next is not null && next.Key != searching && next.Priority != AutoPriority.Background
            && AutoPriorities.Effective(next, now) < current ? next : null;
    }

    /// <summary>
    /// The user's "Проверить сейчас": an applied service is checked with its bypass (and searched again if it fails),
    /// any other is probed without one at once, pauses included; one that found nothing is searched again now.
    /// </summary>
    public string CheckNow(string key, DateTime now)
    {
        if (Find(key) is not { } s)
            return "";
        s.NextCheck = null;
        switch (s.Status)
        {
            case AutoStatus.Applied:
                Move(s, AutoStatus.Degraded, now, "проверка по просьбе пользователя");
                break;
            case AutoStatus.NotFound:
                Move(s, AutoStatus.Blocked, now, "повторный подбор по просьбе пользователя");
                break;
            case AutoStatus.Searching or AutoStatus.Blocked or AutoStatus.Degraded:
                return $"{s.Name}: уже в работе";
            default:
                // a service no probe judges is taken as blocked on the user's word
                s.Suspicions = 2;
                Move(s, AutoStatus.Suspected, now, "проверка по просьбе пользователя");
                break;
        }
        return $"{s.Name}: проверяю сейчас";
    }

    /// <summary>The user pins (or unpins) the applied strategy of a service.</summary>
    public bool Pin(string key, bool pinned)
    {
        if (Find(key) is not { } s || (pinned && s.Strategy is null))
            return false;
        s.Pinned = pinned;
        s.PinnedWarned = false;
        return true;
    }

    /// <summary>The user's word about a service's importance.</summary>
    public bool SetUserPriority(string key, AutoUserPriority p)
    {
        if (Find(key) is not { } s)
            return false;
        s.UserPriority = p;
        s.Priority = AutoPriorities.Base(s, _important, _unimportant, _lists.KnownImportant);
        return true;
    }

    /// <summary>
    /// The strategy that works for another member of the service's family (YouTube's videos for its site): the first
    /// one to try. Null when there is none.
    /// </summary>
    public string? FamilyStrategy(AutoService s)
    {
        if (AutoFamilies.Of(s) is not { } family)
            return null;
        return _services.Values
            .Where(x => x.Key != s.Key && x.IsActive && x.Transport == s.Transport && AutoFamilies.Of(x) == family)
            .OrderByDescending(x => x.AppliedAt)
            .Select(x => x.Strategy)
            .FirstOrDefault();
    }

    /// <summary>The probe's verdict on a suspected service (or, for a degraded one, the probe with its strategy on).</summary>
    public string Confirmed(string key, AutoConfirm result, DateTime now)
    {
        if (Find(key) is not { } s)
            return "";
        bool degraded = s.Status == AutoStatus.Degraded;
        switch (result)
        {
            case AutoConfirm.NotBlocked when degraded:
                // the strategy still works: the failures were something else
                s.Fails.Clear();
                s.NoConnections.Clear();
                s.Detected.Clear();
                s.AppliedAt = now;
                Move(s, AutoStatus.Applied, now, "проверка с обходом прошла");
                return $"{s.Name}: с обходом открывается, оставляю стратегию";
            case AutoConfirm.NotBlocked:
                s.NextCheck = now + AutoRules.NotBlockedPause;
                Move(s, AutoStatus.NotBlocked, now, "без обхода открывается");
                return $"{s.Name}: без обхода открывается, это не блокировка";
            case AutoConfirm.IpBlocked:
                s.NextCheck = now + AutoRules.IpBlockedPause;
                Move(s, AutoStatus.IpBlocked, now, "блокировка по адресу: geneva не поможет, нужен туннель");
                return $"{s.Name}: блокировка по адресу, обход пакетами не поможет";
            case AutoConfirm.Unknown when s.Suspicions < 2 && !degraded:
                s.NextCheck = now + TimeSpan.FromMinutes(1);
                return "";
            case AutoConfirm.Blocked or AutoConfirm.Unknown when degraded && s.Pinned:
                s.AppliedAt = now;
                s.Fails.Clear();
                s.NoConnections.Clear();
                s.Detected.Clear();
                Move(s, AutoStatus.Applied, now, "закреплена; проверка с обходом не прошла");
                return $"{s.Name}: проверка с обходом не прошла, но стратегия закреплена — оставляю";
            case AutoConfirm.Blocked or AutoConfirm.Unknown when degraded && _noSearch.Matches(s):
                // its bypass stopped working and the user does not want a new one searched: it leaves, as SetLists does
                _services.Remove(s.Key);
                return $"{s.Name}: обход перестал работать; в списке «не подбирать» — новый не ищу";
            default:
                s.NextCheck = null;
                if (!degraded && result == AutoConfirm.Blocked)
                    s.BaselineAt = now;
                Move(s, AutoStatus.Blocked, now, degraded ? "обход перестал работать: ищу новую стратегию" : "заблокирован");
                return degraded ? $"{s.Name}: стратегия больше не работает, ищу новую" : $"{s.Name}: блокировка подтверждена, ищу обход";
        }
    }

    public void Searching(string key, DateTime now)
    {
        if (Find(key) is { } s)
            Move(s, AutoStatus.Searching, now, "подбор");
    }

    public void Applied(string key, string strategy, double fitness, DateTime now)
    {
        if (Find(key) is not { } s)
            return;
        s.Strategy = strategy;
        s.Fitness = fitness;
        s.AppliedAt = now;
        s.Attempts = 0;
        s.NextCheck = null;
        s.Fails.Clear();
        s.NoConnections.Clear();
        s.Detected.Clear();
        Move(s, AutoStatus.Applied, now, "обход работает");
    }

    /// <summary>Nothing worked: the next search (continued, with more generations) after a growing pause.</summary>
    public void NotFound(string key, DateTime now)
    {
        if (Find(key) is not { } s)
            return;
        s.Attempts++;
        var pause = TimeSpan.FromTicks(Math.Min(AutoRules.MaxRetryPause.Ticks, AutoRules.RetryPause.Ticks * (1L << Math.Min(s.Attempts - 1, 10))));
        s.NextCheck = now + pause;
        Move(s, AutoStatus.NotFound, now, $"обход не найден, следующая попытка через {pause.TotalHours.ToString("0", CultureInfo.InvariantCulture)} ч");
    }

    /// <summary>Back to watching (the user's "Сбросить" on one service): its strategy is no longer applied.</summary>
    public void Reset(string key, DateTime now)
    {
        if (Find(key) is not { } s)
            return;
        s.Strategy = null;
        s.AppliedAt = null;
        s.NextCheck = null;
        s.Attempts = 0;
        s.Pinned = false;
        s.Fails.Clear();
        s.NoConnections.Clear();
        s.Detected.Clear();
        Move(s, AutoStatus.Watching, now, "");
    }

    /// <summary>A search was interrupted (the mode was turned off, the program closed): it is blocked and waits again.</summary>
    public void Interrupted(string key, DateTime now)
    {
        if (Find(key) is not { Status: AutoStatus.Searching } s)
            return;
        // stopped because the user took it out of the search: it leaves the problems, as SetLists does
        if (!s.IsActive && _noSearch.Matches(s))
        {
            _services.Remove(key);
            return;
        }
        Move(s, AutoStatus.Blocked, now, "подбор прерван, продолжу");
    }
}
