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

    /// <summary>When a paused service is looked at again (not blocked, address block, nothing found).</summary>
    public DateTime? NextCheck { get; set; }

    /// <summary>Searches that found nothing in a row: the pause before the next one doubles.</summary>
    public int Attempts { get; set; }

    /// <summary>Slices in a row that found it suspicious: a service no probe can judge is blocked after two.</summary>
    public int Suspicions { get; set; }

    [JsonIgnore]
    public bool CanReplay => Replay.Length > 0;

    /// <summary>The probe without a bypass can judge it: a page load (web) or a replay; else only its own traffic can.</summary>
    [JsonIgnore]
    public bool Probeable => Kind == AutoKind.Web || CanReplay;

    [JsonIgnore]
    public int Port => Ports.Count > 0 ? Ports[0] : Kind switch
    {
        AutoKind.Web or AutoKind.Quic => 443,
        AutoKind.Dns => 53,
        _ => 0,
    };

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

    public AutoBook(IEnumerable<AutoService>? saved = null)
    {
        foreach (var s in saved ?? [])
        {
            if (s.Key.Length > 0)
                _services[s.Key] = s;
        }
    }

    public IReadOnlyCollection<AutoService> Services => _services.Values;

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
            if (!_services.TryGetValue(x.Key, out var s))
            {
                if (_services.Count >= AutoRules.MaxServices && !Evict())
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
                };
                _services[x.Key] = s;
            }
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
                s.Replay = AutoObserver.ToBase64(x.Replay);
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

    private static void AddAddress(AutoService s, IPAddress a, DateTime seen)
    {
        var ip = a.ToString();
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
        foreach (var list in new[] { s.Fails, s.Oks, s.NoConnections })
        {
            list.RemoveAll(t => t < from);
            if (list.Count > 200)
                list.RemoveRange(0, list.Count - 200);
        }
    }

    /// <summary>Drops the service seen longest ago among the ones nothing is done for; false when there is none.</summary>
    private bool Evict()
    {
        var victim = _services.Values
            .Where(s => s.Status is AutoStatus.Watching or AutoStatus.NotBlocked or AutoStatus.Fallback or AutoStatus.IpBlocked)
            .OrderBy(s => s.LastSeen)
            .FirstOrDefault();
        return victim is not null && _services.Remove(victim.Key);
    }

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
                    if (oks == 0 && fails >= Threshold(s))
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

    /// <summary>A suspected or degraded service whose probe is due (the most failing first).</summary>
    public AutoService? NextToConfirm(DateTime now) => _services.Values
        .Where(s => s.Status is AutoStatus.Suspected or AutoStatus.Degraded && (s.NextCheck is null || now >= s.NextCheck))
        .OrderByDescending(s => s.Status == AutoStatus.Degraded)
        .ThenByDescending(s => s.Fails.Count + s.NoConnections.Count)
        .FirstOrDefault();

    /// <summary>The blocked service to search next: sites first, then DNS, servers, QUIC, peer-to-peer.</summary>
    public AutoService? NextToSearch(DateTime now) => _services.Values
        .Where(s => s.Status == AutoStatus.Blocked && (s.NextCheck is null || now >= s.NextCheck))
        .OrderBy(s => s.Kind switch { AutoKind.Web => 0, AutoKind.Dns => 1, AutoKind.Endpoint => 2, AutoKind.Quic => 3, _ => 4 })
        .ThenByDescending(s => s.Fails.Count + s.NoConnections.Count)
        .FirstOrDefault();

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
            default:
                s.NextCheck = null;
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
        s.Fails.Clear();
        s.NoConnections.Clear();
        Move(s, AutoStatus.Watching, now, "");
    }

    /// <summary>A search was interrupted (the mode was turned off, the program closed): it is blocked and waits again.</summary>
    public void Interrupted(string key, DateTime now)
    {
        if (Find(key) is { Status: AutoStatus.Searching } s)
            Move(s, AutoStatus.Blocked, now, "подбор прерван, продолжу");
    }
}
