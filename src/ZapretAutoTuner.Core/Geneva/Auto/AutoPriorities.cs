using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Providers;

namespace ZapretAutoTuner.Core.Geneva.Auto;

/// <summary>
/// Services that are one thing for the user but several sites on the wire: YouTube is youtube.com, its videos come
/// from googlevideo.com and its pictures from ytimg.com. A strategy found for one member is the first one tried for the
/// others, and the mode applies it by name to the whole family (geneva_c 2.0), so a new CDN host works at once.
/// </summary>
public static class AutoFamilies
{
    /// <summary>The families by their name; the domains are registrable domains (subdomains belong to them).</summary>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> All { get; } = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
    {
        ["YouTube"] = ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com", "youtubei.googleapis.com", "yt.be"],
        ["Discord"] = ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com", "discord.dev", "discordstatus.com"],
        ["Telegram"] = ["telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com", "telegra.ph", "cdn-telegram.org"],
        ["WhatsApp"] = ["whatsapp.com", "whatsapp.net", "wa.me"],
        ["Instagram"] = ["instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "fb.com", "facebook.net", "fbsbx.com"],
        ["X"] = ["x.com", "twitter.com", "twimg.com", "t.co"],
    };

    private static readonly Dictionary<string, string> ByDomain = All
        .SelectMany(f => f.Value.Select(d => (Domain: d, Family: f.Key)))
        .ToDictionary(x => x.Domain, x => x.Family, StringComparer.OrdinalIgnoreCase);

    /// <summary>The family of a name (a host or a registrable domain) or null.</summary>
    public static string? Of(string? name)
    {
        if (string.IsNullOrEmpty(name))
            return null;
        var n = name.Trim().TrimEnd('.').ToLowerInvariant();
        // "youtube.com (QUIC)" is shown for QUIC: the name is the first word
        int sp = n.IndexOf(' ', StringComparison.Ordinal);
        if (sp > 0)
            n = n[..sp];
        while (n.Length > 0)
        {
            if (ByDomain.TryGetValue(n, out var f))
                return f;
            int dot = n.IndexOf('.', StringComparison.Ordinal);
            if (dot < 0)
                break;
            n = n[(dot + 1)..];
        }
        return null;
    }

    /// <summary>The family of a site or QUIC service; null for anything else.</summary>
    public static string? Of(AutoService s) => s.Kind is AutoKind.Web or AutoKind.Quic ? Of(SiteOf(s)) : null;

    /// <summary>The registrable domain of a site or QUIC service (its key without the kind).</summary>
    public static string SiteOf(AutoService s) => s.Key.StartsWith("web:", StringComparison.Ordinal) ? s.Key[4..]
        : s.Key.StartsWith("quic:", StringComparison.Ordinal) ? s.Key[5..]
        : s.Name;

    public static IReadOnlyList<string> Domains(string family) => All.TryGetValue(family, out var d) ? d : [];
}

/// <summary>
/// A list the user keeps: domains (with their subdomains), addresses and subnets. Used for the important and the
/// unimportant services, the services the mode does not search for, and the traffic no bypass may touch (a VPN, a
/// proxy). The lists the mode only reads in the App (not "не трогать", which the Agent's firewall and geneva's name
/// lists take as they are) also take masks: a whole zone (<c>*.ru</c>, <c>.ru</c>), a pattern with <c>*</c> and
/// <c>?</c> (<c>*google*</c>), and a provider's network by its AS number (<c>AS12389</c>), whose announced prefixes
/// come from <paramref name="asn"/>.
/// </summary>
public sealed class AutoNameList
{
    private readonly HashSet<string> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(IPAddress Net, int Bits)> _nets = [];
    private readonly List<Regex> _patterns = [];
    private readonly List<Cidr> _asnNets = [];
    private Cidr[] _asnV4 = [];
    private Cidr[] _asnV6 = [];
    private readonly List<int> _asns = [];

    /// <param name="asn">Announced prefixes by AS number ("12389"); an AS without them matches nothing yet.</param>
    public AutoNameList(IEnumerable<string>? entries, IReadOnlyDictionary<string, IReadOnlyList<string>>? asn = null)
    {
        foreach (var raw in entries ?? [])
        {
            var e = raw.Trim().TrimEnd('.').ToLowerInvariant();
            if (e.Length == 0 || e.StartsWith('#'))
                continue;
            if (TryNet(e, out var net, out var bits))
                _nets.Add((net, bits));
            else if (IsDomain(e))
                _domains.Add(e.TrimStart('*', '.'));
            else if (Zone(e) is { } zone)
                _domains.Add(zone);
            else if (Asn(e) is { } number)
            {
                _asns.Add(number);
                if (asn is not null && asn.TryGetValue(number.ToString(CultureInfo.InvariantCulture), out var prefixes))
                {
                    foreach (var p in prefixes)
                    {
                        if (Cidr.TryParse(p, out var c))
                            _asnNets.Add(c);
                    }
                }
            }
            else if (IsPattern(e))
                _patterns.Add(new Regex("^" + Regex.Escape(e).Replace("\\*", ".*", StringComparison.Ordinal).Replace("\\?", ".", StringComparison.Ordinal) + "$",
                    RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50)));
        }
        if (_asnNets.Count > 0)
        {
            // a carrier announces thousands of prefixes: merged and sorted, an address is found by a binary search
            var merged = CidrSet.Aggregate(_asnNets);
            _asnV4 = [.. merged.Where(c => c.Family == AddressFamily.InterNetwork)];
            _asnV6 = [.. merged.Where(c => c.Family == AddressFamily.InterNetworkV6)];
        }
    }

    public static AutoNameList Empty { get; } = new([]);

    public bool IsEmpty => _domains.Count == 0 && _nets.Count == 0 && _patterns.Count == 0 && _asnNets.Count == 0;

    /// <summary>The plain domains (a zone such as <c>ru</c> and the patterns are left out: geneva's name lists take names).</summary>
    public IReadOnlyCollection<string> Domains => [.. _domains.Where(d => d.Contains('.', StringComparison.Ordinal))];

    /// <summary>The subnets in CIDR form (an address is /32 or /128); the AS networks are left out.</summary>
    public IEnumerable<string> Subnets => _nets.Select(n => $"{n.Net}/{n.Bits.ToString(CultureInfo.InvariantCulture)}");

    /// <summary>The AS numbers the list names.</summary>
    public IReadOnlyList<int> Asns => _asns;

    /// <summary>The AS numbers named in <paramref name="entries"/> ("AS12389" or "as12389").</summary>
    public static List<int> AsnsOf(IEnumerable<string> entries) =>
        [.. entries.Select(e => Asn(e.Trim().ToLowerInvariant())).Where(a => a is not null).Select(a => a!.Value).Distinct()];

    /// <summary>
    /// Why an entry is not a domain, an address or a subnet; null when it is one. The strict form: the "не трогать" list,
    /// which the Agent and geneva take as it is.
    /// </summary>
    public static string? Problem(string entry)
    {
        var e = entry.Trim().TrimEnd('.').ToLowerInvariant();
        if (e.Length == 0 || e.StartsWith('#'))
            return null;
        return TryNet(e, out _, out _) || IsDomain(e) ? null : $"не домен и не адрес / neither a domain nor an address: {entry.Trim()}";
    }

    /// <summary>Like <see cref="Problem"/>, with the masks too: a zone (<c>*.ru</c>), a pattern (<c>*google*</c>), an AS (<c>AS12389</c>).</summary>
    public static string? MaskProblem(string entry)
    {
        var e = entry.Trim().TrimEnd('.').ToLowerInvariant();
        if (e.Length == 0 || e.StartsWith('#'))
            return null;
        return TryNet(e, out _, out _) || IsDomain(e) || Zone(e) is not null || Asn(e) is not null || IsPattern(e) ? null
            : $"не домен, не маска, не адрес и не AS / neither a domain, a mask, an address nor an AS: {entry.Trim()}";
    }

    public bool MatchesName(string? name)
    {
        if (string.IsNullOrEmpty(name) || _domains.Count == 0 && _patterns.Count == 0)
            return false;
        var n = name.Trim().TrimEnd('.').ToLowerInvariant();
        foreach (var p in _patterns)
        {
            try
            {
                if (p.IsMatch(n))
                    return true;
            }
            catch (RegexMatchTimeoutException)
            {
            }
        }
        while (n.Length > 0)
        {
            if (_domains.Contains(n))
                return true;
            int dot = n.IndexOf('.', StringComparison.Ordinal);
            if (dot < 0)
                return false;
            n = n[(dot + 1)..];
        }
        return false;
    }

    public bool MatchesAddress(IPAddress? a)
    {
        if (a is null)
            return false;
        if (a.IsIPv4MappedToIPv6)
            a = a.MapToIPv4();
        foreach (var (net, bits) in _nets)
        {
            if (InNet(a, net, bits))
                return true;
        }
        var sorted = a.AddressFamily == AddressFamily.InterNetwork ? _asnV4 : _asnV6;
        if (sorted.Length == 0)
            return false;
        var n = Cidr.ToNumber(a);
        int lo = 0, hi = sorted.Length - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (sorted[mid].Start <= n)
            {
                found = mid;
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }
        return found >= 0 && n <= sorted[found].Last;
    }

    /// <summary>A service the list names: by its site, its host or any of its addresses.</summary>
    public bool Matches(AutoService s)
    {
        if (IsEmpty)
            return false;
        if (s.Kind is AutoKind.Web or AutoKind.Quic && (MatchesName(AutoFamilies.SiteOf(s)) || MatchesName(s.Host)))
            return true;
        if (s.Kind == AutoKind.Endpoint && MatchesName(s.Host))
            return true;
        return s.Addresses.Any(x => IPAddress.TryParse(x.Ip, out var ip) && MatchesAddress(ip));
    }

    /// <summary>A flow the list names: by its name or its server's address.</summary>
    public bool Matches(AutoSample x) => !IsEmpty && (MatchesName(x.Host) || MatchesAddress(x.Server.Address));

    /// <summary>A whole zone: <c>*.ru</c> or <c>.ru</c> (one label, which <see cref="IsDomain"/> does not take).</summary>
    private static string? Zone(string e)
    {
        if (!(e.StartsWith("*.", StringComparison.Ordinal) || e.StartsWith('.')))
            return null;
        var z = e.TrimStart('*', '.');
        return z.Length is > 0 and <= 63 && z.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') ? z : null;
    }

    private static int? Asn(string e) =>
        e.Length is > 2 and <= 12 && e.StartsWith("as", StringComparison.Ordinal)
        && int.TryParse(e.AsSpan(2), NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n > 0 ? n : null;

    /// <summary>A name pattern: letters, digits, '-', '.', '_' with at least one '*' or '?' and something besides them.</summary>
    private static bool IsPattern(string e) => e.Length <= 253
        && e.Any(c => c is '*' or '?') && e.Any(char.IsAsciiLetterOrDigit)
        && e.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '*' or '?');

    private static bool IsDomain(string e)
    {
        // a leading '*' only as "*.": "*cdn.net" is a pattern (fastcdn.net), not the domain cdn.net
        if (e.StartsWith('*') && !e.StartsWith("*.", StringComparison.Ordinal))
            return false;
        var d = e.TrimStart('*', '.');
        if (d.Length is 0 or > 253 || !d.Contains('.', StringComparison.Ordinal))
            return false;
        foreach (var c in d)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_'))
                return false;
        }
        return !d.StartsWith('.') && !d.EndsWith('.') && !d.Contains("..", StringComparison.Ordinal);
    }

    private static bool TryNet(string e, out IPAddress net, out int bits)
    {
        net = IPAddress.None;
        bits = 0;
        var parts = e.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var ip))
            return false;
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        int max = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        bits = max;
        if (parts.Length == 2 && (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out bits) || bits < 0 || bits > max))
            return false;
        net = ip;
        return true;
    }

    private static bool InNet(IPAddress a, IPAddress net, int bits)
    {
        if (a.AddressFamily != net.AddressFamily)
            return false;
        var x = a.GetAddressBytes();
        var y = net.GetAddressBytes();
        int full = bits / 8, rest = bits % 8;
        for (int i = 0; i < full; i++)
        {
            if (x[i] != y[i])
                return false;
        }
        if (rest == 0)
            return true;
        int mask = 0xFF << (8 - rest) & 0xFF;
        return (x[full] & mask) == (y[full] & mask);
    }
}

/// <summary>The lists that steer the mode, as the user keeps them (settings of the "Авто" page, MCP).</summary>
public sealed record AutoLists
{
    /// <summary>Always first: confirmed and searched before anything else, may interrupt a search for less.</summary>
    public IReadOnlyList<string> Important { get; init; } = [];

    /// <summary>Last: background, never interrupts anyone.</summary>
    public IReadOnlyList<string> Unimportant { get; init; } = [];

    /// <summary>Never touched by any geneva bypass: a VPN or proxy server, a game, a bank.</summary>
    public IReadOnlyList<string> Excluded { get; init; } = [];

    /// <summary>
    /// Not searched for: a service these name is neither confirmed nor searched and leaves the list of problems (the
    /// user does not need a bypass for <c>*.ru</c>). A strategy already applied stays. Masks and AS numbers work here.
    /// </summary>
    public IReadOnlyList<string> NoSearch { get; init; } = [];

    /// <summary>The announced prefixes of the AS numbers in the lists, by number ("12389"), as RIPEstat gave them.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> AsnPrefixes { get; init; } = new Dictionary<string, IReadOnlyList<string>>();

    /// <summary>When <see cref="AsnPrefixes"/> were fetched (UTC), by number; they are fetched again after a week.</summary>
    public IReadOnlyDictionary<string, DateTime> AsnFetched { get; init; } = new Dictionary<string, DateTime>();

    /// <summary>The well-known services (<see cref="AutoFamilies"/>) count as important.</summary>
    public bool KnownImportant { get; init; } = true;
}

/// <summary>The importance of a service (issue 28): who is confirmed and searched first.</summary>
public static class AutoPriorities
{
    /// <summary>The computed importance before the wait is counted (<see cref="Effective"/>).</summary>
    public static AutoPriority Base(AutoService s, AutoNameList important, AutoNameList unimportant, bool knownImportant = true)
    {
        if (s.UserPriority == AutoUserPriority.Important)
            return AutoPriority.Important;
        if (s.UserPriority == AutoUserPriority.Unimportant)
            return AutoPriority.Background;
        if (important.Matches(s))
            return AutoPriority.Important;
        if (unimportant.Matches(s))
            return AutoPriority.Background;
        if (knownImportant && AutoFamilies.Of(s) is not null)
            return AutoPriority.Important;
        return s.Kind switch
        {
            AutoKind.Web or AutoKind.Quic or AutoKind.Dns => AutoPriority.Normal,
            AutoKind.LocalPort => AutoPriority.Background,
            _ => IsBare(s) ? AutoPriority.Background : AutoPriority.Low,
        };
    }

    /// <summary>
    /// A peer more than a server: no name, a protocol nobody recognised, a port above the well-known and registered ones
    /// that servers use. Torrent peers look like this; a VPN server on 51820 is recognised as WireGuard.
    /// </summary>
    public static bool IsBare(AutoService s) => s.Kind == AutoKind.Endpoint && string.IsNullOrEmpty(s.Host)
        && s.App is "tcp" or "udp" or "" && s.Port >= 10000;

    /// <summary>
    /// The importance while the service waits: a background one rises a level for every
    /// <see cref="AutoRules.StarvationStep"/> it waited, never above <see cref="AutoPriority.Low"/>, so it is searched
    /// one day and still never interrupts a site.
    /// </summary>
    public static AutoPriority Effective(AutoService s, DateTime now)
    {
        if (s.Priority != AutoPriority.Background || s.Status is not (AutoStatus.Blocked or AutoStatus.Suspected))
            return s.Priority;
        var waited = now - s.Since;
        return waited >= AutoRules.StarvationStep ? AutoPriority.Low : AutoPriority.Background;
    }
}
