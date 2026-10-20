using System.Globalization;
using System.Text.RegularExpressions;

namespace ZapretAutoTuner.Core.Monitor;

public enum AutoHostlistEvent
{
    /// <summary>"fail counter N/M": a failure was counted.</summary>
    FailCounter,

    /// <summary>"fail counter reset. website is working."</summary>
    Working,

    /// <summary>"adding to FILE": the domain went into the auto list.</summary>
    Added,

    /// <summary>"NOT adding, duplicate detected".</summary>
    Duplicate,

    /// <summary>A failure detector fired: "retrans threshold reached", "incoming RST", "redirect to another domain", "udp_in … udp_out …".</summary>
    Failure,
}

public sealed record AutoHostlistEntry(DateTime Time, string Host, int Profile, string ProfileName, string Client, string Proto, AutoHostlistEvent Event, string Detail);

/// <summary>
/// The engine's autohostlist debug log (<c>--hostlist-auto-debug</c>, nfq2/desync.c via LOG_APPEND):
/// <c>DD.MM.YYYY HH:MM:SS : host : profile N (name) : client ip:port : proto P : message</c>. On a router it shows
/// which domains fail with the current strategy (PLAN 7.4).
/// </summary>
public static partial class AutoHostlistLog
{
    [GeneratedRegex(@"^(\d\d\.\d\d\.\d{4} \d\d:\d\d:\d\d) : (\S+) : profile (\d+) \((.*?)\) : client (\S+) : proto (\S+) : (.*)$")]
    private static partial Regex LineRe();

    [GeneratedRegex(@"^fail counter (\d+)/(\d+)$")]
    private static partial Regex CounterRe();

    public static List<AutoHostlistEntry> Parse(string text)
    {
        var list = new List<AutoHostlistEntry>();
        foreach (var raw in text.Split('\n'))
        {
            var m = LineRe().Match(raw.TrimEnd('\r'));
            if (!m.Success || !DateTime.TryParseExact(m.Groups[1].Value, "dd.MM.yyyy HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var time))
                continue;
            var msg = m.Groups[7].Value;
            var ev = msg switch
            {
                _ when CounterRe().IsMatch(msg) => AutoHostlistEvent.FailCounter,
                _ when msg.StartsWith("fail counter reset", StringComparison.Ordinal) => AutoHostlistEvent.Working,
                _ when msg.StartsWith("adding to ", StringComparison.Ordinal) => AutoHostlistEvent.Added,
                _ when msg.StartsWith("NOT adding", StringComparison.Ordinal) => AutoHostlistEvent.Duplicate,
                _ => AutoHostlistEvent.Failure,
            };
            list.Add(new AutoHostlistEntry(time, m.Groups[2].Value.ToLowerInvariant(), int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture),
                m.Groups[4].Value, m.Groups[5].Value, m.Groups[6].Value, ev, msg));
        }
        return list;
    }

    /// <summary>Per host: failures (detector hits) and "working" resets since <paramref name="since"/>, failing hosts first.</summary>
    public static List<(string Host, int Failures, int Working, bool Added)> Summary(IEnumerable<AutoHostlistEntry> entries, DateTime since) =>
        entries.Where(e => e.Time >= since)
            .GroupBy(e => e.Host, StringComparer.Ordinal)
            .Select(g => (g.Key, g.Count(e => e.Event == AutoHostlistEvent.Failure), g.Count(e => e.Event == AutoHostlistEvent.Working), g.Any(e => e.Event == AutoHostlistEvent.Added)))
            .OrderByDescending(x => x.Item2 - x.Item3)
            .ToList();
}
