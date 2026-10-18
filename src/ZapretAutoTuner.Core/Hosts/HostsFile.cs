using System.Net;
using System.Text;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Hosts;

/// <summary>A domain pinned to an address that is not blocked (dpi-diagnostics §2a).</summary>
public sealed record HostsPin(string Host, IPAddress Address)
{
    public override string ToString() => $"{Address} {Host}";
}

/// <summary>
/// Edits the AutoTuner block of a hosts file (dpi-diagnostics §2a): entries live between
/// <c># BEGIN ZapretAutoTuner</c> and <c># END ZapretAutoTuner</c>; everything else is kept byte for byte, line
/// endings included. Pure text in, text out: the Agent does the file I/O, backup and DNS flush.
/// </summary>
public static class HostsFile
{
    public const string Begin = "# BEGIN ZapretAutoTuner";
    public const string End = "# END ZapretAutoTuner";

    public static string DefaultPath => OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts")
        : "/etc/hosts";

    /// <summary>Pins in the AutoTuner block.</summary>
    public static List<HostsPin> Read(string content)
    {
        var pins = new List<HostsPin>();
        var lines = content.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        int begin = lines.FindIndex(l => l.Trim() == Begin);
        while (begin >= 0)
        {
            int end = BlockEnd(lines, begin);
            foreach (var line in lines.Skip(begin + 1).Take(end - begin).Select(l => l.Trim()))
            {
                if (line.Length == 0 || line[0] == '#')
                    continue;
                var parts = line.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && IPAddress.TryParse(parts[0], out var ip))
                {
                    foreach (var h in parts.Skip(1).TakeWhile(p => p[0] != '#'))
                        pins.Add(new HostsPin(h, ip));
                }
            }
            begin = end + 1 < lines.Count ? lines.FindIndex(end + 1, l => l.Trim() == Begin) : -1;
        }
        return pins;
    }

    /// <summary>
    /// Replaces the AutoTuner block with <paramref name="pins"/> (an empty list removes the block). The block goes
    /// where the old one was, or at the end of the file.
    /// </summary>
    public static string Apply(string content, IReadOnlyList<HostsPin> pins)
    {
        foreach (var p in pins)
            Validate(p);
        string nl = content.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : OperatingSystem.IsWindows() && content.Length == 0 ? "\r\n" : "\n";
        var lines = content.Length == 0 ? [] : content.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        bool endsWithNewline = content.EndsWith('\n');
        if (endsWithNewline)
            lines.RemoveAt(lines.Count - 1);

        int begin = lines.FindIndex(l => l.Trim() == Begin);
        int at = begin;
        // remove every AutoTuner block, there should be at most one
        while (begin >= 0)
        {
            int end = BlockEnd(lines, begin);
            lines.RemoveRange(begin, end - begin + 1);
            begin = lines.FindIndex(l => l.Trim() == Begin);
        }

        if (pins.Count > 0)
        {
            var block = new List<string> { Begin, "# Added by Zapret2 AutoTuner: addresses that are not blocked. Remove in the app or delete this block." };
            block.AddRange(pins
                .DistinctBy(p => (p.Host.ToLowerInvariant(), p.Address))
                .OrderBy(p => p.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(p => p.Address.AddressFamily)
                .Select(p => $"{p.Address} {p.Host.ToLowerInvariant()}"));
            block.Add(End);
            if (at < 0 || at > lines.Count)
                at = lines.Count;
            lines.InsertRange(at, block);
        }

        if (lines.Count == 0)
            return "";
        var sb = new StringBuilder(string.Join(nl, lines));
        if (endsWithNewline || pins.Count > 0)
            sb.Append(nl);
        return sb.ToString();
    }

    /// <summary>
    /// The last line of the block that starts at <paramref name="begin"/>. A block whose END line was deleted by hand
    /// ends at the last of its own lines (our comments and <c>IP host</c> pins) before the first blank or foreign
    /// line, so the user's lines further down are never taken with it.
    /// </summary>
    private static int BlockEnd(List<string> lines, int begin)
    {
        int end = lines.FindIndex(begin + 1, l => l.Trim() == End);
        int nextBegin = lines.FindIndex(begin + 1, l => l.Trim() == Begin);
        if (end >= 0 && (nextBegin < 0 || end < nextBegin))
            return end;
        int last = begin;
        for (int i = begin + 1; i < lines.Count; i++)
        {
            var t = lines[i].Trim();
            bool ours = t.StartsWith("# Added by Zapret2 AutoTuner", StringComparison.Ordinal) || IsPinLine(t);
            if (!ours)
                break;
            last = i;
        }
        return last;
    }

    private static bool IsPinLine(string t)
    {
        var parts = t.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 2 && IPAddress.TryParse(parts[0], out _) && Target.IsValidHostName(parts[1]);
    }

    /// <summary>Removes the AutoTuner block.</summary>
    public static string Remove(string content) => Apply(content, []);

    /// <summary>A pin must be one valid host name and one address: nothing that could inject other lines.</summary>
    public static void Validate(HostsPin p)
    {
        if (!Target.IsValidHostName(p.Host) || p.Host.Any(char.IsWhiteSpace))
            throw new ArgumentException($"не похоже на имя сайта: {p.Host}");
        if (IPAddress.IsLoopback(p.Address) || p.Address.Equals(IPAddress.Any) || p.Address.Equals(IPAddress.IPv6Any))
            throw new ArgumentException($"адрес {p.Address} не подходит для закрепления");
    }
}
