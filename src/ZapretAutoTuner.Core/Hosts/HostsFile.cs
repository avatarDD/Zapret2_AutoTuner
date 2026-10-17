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
        bool inside = false;
        foreach (var raw in content.Split('\n'))
        {
            var line = raw.TrimEnd('\r').Trim();
            if (line == Begin)
                inside = true;
            else if (line == End)
                inside = false;
            else if (inside && line.Length > 0 && line[0] != '#')
            {
                var parts = line.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && IPAddress.TryParse(parts[0], out var ip))
                {
                    foreach (var h in parts.Skip(1).TakeWhile(p => p[0] != '#'))
                        pins.Add(new HostsPin(h, ip));
                }
            }
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
        int end = begin < 0 ? -1 : lines.FindIndex(begin + 1, l => l.Trim() == End);
        if (begin >= 0 && end < 0)
            end = lines.Count - 1; // a cut block (manual edit): drop it to the end
        int at = begin;
        // remove every AutoTuner block, there should be at most one
        while (begin >= 0)
        {
            lines.RemoveRange(begin, end - begin + 1);
            begin = lines.FindIndex(l => l.Trim() == Begin);
            end = begin < 0 ? -1 : lines.FindIndex(begin + 1, l => l.Trim() == End);
            if (begin >= 0 && end < 0)
                end = lines.Count - 1;
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
