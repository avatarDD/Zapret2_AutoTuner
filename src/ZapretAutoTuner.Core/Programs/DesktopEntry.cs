using System.Globalization;
using System.Text;

namespace ZapretAutoTuner.Core.Programs;

/// <summary>
/// An XDG desktop entry (Desktop Entry Specification 1.5): the <c>[Desktop Entry]</c> group, localized Name, Exec
/// split by the spec's quoting with field codes (<c>%f %U …</c>) dropped.
/// </summary>
public static class DesktopEntry
{
    /// <summary>The program of a .desktop file, or null for hidden entries, links and entries without Exec.</summary>
    public static ProgramInfo? Parse(string text, string path, string? language = null)
    {
        language ??= CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
        var keys = new Dictionary<string, string>(StringComparer.Ordinal);
        bool inGroup = false;
        foreach (var raw in text.ReplaceLineEndings("\n").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
                continue;
            if (line[0] == '[')
            {
                inGroup = line == "[Desktop Entry]";
                continue;
            }
            int eq = line.IndexOf('=', StringComparison.Ordinal);
            if (inGroup && eq > 0)
                keys.TryAdd(line[..eq].Trim(), line[(eq + 1)..].Trim());
        }
        if (keys.GetValueOrDefault("Type", "Application") != "Application"
            || keys.GetValueOrDefault("NoDisplay") == "true" || keys.GetValueOrDefault("Hidden") == "true"
            || !keys.TryGetValue("Exec", out var exec))
            return null;
        var argv = SplitExec(exec);
        if (argv.Count == 0)
            return null;
        var name = keys.GetValueOrDefault($"Name[{language}]") ?? keys.GetValueOrDefault("Name") ?? Path.GetFileNameWithoutExtension(path);
        return new ProgramInfo
        {
            Id = path,
            Name = name,
            Executable = argv[0],
            Arguments = argv.Skip(1).ToList(),
            Source = ProgramSource.Desktop,
            Icon = keys.GetValueOrDefault("Icon"),
        };
    }

    /// <summary>Exec splitting: double quotes group, backslash escapes inside them, <c>%%</c> is a percent and other
    /// field codes vanish (an argument that was only a field code is dropped).</summary>
    public static List<string> SplitExec(string exec)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        bool quoted = false, inWord = false, onlyCode = false;
        for (int i = 0; i < exec.Length; i++)
        {
            char c = exec[i];
            if (quoted)
            {
                if (c == '"')
                    quoted = false;
                else if (c == '\\' && i + 1 < exec.Length)
                    sb.Append(exec[++i]);
                else
                    sb.Append(c);
                continue;
            }
            if (c is ' ' or '\t')
            {
                if (inWord && !(onlyCode && sb.Length == 0))
                    result.Add(sb.ToString());
                sb.Clear();
                inWord = onlyCode = false;
                continue;
            }
            inWord = true;
            if (c == '"')
            {
                quoted = true;
            }
            else if (c == '%' && i + 1 < exec.Length)
            {
                char code = exec[++i];
                if (code == '%')
                    sb.Append('%');
                else
                    onlyCode = sb.Length == 0;
            }
            else
            {
                sb.Append(c);
            }
        }
        if (inWord && !(onlyCode && sb.Length == 0))
            result.Add(sb.ToString());
        return result;
    }
}
