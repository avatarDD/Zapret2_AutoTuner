namespace ZapretAutoTuner.Core.Engine;

/// <summary>
/// What the privileged Agent refuses to pass to the engine, on top of the Validator. The engine starts as root
/// (Administrator on Windows) and drops privileges itself; before the drop it reads blob files and creates and
/// chowns files named by some options. So: no options that keep root or detach the process, files the engine
/// writes must lie inside the Agent's data directory, and blob files inside the data or engine directory (a blob
/// is sent on the wire, so reading e.g. /etc/shadow into one would leak it). Lists and lua files are read after
/// the privilege drop and need no rule. On Windows winws2 keeps Administrator rights; the session token limits
/// the Agent to the user who approved the UAC prompt.
/// </summary>
public static class EngineArgvPolicy
{
    /// <summary>Options that would keep privileges, detach from the Agent or write outside its control.</summary>
    public static readonly IReadOnlySet<string> Forbidden = new HashSet<string>(StringComparer.Ordinal)
    {
        "user", "uid", "daemon", "pidfile", "qnum", "fwmark",
    };

    /// <summary>Options whose value is a file the engine creates or writes.</summary>
    public static readonly IReadOnlySet<string> WrittenPaths = new HashSet<string>(StringComparer.Ordinal)
    {
        "writable", "hostlist-auto", "hostlist-auto-debug",
    };

    /// <summary>
    /// Problems with <paramref name="argv"/>, in Russian; empty if the Agent may run it. <c>--qnum</c> and
    /// <c>--fwmark</c> are managed by the Agent (they must match its firewall rule), so the caller must not set
    /// them; <paramref name="managedAllowed"/> lets the Agent itself check the final argv.
    /// </summary>
    public static List<string> Check(IReadOnlyList<string> argv, IReadOnlyList<string> writeRoots, IReadOnlyList<string>? readRoots = null, bool managedAllowed = false)
    {
        readRoots ??= writeRoots;
        var problems = new List<string>();
        foreach (var tok in argv)
        {
            if (!tok.StartsWith("--", StringComparison.Ordinal))
                continue;
            var (name, value) = Model.ArgTokenizer.SplitOption(tok);
            var key = name[2..];
            if (Forbidden.Contains(key) && !(managedAllowed && key is "qnum" or "fwmark"))
            {
                problems.Add($"{name}: опцию задаёт Agent, в запросе она запрещена");
                continue;
            }
            if (key == "debug" && value is { Length: > 0 } && value[0] == '@')
            {
                if (!IsUnder(value[1..], writeRoots))
                    problems.Add($"{name}: файл лога должен лежать в каталоге данных программы");
                continue;
            }
            if (key == "blob" && value is not null)
            {
                // name:@file or name:+ofs@file
                int at = value.IndexOf('@', StringComparison.Ordinal);
                if (at > 0 && !IsUnder(value[(at + 1)..], readRoots))
                    problems.Add($"{name}: файл блоба должен лежать в каталоге данных или движка");
                continue;
            }
            if (WrittenPaths.Contains(key) && value is not null && !IsUnder(value, writeRoots))
                problems.Add($"{name}: файл должен лежать в каталоге данных программы");
        }
        return problems;
    }

    /// <summary>Is <paramref name="path"/> an absolute path inside one of the roots (after resolving <c>..</c>)?</summary>
    public static bool IsUnder(string path, IReadOnlyList<string> roots)
    {
        if (!Path.IsPathFullyQualified(path))
            return false;
        var full = Path.GetFullPath(path);
        var cmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        foreach (var root in roots)
        {
            var r = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
            if (full.StartsWith(r, cmp))
                return true;
        }
        return false;
    }
}
