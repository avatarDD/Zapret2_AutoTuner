namespace ZapretAutoTuner.Core.Engine;

/// <summary>
/// What the privileged Agent refuses to pass to the engine, on top of the Validator. The engine starts as root
/// (Administrator on Windows) and drops privileges itself; before the drop it reads blob files and creates and
/// chowns files named by some options. So: no options that keep root or detach the process, files the engine
/// writes must lie inside the Agent's data directory, and blob files inside the read roots the Agent passes (its
/// engine directory and its own copy folder: a blob is sent on the wire, so reading e.g. /etc/shadow into one through
/// a symlink in the user's folder would leak it; the UI sends a blob's content like a Lua file's). Lists and Lua files are read after the
/// privilege drop on Linux (nfqws.c: droproot, then test_list_files and lua_test_init_script_files), so a Lua file
/// in the user's home (often 0700/0750) would be unreadable; on Windows winws2 keeps Administrator rights and reads
/// Lua as Administrator, so a Lua file the user can write could be swapped between the check and the load. Hence
/// every <c>--lua-init=@file</c> must lie in the engine's directory or the Agent's own protected copy folder
/// (the luaRoots of <see cref="Check"/>; the UI sends the content and the Agent writes the copy).
/// The session token limits the Agent to the user who approved the UAC / pkexec prompt.
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
    /// <param name="luaRoots">Where <c>--lua-init=@file</c> may lie; null leaves Lua files unchecked.</param>
    public static List<string> Check(IReadOnlyList<string> argv, IReadOnlyList<string> writeRoots, IReadOnlyList<string>? readRoots = null, bool managedAllowed = false,
        IReadOnlyList<string>? luaRoots = null)
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
            if (key == "lua-init" && luaRoots is not null && value is { Length: > 1 } && value[0] == '@')
            {
                if (!IsUnder(value[1..], luaRoots))
                    problems.Add($"{name}: Lua-файл должен лежать в каталоге движка или в защищённом каталоге Agent'а");
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
