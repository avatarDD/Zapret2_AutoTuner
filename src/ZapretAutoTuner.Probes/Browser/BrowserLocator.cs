namespace ZapretAutoTuner.Probes.Browser;

/// <summary>
/// Finds the browsers for <see cref="BrowserProbe"/>: an explicit path from the environment, the copy bundled next to
/// the app (<c>browsers/</c>, release builds carry Playwright's Chromium headless shell there), or a Playwright install
/// (its own cache too). The user's own browsers are never used: the check runs in the program's browser only.
/// </summary>
public static class BrowserLocator
{
    public static string? Chromium() => Chromium(Environment.GetEnvironmentVariable, File.Exists, Directory.Exists, Directory.GetDirectories, OperatingSystem.IsWindows());

    public static string? Firefox()
    {
        // Playwright drives only its own Firefox build (Juggler); a system Firefox is no use
        return Find(Environment.GetEnvironmentVariable("ZT_FIREFOX"), Roots(Environment.GetEnvironmentVariable, OperatingSystem.IsWindows()),
            [("firefox", OperatingSystem.IsWindows() ? ["firefox/firefox.exe"] : ["firefox/firefox"])],
            File.Exists, Directory.Exists, Directory.GetDirectories);
    }

    internal static string? Chromium(Func<string, string?> env, Func<string, bool> fileExists, Func<string, bool> dirExists,
        Func<string, string, string[]> getDirs, bool windows)
    {
        (string, string[])[] layouts = windows
            ?
            [
                ("chromium", ["chrome-win64/chrome.exe", "chrome-win/chrome.exe"]),
                ("chromium_headless_shell", ["chrome-headless-shell-win64/chrome-headless-shell.exe", "chrome-win/headless_shell.exe"]),
            ]
            :
            [
                ("chromium", ["chrome-linux64/chrome", "chrome-linux/chrome"]),
                ("chromium_headless_shell", ["chrome-headless-shell-linux64/chrome-headless-shell", "chrome-headless-shell-linux-arm64/chrome-headless-shell", "chrome-linux/headless_shell"]),
            ];
        return Find(env("ZT_CHROMIUM"), Roots(env, windows), layouts, fileExists, dirExists, getDirs);
    }

    /// <summary>Bundled first, then an explicit Playwright folder, then Playwright's default cache.</summary>
    private static List<string> Roots(Func<string, string?> env, bool windows)
    {
        var roots = new List<string> { Path.Combine(AppContext.BaseDirectory, "browsers") };
        if (env("PLAYWRIGHT_BROWSERS_PATH") is { Length: > 0 } pw && pw != "0")
            roots.Add(pw);
        if (windows)
        {
            if (env("LOCALAPPDATA") is { Length: > 0 } local)
                roots.Add(Path.Combine(local, "ms-playwright"));
        }
        else if (env("XDG_CACHE_HOME") is { Length: > 0 } cache)
        {
            roots.Add(Path.Combine(cache, "ms-playwright"));
        }
        else if (env("HOME") is { Length: > 0 } home)
        {
            roots.Add(Path.Combine(home, ".cache", "ms-playwright"));
        }
        return roots;
    }

    private static string? Find(string? explicitPath, List<string> roots, (string Prefix, string[] Relative)[] layouts,
        Func<string, bool> fileExists, Func<string, bool> dirExists, Func<string, string, string[]> getDirs)
    {
        if (explicitPath is { Length: > 0 } && fileExists(explicitPath))
            return explicitPath;
        foreach (var root in roots.Where(dirExists))
        {
            foreach (var (prefix, relative) in layouts)
            {
                // chromium-1194, firefox-1543: the newest revision wins
                var dirs = getDirs(root, prefix + "*")
                    .Where(d => Path.GetFileName(d) == prefix || Path.GetFileName(d).StartsWith(prefix + "-", StringComparison.Ordinal))
                    .OrderByDescending(d => Revision(Path.GetFileName(d)));
                foreach (var d in dirs)
                {
                    foreach (var rel in relative)
                    {
                        var exe = Path.Combine(d, rel);
                        if (fileExists(exe))
                            return exe;
                    }
                }
            }
        }
        return null;
    }

    private static int Revision(string dir)
    {
        int dash = dir.LastIndexOf('-');
        return dash >= 0 && int.TryParse(dir.AsSpan(dash + 1), out var r) ? r : 0;
    }
}
