namespace ZapretAutoTuner.Probes.Browser;

/// <summary>
/// Finds the browsers for <see cref="BrowserProbe"/>: an explicit path from the environment, the copy bundled next to
/// the app (<c>browsers/</c>), or a Playwright install. Null lets Playwright use its own default.
/// </summary>
public static class BrowserLocator
{
    public static string? Chromium() => Find("ZT_CHROMIUM", "chromium", OperatingSystem.IsWindows()
        ? ["chrome-win64/chrome.exe", "chrome-win/chrome.exe"]
        : ["chrome-linux64/chrome", "chrome-linux/chrome"]);

    public static string? Firefox() => Find("ZT_FIREFOX", "firefox", OperatingSystem.IsWindows()
        ? ["firefox/firefox.exe"]
        : ["firefox/firefox"]);

    private static string? Find(string env, string prefix, string[] relative)
    {
        if (Environment.GetEnvironmentVariable(env) is { Length: > 0 } explicitPath && File.Exists(explicitPath))
            return explicitPath;
        var roots = new List<string> { Path.Combine(AppContext.BaseDirectory, "browsers") };
        if (Environment.GetEnvironmentVariable("PLAYWRIGHT_BROWSERS_PATH") is { Length: > 0 } pw)
            roots.Add(pw);
        foreach (var root in roots.Where(Directory.Exists))
        {
            // chromium-1194, firefox-1543: the newest revision wins
            var dirs = Directory.GetDirectories(root, prefix + "*")
                .Where(d => Path.GetFileName(d) == prefix || Path.GetFileName(d).StartsWith(prefix + "-", StringComparison.Ordinal))
                .OrderByDescending(d => Revision(Path.GetFileName(d)));
            foreach (var d in dirs)
            {
                foreach (var rel in relative)
                {
                    var exe = Path.Combine(d, rel);
                    if (File.Exists(exe))
                        return exe;
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
