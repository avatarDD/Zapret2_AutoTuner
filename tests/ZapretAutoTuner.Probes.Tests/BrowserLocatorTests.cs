using ZapretAutoTuner.Probes.Browser;

namespace ZapretAutoTuner.Probes.Tests;

/// <summary>Where the browser for the L3 check comes from, on a made-up file system.</summary>
public sealed class BrowserLocatorTests
{
    private sealed class FakeFs(params string[] files)
    {
        private readonly HashSet<string> _files = files.Select(Norm).ToHashSet();

        public Dictionary<string, string?> Env { get; } = new();

        private static string Norm(string p) => p.Replace('\\', '/');

        public bool FileExists(string p) => _files.Contains(Norm(p));

        public bool DirExists(string p) => _files.Any(f => f.StartsWith(Norm(p).TrimEnd('/') + "/", StringComparison.Ordinal));

        public string[] GetDirs(string root, string pattern)
        {
            var prefix = pattern.TrimEnd('*');
            var r = Norm(root).TrimEnd('/') + "/";
            return _files.Where(f => f.StartsWith(r, StringComparison.Ordinal))
                .Select(f => f[r.Length..].Split('/')[0])
                .Where(d => d.StartsWith(prefix, StringComparison.Ordinal))
                .Distinct().Select(d => r + d).ToArray();
        }

        public string? Find(bool windows) => BrowserLocator.Chromium(k => Env.GetValueOrDefault(k), FileExists, DirExists, GetDirs, windows);
    }

    [Fact]
    public void The_users_own_browsers_are_never_picked()
    {
        var fs = new FakeFs(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe");
        fs.Env["ProgramFiles"] = @"C:\Program Files";
        fs.Env["ProgramFiles(x86)"] = @"C:\Program Files (x86)";
        Assert.Null(fs.Find(windows: true));
        Assert.Null(new FakeFs("/usr/bin/chromium", "/opt/google/chrome/chrome").Find(windows: false));
    }

    [Fact]
    public void The_headless_shell_from_the_playwright_cache_is_found_on_windows()
    {
        var fs = new FakeFs(@"C:\Users\u\AppData\Local\ms-playwright\chromium_headless_shell-1243\chrome-headless-shell-win64\chrome-headless-shell.exe");
        fs.Env["LOCALAPPDATA"] = @"C:\Users\u\AppData\Local";
        Assert.EndsWith("chrome-headless-shell.exe", fs.Find(windows: true));
    }

    [Fact]
    public void The_newest_revision_in_the_playwright_cache_is_taken()
    {
        var fs = new FakeFs(
            "/home/u/.cache/ms-playwright/chromium_headless_shell-1200/chrome-headless-shell-linux64/chrome-headless-shell",
            "/home/u/.cache/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell");
        fs.Env["HOME"] = "/home/u";
        Assert.Equal("/home/u/.cache/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell", fs.Find(windows: false)?.Replace('\\', '/'));
    }

    [Fact]
    public void The_arm64_headless_shell_is_found()
    {
        var fs = new FakeFs("/home/u/.cache/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-linux-arm64/chrome-headless-shell");
        fs.Env["HOME"] = "/home/u";
        Assert.EndsWith("chrome-headless-shell-linux-arm64/chrome-headless-shell", fs.Find(windows: false)?.Replace('\\', '/'));
    }

    [Fact]
    public void Explicit_path_wins_and_nothing_found_is_null()
    {
        var fs = new FakeFs("/opt/my/chrome");
        fs.Env["ZT_CHROMIUM"] = "/opt/my/chrome";
        Assert.Equal("/opt/my/chrome", fs.Find(windows: false));
        Assert.Null(new FakeFs().Find(windows: false));
        Assert.Null(new FakeFs().Find(windows: true));
    }

    [Fact]
    public async Task A_missing_browser_is_reported_in_plain_words()
    {
        var e = await Assert.ThrowsAsync<BrowserNotFoundException>(() =>
            BrowserProbe.RunAsync(new BrowserProbeOptions { Url = "https://example.test/", ExecutablePath = Path.Combine(Path.GetTempPath(), "no-such-browser", "chrome") }));
        Assert.Contains("ZapretAutoTuner", e.Message);
        Assert.Contains("ZT_CHROMIUM", e.Message);
    }
}
