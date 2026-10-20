using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Probes.Programs;

namespace ZapretAutoTuner.Probes.Tests;

/// <summary>Process trees and the installed program list (PLAN 6.1–6.2).</summary>
public sealed class ProgramDiscoveryTests
{
    [Theory]
    [InlineData("1 (systemd) S 0 1 1 0 -1 4194560", 0)]
    [InlineData("1234 (Web Content) S 42 1234 1234 0", 42)]
    [InlineData("777 (a) b) (c) R 9 777 777", 9)]
    [InlineData("88 ()) S 7 88", 7)]
    public void Stat_parent_survives_spaces_and_parentheses_in_comm(string stat, int parent) =>
        Assert.Equal(parent, ProcessTree.ParseStatParent(stat));

    [Theory]
    [InlineData("")]
    [InlineData("1234 no parentheses S 1")]
    [InlineData("5 (x)")]
    [InlineData("5 (x) S")]
    [InlineData("5 (x) S -1")]
    public void Odd_stat_gives_no_parent(string stat) => Assert.Null(ProcessTree.ParseStatParent(stat));

    [Fact]
    public void Closure_is_the_root_and_all_its_descendants()
    {
        var parents = new Dictionary<int, int> { [0] = 0, [1] = 0, [10] = 1, [11] = 10, [12] = 10, [13] = 12, [20] = 1, [30] = 99 };
        Assert.Equal(new HashSet<int> { 10, 11, 12, 13 }, ProcessTree.Closure(10, parents));
        Assert.Equal(new HashSet<int> { 20 }, ProcessTree.Closure(20, parents));
        // a self-parented pid 0 does not loop
        Assert.Equal(parents.Keys.Where(k => k != 30).ToHashSet(), ProcessTree.Closure(0, parents));
    }

    [Fact]
    public void Closure_drops_a_root_that_exited_but_keeps_its_children()
    {
        var parents = new Dictionary<int, int> { [6] = 5, [7] = 6, [8] = 1 };
        Assert.Equal(new HashSet<int> { 6, 7 }, ProcessTree.Closure(5, parents));
        Assert.Empty(ProcessTree.Closure(4, parents));
    }

    [Fact]
    public void Closure_terminates_on_a_cycle()
    {
        var parents = new Dictionary<int, int> { [7] = 8, [8] = 7 };
        Assert.Equal(new HashSet<int> { 7, 8 }, ProcessTree.Closure(7, parents));
    }

    [Theory]
    [InlineData("1234 (Web Content) S 42 1234 1234 0 -1 4194304 100 0 0 0 5 3 0 0 20 0 4 0 987654 1000 10", 987654L)]
    [InlineData("777 (a) b) (c) R 9 777 777 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 55 0 0", 55L)]
    public void Stat_start_time_is_field_22(string stat, long start) => Assert.Equal(start, ProcessTree.ParseStatStart(stat));

    [Fact]
    public void Stat_without_start_time_gives_null() => Assert.Null(ProcessTree.ParseStatStart("5 (x) S 1 5 5"));

    private static Dictionary<int, ProcessEntry> Snap(params (int Pid, int Parent, long Start)[] list) =>
        list.ToDictionary(x => x.Pid, x => new ProcessEntry(x.Pid, x.Parent, x.Start));

    [Fact]
    public void Keyed_closure_follows_children_that_started_after_their_parent()
    {
        var snap = Snap((10, 1, 100), (11, 10, 110), (12, 11, 120), (13, 10, 50));
        // 13 claims parent 10 but is older: its real parent had pid 10 before
        Assert.Equal(new HashSet<int> { 10, 11, 12 }, ProcessTree.Closure(new ProcessKey(10, 100), snap).Select(k => k.Pid).ToHashSet());
    }

    [Fact]
    public void Keyed_closure_ignores_a_reused_root_pid()
    {
        // the root (10, started at 100) exited; its orphan 11 stays; pid 10 is now another program with its own child
        var snap = Snap((10, 1, 500), (11, 10, 110), (14, 10, 510));
        var keys = ProcessTree.Closure(new ProcessKey(10, 100), snap);
        Assert.Equal(new HashSet<ProcessKey> { new(11, 110) }, keys);
        Assert.Empty(ProcessTree.Alive([new ProcessKey(10, 100)], snap));
        Assert.Equal([new ProcessKey(11, 110)], ProcessTree.Alive([new ProcessKey(11, 110), new ProcessKey(12, 1)], snap));
        // an unknown start time matches any process with the pid
        Assert.Single(ProcessTree.Alive([new ProcessKey(10, 0)], snap));
    }

    [Fact]
    public void Image_cache_reads_each_process_once_and_again_after_pid_reuse()
    {
        var root = OperatingSystem.IsWindows() ? @"C:\Apps\Game" : "/opt/game";
        var paths = new Dictionary<int, string> { [1] = Path.Combine(root, "game.exe"), [2] = OperatingSystem.IsWindows() ? @"C:\Apps\Other\x.exe" : "/opt/other/x", [3] = Path.Combine(root, "sub", "helper") };
        var cache = new ProcessImageCache(pid => paths.GetValueOrDefault(pid));
        var snap = Snap((1, 0, 10), (2, 0, 20), (3, 1, 30));
        Assert.Equal(new HashSet<int> { 1, 3 }, cache.UnderDirectory(root, snap));
        Assert.Equal(3, cache.Reads);
        Assert.Equal(new HashSet<int> { 1, 3 }, cache.UnderDirectory(root, snap));
        Assert.Equal(3, cache.Reads); // nothing read again
        paths[3] = "/elsewhere/x";
        var reused = Snap((1, 0, 10), (2, 0, 20), (3, 2, 99));
        Assert.Equal(new HashSet<int> { 1 }, cache.UnderDirectory(root, reused));
        Assert.Equal(4, cache.Reads);
    }

    [Fact]
    public void Own_process_has_a_start_time_and_an_image()
    {
        var key = ProcessTree.KeyOf(Environment.ProcessId);
        Assert.NotNull(key);
        Assert.NotEqual(0, key.Value.Start);
        Assert.Contains(key.Value, ProcessTree.Alive([key.Value]));
        Assert.False(string.IsNullOrEmpty(ProcessTree.ImagePath(Environment.ProcessId)));
    }

    [Fact]
    public void Own_process_is_in_its_tree()
    {
        var parents = ProcessTree.Parents();
        Assert.Contains(Environment.ProcessId, parents.Keys);
        Assert.Contains(Environment.ProcessId, ProcessTree.Descendants(Environment.ProcessId));
    }

    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("ztuner-desktop-").FullName;

        public string Write(string relative, string text)
        {
            var full = System.IO.Path.Combine(Path, relative);
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
            File.WriteAllText(full, text);
            return full;
        }

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }

    private static string Entry(string name, string exec, string extra = "") =>
        $"[Desktop Entry]\nType=Application\nName={name}\nExec={exec}\n{extra}\n";

    [Fact]
    public void Desktop_entries_user_first_hidden_skipped_recursive()
    {
        using var user = new TempDir();
        using var system = new TempDir();
        var userA = user.Write("app-a.desktop", Entry("A (user)", "/opt/a/a --user %U"));
        system.Write("app-a.desktop", Entry("A (system)", "/opt/a/a"));
        system.Write(Path.Combine("vendor", "app-b.desktop"), Entry("B", "\"/opt/b app/b\" %F"));
        system.Write("hidden.desktop", Entry("Hidden", "/opt/h", "Hidden=true"));
        system.Write("nodisplay.desktop", Entry("NoDisplay", "/opt/n", "NoDisplay=true"));
        system.Write("link.desktop", "[Desktop Entry]\nType=Link\nName=L\nURL=https://example.com\n");
        system.Write("readme.txt", Entry("Txt", "/opt/t"));

        var list = ProgramCatalog.FromDesktopEntries([user.Path, Path.Combine(user.Path, "missing"), system.Path, user.Path]);

        Assert.Equal(["A (user)", "B"], list.Select(p => p.Name).Order(StringComparer.Ordinal));
        var a = list.Single(p => p.Name == "A (user)");
        Assert.Equal(userA, a.Id);
        Assert.Equal("/opt/a/a", a.Executable);
        Assert.Equal(["--user"], a.Arguments);
        Assert.Equal(ProgramSource.Desktop, a.Source);
        var b = list.Single(p => p.Name == "B");
        Assert.Equal("/opt/b app/b", b.Executable);
        Assert.Empty(b.Arguments);
    }

    [Fact]
    public void Bare_commands_resolve_through_path()
    {
        using var bin = new TempDir();
        var tool = bin.Write("ztuner-fake-tool", "#!/bin/sh\n");
        var oldPath = Environment.GetEnvironmentVariable("PATH");
        Assert.Equal("/abs/tool", ProgramCatalog.ResolveOnPath("/abs/tool"));
        Assert.Equal("dir/tool", ProgramCatalog.ResolveOnPath("dir/tool"));
        Assert.Equal("ztuner-no-such-command", ProgramCatalog.ResolveOnPath("ztuner-no-such-command"));

        using var apps = new TempDir();
        apps.Write("t.desktop", Entry("T", "ztuner-fake-tool --x"));
        try
        {
            Environment.SetEnvironmentVariable("PATH", bin.Path + Path.PathSeparator + oldPath);
            Assert.Equal(tool, ProgramCatalog.ResolveOnPath("ztuner-fake-tool"));
            Assert.Equal(tool, Assert.Single(ProgramCatalog.FromDesktopEntries([apps.Path])).Executable);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PATH", oldPath);
        }
    }

    [Fact]
    public void Desktop_directories_put_the_user_first()
    {
        var dirs = ProgramCatalog.DesktopDirectories();
        Assert.True(dirs.Count >= 4);
        Assert.All(dirs, d => Assert.EndsWith("applications", d, StringComparison.Ordinal));
        Assert.Contains("/var/lib/snapd/desktop/applications", dirs);
    }
}
