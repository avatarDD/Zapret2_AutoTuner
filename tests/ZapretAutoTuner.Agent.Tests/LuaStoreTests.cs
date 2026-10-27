using System.Text;
using ZapretAutoTuner.Agent.Engine;
using ZapretAutoTuner.Core.Engine;

namespace ZapretAutoTuner.Agent.Tests;

/// <summary>
/// User Lua (review H1): the engine never loads a Lua file from the user's folders. The UI sends the content, the
/// Agent writes it once into its own folder (0755 / 0644 on Linux, readable after nfqws2 drops root) and runs the
/// engine against the copy; a path outside the engine directory without content is refused.
/// </summary>
public class LuaStoreTests
{
    [Fact]
    public void User_lua_is_copied_into_the_agent_folder_and_the_argv_points_at_the_copy()
    {
        var dir = TestEnv.NewTempDir();
        var engineDir = Path.Combine(dir, "engine");
        Directory.CreateDirectory(Path.Combine(engineDir, "lua"));
        var store = new LuaStore(Path.Combine(dir, "agent", "lua-1"), engineDir);
        var bundled = Path.Combine(engineDir, "lua", "zapret-lib.lua");
        var user = Path.Combine(dir, "home", "zt-mine.lua");
        var content = Encoding.UTF8.GetBytes("function mine(ctx, desync) end\n");

        var argv = store.Prepare(["--lua-init=@" + bundled, "--lua-init=@" + user, "--filter-tcp=443"],
            new Dictionary<string, byte[]> { [user] = content });

        Assert.Equal("--lua-init=@" + bundled, argv[0]);
        var copy = argv[1]["--lua-init=@".Length..];
        Assert.StartsWith(store.Root, copy, StringComparison.Ordinal);
        Assert.Equal("zt-mine.lua", Path.GetFileName(copy));
        Assert.Equal(content, File.ReadAllBytes(copy));
        Assert.Equal("--filter-tcp=443", argv[2]);
        Assert.Empty(EngineArgvPolicy.Check(argv, [dir], luaRoots: store.AllowedRoots));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal((UnixFileMode)0b110_100_100, File.GetUnixFileMode(copy));
            Assert.Equal((UnixFileMode)0b111_101_101, File.GetUnixFileMode(Path.GetDirectoryName(copy)!));
            Assert.Equal((UnixFileMode)0b111_101_101, File.GetUnixFileMode(store.Root));
        }

        // a changed file on the user's side changes nothing: the copy is what runs
        Directory.CreateDirectory(Path.GetDirectoryName(user)!);
        File.WriteAllText(user, "os.execute('x')");
        Assert.Equal(content, File.ReadAllBytes(copy));

        store.Clear();
        Assert.False(Directory.Exists(store.Root));
    }

    [Fact]
    public void Lua_outside_the_engine_directory_without_content_is_refused()
    {
        var dir = TestEnv.NewTempDir();
        var store = new LuaStore(Path.Combine(dir, "agent", "lua-1"), Path.Combine(dir, "engine"));
        // the UI could not read it: an environment problem, not the strategy's fault (review 2)
        var e = Assert.Throws<EngineStartException>(() => store.Prepare(["--lua-init=@" + Path.Combine(dir, "zt-x.lua")], new Dictionary<string, byte[]>()));
        Assert.Equal("engine", e.Stage);
        var bad = Path.Combine(dir, "evil name.lua");
        Assert.Equal("policy", Assert.Throws<EngineStartException>(() => store.Prepare(["--lua-init=@" + bad], new Dictionary<string, byte[]> { [bad] = [1] })).Stage);
    }

    /// <summary>
    /// Review 2: nfqws2 reads blobs as root while parsing the options (nfqws.c load_blob_to_collection, before droproot),
    /// so a blob from the user's data directory is never read there: the UI sends it and the engine gets the copy.
    /// </summary>
    [Fact]
    public void Blob_outside_the_engine_directory_is_copied_and_its_offset_kept()
    {
        var dir = TestEnv.NewTempDir();
        var engineDir = Path.Combine(dir, "engine");
        var store = new LuaStore(Path.Combine(dir, "agent", "lua-x"), engineDir);
        var mine = Path.Combine(dir, "data", "fake.bin");
        var bundled = Path.Combine(engineDir, "files", "fake", "tls.bin");
        var argv = store.Prepare(["--blob=a:@" + mine, "--blob=b:+5@" + mine, "--blob=c:@" + bundled, "--blob=d:0x0102"],
            new Dictionary<string, byte[]> { [mine] = [1, 2, 3, 4, 5, 6, 7] });
        Assert.StartsWith("--blob=a:@" + store.Root, argv[0], StringComparison.Ordinal);
        Assert.StartsWith("--blob=b:+5@" + store.Root, argv[1], StringComparison.Ordinal);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7 }, File.ReadAllBytes(argv[0]["--blob=a:@".Length..]));
        Assert.Equal("--blob=c:@" + bundled, argv[2]);
        Assert.Equal("--blob=d:0x0102", argv[3]);
        Assert.Empty(EngineArgvPolicy.Check(argv, [Path.Combine(dir, "data")], store.AllowedRoots));

        var e = Assert.Throws<EngineStartException>(() => store.Prepare(["--blob=a:@" + Path.Combine(dir, "data", "other.bin")], new Dictionary<string, byte[]>()));
        Assert.Equal("engine", e.Stage);
    }

    [Fact]
    public void The_store_prunes_copies_no_engine_uses_and_refuses_when_full()
    {
        var dir = TestEnv.NewTempDir();
        var engineDir = Path.Combine(dir, "engine");
        var used = new List<string>();
        var store = new LuaStore(Path.Combine(dir, "agent", "lua-x"), engineDir, () => used) { StoreFoldersCap = 2, Grace = TimeSpan.Zero };
        string Copy(byte b)
        {
            var f = Path.Combine(dir, "data", $"b{b}.bin");
            return store.Prepare(["--blob=x:@" + f], new Dictionary<string, byte[]> { [f] = [b] })[0]["--blob=x:@".Length..];
        }
        var first = Copy(1);
        used.Add(first);
        var second = Copy(2);
        // full: the second (unused) goes, the first (a running engine has it) stays
        var third = Copy(3);
        Assert.True(File.Exists(first));
        Assert.False(File.Exists(second));
        Assert.True(File.Exists(third));
        used.Add(third);
        Assert.Equal("engine", Assert.Throws<EngineStartException>(() => Copy(4)).Stage);
    }

    /// <summary>Review 2: a folder of a gone Agent goes, a live one stays; the owner is the pid and its start time.</summary>
    [Fact]
    public void Stale_folders_are_those_whose_owner_is_not_alive()
    {
        var dir = TestEnv.NewTempDir();
        var parent = Path.Combine(dir, "agent");
        var store = new LuaStore(Path.Combine(parent, "lua-" + Guid.NewGuid().ToString("N")), Path.Combine(dir, "engine"));
        var f = Path.Combine(dir, "zt-a.lua");
        store.Prepare(["--lua-init=@" + f], new Dictionary<string, byte[]> { [f] = [1] });
        using var self = System.Diagnostics.Process.GetCurrentProcess();
        string Folder(string name, string? owner)
        {
            var d = Path.Combine(parent, name);
            Directory.CreateDirectory(d);
            if (owner is not null)
                File.WriteAllText(Path.Combine(d, "owner"), owner);
            return d;
        }
        var live = Folder("lua-live", LuaStore.OwnerText(Environment.ProcessId, self.StartTime.ToUniversalTime()));
        var recycled = Folder("lua-recycled", LuaStore.OwnerText(Environment.ProcessId, self.StartTime.ToUniversalTime().AddHours(-1)));
        var garbage = Folder("lua-garbage", "x");
        var fresh = Folder("lua-fresh", null);
        store.RemoveStale();
        Assert.True(Directory.Exists(store.Root));
        Assert.True(Directory.Exists(live));
        Assert.True(Directory.Exists(fresh));
        Assert.False(Directory.Exists(recycled));
        Assert.False(Directory.Exists(garbage));
    }

    [Fact]
    public void Default_root_name_is_unpredictable()
    {
        Assert.NotEqual(LuaStore.DefaultRoot("/tmp/x"), LuaStore.DefaultRoot("/tmp/x"));
        Assert.Matches("^lua-[0-9a-f]{32}$", Path.GetFileName(LuaStore.DefaultRoot("/tmp/x")));
    }

    /// <summary>Review 2: the engine opens and chowns written files as root; a symlink on their way is refused.</summary>
    [Fact]
    public void Written_paths_through_a_symlink_are_refused()
    {
        if (OperatingSystem.IsWindows())
            return;
        var dir = TestEnv.NewTempDir();
        var data = Path.Combine(dir, "data");
        Directory.CreateDirectory(data);
        File.CreateSymbolicLink(Path.Combine(data, "log.txt"), "/etc/passwd");
        Directory.CreateSymbolicLink(Path.Combine(data, "lists"), "/etc");
        Assert.Single(EngineManager.LinkProblems(["--debug=@" + Path.Combine(data, "log.txt")], [data]));
        Assert.Single(EngineManager.LinkProblems(["--hostlist-auto=" + Path.Combine(data, "lists", "auto.txt")], [data]));
        Assert.Empty(EngineManager.LinkProblems(["--hostlist-auto=" + Path.Combine(data, "auto.txt"), "--debug=1"], [data]));
    }

    [Fact]
    public void Policy_refuses_lua_outside_the_allowed_roots()
    {
        var root = Path.Combine(Path.GetTempPath(), "zt-policy");
        var problems = EngineArgvPolicy.Check(["--lua-init=@" + Path.Combine(Path.GetTempPath(), "home", "zt-x.lua")], [root], luaRoots: [root]);
        Assert.Single(problems);
        Assert.Empty(EngineArgvPolicy.Check(["--lua-init=return 1"], [root], luaRoots: [root]));
    }
}
