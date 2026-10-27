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
        var e = Assert.Throws<EngineStartException>(() => store.Prepare(["--lua-init=@" + Path.Combine(dir, "zt-x.lua")], new Dictionary<string, byte[]>()));
        Assert.Equal("policy", e.Stage);
        var bad = Path.Combine(dir, "evil name.lua");
        Assert.Throws<EngineStartException>(() => store.Prepare(["--lua-init=@" + bad], new Dictionary<string, byte[]> { [bad] = [1] }));
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
