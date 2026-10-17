using ZapretAutoTuner.Core.Catalog;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>
/// The catalog is data copied from the zapret2 sources (AGENTS.md rule 3). It must match the bundled lua and
/// protocol.c exactly, and the check must notice when a function or an argument disappears.
/// </summary>
public sealed class CatalogSyncTests
{
    private static string LuaDir => Path.Combine(RepoPaths.Zapret2, "lua");

    private static string ProtocolC => File.ReadAllText(Path.Combine(RepoPaths.Zapret2, "nfq2", "protocol.c"));

    [Fact]
    public void Catalog_matches_the_bundled_zapret2()
    {
        var problems = CatalogVerifier.Verify(LuaCatalog.Default, LuaSourceIndex.FromDirectory(LuaDir), ProtocolC);
        Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems));
    }

    [Fact]
    public void Missing_function_is_detected()
    {
        var problems = VerifyMutated("zapret-antidpi.lua", t => t.Replace("function fakedsplit(ctx, desync)", "function fakedsplit_gone(ctx, desync)", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains("fakedsplit отсутствует", StringComparison.Ordinal));
    }

    [Fact]
    public void Missing_argument_is_detected()
    {
        // dht_dn reads desync.arg.dn and documents "-- arg : dn=N"; rename both.
        var problems = VerifyMutated("zapret-antidpi.lua", t => t.Replace("-- arg : dn=N", "-- arg : dnx=N", StringComparison.Ordinal).Replace("arg.dn", "arg.dnx", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains("dht_dn: аргумент dn не найден", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains("dnx", StringComparison.Ordinal));
    }

    [Fact]
    public void New_desync_function_is_detected()
    {
        var problems = VerifyMutated("zapret-antidpi.lua", t => t + "\nfunction brand_new(ctx, desync)\nend\n");
        Assert.Contains(problems, p => p.Contains("brand_new", StringComparison.Ordinal));
    }

    [Fact]
    public void Changed_standard_blocks_are_detected()
    {
        var problems = VerifyMutated("zapret-antidpi.lua", t => t.Replace("-- standard args : direction, payload\nfunction drop", "-- standard args : direction\nfunction drop", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.StartsWith("drop: стандартные блоки", StringComparison.Ordinal));
    }

    [Fact]
    public void Compat_version_change_is_detected()
    {
        var problems = VerifyMutated("zapret-lib.lua", t => t.Replace("NFQWS2_COMPAT_VER_REQUIRED=6", "NFQWS2_COMPAT_VER_REQUIRED=7", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains("NFQWS2_COMPAT_VER_REQUIRED=7", StringComparison.Ordinal));
    }

    [Fact]
    public void Protocol_name_change_is_detected()
    {
        var problems = CatalogVerifier.Verify(LuaCatalog.Default, LuaSourceIndex.FromDirectory(LuaDir), ProtocolC.Replace("\"mtproto_initial\",", "", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.StartsWith("l7payload_name", StringComparison.Ordinal));
    }

    [Fact]
    public void Lua_compat_constants_agree()
    {
        Assert.Equal(AppInfo.LuaCompatVersion, LuaCatalog.Default.Data.LuaCompat);
        Assert.Equal(AppInfo.Zapret2Version, LuaCatalog.Default.Data.Zapret2Version);
        Assert.Equal(["zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"], LuaCatalog.Default.Data.LuaInitOrder.Take(3));
    }

    private static List<string> VerifyMutated(string file, Func<string, string> mutate)
    {
        var dir = Directory.CreateTempSubdirectory("zt-lua-");
        try
        {
            foreach (var f in Directory.GetFiles(LuaDir, "*.lua"))
            {
                var text = File.ReadAllText(f).ReplaceLineEndings("\n");
                if (Path.GetFileName(f) == file)
                {
                    var changed = mutate(text);
                    Assert.NotEqual(text, changed);
                    text = changed;
                }
                File.WriteAllText(Path.Combine(dir.FullName, Path.GetFileName(f)), text);
            }
            return CatalogVerifier.Verify(LuaCatalog.Default, LuaSourceIndex.FromDirectory(dir.FullName), ProtocolC);
        }
        finally
        {
            dir.Delete(true);
        }
    }
}
