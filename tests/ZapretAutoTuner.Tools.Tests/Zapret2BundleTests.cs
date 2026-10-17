using System.Text.Json;

namespace ZapretAutoTuner.Tools.Tests;

public sealed class Zapret2BundleTests : IDisposable
{
    private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("zt-bundle-");

    public void Dispose() => _dir.Delete(true);

    [Theory]
    [InlineData("github version v1.0.6 (a1adf7b) lua_compat_ver 6", "1.0.6", 6)]
    [InlineData("self-built version Oct  4 2026 10:18:18 lua_compat_ver 6", null, 6)]
    [InlineData("garbage", null, null)]
    public void Parses_engine_version(string output, string? version, int? compat)
    {
        var v = Zapret2Bundle.ParseVersion(output);
        Assert.Equal(version, v.Version);
        Assert.Equal(compat, v.LuaCompat);
    }

    [Fact]
    public void Verify_reports_missing_and_changed_files()
    {
        var b = MakeBundle();
        Assert.True(b.Verify().Ok, string.Join("; ", b.Verify().Problems));

        File.WriteAllText(Path.Combine(b.LuaDir, "zapret-auto.lua"), "-- tampered");
        File.Delete(Path.Combine(b.FakeDir, "stun.bin"));
        var check = b.Verify();
        Assert.False(check.Ok);
        Assert.Contains(check.Problems, p => p.Contains("zapret-auto.lua изменён", StringComparison.Ordinal));
        Assert.Contains(check.Problems, p => p.Contains("stun.bin пропал", StringComparison.Ordinal));
    }

    [Fact]
    public void Verify_reports_wrong_lua_compat()
    {
        var b = MakeBundle(compat: 7);
        Assert.Contains(b.Verify().Problems, p => p.Contains("NFQWS2_COMPAT_VER 7", StringComparison.Ordinal));
    }

    [Fact]
    public void Missing_bundle_is_reported()
    {
        var b = new Zapret2Bundle(Path.Combine(_dir.FullName, "none"));
        var check = b.Verify();
        Assert.False(check.Ok);
        Assert.Contains(check.Problems, p => p.Contains("не найден движок", StringComparison.Ordinal));
    }

    private Zapret2Bundle MakeBundle(int compat = 6)
    {
        var b = new Zapret2Bundle(_dir.FullName);
        Directory.CreateDirectory(b.LuaDir);
        Directory.CreateDirectory(b.FakeDir);
        File.WriteAllText(b.EnginePath, "engine");
        File.WriteAllText(Path.Combine(b.LuaDir, "zapret-lib.lua"), $"NFQWS2_COMPAT_VER_REQUIRED={compat}\n");
        File.WriteAllText(Path.Combine(b.LuaDir, "zapret-auto.lua"), "-- auto");
        File.WriteAllBytes(Path.Combine(b.FakeDir, "stun.bin"), [1, 2, 3]);
        var files = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var f in Directory.GetFiles(_dir.FullName, "*", SearchOption.AllDirectories))
            files[Path.GetRelativePath(_dir.FullName, f).Replace('\\', '/')] = Zapret2Bundle.Sha256File(f);
        var manifest = new { tag = "v1.0.6", version = "1.0.6", rid = "linux-x64", lua_compat = 6, source_sha256 = "x", files };
        File.WriteAllText(b.ManifestPath, JsonSerializer.Serialize(manifest));
        return b;
    }
}
