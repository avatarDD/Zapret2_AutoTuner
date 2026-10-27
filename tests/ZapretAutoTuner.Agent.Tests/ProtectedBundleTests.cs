using System.Text.Json.Nodes;
using ZapretAutoTuner.Agent.Engine;
using ZapretAutoTuner.Tools;

namespace ZapretAutoTuner.Agent.Tests;

/// <summary>Final review 9: a privileged Agent runs a bundle others can write only from its verified copy.</summary>
public sealed class ProtectedBundleTests
{
    /// <summary>The engine file the bundle check looks for on this platform.</summary>
    private static readonly string Eng = OperatingSystem.IsWindows() ? "winws2.exe" : "nfqws2";

    private static string Bundle(Action<string, JsonObject>? tweak = null)
    {
        var dir = TestEnv.NewTempDir();
        Directory.CreateDirectory(Path.Combine(dir, "lua"));
        File.WriteAllText(Path.Combine(dir, Eng), "#!/bin/sh\necho engine\n");
        File.WriteAllText(Path.Combine(dir, "lua", "zapret-lib.lua"), "-- lib\n");
        var files = new JsonObject
        {
            [Eng] = Zapret2Bundle.Sha256File(Path.Combine(dir, Eng)),
            ["lua/zapret-lib.lua"] = Zapret2Bundle.Sha256File(Path.Combine(dir, "lua", "zapret-lib.lua")),
        };
        var manifest = new JsonObject { ["tag"] = "v1", ["version"] = "1", ["rid"] = "linux-x64", ["lua_compat"] = Core.AppInfo.LuaCompatVersion, ["files"] = files };
        tweak?.Invoke(dir, manifest);
        File.WriteAllText(Path.Combine(dir, "bundle.json"), manifest.ToJsonString());
        return dir;
    }

    [Fact]
    public void AVerifiedCopyIsMade()
    {
        var src = Bundle();
        var dst = TestEnv.NewTempDir();
        ProtectedBundle.CopyAndVerify(src, dst, Eng);
        Assert.Equal("-- lib\n", File.ReadAllText(Path.Combine(dst, "lua", "zapret-lib.lua")));
        Assert.True(File.Exists(Path.Combine(dst, "bundle.json")));
        if (!OperatingSystem.IsWindows())
            Assert.True(File.GetUnixFileMode(Path.Combine(dst, Eng)).HasFlag(UnixFileMode.UserExecute));
    }

    [Fact]
    public void ATamperedFileOrAMissingManifestIsRefused()
    {
        var src = Bundle((dir, _) => File.WriteAllText(Path.Combine(dir, Eng), "#!/bin/sh\nevil\n"));
        var e = Assert.Throws<EngineStartException>(() => ProtectedBundle.CopyAndVerify(src, TestEnv.NewTempDir(), Eng));
        Assert.Equal("engine", e.Stage);
        Assert.Contains(e.Problems, p => p.Contains(Eng, StringComparison.Ordinal));

        var none = Bundle();
        File.Delete(Path.Combine(none, "bundle.json"));
        Assert.Equal("engine", Assert.Throws<EngineStartException>(() => ProtectedBundle.CopyAndVerify(none, TestEnv.NewTempDir(), Eng)).Stage);

        var escape = Bundle((_, m) => m["files"]!["../outside"] = new string('0', 64));
        Assert.Contains(Assert.Throws<EngineStartException>(() => ProtectedBundle.CopyAndVerify(escape, TestEnv.NewTempDir(), Eng)).Problems,
            p => p.Contains("../outside", StringComparison.Ordinal));
    }

    [Fact]
    public void OwnersAndModesUpThePathDecide()
    {
        var stat = new Dictionary<string, (int Uid, int Mode)>
        {
            ["/opt/zt/zapret2"] = (0, 0x1ED),       // 0755
            ["/opt/zt/zapret2/nfqws2"] = (0, 0x1ED),
            ["/opt/zt"] = (0, 0x1ED),
            ["/opt"] = (0, 0x1ED),
            ["/"] = (0, 0x1ED),
        };
        List<string> Check() => ProtectedBundle.UnixProblems(["/opt/zt/zapret2"], ["/opt/zt/zapret2/nfqws2"], ["/opt/zt", "/opt", "/"], _ => stat);
        Assert.Empty(Check());
        stat["/opt"] = (0, 0x3FF);                  // 1777: sticky ancestor such as /tmp
        Assert.Empty(Check());
        stat["/opt/zt"] = (1000, 0x1ED);            // the user's folder up the path
        Assert.Contains(Check(), p => p.Contains("/opt/zt:", StringComparison.Ordinal));
        stat["/opt/zt"] = (0, 0x1FD);               // 0775: group-writable
        Assert.Contains(Check(), p => p.Contains("group", StringComparison.Ordinal));
        stat["/opt/zt"] = (0, 0x1ED);
        stat["/opt/zt/zapret2"] = (0, 0x3FF);       // sticky is not enough for the bundle's own folder
        Assert.NotEmpty(Check());
    }

    [Fact]
    public void ARealFolderWritableByOthersIsFound()
    {
        if (!OperatingSystem.IsLinux() || !TestEnv.IsRootLinux)
            return;
        var dir = Bundle();
        File.SetUnixFileMode(dir, (UnixFileMode)0x1ED);
        Assert.Empty(ProtectedBundle.WritableByOthers(dir, "nfqws2"));
        File.SetUnixFileMode(Path.Combine(dir, "lua"), (UnixFileMode)0x1FF);
        Assert.Contains(ProtectedBundle.WritableByOthers(dir, "nfqws2"), p => p.Contains("lua", StringComparison.Ordinal));
    }
}
