using ZapretAutoTuner.Agent.Os;

namespace ZapretAutoTuner.Agent.Tests;

public sealed class WinwsServiceTests
{
    [Fact]
    public void Relative_paths_become_absolute_under_the_service_directory()
    {
        var config = "--wf-tcp-out=443\n--lua-init=@lua/zapret-lib.lua\n--blob=tls_wl:@files/tls_wl.bin --blob=x:0x00\n--filter-tcp=443 --hostlist=lists/zt-tcp1.txt --lua-desync=fake:blob=tls_wl\n";
        var dir = Path.Combine(Path.GetTempPath(), "svc dir").Replace('\\', '/');
        var r = WinwsService.RewriteConfig(config, dir);
        Assert.Contains($"'--lua-init=@{dir}/lua/zapret-lib.lua'", r, StringComparison.Ordinal);
        Assert.Contains($"'--blob=tls_wl:@{dir}/files/tls_wl.bin'", r, StringComparison.Ordinal);
        Assert.Contains("--blob=x:0x00", r, StringComparison.Ordinal);
        Assert.Contains($"'--hostlist={dir}/lists/zt-tcp1.txt'", r, StringComparison.Ordinal);
        Assert.Contains("--lua-desync=fake:blob=tls_wl", r, StringComparison.Ordinal);
        // and the engine reads it back as one token each
        Assert.Contains($"--hostlist={dir}/lists/zt-tcp1.txt", WinwsService.Argv(r));
    }

    [Fact]
    public void A_windows_directory_comes_out_in_forward_slashes_that_wordexp_keeps()
    {
        var r = WinwsService.RewriteConfig("--hostlist=lists/zt-a.txt --out-range=<n2\n", @"C:\ProgramData\ZapretAutoTuner-service");
        var argv = WinwsService.Argv(r);
        Assert.Contains("--hostlist=C:/ProgramData/ZapretAutoTuner-service/lists/zt-a.txt", argv);
        Assert.Contains("--out-range=<n2", argv);
        Assert.Contains("'--out-range=<n2'", r, StringComparison.Ordinal);
    }

    [Fact]
    public void Files_from_outside_the_service_directory_are_refused()
    {
        var dir = Path.Combine(Path.GetTempPath(), "svc");
        var inside = Path.Combine(dir, "lists", "zt-a.txt");
        var home = Path.Combine(Path.GetTempPath(), "user", "x.lua");
        var bad = WinwsService.OutsideFiles(
        [
            "--hostlist=" + inside, "--lua-init=@" + home, "--blob=b:@" + Path.Combine(dir, "..", "evil.bin"),
            "--blob=c:0x00", "--ipset=relative.txt", "--writable", "--lua-desync=fake",
        ], dir);
        Assert.Equal(4, bad.Count);
        Assert.DoesNotContain("--hostlist=" + inside, bad);
    }

    [Fact]
    public void Only_export_files_are_accepted()
    {
        Assert.Null(WinwsService.CheckFiles(new Dictionary<string, byte[]> { ["zt-config.txt"] = [], ["lists/zt-a.txt"] = [], ["files/b.bin"] = [] }));
        Assert.NotNull(WinwsService.CheckFiles(new Dictionary<string, byte[]> { ["lists/a.txt"] = [] }));
        Assert.NotNull(WinwsService.CheckFiles(new Dictionary<string, byte[]> { ["zt-config.txt"] = [], ["../evil.exe"] = [] }));
        Assert.NotNull(WinwsService.CheckFiles(new Dictionary<string, byte[]> { ["zt-config.txt"] = [], ["lists/../../x"] = [] }));
        Assert.NotNull(WinwsService.CheckFiles(new Dictionary<string, byte[]> { ["zt-config.txt"] = [], ["winws2.exe"] = [] }));
    }
}
