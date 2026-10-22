using System.Diagnostics;

namespace ZapretAutoTuner.Tools.Tests;

/// <summary>The release packaging: versions dpkg and rpm accept, the polkit rule, what the uninstaller may kill.</summary>
public sealed class PackagingTests
{
    private static string Root([System.Runtime.CompilerServices.CallerFilePath] string here = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(here)!, "..", ".."));

    private static string Packaging(params string[] parts) => Path.Combine([Root(), "packaging", .. parts]);

    [Theory]
    [InlineData("1.2.0", "1.2.0")]
    [InlineData("v1.2.0", "1.2.0")]
    [InlineData("1.2.0-rc.1", "1.2.0~rc.1")]
    [InlineData("0.0.0-test-2", "0.0.0~test~2")]
    public void Prerelease_versions_sort_before_the_release_in_deb_and_rpm(string version, string expected)
    {
        if (OperatingSystem.IsWindows())
            return; // the Linux packages are built on Linux
        var psi = new ProcessStartInfo("bash") { RedirectStandardOutput = true, UseShellExecute = false };
        psi.ArgumentList.Add(Packaging("linux", "pkgversion.sh"));
        psi.ArgumentList.Add(version);
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd().Trim();
        p.WaitForExit();
        Assert.Equal(0, p.ExitCode);
        Assert.Equal(expected, output);
    }

    [Fact]
    public void Polkit_asks_every_time()
    {
        var policy = File.ReadAllText(Packaging("linux", "org.zapret.autotuner.policy"));
        Assert.DoesNotContain(">auth_admin_keep<", policy, StringComparison.Ordinal);
        Assert.Contains("<allow_active>auth_admin</allow_active>", policy, StringComparison.Ordinal);
    }

    [Fact]
    public void Release_1_has_no_appimage()
    {
        Assert.DoesNotContain("APPIMAGETOOL", File.ReadAllText(Packaging("linux", "build.sh")), StringComparison.Ordinal);
        Assert.DoesNotContain("appimagetool", File.ReadAllText(Path.Combine(Root(), ".github", "workflows", "release.yml")), StringComparison.Ordinal);
    }

    [Fact]
    public void Uninstaller_kills_only_our_processes()
    {
        var iss = File.ReadAllText(Packaging("windows", "autotuner.iss"));
        Assert.DoesNotContain("/IM winws2.exe", iss, StringComparison.Ordinal);
        Assert.Contains("$_.Path.StartsWith($d", iss, StringComparison.Ordinal);
    }
}
