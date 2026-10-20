using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json.Nodes;
using Microsoft.Win32;
using ZapretAutoTuner.Core.Programs;

namespace ZapretAutoTuner.Probes.Programs;

/// <summary>
/// The installed programs (PLAN 6.1). Windows: the Uninstall keys, Start Menu shortcuts and packaged apps; Linux: the
/// XDG desktop entries (system, user, Flatpak, Snap). Nothing here needs privileges.
/// </summary>
public static class ProgramCatalog
{
    public static async Task<List<ProgramInfo>> ListInstalledAsync(CancellationToken ct = default)
    {
        var all = new List<ProgramInfo>();
        if (OperatingSystem.IsWindows())
        {
            all.AddRange(FromUninstall());
            all.AddRange(FromStartMenu());
            all.AddRange(await FromPackagesAsync(ct).ConfigureAwait(false));
        }
        else
        {
            all.AddRange(FromDesktopEntries(DesktopDirectories()));
        }
        return ProgramInfo.Merge(all);
    }

    /// <summary>XDG application directories, user first (a user entry overrides a system one with the same name).</summary>
    public static List<string> DesktopDirectories()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var dataHome = Environment.GetEnvironmentVariable("XDG_DATA_HOME") is { Length: > 0 } h ? h : Path.Combine(home, ".local", "share");
        var dataDirs = (Environment.GetEnvironmentVariable("XDG_DATA_DIRS") is { Length: > 0 } d ? d : "/usr/local/share:/usr/share").Split(':', StringSplitOptions.RemoveEmptyEntries);
        return
        [
            Path.Combine(dataHome, "applications"),
            Path.Combine(dataHome, "flatpak", "exports", "share", "applications"),
            .. dataDirs.Select(x => Path.Combine(x, "applications")),
            "/var/lib/flatpak/exports/share/applications",
            "/var/lib/snapd/desktop/applications",
        ];
    }

    public static List<ProgramInfo> FromDesktopEntries(IEnumerable<string> directories)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var list = new List<ProgramInfo>();
        foreach (var dir in directories.Distinct(StringComparer.Ordinal).Where(Directory.Exists))
        {
            foreach (var file in Directory.EnumerateFiles(dir, "*.desktop", SearchOption.AllDirectories))
            {
                // the desktop file id: the same id in a later directory is shadowed
                if (!seen.Add(Path.GetRelativePath(dir, file)))
                    continue;
                try
                {
                    if (DesktopEntry.Parse(File.ReadAllText(file), file) is { } p)
                        list.Add(p with { Executable = ResolveOnPath(p.Executable!) });
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }
        return list;
    }

    /// <summary>A bare command name resolved through <c>$PATH</c>; paths stay as they are.</summary>
    public static string ResolveOnPath(string command)
    {
        if (command.Contains(Path.DirectorySeparatorChar, StringComparison.Ordinal) || command.Contains('/', StringComparison.Ordinal))
            return command;
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var full = Path.Combine(dir, command);
            if (File.Exists(full))
                return full;
            if (OperatingSystem.IsWindows() && File.Exists(full + ".exe"))
                return full + ".exe";
        }
        return command;
    }

    [SupportedOSPlatform("windows")]
    private static IEnumerable<ProgramInfo> FromUninstall()
    {
        const string key = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        foreach (var (hive, path) in new[] { (Registry.LocalMachine, key), (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"), (Registry.CurrentUser, key) })
        {
            using var root = hive.OpenSubKey(path);
            if (root is null)
                continue;
            foreach (var name in root.GetSubKeyNames())
            {
                using var k = root.OpenSubKey(name);
                if (k?.GetValue("DisplayName") is not string display || k.GetValue("SystemComponent") is 1)
                    continue;
                var icon = (k.GetValue("DisplayIcon") as string)?.Split(',')[0].Trim('"');
                var exe = icon is not null && icon.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !IsUninstaller(icon) ? icon : null;
                yield return new ProgramInfo { Id = exe ?? "uninstall:" + name, Name = display, Executable = exe, Source = ProgramSource.Uninstall, Icon = icon };
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static IEnumerable<ProgramInfo> FromStartMenu()
    {
        foreach (var dir in new[] { Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), Environment.GetFolderPath(Environment.SpecialFolder.Programs) })
        {
            if (!Directory.Exists(dir))
                continue;
            foreach (var lnk in Directory.EnumerateFiles(dir, "*.lnk", SearchOption.AllDirectories))
            {
                ShellLinkInfo? info;
                try
                {
                    info = ShellLink.Parse(File.ReadAllBytes(lnk));
                }
                catch (IOException)
                {
                    continue;
                }
                if (info?.Target is not { } target || !target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || IsUninstaller(target) || IsUninstaller(lnk))
                    continue;
                yield return new ProgramInfo
                {
                    Id = target,
                    Name = Path.GetFileNameWithoutExtension(lnk),
                    Executable = target,
                    Arguments = string.IsNullOrWhiteSpace(info.Arguments) ? [] : Core.Model.ArgTokenizer.Split(info.Arguments.Replace('\\', '/')),
                    Source = ProgramSource.StartMenu,
                    Icon = info.IconLocation,
                };
            }
        }
    }

    /// <summary>
    /// Packaged apps from <c>Get-StartApps</c> (their AUMID) joined with <c>Get-AppxPackage</c> (their folder, which
    /// is how the recorder finds their processes: they are started by the shell, not by us).
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static async Task<List<ProgramInfo>> FromPackagesAsync(CancellationToken ct)
    {
        const string script = "$p=@{}; Get-AppxPackage -PackageTypeFilter Main | ForEach-Object { $p[$_.PackageFamilyName]=$_.InstallLocation }; "
            + "Get-StartApps | Where-Object { $_.AppID -like '*!*' } | ForEach-Object { [pscustomobject]@{ Name=$_.Name; AppId=$_.AppID; Dir=$p[$_.AppID.Split('!')[0]] } } | ConvertTo-Json -Compress";
        var list = new List<ProgramInfo>();
        try
        {
            using var proc = Process.Start(new ProcessStartInfo("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script])
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (proc is null)
                return list;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            var json = await proc.StandardOutput.ReadToEndAsync(timeout.Token).ConfigureAwait(false);
            var node = JsonNode.Parse(json.Length == 0 ? "[]" : json);
            foreach (var x in node is JsonArray a ? a : new JsonArray(node))
            {
                if ((string?)x?["AppId"] is not { } aumid || (string?)x["Name"] is not { } name)
                    continue;
                list.Add(new ProgramInfo
                {
                    Id = aumid,
                    Name = name,
                    Executable = "explorer.exe",
                    Arguments = [$"shell:AppsFolder\\{aumid}"],
                    Source = ProgramSource.Uwp,
                    Icon = (string?)x["Dir"],
                });
            }
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or System.Text.Json.JsonException or OperationCanceledException or InvalidOperationException)
        {
            // no PowerShell, or it took too long: the other sources still list the program
        }
        return list;
    }

    private static bool IsUninstaller(string path) =>
        Path.GetFileName(path).Contains("unins", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(path).Contains("uninst", StringComparison.OrdinalIgnoreCase)
        || Path.GetFileName(path).Contains("удал", StringComparison.OrdinalIgnoreCase);
}
