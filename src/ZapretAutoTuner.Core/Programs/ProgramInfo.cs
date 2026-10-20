namespace ZapretAutoTuner.Core.Programs;

public enum ProgramSource
{
    /// <summary>Windows: HKLM/HKCU …\Uninstall.</summary>
    Uninstall,

    /// <summary>Windows: a shortcut in the Start Menu.</summary>
    StartMenu,

    /// <summary>Windows: a packaged (UWP/MSIX) app.</summary>
    Uwp,

    /// <summary>Linux: an XDG <c>.desktop</c> entry.</summary>
    Desktop,

    /// <summary>Linux: an executable on <c>$PATH</c>.</summary>
    Path,

    /// <summary>Chosen by the user as a file.</summary>
    File,
}

/// <summary>An installed program the user can pick as a target (PLAN 6.1).</summary>
public sealed record ProgramInfo
{
    /// <summary>Stable id: the executable path, or the package family for UWP.</summary>
    public required string Id { get; init; }

    public required string Name { get; init; }

    /// <summary>What to start; null when only the name is known (an uninstall entry without an executable).</summary>
    public string? Executable { get; init; }

    public IReadOnlyList<string> Arguments { get; init; } = [];

    public required ProgramSource Source { get; init; }

    public string? Icon { get; init; }

    /// <summary>
    /// The program's own folder when it is known apart from the executable: a packaged app's install location (it is
    /// started through <c>explorer.exe</c>), an uninstall entry's InstallLocation. The recorder takes processes
    /// started from here as the program's.
    /// </summary>
    public string? InstallDirectory { get; init; }

    public bool CanLaunch => Executable is not null;

    /// <summary>
    /// One list without duplicates: the same command (executable and arguments) found in several places is kept
    /// once, the most descriptive source first. The arguments are part of the identity: every packaged app starts as
    /// <c>explorer.exe shell:AppsFolder\…</c>, a Chrome web app is <c>chrome.exe --app-id=…</c>, a Flatpak is
    /// <c>flatpak run …</c>. A merged entry keeps an install folder another source knew.
    /// </summary>
    public static List<ProgramInfo> Merge(IEnumerable<ProgramInfo> all)
    {
        static int Rank(ProgramSource s) => s switch
        {
            ProgramSource.Desktop or ProgramSource.StartMenu => 0,
            ProgramSource.Uwp => 1,
            ProgramSource.Uninstall => 2,
            _ => 3,
        };
        var cmp = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        return all
            .GroupBy(p => p.Executable is null ? ("name:" + p.Name, "") : (p.Executable, string.Join('\0', p.Arguments)), new KeyComparer(cmp))
            .Select(g =>
            {
                var best = g.OrderBy(p => Rank(p.Source)).First();
                return best.InstallDirectory is null && g.FirstOrDefault(p => p.InstallDirectory is not null) is { } withDir
                    ? best with { InstallDirectory = withDir.InstallDirectory } : best;
            })
            .OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    /// <summary>The executable compared as a path of the platform, the arguments exactly.</summary>
    private sealed class KeyComparer(StringComparer exe) : IEqualityComparer<(string Exe, string Args)>
    {
        public bool Equals((string Exe, string Args) x, (string Exe, string Args) y) => exe.Equals(x.Exe, y.Exe) && string.Equals(x.Args, y.Args, StringComparison.Ordinal);

        public int GetHashCode((string Exe, string Args) k) => HashCode.Combine(exe.GetHashCode(k.Exe), StringComparer.Ordinal.GetHashCode(k.Args));
    }
}
