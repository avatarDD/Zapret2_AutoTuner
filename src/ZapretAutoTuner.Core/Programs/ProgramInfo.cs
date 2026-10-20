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

    public bool CanLaunch => Executable is not null;

    /// <summary>One list without duplicates: the same executable found in several places is kept once, the
    /// most descriptive source first (a shortcut or .desktop has the arguments the program expects).</summary>
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
            .GroupBy(p => p.Executable ?? "name:" + p.Name, cmp)
            .Select(g => g.OrderBy(p => Rank(p.Source)).First())
            .OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }
}
