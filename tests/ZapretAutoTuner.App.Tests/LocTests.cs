using System.Text.RegularExpressions;

namespace ZapretAutoTuner.App.Tests;

/// <summary>AGENTS.md rule 9: every UI text in Russian and English, and every key the code uses exists.</summary>
public sealed partial class LocTests
{
    private static string AppDir([System.Runtime.CompilerServices.CallerFilePath] string here = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(here)!, "..", "..", "src", "ZapretAutoTuner.App"));

    [Fact]
    public void EveryKeyHasBothLanguages() => Assert.Empty(Loc.Loc.I.Incomplete);

    [Fact]
    public void EveryKeyUsedInTheCodeExists()
    {
        var used = new HashSet<string>(StringComparer.Ordinal);
        foreach (var f in Directory.EnumerateFiles(AppDir(), "*.*", SearchOption.AllDirectories)
                     .Where(f => (f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".axaml", StringComparison.Ordinal)) && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)))
        {
            foreach (Match m in KeyRe().Matches(File.ReadAllText(f)))
                used.Add(m.Groups.Cast<Group>().Skip(1).First(g => g.Success).Value);
        }
        Assert.NotEmpty(used);
        Assert.Equal([], used.Where(k => !Loc.Loc.I.Keys.Contains(k)).Order().ToList());
    }

    /// <summary>Keys built at run time from enums: each value needs its text.</summary>
    [Fact]
    public void EnumKeysExist()
    {
        var keys = Enum.GetNames<Tuning.PipelineStage>().Select(s => "stage." + s.ToLowerInvariant())
            .Concat(Enum.GetNames<Core.Monitor.SessionOutcome>().Select(s => "outcome." + s.ToLowerInvariant()))
            .Concat(Enum.GetValues<Tuning.RepairVerdict>().Select(v => "journal." + Tuning.RepairRunner.JournalKind(v)))
            .Concat(["journal.degraded", "journal.applied", "journal.removed", "journal.dismissed", "monitor.state_repairing", "monitor.state_broken"]);
        Assert.Equal([], keys.Where(k => !Loc.Loc.I.Keys.Contains(k)).ToList());
    }

    [Fact]
    public void SwitchingTheLanguageChangesTheText()
    {
        var was = Loc.Loc.I.English;
        try
        {
            Loc.Loc.I.English = false;
            Assert.Equal("Настройки", Loc.Loc.I["nav.settings"]);
            Loc.Loc.I.English = true;
            Assert.Equal("Settings", Loc.Loc.I["nav.settings"]);
        }
        finally
        {
            Loc.Loc.I.English = was;
        }
    }

    [GeneratedRegex(@"L\[""([a-z0-9_.]+)""\]|\.F\(""([a-z0-9_.]+)""|I\[""([a-z0-9_.]+)""\]|\{l:T ([a-z0-9_.]+)\}|""((?:nav|export)\.[a-z0-9_]+)""|SetState\([^,]+, ""([a-z0-9_.]+)""")]
    private static partial Regex KeyRe();
}
