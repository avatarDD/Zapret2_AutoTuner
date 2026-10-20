using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>
/// "Эксперт": import a strategy from any supported format (PLAN 5.2), see what the Validator says about every
/// profile, and use it as the current solution (export, protection). Also a single strategy line checked alone.
/// </summary>
public sealed partial class ExpertViewModel : PageViewModel
{
    private Solution? _imported;

    public override string TitleKey => "nav.expert";

    public Func<Task<(string Name, byte[] Bytes)?>>? OpenFile { get; set; }

    [ObservableProperty]
    private string _importText = "";

    [ObservableProperty]
    private string _importKind = "";

    [ObservableProperty]
    private bool _canUse;

    public ObservableCollection<string> Profiles { get; } = [];

    public ObservableCollection<string> Issues { get; } = [];

    [ObservableProperty]
    private string _strategyText = "";

    [ObservableProperty]
    private string _strategyResult = "";

    [ObservableProperty]
    private string _status = "";

    [RelayCommand]
    private async Task OpenAsync()
    {
        if (OpenFile is null || await OpenFile() is not { } f)
            return;
        if (f.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            Dictionary<string, byte[]> files;
            try
            {
                files = Zip.Read(f.Bytes);
            }
            catch (InvalidDataException e)
            {
                Status = e.Message;
                return;
            }
            var main = files.Keys.FirstOrDefault(k => k.EndsWith("strategy.json", StringComparison.Ordinal) || k.EndsWith("nfqws2.conf", StringComparison.Ordinal)
                || k.EndsWith("config", StringComparison.Ordinal) || k.EndsWith(".cmd", StringComparison.Ordinal) || k.EndsWith("args.txt", StringComparison.Ordinal));
            ImportText = main is null ? "" : System.Text.Encoding.UTF8.GetString(files[main]);
            Run(files);
        }
        else
        {
            ImportText = System.Text.Encoding.UTF8.GetString(f.Bytes);
            Run(null);
        }
    }

    [RelayCommand]
    private void Import() => Run(null);

    private void Run(IReadOnlyDictionary<string, byte[]>? files)
    {
        Profiles.Clear();
        Issues.Clear();
        var r = StrategyImporter.Import(ImportText, files);
        ImportKind = L.F("expert.kind", r.Kind, r.Solution.Profiles.Count);
        foreach (var w in r.Warnings)
            Issues.Add("⚠ " + w);
        var validator = Validator(r.Solution);
        bool ok = r.Solution.Profiles.Count > 0;
        foreach (var p in r.Solution.Profiles)
        {
            Profiles.Add($"{p.Name}: {p}");
            var v = validator.ValidateProfile(p, p.Name);
            ok &= v.Ok;
            foreach (var i in v.Issues)
                Issues.Add((i.Severity == Severity.Error ? "✖ " : "⚠ ") + i.Message(!L.English));
        }
        _imported = r.Solution;
        CanUse = ok;
    }

    /// <summary>Makes the import the current solution: the wizard's export and the monitor work on it.</summary>
    [RelayCommand]
    private void Use()
    {
        if (_imported is null || !CanUse)
            return;
        SessionState.I.Last = new PipelineResult([], null, _imported);
        Status = L["expert.used"];
    }

    [RelayCommand]
    private void CheckStrategy()
    {
        try
        {
            var s = Strategy.Parse(StrategyText);
            var v = Validator(null).ValidateStrategy(s);
            StrategyResult = v.Issues.Count == 0 ? L["expert.valid"] : string.Join("\n", v.Issues.Select(i => (i.Severity == Severity.Error ? "✖ " : "⚠ ") + i.Message(!L.English)));
        }
        catch (FormatException e)
        {
            StrategyResult = "✖ " + e.Message;
        }
    }

    private StrategyValidator Validator(Solution? s) => new(new ValidationContext
    {
        DeclaredBlobs = s?.Blobs.ToDictionary(b => b.Key, b => (long?)b.Value.Length, StringComparer.Ordinal) ?? new Dictionary<string, long?>(),
    });
}
