using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Resources;
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

    /// <summary>The user's resources: approved Lua functions pass the Validator, drafts are refused (PLAN 4a.5).</summary>
    public Storage.ResourceStore? Resources { get; init; }

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
    [NotifyPropertyChangedFor(nameof(HasStatus))]
    private string _status = "";

    public bool HasStatus => Status.Length > 0;

    /// <summary>For which sites the single strategy is meant: its hostlist (one per line or separated by spaces/commas).</summary>
    [ObservableProperty]
    private string _strategySites = "";

    /// <summary>The single strategy passed the Validator: "Использовать" can make it the current solution.</summary>
    [ObservableProperty]
    private bool _canUseStrategy;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasStrategyStatus))]
    private string _strategyStatus = "";

    public bool HasStrategyStatus => StrategyStatus.Length > 0;

    /// <summary>
    /// A strategy was made the current one here: the next steps (turn it on here, install it elsewhere) are offered next
    /// to the button, not left for the user to find (UX audit: "после «Использовать» нет кнопки «что дальше»").
    /// </summary>
    [ObservableProperty]
    private bool _used;

    /// <summary>"Включить на этом компьютере": the protection runs the current solution (set by the window's view model).</summary>
    public Func<Task>? ProtectHere { get; set; }

    /// <summary>The wizard's last step for the current solution (set by the window's view model).</summary>
    public Action? OpenExport { get; set; }

    [RelayCommand]
    private async Task ProtectAsync()
    {
        if (ProtectHere is not null)
            await ProtectHere();
    }

    [RelayCommand]
    private void Export() => OpenExport?.Invoke();

    partial void OnStrategyTextChanged(string value)
    {
        CanUseStrategy = false;
        StrategyStatus = "";
    }

    partial void OnImportTextChanged(string value) => Used = false;

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
        // a list the strategy names by file and that did not come with it is taken from "Ресурсы" when one has its name
        var fromStore = Resources?.ResolveListPaths(r.Solution) ?? [];
        foreach (var w in r.Warnings.Where(w => !fromStore.Any(path => w.Contains(path, StringComparison.Ordinal))))
            Issues.Add("⚠ " + w);
        foreach (var path in fromStore)
            Issues.Add("✓ " + L.F("expert.list_from_resources", path, ResourceNames.Normalize(path)));
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
        Used = true;
    }

    [RelayCommand]
    private void CheckStrategy()
    {
        try
        {
            var s = Strategy.Parse(StrategyText);
            var v = Validator(null).ValidateStrategy(s);
            StrategyResult = v.Issues.Count == 0 ? L["expert.valid"] : string.Join("\n", v.Issues.Select(i => (i.Severity == Severity.Error ? "✖ " : "⚠ ") + i.Message(!L.English)));
            CanUseStrategy = v.Ok && s.Calls.Any();
        }
        catch (FormatException e)
        {
            StrategyResult = "✖ " + e.Message;
            CanUseStrategy = false;
        }
    }

    /// <summary>The sites of <see cref="StrategySites"/>, as hostnames (a pasted URL keeps its host).</summary>
    internal static List<string> ParseSites(string text) =>
        [.. text.Split([' ', ',', ';', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(t => Uri.TryCreate(t.Contains("://", StringComparison.Ordinal) ? t : "https://" + t, UriKind.Absolute, out var u) ? u.IdnHost : "")
            .Where(h => h.Contains('.', StringComparison.Ordinal))
            .Select(h => h.TrimEnd('.').ToLowerInvariant())
            .Distinct(StringComparer.Ordinal)];

    /// <summary>
    /// The single strategy as the current solution: one profile for TCP 80 and 443 limited to the given sites (never
    /// to every site: a strategy meant for one service must not touch the rest). It passes the Validator first (rule 4).
    /// </summary>
    [RelayCommand]
    private void UseStrategy()
    {
        CheckStrategy();
        if (!CanUseStrategy)
        {
            StrategyStatus = L["expert.strategy_invalid"];
            return;
        }
        var sites = ParseSites(StrategySites);
        if (sites.Count == 0)
        {
            StrategyStatus = L["expert.strategy_need_sites"];
            return;
        }
        var solution = new Solution
        {
            Profiles =
            [
                new Profile
                {
                    Name = "expert",
                    TcpPorts = "80,443",
                    HostlistDomains = sites,
                    Strategy = Strategy.Parse(StrategyText),
                },
            ],
            Meta = new SolutionMeta { Targets = sites, Title = "expert" },
        };
        SessionState.I.Last = new PipelineResult([], null, solution);
        StrategyStatus = L.F("expert.strategy_used", string.Join(", ", sites));
        Used = true;
    }

    private StrategyValidator Validator(Solution? s)
    {
        var ctx = new ValidationContext
        {
            DeclaredBlobs = s?.Blobs.ToDictionary(b => b.Key, b => (long?)b.Value.Length, StringComparer.Ordinal) ?? new Dictionary<string, long?>(),
        };
        return new(Resources?.ApplyTo(ctx) ?? ctx);
    }
}
