using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Resources;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Storage;
using ZapretAutoTuner.Core.Validation;
using ZapretAutoTuner.Protocol;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>
/// "Эксперт": import a strategy from any supported format (PLAN 5.2), see what the Validator says about every
/// profile, and use it as the current solution (export, protection). Also a single strategy line: checked by the
/// Validator, then on a real site (baseline without a bypass, then full loads with it), and used or exported from
/// the same tab.
/// </summary>
public sealed partial class ExpertViewModel : PageViewModel
{
    private Solution? _imported;

    public override string TitleKey => "nav.expert";

    public Func<Task<(string Name, byte[] Bytes)?>>? OpenFile { get; set; }

    /// <summary>The Agent, the bundle and the resources for «Проверить на сайте»; null in tests that only validate.</summary>
    public AppHost? Host { get; init; }

    /// <summary>Why the engine cannot run a check now (geneva bypasses, the wizard tunes); null when it can.</summary>
    public Func<string?>? Busy { get; set; }

    /// <summary>«Экспортировать»: the wizard's export step for the current solution.</summary>
    public Action? OpenExport { get; set; }

    /// <summary>«Включить на этом компьютере»: the monitor runs the current solution as protection.</summary>
    public Func<Task>? ProtectHere { get; set; }

    private CancellationTokenSource? _checkCts;

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
    private string _status = "";

    /// <summary>The site the single strategy is checked on and used for.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CheckOnSiteCommand))]
    [NotifyCanExecuteChangedFor(nameof(UseStrategyCommand))]
    private string _siteText = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CheckOnSiteCommand))]
    [NotifyCanExecuteChangedFor(nameof(UseStrategyCommand))]
    [NotifyCanExecuteChangedFor(nameof(StopCheckCommand))]
    private bool _checking;

    [ObservableProperty]
    private string _siteResult = "";

    /// <summary>The import was made current: «Экспортировать» and «Включить на этом компьютере» next to «Использовать».</summary>
    [ObservableProperty]
    private bool _importNextStep;

    /// <summary>The single strategy was made current for the site: the same two buttons on the «Стратегия» tab.</summary>
    [ObservableProperty]
    private bool _strategyNextStep;

    // the buttons act on what was made current: once the text changes they would act on something else than is shown
    partial void OnImportTextChanged(string value) => ImportNextStep = false;

    partial void OnStrategyTextChanged(string value)
    {
        StrategyNextStep = false;
        UseStrategyCommand.NotifyCanExecuteChanged();
    }

    partial void OnSiteTextChanged(string value) => StrategyNextStep = false;

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
        ImportNextStep = false;
    }

    /// <summary>Makes the import the current solution: the wizard's export and the monitor work on it.</summary>
    [RelayCommand]
    private void Use()
    {
        if (_imported is null || !CanUse)
            return;
        SessionState.I.Last = new PipelineResult([], null, _imported);
        Status = L["expert.used"];
        ImportNextStep = true;
    }

    [RelayCommand]
    private void Export() => OpenExport?.Invoke();

    [RelayCommand]
    private async Task ProtectAsync()
    {
        if (ProtectHere is not null)
            await ProtectHere();
    }

    /// <summary>The site as typed («https://site/path» is fine), or null when it is not a plain domain.</summary>
    private string? Site()
    {
        var (domains, problems) = ResourceRules.NormalizeDomains([SiteText]);
        return domains.Count == 1 && !problems.Any(p => p.IsError) && domains[0][0] is not ('^' or '!') ? domains[0] : null;
    }

    /// <summary>The strategy line if it parses and the Validator finds no error; problems go to <see cref="StrategyResult"/>.</summary>
    private Strategy? ValidStrategy()
    {
        try
        {
            var s = Strategy.Parse(StrategyText);
            var v = Validator(null).ValidateStrategy(s);
            StrategyResult = v.Issues.Count == 0 ? L["expert.valid"] : string.Join("\n", v.Issues.Select(i => (i.Severity == Severity.Error ? "✖ " : "⚠ ") + i.Message(!L.English)));
            return v.Ok ? s : null;
        }
        catch (FormatException e)
        {
            StrategyResult = "✖ " + e.Message;
            return null;
        }
    }

    /// <summary>
    /// The site, the validated strategy and its one-profile solution with the user's blobs and approved Lua attached;
    /// null with the reason in <see cref="SiteResult"/>.
    /// </summary>
    private (string Site, Strategy Strategy, Solution Solution)? Prepare(ResourceStore? store)
    {
        if (Site() is not { } site)
        {
            SiteResult = "✖ " + L["expert.site_bad"];
            return null;
        }
        if (ValidStrategy() is not { } strategy)
        {
            SiteResult = "✖ " + L["expert.site_invalid"];
            return null;
        }
        var solution = StrategySiteCheck.SolutionFor(strategy, site);
        try
        {
            store?.AttachTo(solution);
        }
        catch (ResourceException e)
        {
            SiteResult = "✖ " + L.Pick(e.Ru, e.En);
            return null;
        }
        return (site, strategy, solution);
    }

    private bool CanCheckOnSite() => !Checking && Host is not null && SiteText.Trim().Length > 0;

    /// <summary>
    /// «Проверить на сайте»: Validator, then the site without a bypass (it must be blocked, AGENTS.md rule 5), then
    /// a series of full loads with the strategy in a short-lived engine instance of its own.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanCheckOnSite))]
    private async Task CheckOnSiteAsync()
    {
        if (Host is not { } host || Prepare(host.Resources) is not var (site, strategy, solution))
            return;
        if (Busy?.Invoke() is { } busy)
        {
            SiteResult = busy;
            return;
        }
        Checking = true;
        host.ExpertCheckStarted();
        _checkCts = new CancellationTokenSource();
        var ct = _checkCts.Token;
        try
        {
            SiteResult = L.F("expert.site_resolving", site);
            var addresses = await LiveAddresses.ResolveAsync(site, ct);
            if (addresses.Count == 0)
            {
                SiteResult = "✖ " + L.F("expert.site_no_address", site);
                return;
            }
            SiteResult = L.F("expert.site_running", site, StrategySiteCheck.Attempts);
            var agent = await host.AgentAsync(ct);
            var options = new AgentTrialOptions
            {
                LuaDir = host.Bundle.LuaDir,
                QueueNum = StrategySiteCheck.QueueNum,
                Blobs = solution.Blobs.ToDictionary(b => b.Key, b => "0x" + Convert.ToHexString(b.Value), StringComparer.Ordinal),
                UserLua = host.Resources.ApprovedLuaPaths(),
            };
            var executor = new AgentTrialExecutor(new AgentEngineControl(agent.Client), new TrialTarget { Host = site, Addresses = addresses }, options);
            var r = await Task.Run(() => StrategySiteCheck.RunAsync(executor, (n, c) => executor.ProbeSeriesAsync(n, _ => false, c), strategy, ct), ct);
            SiteResult = Describe(r, site);
        }
        catch (OperationCanceledException)
        {
            SiteResult = L["common.stopped"];
        }
        catch (Exception e) when (e is EngineRefusedException or AgentStartException or InvalidOperationException or ArgumentException
            or Grpc.Core.RpcException or System.Net.Sockets.SocketException or IOException)
        {
            SiteResult = "✖ " + e.Message;
        }
        finally
        {
            host.ExpertCheckFinished();
            Checking = false;
            _checkCts?.Dispose();
            _checkCts = null;
        }
    }

    private bool CanStopCheck() => Checking;

    [RelayCommand(CanExecute = nameof(CanStopCheck))]
    private void StopCheck() => _checkCts?.Cancel();

    private string Describe(SiteCheckResult r, string site)
    {
        var text = r.Verdict switch
        {
            SiteCheckVerdict.NotBlocked => "ℹ " + L.F("expert.site_not_blocked", site),
            SiteCheckVerdict.Works => "✓ " + L.F("expert.site_works", site, r.Ok, r.Outcomes.Count),
            SiteCheckVerdict.Unstable => "⚠ " + L.F("expert.site_unstable", site, r.Ok, r.Outcomes.Count, Failure(r.MainFailure)),
            _ => "✖ " + L.F("expert.site_fails", site, Failure(r.MainFailure)),
        };
        // the engine's own words when it refused to start or broke (the Agent's refusal comes as one failed attempt)
        return r.MainDetail is { Length: > 0 } detail && r.Verdict is SiteCheckVerdict.Fails or SiteCheckVerdict.Unstable ? text + "\n" + detail : text;
    }

    private string Failure(TrialFailure f) => L["expert.failure." + f.ToString().ToLowerInvariant()];

    private bool CanUseStrategy() => !Checking && StrategyText.Trim().Length > 0 && SiteText.Trim().Length > 0;

    /// <summary>
    /// «Использовать для сайта»: the strategy for the site as the current solution (one TCP 443 profile limited
    /// to the site), which «Экспортировать» and «Включить на этом компьютере» then take.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanUseStrategy))]
    private void UseStrategy()
    {
        if (Prepare(Resources) is not var (site, _, solution))
            return;
        SessionState.I.Last = new PipelineResult([], null, solution);
        SiteResult = L.F("expert.strategy_used", site);
        StrategyNextStep = true;
    }

    [RelayCommand]
    private void CheckStrategy() => ValidStrategy();

    private StrategyValidator Validator(Solution? s)
    {
        var ctx = new ValidationContext
        {
            DeclaredBlobs = s?.Blobs.ToDictionary(b => b.Key, b => (long?)b.Value.Length, StringComparer.Ordinal) ?? new Dictionary<string, long?>(),
        };
        return new(Resources?.ApplyTo(ctx) ?? ctx);
    }
}
