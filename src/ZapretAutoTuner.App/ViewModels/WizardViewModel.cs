using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Providers;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Unify;
using ZapretAutoTuner.Delivery;
using ZapretAutoTuner.Probes.Providers;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.ViewModels;

public sealed partial class ProviderItem(Provider p) : ObservableObject
{
    public Provider Provider { get; } = p;

    public string Name => Provider.Name;

    public bool Major => Provider.Major;

    [ObservableProperty]
    private bool _checked;
}

/// <summary>One target in the run: its stage ribbon and the line of what is happening now.</summary>
public sealed partial class TargetRowViewModel(string host) : ObservableObject
{
    public string Host { get; } = host;

    [ObservableProperty]
    private PipelineStage _stage = PipelineStage.Waiting;

    [ObservableProperty]
    private string _message = "";

    [ObservableProperty]
    private int _found;

    [ObservableProperty]
    private string _result = "";

    public string StageText => Loc.Loc.I["stage." + Stage.ToString().ToLowerInvariant()];

    partial void OnStageChanged(PipelineStage value) => OnPropertyChanged(nameof(StageText));
}

public sealed record ExportTile(string Key, string TitleKey, string HintKey)
{
    public string Title => Loc.Loc.I[TitleKey];

    public string Hint => Loc.Loc.I[HintKey];
}

/// <summary>
/// The main scenario, a 5-step wizard (PLAN 8): what does not work → diagnostics → search → check → export. The
/// search runs through <see cref="TuningPipeline"/>; this only turns its events into rows, bars and log lines.
/// </summary>
public sealed partial class WizardViewModel : PageViewModel
{
    private readonly AppHost _host;
    private CancellationTokenSource? _cts;
    private readonly Stopwatch _clock = new();

    public WizardViewModel(AppHost host)
    {
        _host = host;
        Providers = [.. ProviderCatalog.Default.Providers.Select(p => new ProviderItem(p))];
        _guiUrl = host.Settings.GuiUrl;
        _routerHost = host.Settings.RouterHost;
    }

    public override string TitleKey => "nav.wizard";

    /// <summary>Set by the view: save a file the user picks.</summary>
    public Func<string, byte[], Task>? SaveFile { get; set; }

    /// <summary>Set by the view: put text on the clipboard.</summary>
    public Func<string, Task>? CopyText { get; set; }

    /// <summary>Set by the view: a yes/no dialog. Rule 7: nothing goes to a router or zapret-gui without it.</summary>
    public Func<string, string, Task<bool>>? Confirm { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsStep1), nameof(IsStep2), nameof(IsStep4), nameof(IsStep5))]
    private int _step = 1;

    public bool IsStep1 => Step == 1;

    /// <summary>Steps 2 and 3 share the screen: the diagnostics cards become search rows.</summary>
    public bool IsStep2 => Step is 2 or 3;

    public bool IsStep4 => Step == 4;

    public bool IsStep5 => Step == 5;

    [ObservableProperty]
    private string _inputText = "";

    public ObservableCollection<ProviderItem> Providers { get; }

    public static IReadOnlyDictionary<string, string[]> Presets { get; } = new Dictionary<string, string[]>
    {
        ["YouTube"] = ["www.youtube.com", "i.ytimg.com", "rr1---sn-n8v7knez.googlevideo.com", "yt3.ggpht.com"],
        ["Discord"] = ["discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net"],
        ["Telegram"] = ["web.telegram.org", "telegram.org", "t.me"],
        ["Instagram"] = ["www.instagram.com", "static.cdninstagram.com", "scontent.cdninstagram.com"],
    };

    public IEnumerable<string> PresetNames => Presets.Keys;

    public ObservableCollection<TargetRowViewModel> Targets { get; } = [];

    public ObservableCollection<string> Log { get; } = [];

    public ObservableCollection<string> FoundList { get; } = [];

    [ObservableProperty]
    private bool _running;

    [ObservableProperty]
    private double _percent;

    [ObservableProperty]
    private string _elapsedText = "";

    [ObservableProperty]
    private string _remainingText = "";

    [ObservableProperty]
    private string _currentLine = "";

    [ObservableProperty]
    private string _error = "";

    [ObservableProperty]
    private string _summary = "";

    [ObservableProperty]
    private bool _openPages;

    public ObservableCollection<string> Results { get; } = [];

    public IReadOnlyList<ExportTile> Tiles { get; } =
    [
        new("pc", "export.pc", "export.pc_hint"),
        new("keenetic", "export.keenetic", "export.keenetic_hint"),
        new("gui", "export.gui", "export.gui_hint"),
        new("zapret2", "export.zapret2", "export.zapret2_hint"),
        new("argv", "export.argv", "export.argv_hint"),
    ];

    [ObservableProperty]
    private string _exportStatus = "";

    [ObservableProperty]
    private string _routerHost = "";

    [ObservableProperty]
    private string _routerPassword = "";

    [ObservableProperty]
    private string _guiUrl = "";

    [ObservableProperty]
    private string _guiPassword = "";

    [RelayCommand]
    private void AddPreset(string name)
    {
        if (!Presets.TryGetValue(name, out var hosts))
            return;
        var lines = InputText.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        lines.AddRange(hosts.Where(h => !lines.Contains(h, StringComparer.OrdinalIgnoreCase)));
        InputText = string.Join(Environment.NewLine, lines);
    }

    [RelayCommand]
    private void AllMajor()
    {
        foreach (var p in Providers)
            p.Checked = p.Major;
    }

    [RelayCommand]
    private void Back() => Step = Math.Max(1, Step - 1);

    [RelayCommand]
    private void Next() => Step = Math.Min(5, Step + 1);

    [RelayCommand]
    private async Task StartAsync()
    {
        var targets = Target.ParseInputs(InputText);
        var hosts = targets.Where(t => t.Kind == TargetKind.Domain).Select(t => t.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var providers = Providers.Where(p => p.Checked).Select(p => p.Provider).ToList();
        if (hosts.Count == 0 && providers.Count == 0)
        {
            Error = L["wizard.nothing"];
            return;
        }
        Error = "";
        _host.Settings.AddTargets(hosts); // the MCP tools probe only the user's targets
        Step = 2;
        Running = true;
        Targets.Clear();
        Log.Clear();
        FoundList.Clear();
        Results.Clear();
        SessionState.I.Attempts.Clear();
        SessionState.I.Log.Clear();
        foreach (var h in hosts)
            Targets.Add(new TargetRowViewModel(h));
        foreach (var p in providers)
            Targets.Add(new TargetRowViewModel(p.Name));
        _cts = new CancellationTokenSource();
        _clock.Restart();
        try
        {
            AddLog(L["wizard.agent_start"]);
            var agent = await _host.AgentAsync(_cts.Token);
            var engine = new AgentEngineControl(agent.Client);
            var mode = Enum.TryParse<SearchMode>(_host.Settings.SearchMode, out var m) ? m : SearchMode.Standard;
            var context = SearchContext.For(_host);
            var options = new PipelineOptions { Search = new SearchOptions { Generator = new GeneratorOptions { Mode = mode }, Learning = context.Learning } };
            var pipeline = new TuningPipeline(new PcPipelineServices(_host, engine, OpenPages, context), options);
            pipeline.Event += e => Avalonia.Threading.Dispatcher.UIThread.Post(() => OnEvent(e));
            var result = await Task.Run(() => pipeline.RunAsync(hosts, _cts.Token));
            if (providers.Count > 0 && !_cts.IsCancellationRequested)
                result = await ProvidersAsync(result, providers, engine, _cts.Token);
            SessionState.I.Last = result;
            ShowResults(result);
            Step = 4;
        }
        catch (OperationCanceledException)
        {
            AddLog(L["common.stopped"]);
        }
        catch (Exception e)
        {
            Error = e.Message;
            AddLog(e.Message);
        }
        finally
        {
            Running = false;
            _clock.Stop();
        }
    }

    [RelayCommand]
    private void Stop() => _cts?.Cancel();

    /// <summary>PLAN 6.4: the provider as a whole, its sampled ranges as targets, the profile filtered by its ipset.</summary>
    private async Task<PipelineResult> ProvidersAsync(PipelineResult result, List<Provider> providers, IEngineControl engine, CancellationToken ct)
    {
        var solution = result.Solution ?? new Solution();
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        foreach (var p in providers)
        {
            var row = Targets.First(t => t.Host == p.Name);
            row.Stage = PipelineStage.Classify;
            row.Message = L["wizard.provider_ranges"];
            var (ranges, _) = await ProviderTargets.FetchRangesAsync(p, http, ct);
            var targets = await ProviderTargets.FindAsync(p, ranges, 4, ct: ct);
            if (targets.Count == 0)
            {
                row.Stage = PipelineStage.Failed;
                row.Message = L["wizard.provider_no_targets"];
                continue;
            }
            row.Stage = PipelineStage.Search;
            var executor = new ProviderTrialExecutor(engine, targets, new AgentTrialOptions { LuaDir = _host.Bundle.LuaDir });
            var mode = Enum.TryParse<SearchMode>(_host.Settings.SearchMode, out var m) ? m : SearchMode.Standard;
            var learning = SearchContext.For(_host, nameof(Core.Diagnostics.BlockLabel.Cutoff16K)).Learning;
            var search = await new StrategySearch(executor, new SearchOptions { Generator = new GeneratorOptions { Mode = mode, Labels = [Core.Diagnostics.BlockLabel.Cutoff16K] }, Learning = learning },
                null, new Progress<SearchProgress>(sp => row.Message = L.Pick(sp.MessageRu, sp.MessageEn))).RunAsync(ct);
            if (search.Best is { } best)
            {
                Unifier.AddIpProfiles(solution, [AddressResults.Provider(p, ranges, best.Candidate.Strategy)]);
                row.Stage = PipelineStage.Done;
                row.Result = best.Candidate.Strategy.ToString();
                row.Found = search.Working.Count;
            }
            else
            {
                row.Stage = PipelineStage.Failed;
                row.Message = L["wizard.not_found"];
            }
        }
        return result with { Solution = solution.Profiles.Count > 0 ? solution : null };
    }

    private void OnEvent(PipelineEvent e)
    {
        var row = Targets.FirstOrDefault(t => string.Equals(t.Host, e.Target, StringComparison.OrdinalIgnoreCase));
        switch (e)
        {
            case StageChanged s:
                if (row is not null)
                {
                    row.Stage = s.Stage;
                    row.Message = L.Pick(s.MessageRu, s.MessageEn);
                    if (s.Stage is PipelineStage.Classify && Step == 2)
                        Step = 2;
                    if (s.Stage is PipelineStage.Search)
                        Step = 3;
                }
                AddLog($"{e.Target}: {L.Pick(s.MessageRu, s.MessageEn)}");
                break;
            case TrialStarted t:
                CurrentLine = L.F("wizard.trying", t.Target, t.Candidate.Family, t.Candidate.Strategy);
                break;
            case TrialResult r:
                SessionState.I.Attempts.Add((r.Target, r.Candidate, r.Outcome));
                CurrentLine = r.Outcome.Ok
                    ? L.F("wizard.trial_ok", r.Target, r.Outcome.BytesIn / 1024)
                    : L.F("wizard.trial_fail", r.Target, r.Outcome.Failure, r.Outcome.Detail ?? "");
                break;
            case CandidateFound f:
                if (row is not null)
                    row.Found++;
                FoundList.Add($"{f.Target}: {f.Found.Efficiency.Successes}/{f.Found.Efficiency.Attempts} {f.Found.Candidate.Strategy}");
                break;
            case OverallProgress p:
                Percent = p.Percent;
                ElapsedText = p.Elapsed.ToString(@"hh\:mm\:ss");
                RemainingText = p.Remaining is { } rem ? "≈ " + rem.ToString(@"hh\:mm\:ss") : "";
                break;
        }
    }

    private void AddLog(string line)
    {
        var text = $"{DateTime.Now:HH:mm:ss} {line}";
        Log.Add(text);
        SessionState.I.Log.Add(text);
        if (Log.Count > 2000)
            Log.RemoveAt(0);
    }

    private void ShowResults(PipelineResult r)
    {
        foreach (var t in r.Targets)
        {
            var row = Targets.FirstOrDefault(x => x.Host == t.Host);
            var line = t.Best is { } b
                ? L.F("wizard.result_ok", t.Host, b.Efficiency.Successes, b.Efficiency.Attempts, b.Candidate.Strategy)
                : t.Verdict is { } v ? $"{t.Host}: {L.Pick(v.SummaryRu, v.SummaryEn)}" : $"{t.Host}: {t.Error}";
            Results.Add(line);
            if (row is not null)
                row.Result = t.Best?.Candidate.Strategy.ToString() ?? "";
        }
        Summary = r.Solution is null ? L["wizard.no_solution"] : L.F("wizard.solution", r.Solution.Profiles.Count);
    }

    [RelayCommand]
    private async Task ExportAsync(string key)
    {
        var s = SessionState.I.Last?.Solution;
        if (s is null)
        {
            ExportStatus = L["wizard.no_solution"];
            return;
        }
        try
        {
            switch (key)
            {
                case "pc":
                    await Save(OperatingSystem.IsWindows() ? WinwsExporter.Build(s) : Zapret2Exporter.Build(s), "autotuner-pc.zip");
                    break;
                case "zapret2":
                    await Save(Zapret2Exporter.Build(s), "autotuner-zapret2.zip");
                    break;
                case "keenetic":
                    await KeeneticAsync(s);
                    break;
                case "gui":
                    await GuiAsync(s);
                    break;
                case "argv":
                    var argv = ArgvExporter.Build(s, OperatingSystem.IsWindows() ? Core.Validation.EnginePlatform.Windows : Core.Validation.EnginePlatform.Linux, _host.Bundle.LuaDir);
                    if (CopyText is not null)
                        await CopyText(argv.Text);
                    ExportStatus = L["export.copied"];
                    break;
            }
        }
        catch (TaskCanceledException e)
        {
            // HttpClient's timeout comes as a cancellation
            ExportStatus = L.F("export.timeout", e.Message);
        }
        catch (Exception e)
        {
            // a wrong address, a refused or dropped connection, a router that said no: shown, never a crash
            ExportStatus = L.F("export.failed", e.Message);
        }
    }

    private async Task Save(ExportPackage pkg, string name)
    {
        if (SaveFile is not null)
            await SaveFile(name, pkg.ToZip());
        ExportStatus = pkg.Warnings.Count > 0 ? string.Join("\n", pkg.Warnings) : L["export.saved"];
    }

    /// <summary>Keenetic: a file by default; over SSH only after the user saw the plan and said yes.</summary>
    private async Task KeeneticAsync(Solution s)
    {
        var pkg = KeeneticExporter.Build(s);
        if (string.IsNullOrWhiteSpace(RouterHost))
        {
            await Save(pkg, "autotuner-keenetic.zip");
            return;
        }
        var host = RouterHost.Trim();
        var target = new SshTarget { Host = host, Password = RouterPassword };
        // trust on first use: the key is learned before any password goes out, shown, and remembered per host
        var seen = await SshRemoteShell.HostKeyAsync(target, CancellationToken.None);
        var remembered = _host.Settings.RouterHostKey(host, target.Port);
        var check = HostKeys.Check(remembered, seen);
        if (check == HostKeyCheck.Mismatch)
        {
            ExportStatus = L.F("export.hostkey_mismatch", host, remembered, seen);
            return;
        }
        var plan = string.Join("\n", KeeneticDeployer.Plan(pkg).Select(st => "• " + L.Pick(st.Ru, st.En)));
        var key = check == HostKeyCheck.FirstUse ? L.F("export.hostkey_first", host, seen) : L.F("export.hostkey_known", seen);
        if (Confirm is null || !await Confirm(L["export.keenetic_confirm"], key + "\n\n" + plan))
            return;
        using var sh = await SshRemoteShell.ConnectAsync(target with { TrustHostKey = fp => fp == seen }, CancellationToken.None);
        if (check == HostKeyCheck.FirstUse)
            _host.Settings.RememberRouterHostKey(host, target.Port, seen);
        var r = await KeeneticDeployer.DeployAsync(sh, pkg, confirmedByUser: true);
        ExportStatus = r.Ok ? L["export.delivered"] : $"{r.Error}{(r.RolledBack ? " — " + L["export.rolled_back"] : "")}";
        _host.Settings.RouterHost = host;
    }

    /// <summary>zapret-gui: save (first yes), then apply (second yes), as strategy-export §3.2 asks.</summary>
    private async Task GuiAsync(Solution s)
    {
        if (string.IsNullOrWhiteSpace(GuiUrl))
        {
            var pkg = ZapretGuiExporter.Build(s);
            await Save(pkg, "autotuner-zapret-gui.zip");
            return;
        }
        if (ZapretGuiClient.BaseAddress(GuiUrl) is not { } baseAddress)
        {
            ExportStatus = L.F("export.bad_url", GuiUrl);
            return;
        }
        using var http = new HttpClient { BaseAddress = baseAddress, Timeout = TimeSpan.FromSeconds(30) };
        var client = new ZapretGuiClient(http, null, string.IsNullOrEmpty(GuiPassword) ? null : GuiPassword);
        var plan = await client.PlanAsync(s);
        var text = string.Join("\n", plan.Steps.Select(st => "• " + L.Pick(st.Ru, st.En)));
        if (Confirm is null || !await Confirm(L["export.gui_confirm"], text))
            return;
        var id = await client.SaveAsync(s, plan, confirmedByUser: true);
        ExportStatus = L.F("export.gui_saved", id);
        _host.Settings.GuiUrl = baseAddress.ToString();
        if (await Confirm(L["export.gui_apply"], L.F("export.gui_apply_text", id)))
        {
            await client.ApplyAsync(id, confirmedByUser: true);
            ExportStatus = L.F("export.gui_applied", id);
        }
    }
}
