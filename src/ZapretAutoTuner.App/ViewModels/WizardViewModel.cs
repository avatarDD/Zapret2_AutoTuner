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
using ZapretAutoTuner.Probes.Browser;
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
        _guiToken = host.Settings.GuiToken;
        _routerHost = host.Settings.RouterHost;
    }

    public override string TitleKey => "nav.wizard";

    /// <summary>Set by the view: save a file the user picks.</summary>
    public Func<string, byte[], Task>? SaveFile { get; set; }

    /// <summary>Set by the view: put text on the clipboard.</summary>
    public Func<string, Task>? CopyText { get; set; }

    /// <summary>Set by the view: a yes/no dialog. Rule 7: nothing goes to a router or zapret-gui without it.</summary>
    public Func<string, string, Task<bool>>? Confirm { get; set; }

    /// <summary>Set by the main view model: the MCP session works on the model's behalf (search, trials, experiments).</summary>
    public Func<bool>? McpBusy { get; set; }

    /// <summary>Set by the main view model: the model's router experiment runs or its kept variant awaits a commit.</summary>
    public Func<bool>? McpRouterBusy { get; set; }

    private bool McpBusyForRouter => McpBusy?.Invoke() == true || McpRouterBusy?.Invoke() == true;

    /// <summary>The search runs on this PC: the MCP tools refuse their own trials meanwhile (review M6).</summary>
    public bool LocalTuningRunning => Volatile.Read(ref _localRunning);

    /// <summary>Trials run on the router or a kept variant waits there: router experiments over MCP refuse meanwhile.</summary>
    public bool RouterTuningRunning => Volatile.Read(ref _routerRunning) || _routerKept;

    private bool _localRunning;
    private bool _routerRunning;

    /// <summary>Set by the window: the "Сообщить о проблеме" dialog (PLAN 4a.6).</summary>
    public Func<BugReportInput, Task>? ReportProblem { get; set; }

    /// <summary>What went wrong last (a failed run, an engine refusal, a zapret-gui error); shows the report button.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasProblem))]
    private BugReportInput? _problem;

    public bool HasProblem => Problem is not null;

    [RelayCommand]
    private async Task ReportProblemAsync()
    {
        if (ReportProblem is not null)
            await ReportProblem(Problem ?? BugReports.From());
    }

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

    /// <summary>"Где подбирать": this PC (default) or the router through zapret-gui (PLAN 4a.4).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(OnPc))]
    private bool _onRouter;

    public bool OnPc
    {
        get => !OnRouter;
        set => OnRouter = !value;
    }

    /// <summary>zapret-gui's MCP token: in memory for this run only (see AppSettings.GuiToken).</summary>
    [ObservableProperty]
    private string _guiToken = "";

    /// <summary>A router search found a solution: it can be kept on the router (after a yes).</summary>
    [ObservableProperty]
    private bool _canCommitRouter;

    [ObservableProperty]
    private string _routerStatus = "";

    private ZapretGuiExperiments? _routerExperiments;
    private IReadOnlyList<(string Name, string Args)> _routerCurrent = [];
    private List<string> _routerTargets = [];
    private bool _routerKept;

    partial void OnGuiTokenChanged(string value) => _host.Settings.GuiToken = value.Trim();

    partial void OnGuiUrlChanged(string value) => _host.Settings.GuiUrl = value.Trim();

    /// <summary>The zapret-gui address and token may have been entered in Settings meanwhile: the settings are the source.</summary>
    public override void OnShown()
    {
        if (GuiUrl.Trim() != _host.Settings.GuiUrl)
            GuiUrl = _host.Settings.GuiUrl;
        if (GuiToken.Trim() != _host.Settings.GuiToken.Trim())
            GuiToken = _host.Settings.GuiToken;
    }

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
        if (McpBusy?.Invoke() == true)
        {
            Error = L["wizard.mcp_busy"];
            return;
        }
        Error = "";
        Problem = null;
        if (OnRouter)
        {
            await RouterAsync(hosts);
            return;
        }
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
        Volatile.Write(ref _localRunning, true);
        try
        {
            // no browser on the machine: the final check loads the page by itself (docs/USER.md), said now and not at the end
            bool openPages = OpenPages && BrowserLocator.Chromium() is not null;
            if (OpenPages && !openPages)
                AddLog(L["wizard.no_browser"]);
            AddLog(L["wizard.agent_start"]);
            var agent = await _host.AgentAsync(_cts.Token);
            var engine = new AgentEngineControl(agent.Client);
            var mode = Enum.TryParse<SearchMode>(_host.Settings.SearchMode, out var m) ? m : SearchMode.Standard;
            var context = SearchContext.For(_host);
            var options = new PipelineOptions { Search = new SearchOptions { Generator = new GeneratorOptions { Mode = mode }, Learning = context.Learning } };
            var pipeline = new TuningPipeline(new PcPipelineServices(_host, engine, openPages, context), options);
            pipeline.Event += e => Avalonia.Threading.Dispatcher.UIThread.Post(() => OnEvent(e));
            var result = await Task.Run(() => pipeline.RunAsync(hosts, _cts.Token));
            if (providers.Count > 0 && !_cts.IsCancellationRequested)
                result = await ProvidersAsync(result, providers, engine, _cts.Token);
            SessionState.I.Last = result;
            ShowResults(result);
            if (result.Solution is null && result.Targets.Count > 0)
                Problem = BugReports.From(null, BugKind.TuningFailed);
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
            Problem = BugReports.From(e);
        }
        finally
        {
            Volatile.Write(ref _localRunning, false);
            Running = false;
            _clock.Stop();
        }
    }

    [RelayCommand]
    private void Stop() => _cts?.Cancel();

    /// <summary>
    /// The closed loop on the router (PLAN 7.6, R1–R4): connect to zapret-gui, one yes for the trial session, then the
    /// usual pipeline with the router as the place of trials. The router measures its own baseline first and reverts
    /// every experiment by itself; nothing stays on it here (keeping is <see cref="CommitRouterAsync"/>). No Agent and
    /// no rights on this PC are needed.
    /// </summary>
    private async Task RouterAsync(List<string> hosts)
    {
        if (hosts.Count == 0)
        {
            Error = L["wizard.router_domains_only"];
            return;
        }
        // the fields write through to the settings as they change; writing them back here would wipe a token entered in
        // Settings after this page was built
        var experiments = _host.Router.Experiments();
        if (experiments is null)
        {
            Error = L["wizard.router_not_set"];
            return;
        }
        CanCommitRouter = false;
        RouterStatus = "";
        _cts = new CancellationTokenSource();
        try
        {
            // R1: the token's tools and the strategy the router runs now
            var (missing, activeId, current) = await RouterTuning.ConnectAsync(experiments, _cts.Token);
            if (missing.Count > 0)
            {
                Error = L.F("wizard.router_missing_tools", string.Join(", ", missing));
                return;
            }
            // every candidate goes with the router's current profiles after it: zapret-gui takes 8, nothing is cut
            if (RouterTuning.DroppedProfiles([(RouterTrialExecutor.ProfileName, "")], current) is { Count: > 0 } dropped)
            {
                Error = L.F("wizard.router_too_many", RouterTuning.MaxProfiles, current.Count + 1, string.Join(", ", dropped));
                return;
            }
            // R2: one yes for the whole trial session (AGENTS.md rule 7)
            var text = L.F("wizard.router_session_text", _host.Settings.GuiUrl, string.Join(", ", hosts), activeId.Length > 0 ? activeId : "—", current.Count);
            if (Confirm is null || !await Confirm(L["wizard.router_session_title"], text))
                return;
            if (McpBusyForRouter)
            {
                Error = L["wizard.mcp_busy"];
                return;
            }
            _routerExperiments = experiments;
            _routerCurrent = current;
            _routerTargets = hosts;
            _host.Settings.AddTargets(hosts);
            Step = 2;
            Running = true;
            Volatile.Write(ref _routerRunning, true);
            Targets.Clear();
            Log.Clear();
            FoundList.Clear();
            Results.Clear();
            SessionState.I.Attempts.Clear();
            SessionState.I.Log.Clear();
            foreach (var h in hosts)
                Targets.Add(new TargetRowViewModel(h));
            _clock.Restart();
            AddLog(L.F("wizard.router_connected", _host.Settings.GuiUrl, current.Count));
            var mode = Enum.TryParse<SearchMode>(_host.Settings.SearchMode, out var m) ? m : SearchMode.Standard;
            var context = SearchContext.For(_host);
            var options = new PipelineOptions { Search = new SearchOptions { Generator = new GeneratorOptions { Mode = mode }, Learning = RouterTuning.ForRouter(context.Learning) } };
            // R3, R4: the usual search with the router as the executor; its trials feed the learned order with source=router
            var services = new RouterPipelineServices(experiments, new RouterTrialOptions { Targets = hosts, CurrentProfiles = current }, ClassifyAsync,
                _host.Kb, context.NetworkId, context.Asn, _host.Settings.SearchMode);
            var pipeline = new TuningPipeline(services, options);
            pipeline.Event += e => Avalonia.Threading.Dispatcher.UIThread.Post(() => OnEvent(e));
            var result = await Task.Run(() => pipeline.RunAsync(hosts, _cts.Token));
            foreach (var (host, x) in services.Executors)
            {
                foreach (var hint in x.LastReport?.Variants.SelectMany(v => v.Hints).Distinct().Take(5) ?? [])
                    AddLog($"{host}: zapret-gui: {hint}");
            }
            SessionState.I.Last = result;
            ShowResults(result);
            CanCommitRouter = result.Solution is not null;
            if (CanCommitRouter)
                RouterStatus = L["wizard.router_found"];
            Step = 4;
        }
        catch (OperationCanceledException)
        {
            AddLog(L["common.stopped"]);
        }
        catch (Exception e) when (e is ZapretGuiException or HttpRequestException or IOException)
        {
            Error = L.F("wizard.router_failed", e.Message);
            AddLog(Error);
        }
        catch (Exception e)
        {
            // a command handler must not crash the app: anything else is shown, logged and offered for a report
            Error = L.F("wizard.router_failed", e.Message);
            AddLog(Error);
            Problem = BugReports.From(e);
        }
        finally
        {
            Volatile.Write(ref _routerRunning, false);
            Running = false;
            _clock.Stop();
        }
    }

    /// <summary>The diagnosis runs on this PC, behind the router: a target that opens here needs nothing on the router either.</summary>
    private static async Task<Core.Diagnostics.ClassifierVerdict> ClassifyAsync(string host, IProgress<(string Ru, string En)> progress, CancellationToken ct)
    {
        var run = await Probes.Diagnostics.ClassifierRunner.RunAsync(host, new Probes.Diagnostics.ClassifierOptions(),
            new Progress<Probes.Diagnostics.ClassifierStep>(s => progress.Report((s.MessageRu, s.MessageEn))), ct).ConfigureAwait(false);
        return run.Verdict;
    }

    /// <summary>
    /// R5: the found solution is applied on the router as a kept variant (measured, still reverting by itself), and only
    /// after the user's yes committed and saved as a user strategy. A no reverts it at once. Then the router's feedback
    /// is read into the monitor's journal.
    /// </summary>
    [RelayCommand]
    private async Task CommitRouterAsync()
    {
        var s = SessionState.I.Last?.Solution;
        var experiments = _routerExperiments;
        if (s is null || experiments is null)
            return;
        var (profiles, problems) = RouterTuning.ProfilesOf(s);
        if (problems.Count > 0)
        {
            RouterStatus = L.F("wizard.router_cannot", string.Join(Environment.NewLine, problems));
            return;
        }
        if (RouterTuning.DroppedProfiles(profiles, _routerCurrent) is { Count: > 0 } dropped)
        {
            RouterStatus = L.F("wizard.router_too_many", RouterTuning.MaxProfiles, profiles.Count + _routerCurrent.Count, string.Join(", ", dropped));
            return;
        }
        if (McpBusyForRouter)
        {
            RouterStatus = L["wizard.mcp_busy"];
            return;
        }
        var all = profiles.Concat(_routerCurrent).ToList();
        _cts = new CancellationTokenSource();
        Running = true;
        Volatile.Write(ref _routerRunning, true);
        try
        {
            RouterStatus = L["wizard.router_keeping"];
            var (report, kept, problem) = await RouterTuning.KeepAsync(experiments, all, _routerTargets, 300, TimeSpan.FromSeconds(2), _cts.Token);
            if (!kept || report is null)
            {
                RouterStatus = L.F("wizard.router_not_kept", problem);
                return;
            }
            _routerKept = true;
            var measured = string.Join(Environment.NewLine, report.Variants.Where(v => v.Label == RouterTuning.KeepLabel)
                .SelectMany(v => v.PerTarget).Select(p => $"• {p.Target}: {p.OkCount}/{Math.Max(p.Attempts, 1)} {p.Code}"));
            var saveAs = RouterTuning.SaveId(DateTimeOffset.Now);
            var strategies = string.Join(Environment.NewLine, profiles.Select(p => p.Args));
            if (Confirm is null || !await Confirm(L["wizard.router_commit_title"], L.F("wizard.router_commit_text", measured, saveAs, strategies)))
            {
                await RouterTuning.RollbackQuietlyAsync(experiments);
                _routerKept = false;
                RouterStatus = L["wizard.router_rolled_back"];
                return;
            }
            var (saved, note) = await RouterTuning.CommitAsync(experiments, confirmedByUser: true, saveAs, "AutoTuner: " + string.Join(", ", _routerTargets.Take(3)), _cts.Token);
            _routerKept = false;
            foreach (var t in _routerTargets)
            {
                _host.Kb.AddChange(t, "router_applied", Storage.JournalReason.Encode(
                    saved ? $"закреплено на роутере и сохранено как {saveAs}" : "закреплено на роутере (без сохранения)",
                    saved ? $"committed on the router and saved as {saveAs}" : "committed on the router (unsaved)"), null, strategies, applied: true);
            }
            _host.Router.StartFeedback(_routerTargets);
            CanCommitRouter = false;
            RouterStatus = (saved ? L.F("wizard.router_saved", saveAs) : L["wizard.router_committed"]) + (note.Length > 0 ? Environment.NewLine + note : "");
        }
        catch (OperationCanceledException)
        {
            // KeepAsync rolled back already; a kept variant left by a cancelled dialog goes too
            if (_routerKept)
                await RouterTuning.RollbackQuietlyAsync(experiments);
            _routerKept = false;
            RouterStatus = L["wizard.router_rolled_back"];
        }
        catch (Exception e) when (e is ZapretGuiException or HttpRequestException or IOException or InvalidOperationException)
        {
            if (_routerKept)
                await RouterTuning.RollbackQuietlyAsync(experiments);
            _routerKept = false;
            RouterStatus = L.F("wizard.router_failed", e.Message);
        }
        finally
        {
            Volatile.Write(ref _routerRunning, false);
            Running = false;
        }
    }

    /// <summary>On exit: a running search stops and nothing uncommitted stays on the router (its dead-man switch would revert it anyway).</summary>
    public async Task ShutdownAsync()
    {
        _cts?.Cancel();
        if (_routerExperiments is { } x && (Running || _routerKept))
            await RouterTuning.RollbackQuietlyAsync(x).ConfigureAwait(false);
    }

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
            // the user's hostlists, blobs and approved Lua scripts the solution uses go along (PLAN 4a.5)
            _host.Resources.AttachTo(s);
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
        catch (Core.Resources.ResourceException e)
        {
            ExportStatus = L.Pick(e.Ru, e.En);
        }
        catch (Exception e)
        {
            // a wrong address, a refused or dropped connection, a router that said no: shown, never a crash
            ExportStatus = L.F("export.failed", e.Message);
            Problem = BugReports.From(e);
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
