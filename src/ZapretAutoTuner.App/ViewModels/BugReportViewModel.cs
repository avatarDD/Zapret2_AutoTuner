using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.Delivery;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>Where a "Сообщить о проблеме" input comes from: what the app knows when something went wrong.</summary>
public static class BugReports
{
    /// <summary>
    /// The input for a problem: the kind read from the exception (engine refusal, zapret-gui error, anything else),
    /// the run's event log, the verdict of a target the run could not open, and the run's domains to mask on request.
    /// </summary>
    public static BugReportInput From(Exception? e = null, BugKind? kind = null, string? summary = null)
    {
        var last = SessionState.I.Last;
        var failed = last?.Targets.FirstOrDefault(t => t.Best is null && t.Verdict is not null);
        var k = kind ?? e switch
        {
            EngineRefusedException => BugKind.EngineRefused,
            ZapretGuiException => BugKind.ZapretGuiError,
            { InnerException: ZapretGuiException } => BugKind.ZapretGuiError,
            null when last is { Solution: null, Targets.Count: > 0 } => BugKind.TuningFailed,
            _ => BugKind.AppError,
        };
        return new BugReportInput
        {
            Kind = k,
            Summary = summary,
            Exception = e,
            EventLog = [.. SessionState.I.Log],
            Verdict = failed?.Verdict,
            Domains = last?.Targets.Select(t => t.Host).ToList() ?? [],
            Russian = !Loc.Loc.I.English,
        };
    }
}

/// <summary>
/// "Сообщить о проблеме" (PLAN 4a.6): the draft of <see cref="BugReport.Build"/> with the tracker to choose, the
/// domain mask switch and the text the user edits. Copy, open GitHub's prefilled page or save the report archive, each
/// on its button only: nothing is sent by the program.
/// </summary>
public sealed partial class BugReportViewModel : ObservableObject
{
    private BugReportInput _input;
    private BugReportDraft _draft;
    private bool _building;

    public BugReportViewModel(BugReportInput input)
    {
        _input = input;
        _maskDomains = input.MaskDomains;
        _draft = BugReport.Build(_input);
        _targetIndex = (int)_draft.Target.Target;
        Show();
    }

    private static Loc.Loc L => Loc.Loc.I;

    /// <summary>Puts text on the clipboard; set by the window.</summary>
    public Func<string, Task>? CopyText { get; set; }

    /// <summary>Opens a page in the browser; set by the window, called by the GitHub button only.</summary>
    public Func<Uri, Task>? OpenUrl { get; set; }

    /// <summary>"Собрать отчёт": saves the archive and gives its file name, or null when nothing was saved.</summary>
    public Func<Task<string?>>? SaveArchive { get; set; }

    public IReadOnlyList<string> Targets => [L["bugreport.target_autotuner"], L["bugreport.target_gui"], L["bugreport.target_zapret2"]];

    public BugReportDraft Draft => _draft;

    [ObservableProperty]
    private int _targetIndex;

    [ObservableProperty]
    private bool _maskDomains;

    [ObservableProperty]
    private string _title = "";

    [ObservableProperty]
    private string _text = "";

    [ObservableProperty]
    private string _notice = "";

    [ObservableProperty]
    private string _status = "";

    partial void OnTargetIndexChanged(int value) => Rebuild();

    partial void OnMaskDomainsChanged(bool value) => Rebuild();

    private BugTarget Target => (BugTarget)Math.Clamp(TargetIndex, 0, 2);

    private void Rebuild()
    {
        if (_building)
            return;
        _input = _input with { MaskDomains = MaskDomains };
        _draft = BugReport.Build(_input, Target);
        Show();
    }

    private void Show()
    {
        _building = true;
        Title = _draft.Title;
        Text = _draft.Body;
        Notice = _draft.Notice;
        _building = false;
    }

    /// <summary>The page to open: the draft's own link, or one from the edited text (cut to the URL limit with a paste note).</summary>
    public (Uri Url, bool NeedsPaste) IssueUrl()
    {
        if (Title == _draft.Title && Text == _draft.Body)
            return (new Uri(_draft.IssueUrl), _draft.UrlShortened);
        var url = BugReport.NewIssueUrl(Target, Title, Text);
        if (url.Length <= BugReport.MaxUrlLength)
            return (new Uri(url), false);
        return (new Uri(BugReport.NewIssueUrl(Target, Title, L["bugreport.paste_here"])), true);
    }

    [RelayCommand]
    private async Task CopyAsync()
    {
        if (CopyText is not null)
            await CopyText(Title + "\n\n" + Text);
        Status = L["export.copied"];
    }

    [RelayCommand]
    private async Task OpenGitHubAsync()
    {
        var (url, paste) = IssueUrl();
        if (paste && CopyText is not null)
        {
            // the page cannot carry it all: the full text waits on the clipboard
            await CopyText(Text);
        }
        if (OpenUrl is not null)
            await OpenUrl(url);
        Status = paste ? L["bugreport.opened_paste"] : L["bugreport.opened"];
    }

    [RelayCommand]
    private async Task SaveArchiveAsync()
    {
        if (SaveArchive is null || await SaveArchive() is not { } name)
        {
            Status = L["reports.empty"];
            return;
        }
        bool edited = Title != _draft.Title || Text != _draft.Body;
        _input = _input with { ArchiveName = name };
        if (edited)
        {
            Status = L.F("bugreport.archive_saved_edited", name);
            return;
        }
        Rebuild();
        Status = L.F("bugreport.archive_saved", name);
    }
}
