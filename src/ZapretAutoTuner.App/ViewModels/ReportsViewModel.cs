using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>
/// "Собрать отчёт" (PLAN, release 1): the last run as a text and an archive with a prompt for Claude. Addresses are
/// always masked, domains on request; nothing is sent anywhere, the user saves or copies it.
/// </summary>
public sealed partial class ReportsViewModel : PageViewModel
{
    public override string TitleKey => "nav.reports";

    public Func<string, byte[], Task>? SaveFile { get; set; }

    public Func<string, Task>? CopyText { get; set; }

    /// <summary>The MCP audit log, included in the report.</summary>
    public Func<IReadOnlyList<string>>? McpAudit { get; set; }

    [ObservableProperty]
    private bool _maskDomains;

    [ObservableProperty]
    private string _environment = "";

    [ObservableProperty]
    private string _preview = "";

    [ObservableProperty]
    private string _status = "";

    partial void OnMaskDomainsChanged(bool value) => Refresh();

    private ReportOptions Options() => new()
    {
        MaskDomains = MaskDomains,
        EngineLog = [.. SessionState.I.Log],
        McpAudit = McpAudit?.Invoke() ?? [],
        Environment = [.. Environment.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)],
    };

    [RelayCommand]
    private void Refresh()
    {
        var last = SessionState.I.Last;
        Preview = last is null ? L["reports.empty"] : FailureReport.Text(last.Targets, Options());
    }

    [RelayCommand]
    private async Task SaveAsync() => await SaveArchiveAsync();

    /// <summary>"Собрать отчёт": the archive of the last run; returns its file name, or null when there is no run.</summary>
    public async Task<string?> SaveArchiveAsync()
    {
        if (SessionState.I.Last is not { } last)
        {
            Status = L["reports.empty"];
            return null;
        }
        var name = $"autotuner-report-{DateTime.Now:yyyyMMdd-HHmm}.zip";
        if (SaveFile is not null)
            await SaveFile(name, FailureReport.Archive(last.Targets, SessionState.I.Attempts, Options()));
        Status = L["export.saved"];
        return name;
    }

    /// <summary>Opens the "Сообщить о проблеме" dialog; set by the window.</summary>
    public Func<BugReportInput, Task>? ReportProblem { get; set; }

    [RelayCommand]
    private async Task ReportProblemAsync()
    {
        var input = BugReports.From() with
        {
            MaskDomains = MaskDomains,
            Environment = [.. Environment.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)],
        };
        if (ReportProblem is not null)
            await ReportProblem(input);
    }

    [RelayCommand]
    private async Task CopyAsync()
    {
        Refresh();
        if (CopyText is not null)
            await CopyText(Preview);
        Status = L["export.copied"];
    }

    [RelayCommand]
    private async Task CopyPromptAsync()
    {
        Refresh();
        if (CopyText is not null)
            await CopyText(FailureReport.Prompt + "\n\n" + Preview);
        Status = L["export.copied"];
    }
}
