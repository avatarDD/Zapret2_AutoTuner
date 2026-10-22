using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.Mcp;
using ZapretAutoTuner.Mcp.Advisor;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>One line of the advisor panel.</summary>
public sealed record AdvisorLine(string Header, string Text, bool IsError);

/// <summary>
/// "Советник" (PLAN 4a.2, MCP M4): a language model works through the program's own MCP tools, in-process, with the MCP
/// permissions, the audit log and the yes/no dialogs. Off by default (Settings); nothing is sent before Start, and Stop
/// (here or on the MCP banner) cancels the request in flight.
/// </summary>
public sealed partial class AdvisorViewModel : PageViewModel
{
    /// <summary>Requests can take minutes with thinking; the Claude SDK has its own timeout on top.</summary>
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(10) };

    private readonly AppHost _host;
    private readonly AutoTunerTools _tools;
    private CancellationTokenSource? _cts;

    /// <param name="tools">The MCP session's tool facade (<see cref="McpService.Tools"/>): one session, audit and set of dialogs for every client.</param>
    public AdvisorViewModel(AppHost host, AutoTunerTools tools)
    {
        _host = host;
        _tools = tools;
    }

    public override string TitleKey => "nav.advisor";

    public AdvisorLimits Limits { get; init; } = new();

    /// <summary>Tests replace the network.</summary>
    internal HttpClient Client { get; init; } = Http;

    public ObservableCollection<AdvisorLine> Lines { get; } = [];

    [ObservableProperty]
    private string _task = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartCommand))]
    [NotifyCanExecuteChangedFor(nameof(StopCommand))]
    private bool _running;

    [ObservableProperty]
    private string _status = "";

    private bool CanStart => !Running;

    [RelayCommand(CanExecute = nameof(CanStart))]
    private async Task StartAsync()
    {
        var s = _host.Settings;
        if (!s.AdvisorEnabled)
        {
            Status = L["advisor.off"];
            return;
        }
        var o = new AdvisorOptions(s.AdvisorProvider, s.AdvisorModel, s.AdvisorEndpoint, s.AdvisorKey);
        if (o.Problem() is { } problem)
        {
            Status = L[MissingKey(problem)];
            return;
        }
        Running = true;
        Lines.Clear();
        Status = L["advisor.running"];
        using var cts = _cts = new CancellationTokenSource();
        var runner = new AdvisorRunner(_tools, Limits)
        {
            Client = "advisor · " + o.Model,
            IncludeSkills = o.Provider == AdvisorProvider.Claude,
            Language = L.English ? "en" : "ru",
        };
        var task = Task;
        try
        {
            var summary = await System.Threading.Tasks.Task.Run(() => runner.RunAsync(AdvisorChats.For(o, Limits, Client), task,
                e => Dispatcher.UIThread.Post(() => Add(e)), cts.Token));
            Status = L.F(OutcomeKey(summary.Outcome), summary.Turns, summary.ToolCalls, summary.Tokens);
        }
        finally
        {
            _cts = null;
            Running = false;
        }
    }

    /// <summary>The status text of each way a session ends (a test checks every outcome has one).</summary>
    internal static string OutcomeKey(AdvisorOutcome o) => "advisor.done_" + o.ToString().ToLowerInvariant();

    /// <summary>What <see cref="AdvisorOptions.Problem"/> found missing: model, key or endpoint.</summary>
    internal static string MissingKey(string problem) => "advisor.missing_" + problem;

    [RelayCommand(CanExecute = nameof(Running))]
    private void Stop() => Cancel();

    /// <summary>Stop here or on the MCP banner: the request in flight is cancelled and nothing more is sent.</summary>
    public void Cancel() => _cts?.Cancel();

    private void Add(AdvisorEvent e)
    {
        var header = e.Kind switch
        {
            AdvisorEventKind.Assistant => L["advisor.says"],
            AdvisorEventKind.ToolCall => "→ " + e.Tool,
            AdvisorEventKind.ToolResult => "← " + e.Tool,
            AdvisorEventKind.Error => L["advisor.error"],
            _ => "•",
        };
        Lines.Add(new AdvisorLine(header, e.Text, e.IsError));
        if (Lines.Count > 500)
            Lines.RemoveAt(0);
    }
}
