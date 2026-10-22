using ZapretAutoTuner.Delivery;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.Services;

/// <summary>
/// zapret-gui on the router for the wizard and the MCP tools alike: one MCP link built from the address in the settings
/// and the token kept in memory (never stored), and after a commit the router's feedback read into the monitor's
/// journal (PLAN 7.4, 7.6.5). Nothing here changes the router: experiments revert by themselves, commits are made by
/// their callers after the user's yes.
/// </summary>
public sealed class RouterService(AppHost host) : IAsyncDisposable
{
    private sealed record Link(string Url, string Token, HttpClient Http, ZapretGuiMcp Mcp, ZapretGuiExperiments Experiments);

    private readonly Lock _lock = new();
    private readonly List<HttpClient> _clients = [];
    private Link? _link;
    private CancellationTokenSource? _feedback;
    private RouterFeedbackWatcher? _watcher;

    /// <summary>The journal got rows from the router (a commit, a failing or recovered host).</summary>
    public event Action? JournalChanged;

    /// <summary>The address and the token are both set.</summary>
    public bool Configured => Current() is not null;

    /// <summary>The experiments over the current link; null when the address or the token is missing or the address is wrong.</summary>
    public ZapretGuiExperiments? Experiments() => Current()?.Experiments;

    /// <summary>The targets whose feedback is read now; empty when none.</summary>
    public IReadOnlyList<string> Watched
    {
        get
        {
            lock (_lock)
                return _watcher?.Targets ?? [];
        }
    }

    public string FeedbackError
    {
        get
        {
            lock (_lock)
                return _watcher?.LastError ?? "";
        }
    }

    private Link? Current()
    {
        var url = host.Settings.GuiUrl.Trim();
        var token = host.Settings.GuiToken.Trim();
        if (url.Length == 0 || token.Length == 0 || ZapretGuiClient.BaseAddress(url) is not { } baseAddress)
            return null;
        lock (_lock)
        {
            if (_link is { } l && l.Url == url && l.Token == token)
                return l;
            // an older link may still serve a run in progress: its client is kept until the app exits
            var http = new HttpClient { BaseAddress = baseAddress, Timeout = TimeSpan.FromSeconds(60) };
            _clients.Add(http);
            var mcp = new ZapretGuiMcp(http, token);
            _link = new Link(url, token, http, mcp, new ZapretGuiExperiments(mcp));
            return _link;
        }
    }

    /// <summary>After a commit: the router's engine log is read every few minutes for these targets (replaces an earlier watch).</summary>
    public void StartFeedback(IReadOnlyList<string> targets)
    {
        var link = Current();
        RouterFeedbackWatcher watcher;
        CancellationTokenSource cts;
        lock (_lock)
        {
            _feedback?.Cancel();
            _feedback?.Dispose();
            _feedback = null;
            _watcher = null;
            if (link is null)
                return;
            cts = _feedback = new CancellationTokenSource();
            watcher = _watcher = new RouterFeedbackWatcher(host.Kb, (since, ct) => RouterFeedback.FromZapretGuiAsync(link.Mcp, since, ct), [.. targets]);
        }
        watcher.Changed += () => JournalChanged?.Invoke();
        _ = Task.Run(() => watcher.RunAsync(RouterFeedbackWatcher.DefaultInterval, cts.Token));
        JournalChanged?.Invoke();
    }

    public void StopFeedback()
    {
        lock (_lock)
        {
            _feedback?.Cancel();
            _feedback?.Dispose();
            _feedback = null;
            _watcher = null;
        }
    }

    public ValueTask DisposeAsync()
    {
        StopFeedback();
        lock (_lock)
        {
            foreach (var c in _clients)
                c.Dispose();
            _clients.Clear();
            _link = null;
        }
        return ValueTask.CompletedTask;
    }
}
