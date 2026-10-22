using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.Mcp;

namespace ZapretAutoTuner.App.Services;

/// <summary>
/// The MCP server inside the app (PLAN 4a.3): one session for stdio and HTTP alike, the permissions from the settings,
/// the yes/no dialog of the window, the banner while an external agent drives the search, and the Stop button.
/// </summary>
public sealed partial class McpService : ObservableObject, IUserConfirm, IAsyncDisposable
{
    private static readonly TimeSpan ActiveWindow = TimeSpan.FromMinutes(2);

    private readonly AppHost _host;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly DispatcherTimer _timer;
    private McpHttpServer? _http;
    private CancellationTokenSource _stdio = new();

    public McpService(AppHost host, MonitorViewModel monitor)
    {
        _host = host;
        Session = new McpSession(new AppMcpHost(host, monitor), this, () => _host.Settings.McpEnabled ? _host.Settings.McpPermissions : new McpPermissions());
        Tools = new AutoTunerTools(Session);
        Session.Audit.Added += _ => Dispatcher.UIThread.Post(Refresh);
        _timer = new DispatcherTimer(TimeSpan.FromSeconds(2), DispatcherPriority.Background, (_, _) => Refresh());
        _timer.Start();
        Loc.Loc.I.PropertyChanged += (_, _) => Refresh();
    }

    public McpSession Session { get; }

    public AutoTunerTools Tools { get; }

    /// <summary>The window's yes/no dialog; set by the main window.</summary>
    public Func<string, string, Task<bool>>? Ask { get; set; }

    public Uri? HttpEndpoint => _http?.Endpoint;

    /// <summary>"Подбором управляет внешний агент": a call came in recently or work runs on the model's behalf.</summary>
    [ObservableProperty]
    private bool _bannerVisible;

    [ObservableProperty]
    private string _bannerText = "";

    [ObservableProperty]
    private string _httpStatus = "";

    public IReadOnlyList<string> AuditLines() => Session.Audit.Lines();

    /// <summary>Starts or stops the HTTP transport to match the settings.</summary>
    public async Task ApplyAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            bool want = _host.Settings.McpEnabled && _host.Settings.McpHttp;
            if (!want && _http is not null)
            {
                await _http.DisposeAsync().ConfigureAwait(false);
                _http = null;
            }
            else if (want && _http is null)
            {
                try
                {
                    try
                    {
                        _http = await McpHttpServer.StartAsync(Tools, _host.Settings.McpPort, _host.Settings.McpToken).ConfigureAwait(false);
                    }
                    catch (IOException)
                    {
                        // the kept port is taken by now: take any free one, clients read it from the settings page
                        _http = await McpHttpServer.StartAsync(Tools, 0, _host.Settings.McpToken).ConfigureAwait(false);
                    }
                    _host.Settings.McpPort = _http.Port;
                }
                catch (Exception e) when (e is IOException or System.Net.Sockets.SocketException or InvalidOperationException)
                {
                    Dispatcher.UIThread.Post(() => HttpStatus = Loc.Loc.I.F("mcp.http_failed", e.Message));
                    return;
                }
            }
            var endpoint = _http?.Endpoint;
            Dispatcher.UIThread.Post(() => HttpStatus = endpoint is null ? "" : Loc.Loc.I.F("mcp.http_running", endpoint));
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>After a new token: the running HTTP server is restarted with it.</summary>
    public async Task RestartHttpAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_http is not null)
            {
                await _http.DisposeAsync().ConfigureAwait(false);
                _http = null;
            }
        }
        finally
        {
            _gate.Release();
        }
        await ApplyAsync().ConfigureAwait(false);
    }

    /// <summary>Serves stdio (the <c>mcp</c> command when no window was running) until the client leaves or Stop.</summary>
    /// <returns>True when the client left (stdin closed), false when the user pressed Stop.</returns>
    public async Task<bool> RunStdioAsync(Stream input, Stream output, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _stdio.Token);
        try
        {
            await McpServerSetup.RunStreamAsync(Tools, input, output, linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
        }
        return !linked.IsCancellationRequested;
    }

    /// <summary>
    /// The banner's Stop: every call and dialog ends, the search stops, the experiment's engine is rolled back, the
    /// transports close and MCP stays off until the user turns it on again in the settings.
    /// </summary>
    [RelayCommand]
    public async Task StopAsync()
    {
        _host.Settings.McpEnabled = false;
        await (Interlocked.Exchange(ref _stdio, new CancellationTokenSource())).CancelAsync().ConfigureAwait(false);
        await Session.StopAllAsync().ConfigureAwait(false);
        await ApplyAsync().ConfigureAwait(false);
        Dispatcher.UIThread.Post(() =>
        {
            Stopped?.Invoke();
            Refresh();
        });
    }

    /// <summary>Raised on the UI thread after Stop, so the settings page shows MCP off.</summary>
    public event Action? Stopped;

    public async Task<bool> ConfirmAsync(ConfirmRequest request, CancellationToken ct)
    {
        var ask = Ask;
        if (ask is null)
            return false;
        var L = Loc.Loc.I;
        var title = L.Pick(request.TitleRu, request.TitleEn);
        var text = L.F("mcp.confirm_from_agent", Session.Client ?? "MCP") + "\n\n" + L.Pick(request.TextRu, request.TextEn);
        return await Dispatcher.UIThread.InvokeAsync(() => ask(title, text)).WaitAsync(ct).ConfigureAwait(false);
    }

    private void Refresh()
    {
        var recent = Session.LastCall is { } t && DateTime.UtcNow - t.ToUniversalTime() < ActiveWindow;
        BannerVisible = _host.Settings.McpEnabled && (Session.Busy || recent || Session.Confirmations.PendingCount > 0);
        BannerText = Loc.Loc.I["mcp.banner"] + (Session.Client is { Length: > 0 } c ? " · " + c : "");
    }

    /// <summary>Call on the UI thread: the timer stops at once, the rest finishes off it.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Dispatcher.UIThread.CheckAccess())
            _timer.Stop();
        await _stdio.CancelAsync().ConfigureAwait(false);
        await Session.StopAllAsync().ConfigureAwait(false);
        if (_http is not null)
            await _http.DisposeAsync().ConfigureAwait(false);
        _stdio.Dispose();
        _gate.Dispose();
    }
}
