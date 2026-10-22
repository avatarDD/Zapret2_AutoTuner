using System.Net;
using Avalonia.Threading;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Mcp;
using ZapretAutoTuner.Probes.Browser;
using ZapretAutoTuner.Probes.Diagnostics;
using ZapretAutoTuner.Probes.Http;
using ZapretAutoTuner.Protocol;
using ZapretAutoTuner.Storage;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.Services;

/// <summary>The MCP tools' view of this program: probes from the UI process, the engine and capture through the Agent.</summary>
public sealed class AppMcpHost(AppHost host, MonitorViewModel monitor) : IAutoTunerHost
{
    public KnowledgeBase Kb => host.Kb;

    public IReadOnlyList<string> Targets => host.Settings.Targets;

    public void AddTarget(string target) => host.Settings.AddTargets([target]);

    public async Task<ClassifierVerdict> ClassifyAsync(string target, CancellationToken ct) =>
        (await ClassifierRunner.RunAsync(target, new ClassifierOptions(), null, ct).ConfigureAwait(false)).Verdict;

    public async Task<IReadOnlyList<IPAddress>> ResolveAsync(string target, CancellationToken ct) =>
        await Dns.GetHostAddressesAsync(target, ct).ConfigureAwait(false);

    public async Task<IEngineControl> EngineAsync(CancellationToken ct) =>
        new AgentEngineControl((await host.AgentAsync(ct).ConfigureAwait(false)).Client);

    public AgentTrialOptions TrialOptions => new() { LuaDir = host.Bundle.LuaDir, UserLua = host.Resources.ApprovedLuaPaths() };

    public ResourceStore? Resources => host.Resources;

    /// <summary>The MCP search learns like the wizard's: the provider from Settings, the label of the verdict.</summary>
    public Core.Search.SearchLearning? SearchLearning(string blockLabel) => SearchContext.For(host, blockLabel).Learning;

    /// <summary>The router of the settings, as the Resources page uses it; the MCP tool asks the user before running it.</summary>
    public Task<Delivery.RouterResourceOperation> PrepareRouterResourceAsync(Delivery.RouterResourceAction action, Core.Resources.ResourceKind kind, string name, CancellationToken ct) =>
        new RouterResourceService(host).PrepareAsync(action, kind, name, ct);

    /// <summary>The run's log belongs to the UI thread: read there.</summary>
    public BugReportInput BugReportContext() =>
        Dispatcher.UIThread.CheckAccess() ? BugReports.From() : Dispatcher.UIThread.Invoke(() => BugReports.From());

    public Task<ProbeResult> ProbeAsync(HttpProbeOptions options, CancellationToken ct) => HttpProbe.RunAsync(options, ct);

    public Func<string, CancellationToken, Task<PageLoad>>? OpenPage { get; } =
        (target, ct) => BrowserProbe.RunAsync(new BrowserProbeOptions { Url = "https://" + target + "/" }, ct);

    public ITrialCapture? Capture { get; } = new AgentCapture(host);

    public bool ProtectionActive => monitor.Active;

    public async Task CommitAsync(Solution solution, CancellationToken ct)
    {
        var started = await Dispatcher.UIThread.InvokeAsync(async () =>
        {
            await monitor.ApplySolutionAsync(solution);
            return monitor.Active;
        });
        if (!started)
            throw new InvalidOperationException(monitor.Status);
    }

    public async Task<string> SaveExportAsync(string name, byte[] zip, CancellationToken ct)
    {
        var dir = Path.Combine(host.DataDir, "exports");
        Directory.CreateDirectory(dir);
        // the name comes from the program, but keep it a bare file name whatever happens
        var file = Path.GetFileName(name);
        if (file.Length == 0 || file.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            file = $"export-{DateTime.Now:yyyyMMdd-HHmmss}.zip";
        await File.WriteAllBytesAsync(Path.Combine(dir, file), zip, ct).ConfigureAwait(false);
        return file;
    }

    public Delivery.ZapretGuiExperiments? RouterExperiments() => host.Router.Experiments();

    public void RouterCommitted(IReadOnlyList<string> targets, string strategy) => host.Router.StartFeedback(targets);

    private sealed class AgentCapture(AppHost host) : ITrialCapture
    {
        public async Task<string> StartAsync(IReadOnlyList<IPAddress> addresses, int port, CancellationToken ct)
        {
            var agent = await host.AgentAsync(ct).ConfigureAwait(false);
            var request = new StartCaptureRequest { MaxBytes = McpSession.MaxPcapBytes, Snaplen = 256 };
            request.Addresses.AddRange(addresses.Select(a => a.ToString()));
            request.Ports.Add(port);
            return (await agent.Client.StartCaptureAsync(request, cancellationToken: ct)).CaptureId;
        }

        public async Task<byte[]> StopAsync(string captureId, CancellationToken ct)
        {
            var agent = await host.AgentAsync(ct).ConfigureAwait(false);
            var (pcap, _) = await new AgentProgramMonitor(agent.Client).StopCaptureAsync(captureId, ct).ConfigureAwait(false);
            return pcap;
        }
    }
}
