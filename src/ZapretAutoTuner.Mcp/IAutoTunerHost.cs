using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Probes.Http;
using ZapretAutoTuner.Storage;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// What the MCP tools need from the program; the App implements it, tests fake it. Everything privileged (the engine,
/// the capture) goes through <see cref="EngineAsync"/> and <see cref="Capture"/>, i.e. the Agent (AGENTS.md rule 6).
/// </summary>
public interface IAutoTunerHost
{
    KnowledgeBase Kb { get; }

    /// <summary>The user's targets: probes go only to these.</summary>
    IReadOnlyList<string> Targets { get; }

    /// <summary>Adds a target; called only after the user said yes.</summary>
    void AddTarget(string host);

    /// <summary>The classifier with its baseline probes (dpi-diagnostics §2).</summary>
    Task<ClassifierVerdict> ClassifyAsync(string host, CancellationToken ct);

    /// <summary>Addresses of a target without a verdict (system DNS).</summary>
    Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken ct);

    /// <summary>The Agent's engine control (starts the Agent on first use).</summary>
    Task<IEngineControl> EngineAsync(CancellationToken ct);

    /// <summary>Engine options of trials (lua directory, platform).</summary>
    AgentTrialOptions TrialOptions { get; }

    /// <summary>One L1/L2 probe.</summary>
    Task<ProbeResult> ProbeAsync(HttpProbeOptions options, CancellationToken ct);

    /// <summary>The page in a real browser (L3); null when no browser is available.</summary>
    Func<string, CancellationToken, Task<PageLoad>>? OpenPage { get; }

    /// <summary>Capture of a trial's packets through the Agent; null when not available.</summary>
    ITrialCapture? Capture { get; }

    /// <summary>"Защита активна" is running: a live experiment would fight it for the traffic.</summary>
    bool ProtectionActive { get; }

    /// <summary>A committed experiment variant becomes the active protection (after the user said yes).</summary>
    Task CommitAsync(Solution solution, CancellationToken ct);

    /// <summary>Saves an export package in the program's export folder (after the user said yes); returns the file name.</summary>
    Task<string> SaveExportAsync(string name, byte[] zip, CancellationToken ct);
}

/// <summary>Packet capture of a trial, limited to the target's addresses and port.</summary>
public interface ITrialCapture
{
    Task<string> StartAsync(IReadOnlyList<IPAddress> addresses, int port, CancellationToken ct);

    Task<byte[]> StopAsync(string captureId, CancellationToken ct);
}

/// <summary>What the user is asked in the AutoTuner window.</summary>
public sealed record ConfirmRequest(string Tool, string TitleRu, string TitleEn, string TextRu, string TextEn);

/// <summary>
/// The yes/no dialog in the AutoTuner window (AGENTS.md rule 7). The model never gets a way to answer it: a tool that
/// needs it returns "pending confirmation" and the decision arrives from the user only.
/// </summary>
public interface IUserConfirm
{
    Task<bool> ConfirmAsync(ConfirmRequest request, CancellationToken ct);
}
