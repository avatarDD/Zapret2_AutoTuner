using Grpc.Core;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning;

/// <summary>Raised when the Agent refuses to start an engine; <see cref="Stage"/> says which check refused it.</summary>
public sealed class EngineRefusedException(string stage, string message) : Exception(message)
{
    /// <summary>"validator" or "policy" (the strategy is wrong), "firewall" or "engine" (the machine is not ready).</summary>
    public string Stage { get; } = stage;

    /// <summary>The refusal is about the machine, not the strategy: every other strategy would be refused too.</summary>
    public bool Infrastructure => Stage is not ("validator" or "policy");

    /// <summary>The Agent's "stage: problems" text.</summary>
    public static EngineRefusedException FromAgent(string detail)
    {
        int colon = detail.IndexOf(':', StringComparison.Ordinal);
        return new EngineRefusedException(colon > 0 ? detail[..colon] : "engine", detail);
    }
}

/// <summary>Starting and stopping engine instances; the Agent does it for real, tests fake it.</summary>
public interface IEngineControl
{
    /// <summary>Starts an instance and returns its id. Throws <see cref="EngineRefusedException"/> on refusal.</summary>
    Task<string> StartAsync(IReadOnlyList<string> argv, QueueRule? queue, string tag, CancellationToken ct);

    Task StopAsync(string engineId, CancellationToken ct);
}

/// <summary><see cref="IEngineControl"/> over the Agent connection (AGENTS.md rule 6: the engine runs only there).</summary>
public sealed class AgentEngineControl(Agent.AgentClient client) : IEngineControl
{
    public async Task<string> StartAsync(IReadOnlyList<string> argv, QueueRule? queue, string tag, CancellationToken ct)
    {
        var req = new StartEngineRequest { Tag = tag, Queue = queue };
        req.Argv.AddRange(argv);
        try
        {
            return (await client.StartEngineAsync(req, cancellationToken: ct)).EngineId;
        }
        catch (RpcException e) when (e.StatusCode is StatusCode.InvalidArgument or StatusCode.FailedPrecondition or StatusCode.PermissionDenied)
        {
            throw EngineRefusedException.FromAgent(e.Status.Detail);
        }
    }

    public async Task StopAsync(string engineId, CancellationToken ct) =>
        await client.StopEngineAsync(new StopEngineRequest { EngineId = engineId }, cancellationToken: ct);
}
