using Grpc.Core;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning;

/// <summary>Raised when the Agent refuses to start an engine (Validator, policy, firewall).</summary>
public sealed class EngineRefusedException(string message) : Exception(message);

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
            throw new EngineRefusedException(e.Status.Detail);
        }
    }

    public async Task StopAsync(string engineId, CancellationToken ct) =>
        await client.StopEngineAsync(new StopEngineRequest { EngineId = engineId }, cancellationToken: ct);
}
