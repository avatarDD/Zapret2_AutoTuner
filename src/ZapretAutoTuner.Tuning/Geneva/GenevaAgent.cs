using System.Runtime.CompilerServices;
using Grpc.Core;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning.Geneva;

/// <summary>Raised when the Agent refuses a geneva start or command; the text is the Agent's (Russian / English).</summary>
public sealed class GenevaRefusedException(string message) : Exception(message);

/// <summary>geneva in the Agent (AGENTS.md rule 6); tests fake it.</summary>
public interface IGenevaAgent
{
    Task<GenevaStartReply> StartAsync(GenevaStartRequest request, CancellationToken ct);

    Task StopAsync(string id, CancellationToken ct);

    IAsyncEnumerable<GenevaOutput> WatchAsync(string id, CancellationToken ct);

    Task AnswerAsync(string id, long requestId, int fitness, string detail, CancellationToken ct);

    Task<GenevaControlReply> ControlAsync(string id, string cmd, string? strategy, CancellationToken ct);

    Task<GenevaInfoReply> InfoAsync(CancellationToken ct);
}

/// <summary><see cref="IGenevaAgent"/> over the Agent's gRPC connection.</summary>
public sealed class AgentGeneva(Agent.AgentClient client) : IGenevaAgent
{
    public async Task<GenevaStartReply> StartAsync(GenevaStartRequest request, CancellationToken ct)
    {
        try
        {
            return await client.GenevaStartAsync(request, cancellationToken: ct);
        }
        catch (RpcException e) when (e.StatusCode is StatusCode.FailedPrecondition or StatusCode.InvalidArgument)
        {
            throw new GenevaRefusedException(e.Status.Detail);
        }
    }

    public async Task StopAsync(string id, CancellationToken ct) =>
        await client.GenevaStopAsync(new GenevaStopRequest { Id = id }, cancellationToken: ct);

    public async IAsyncEnumerable<GenevaOutput> WatchAsync(string id, [EnumeratorCancellation] CancellationToken ct)
    {
        using var call = client.GenevaWatch(new GenevaWatchRequest { Id = id }, cancellationToken: ct);
        while (await call.ResponseStream.MoveNext(ct))
            yield return call.ResponseStream.Current;
    }

    public async Task AnswerAsync(string id, long requestId, int fitness, string detail, CancellationToken ct)
    {
        try
        {
            await client.GenevaAnswerAsync(new GenevaAnswerRequest { Id = id, RequestId = requestId, Fitness = fitness, Detail = detail }, cancellationToken: ct);
        }
        catch (RpcException e) when (e.StatusCode == StatusCode.FailedPrecondition)
        {
            throw new GenevaRefusedException(e.Status.Detail);
        }
    }

    public async Task<GenevaControlReply> ControlAsync(string id, string cmd, string? strategy, CancellationToken ct)
    {
        try
        {
            return await client.GenevaControlAsync(new GenevaControlRequest { Id = id, Cmd = cmd, Strategy = strategy ?? "" }, cancellationToken: ct);
        }
        catch (RpcException e) when (e.StatusCode == StatusCode.FailedPrecondition)
        {
            throw new GenevaRefusedException(e.Status.Detail);
        }
    }

    public async Task<GenevaInfoReply> InfoAsync(CancellationToken ct)
    {
        try
        {
            return await client.GenevaInfoAsync(new GenevaInfoRequest(), cancellationToken: ct);
        }
        catch (RpcException e) when (e.StatusCode == StatusCode.FailedPrecondition)
        {
            throw new GenevaRefusedException(e.Status.Detail);
        }
    }
}
