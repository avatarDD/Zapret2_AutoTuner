using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Probes.Raw;

namespace ZapretAutoTuner.Tuning;

/// <summary>
/// Trials for an endpoint without a page (PLAN 6.3: STUN, WireGuard, Discord voice, MTProto, any UDP): the engine is
/// limited to the endpoint's address and port, and the program's first packets are replayed to it. An answer is the
/// success; the program check later confirms it with the program itself.
/// </summary>
public sealed class EndpointTrialExecutor : ITrialExecutor
{
    private readonly AgentTrialExecutor _engine;
    private readonly ProgramEndpoint _endpoint;
    private readonly Func<ReplayProbeOptions, CancellationToken, Task<ReplayProbeResult>> _probe;

    public EndpointTrialExecutor(IEngineControl engine, ProgramEndpoint endpoint, AgentTrialOptions options,
        Func<ReplayProbeOptions, CancellationToken, Task<ReplayProbeResult>>? probe = null)
    {
        _endpoint = endpoint;
        _probe = probe ?? ReplayProbe.RunAsync;
        _engine = new AgentTrialExecutor(engine, Target(endpoint), options);
    }

    /// <summary>The engine side of the trial: one address, one port, no TLS.</summary>
    internal static TrialTarget Target(ProgramEndpoint e) => new()
    {
        Host = e.Host ?? e.Remote.Address.ToString(),
        Addresses = [e.Remote.Address],
        Port = e.Remote.Port,
        Tls = false,
    };

    internal ReplayProbeOptions ProbeOptions() => new()
    {
        Address = _endpoint.Remote.Address,
        Port = _endpoint.Remote.Port,
        Udp = _endpoint.Protocol == L4Kind.Udp,
        Payloads = _endpoint.InitialPayloads,
        App = _endpoint.App,
        Rounds = FlowVerdict.UdpMinOut,
    };

    public async Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
    {
        try
        {
            return await _engine.WithEngineAsync(candidate, async ct =>
            {
                var outcomes = new List<TrialOutcome>();
                for (int i = 0; i < attempts; i++)
                {
                    var r = await _probe(ProbeOptions(), ct).ConfigureAwait(false);
                    outcomes.Add(ToOutcome(r));
                    if (stopEarly(outcomes))
                        break;
                }
                return (IReadOnlyList<TrialOutcome>)outcomes;
            }, ct).ConfigureAwait(false);
        }
        catch (EngineRefusedException e) when (!e.Infrastructure)
        {
            return [TrialOutcome.Fail(TrialFailure.Other, e.Message)];
        }
    }

    /// <summary>TCP: a connect without the engine; UDP has no handshake to check, so the endpoint counts as reachable.</summary>
    public Task<bool> TargetReachableAsync(CancellationToken ct) =>
        _endpoint.Protocol == L4Kind.Udp ? Task.FromResult(true) : _engine.TargetReachableAsync(ct);

    internal static TrialOutcome ToOutcome(ReplayProbeResult r)
    {
        if (r.Ok)
            return new TrialOutcome(true, TrialFailure.None, null, r.BytesIn, r.Duration);
        // the probe's errors: "сброс (RST)", "нет соединения", "нет ответа", "сервер закрыл соединение" or a SocketError name
        var failure = r.Error switch
        {
            null or "нет ответа" => TrialFailure.Timeout,
            "сброс (RST)" or nameof(System.Net.Sockets.SocketError.ConnectionReset) => TrialFailure.Reset,
            "нет соединения" or nameof(System.Net.Sockets.SocketError.ConnectionRefused) or nameof(System.Net.Sockets.SocketError.TimedOut)
                or nameof(System.Net.Sockets.SocketError.NetworkUnreachable) or nameof(System.Net.Sockets.SocketError.HostUnreachable) => TrialFailure.NoConnect,
            _ => TrialFailure.Other,
        };
        return new TrialOutcome(false, failure, r.Error, r.BytesIn, r.Duration);
    }

    /// <summary>What to generate for the endpoint: its protocol in the generator's terms.</summary>
    public static GeneratorOptions Generator(ProgramEndpoint e, GeneratorOptions? baseOptions = null) =>
        (baseOptions ?? new GeneratorOptions()) with { Protocol = StrategyGenerator.FromApp(e.App, e.Protocol == L4Kind.Udp) };

    public static IPEndPoint Key(ProgramEndpoint e) => e.Remote;
}
