using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Probes.Raw;

namespace ZapretAutoTuner.Tuning;

/// <summary>
/// A strategy for this endpoint cannot be judged by a replay (<see cref="ReplayProbe.CanReplay"/>): it is verified by
/// rerunning the program only (<see cref="ProgramCheck"/>). Thrown before the engine starts, so no trial is spent.
/// </summary>
public sealed class NotReplayableException(ProgramEndpoint endpoint, ReplayCheck check)
    : InvalidOperationException($"{endpoint.Remote}: {check.Ru} — проверка только перезапуском программы / {check.En} — verify by rerunning the program")
{
    public ProgramEndpoint Endpoint { get; } = endpoint;

    public ReplayCheck Check { get; } = check;
}

/// <summary>
/// Trials for an endpoint without a page (PLAN 6.3: STUN, WireGuard, Discord voice, MTProto, any UDP): the engine is
/// limited to the endpoint's address and port, and the program's first packets are replayed to it. An answer is the
/// success; the program check later confirms it with the program itself. Endpoints whose first packets are
/// authenticated or bound to a session (WireGuard, Discord voice, ICE) cannot be replayed: <see cref="VerifyByRerunOnly"/>
/// says so before a search starts, and <see cref="RunAsync"/> refuses them with <see cref="NotReplayableException"/>.
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
        Replay = Replayable(endpoint);
    }

    /// <summary>Whether a replay can judge strategies for this endpoint.</summary>
    public ReplayCheck Replay { get; }

    /// <summary>Strategies for this endpoint are verified by rerunning the program only (no replay search).</summary>
    public bool VerifyByRerunOnly => !Replay.CanReplay;

    public static ReplayCheck Replayable(ProgramEndpoint e) => ReplayProbe.CanReplay(e.App, e.InitialPayloads, e.InitialPayloadsTruncated);

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
        if (VerifyByRerunOnly)
            throw new NotReplayableException(_endpoint, Replay);
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
        var failure = r.Error switch
        {
            ReplayError.None or ReplayError.NoAnswer => TrialFailure.Timeout,
            ReplayError.Reset => TrialFailure.Reset,
            ReplayError.NoConnection => TrialFailure.NoConnect,
            ReplayError.Socket => r.Socket switch
            {
                System.Net.Sockets.SocketError.ConnectionReset => TrialFailure.Reset,
                System.Net.Sockets.SocketError.ConnectionRefused or System.Net.Sockets.SocketError.TimedOut
                    or System.Net.Sockets.SocketError.NetworkUnreachable or System.Net.Sockets.SocketError.HostUnreachable => TrialFailure.NoConnect,
                _ => TrialFailure.Other,
            },
            _ => TrialFailure.Other,
        };
        return new TrialOutcome(false, failure, $"{r.ErrorRu} / {r.ErrorEn}", r.BytesIn, r.Duration);
    }

    /// <summary>What to generate for the endpoint: its protocol in the generator's terms.</summary>
    public static GeneratorOptions Generator(ProgramEndpoint e, GeneratorOptions? baseOptions = null) =>
        (baseOptions ?? new GeneratorOptions()) with { Protocol = StrategyGenerator.FromApp(e.App, e.Protocol == L4Kind.Udp) };

    public static IPEndPoint Key(ProgramEndpoint e) => e.Remote;
}
