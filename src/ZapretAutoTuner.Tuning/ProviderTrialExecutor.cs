using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Probes.Http;
using ZapretAutoTuner.Probes.Providers;

namespace ZapretAutoTuner.Tuning;

/// <summary>
/// Trials for a hosting provider as a whole (PLAN 6.4, dpi-diagnostics §4a): one engine instance limited to the
/// sampled addresses of different prefixes, each attempt on the next of them with its own SNI. A strategy that works
/// on one range only does not get N/N.
/// </summary>
public sealed class ProviderTrialExecutor : ITrialExecutor
{
    private readonly AgentTrialExecutor _engine;
    private readonly IReadOnlyList<ProviderTarget> _targets;
    private readonly AgentTrialOptions _options;
    private readonly Func<HttpProbeOptions, CancellationToken, Task<ProbeResult>> _probe;

    public ProviderTrialExecutor(IEngineControl engine, IReadOnlyList<ProviderTarget> targets, AgentTrialOptions options,
        Func<HttpProbeOptions, CancellationToken, Task<ProbeResult>>? probe = null)
    {
        if (targets.Count == 0)
            throw new ArgumentException("нет адресов провайдера для проверки / no provider targets", nameof(targets));
        _targets = targets;
        _options = options;
        _probe = probe ?? HttpProbe.RunAsync;
        _engine = new AgentTrialExecutor(engine, new TrialTarget
        {
            Host = targets[0].Provider,
            Addresses = targets.Select(t => t.Address).Distinct().ToList(),
        }, options);
    }

    internal HttpProbeOptions ProbeOptions(ProviderTarget t)
    {
        var o = new HttpProbeOptions { Host = t.Host, Address = t.Address, Path = t.Path, MinBytes = t.MinBytes, PadBytes = t.PadBytes };
        return _options.TweakHttp?.Invoke(o) ?? o;
    }

    public async Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
    {
        // at least one attempt per sampled address: N/N must mean every range
        attempts = Math.Max(attempts, _targets.Count);
        try
        {
            return await _engine.WithEngineAsync(candidate, async ct =>
            {
                var outcomes = new List<TrialOutcome>();
                for (int i = 0; i < attempts; i++)
                {
                    if (i > 0)
                        await Task.Delay(_options.Pause, ct).ConfigureAwait(false);
                    var t = _targets[i % _targets.Count];
                    var r = await _probe(ProbeOptions(t), ct).ConfigureAwait(false);
                    outcomes.Add(AgentTrialExecutor.ToOutcome(r, t.MinBytes));
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

    public Task<bool> TargetReachableAsync(CancellationToken ct) => _engine.TargetReachableAsync(ct);
}
