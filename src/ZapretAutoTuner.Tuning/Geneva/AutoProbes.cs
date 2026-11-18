using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Probes.Http;
using ZapretAutoTuner.Probes.Raw;

namespace ZapretAutoTuner.Tuning.Geneva;

/// <summary>The probes of the "Авто" mode; tests fake them.</summary>
public interface IAutoProbes
{
    /// <summary>
    /// The service now, with whatever is applied to it: without a bypass this is the baseline (AGENTS.md rule 5), with
    /// its strategy on it checks the bypass. Only services with <see cref="AutoService.Probeable"/> are asked.
    /// </summary>
    Task<AutoConfirm> CheckAsync(AutoService s, CancellationToken ct);

    /// <summary>How geneva's search judges a strategy for the service from a local port; null: the page's full download.</summary>
    GenevaJudge? Judge(AutoService s);

    /// <summary>
    /// The site's own browser handshakes (<see cref="AutoService.Replays"/>), sent again with whatever is applied: every
    /// one must get an answer. True when there are none. A strategy that lets the program's small ClientHello through
    /// but not Chrome's two-packet one with ML-KEM would otherwise be "found" and fail in the browser a minute later.
    /// </summary>
    Task<bool> HandshakesAsync(AutoService s, CancellationToken ct) => Task.FromResult(true);

    /// <summary>
    /// A strategy on the service works: the probe passes <see cref="AutoRules.TrialPasses"/> times in a row (one lucky
    /// load through a DPI that lets some connections pass is not a bypass) and the browser's handshakes get answers.
    /// </summary>
    async Task<bool> WorksAsync(AutoService s, CancellationToken ct)
    {
        for (int i = 0; i < AutoRules.TrialPasses; i++)
        {
            if (await CheckAsync(s, ct).ConfigureAwait(false) != AutoConfirm.NotBlocked)
                return false;
        }
        return await HandshakesAsync(s, ct).ConfigureAwait(false);
    }
}

/// <summary>
/// A site: the page's full download (L2) from the address it was seen at, with the name it was asked by. Anything
/// else: the program's first packets sent again, and any answer counts (dpi-diagnostics §8).
/// </summary>
public sealed class AutoProbes : IAutoProbes
{
    public static TimeSpan PageTime { get; } = TimeSpan.FromSeconds(12);

    public async Task<AutoConfirm> CheckAsync(AutoService s, CancellationToken ct)
    {
        if (s.Address is not { } address)
            return AutoConfirm.Unknown;
        if (s.Kind == AutoKind.Web)
        {
            var r = await HttpProbe.RunAsync(PageOptions(s, address, 0), ct).ConfigureAwait(false);
            if (r.Passes(ProbeLevel.L2Body))
                return AutoConfirm.NotBlocked;
            return r.Error is ProbeError.ConnectTimeout or ProbeError.Unreachable ? AutoConfirm.IpBlocked : AutoConfirm.Blocked;
        }
        if (!s.CanReplay)
            return AutoConfirm.Unknown;
        // two tries: one lost datagram is not a block
        ReplayProbeResult? last = null;
        for (int i = 0; i < 2; i++)
        {
            last = await ReplayProbe.RunAsync(ReplayOptions(s, address, 0), ct).ConfigureAwait(false);
            if (last.Ok)
                return AutoConfirm.NotBlocked;
        }
        return last!.Error == ReplayError.NoConnection ? AutoConfirm.IpBlocked : AutoConfirm.Blocked;
    }

    public async Task<bool> HandshakesAsync(AutoService s, CancellationToken ct)
    {
        if (s.Address is not { } address)
            return true;
        // the recorded hellos are TLS: they go to the site's TLS port, never to its plain-HTTP 80
        int tls = s.Ports.Count == 0 || s.Ports.Contains(443) ? 443 : s.Ports.FirstOrDefault(p => p != 80);
        if (tls == 0)
            return true;
        foreach (var replay in s.Replays)
        {
            bool ok = false;
            // two tries each: one lost segment is not a block
            for (int i = 0; i < 2 && !ok; i++)
            {
                var r = await ReplayProbe.RunAsync(new ReplayProbeOptions
                {
                    Address = address,
                    Port = tls,
                    Udp = false,
                    Payloads = AutoObserver.FromBase64(replay),
                    App = AppProtocol.Unknown,
                }, ct).ConfigureAwait(false);
                ok = r.Ok;
            }
            if (!ok)
                return false;
        }
        return true;
    }

    public GenevaJudge? Judge(AutoService s)
    {
        if (s.Kind == AutoKind.Web || !s.CanReplay)
            return null;
        var snapshot = s.Clone();
        return async (port, ct) =>
        {
            if (snapshot.Address is not { } address)
                return new GenevaJudgement(-400, "failed: no address");
            var r = await ReplayProbe.RunAsync(ReplayOptions(snapshot, address, port), ct).ConfigureAwait(false);
            if (ReplayProbe.LocalPortUnavailable(r))
                return new GenevaJudgement(0, $"{ProbeDetail.LocalPortPrefix}{port} {r.Socket}", PortUnavailable: true);
            return Fitness(r);
        };
    }

    /// <summary>A replay's result on geneva's scale (<see cref="GenevaFitness"/>): an answer is the full exchange of these protocols.</summary>
    public static GenevaJudgement Fitness(ReplayProbeResult r) => r.Error switch
    {
        ReplayError.None => new GenevaJudgement(400, "ok: answer"),
        ReplayError.Reset => new GenevaJudgement(-360, "reset"),
        ReplayError.NoConnection => new GenevaJudgement(-400, "connect_timeout"),
        ReplayError.NoAnswer => new GenevaJudgement(-400, "timeout: no answer"),
        ReplayError.ServerClosed => new GenevaJudgement(-480, "broken: closed"),
        _ => new GenevaJudgement(-400, $"failed: {r.Socket}"),
    };

    public static HttpProbeOptions PageOptions(AutoService s, System.Net.IPAddress address, int localPort) => new()
    {
        Host = s.Host.Length > 0 ? s.Host : s.Name,
        Address = address,
        Port = s.Port,
        Tls = s.Port != 80,
        Level = ProbeLevel.L2Body,
        LocalPort = localPort,
        MaxTime = PageTime,
    };

    public static ReplayProbeOptions ReplayOptions(AutoService s, System.Net.IPAddress address, int localPort) => new()
    {
        Address = address,
        Port = s.Port,
        Udp = s.Transport == L4Kind.Udp,
        Payloads = AutoObserver.FromBase64(s.Replay),
        App = s.App == "stun" ? AppProtocol.Stun : AppProtocol.Unknown,
        LocalPort = localPort,
    };
}
