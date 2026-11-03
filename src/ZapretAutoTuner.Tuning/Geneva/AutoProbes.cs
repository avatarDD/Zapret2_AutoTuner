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
