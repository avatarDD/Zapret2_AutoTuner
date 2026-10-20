using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Core.Diagnostics;

public enum FlowHealth
{
    /// <summary>Too little traffic to say anything.</summary>
    Unknown,
    Ok,

    /// <summary>The client keeps sending, nothing comes back (the UDP detector of dpi-diagnostics §8).</summary>
    NoReply,

    /// <summary>A TCP flow cut by a RST that did not come from the server.</summary>
    Reset,

    /// <summary>A TCP flow that got its handshake and then no data.</summary>
    Stalled,
}

/// <summary>
/// The health of a program's flow from the capture alone, for protocols without a page to load (dpi-diagnostics §8):
/// for UDP "out ≥ 4, in ≤ 1" is a failure; for TCP an injected RST or silence after the client spoke.
/// </summary>
public static class FlowVerdict
{
    public const int UdpMinOut = 4;

    public static FlowHealth Judge(Flow f)
    {
        if (f.Protocol == "udp")
        {
            if (f.PacketsIn >= 2)
                return FlowHealth.Ok;
            return f.PacketsOut >= UdpMinOut && f.PacketsIn <= 1 ? FlowHealth.NoReply : FlowHealth.Unknown;
        }
        if (f.Rsts.Any(r => r.FromServer && r.Origin == Packets.RstOrigin.Injected))
            return FlowHealth.Reset;
        if (f.BytesIn > 0)
            return FlowHealth.Ok;
        if (f.Rsts.Any(r => r.FromServer))
            return FlowHealth.Reset;
        return f.BytesOut > 0 && f.SynAckTime is not null ? FlowHealth.Stalled : FlowHealth.Unknown;
    }
}
