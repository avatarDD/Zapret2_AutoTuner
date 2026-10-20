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

    /// <summary>Data stopped at 8–32 KB and the flow hung while the client retransmitted: the 16 KB cut-off.</summary>
    Cutoff,
}

/// <summary>
/// The health of a program's flow from the capture alone, for protocols without a page to load (dpi-diagnostics §8).
/// The same rules as the live monitor (<see cref="Monitor.SessionClassifier.Outcome"/>): UDP "out ≥ 4, in ≤ 1" is a
/// failure; TCP: an injected RST, a stall at 8–32 KB with retransmissions, or silence after the client spoke. A flow
/// younger than <see cref="Monitor.SessionClassifier.StallGap"/> at the end of the capture is not judged.
/// </summary>
public static class FlowVerdict
{
    public const int UdpMinOut = 4;

    /// <param name="captureEnd">The end of the capture; by default the flow's own last packet (so a flow is judged
    /// only on what it shows itself). Pass the real end: a flow opened just before it is then still young.</param>
    public static FlowHealth Judge(Flow f, DateTime? captureEnd = null)
    {
        var outcome = Monitor.SessionClassifier.Outcome(f, captureEnd ?? f.LastSeen);
        return outcome switch
        {
            Monitor.SessionOutcome.Ok => FlowHealth.Ok,
            Monitor.SessionOutcome.NoReply => FlowHealth.NoReply,
            Monitor.SessionOutcome.Reset => FlowHealth.Reset,
            Monitor.SessionOutcome.Stalled16k => FlowHealth.Cutoff,
            // no data at all: the server of a request-response protocol answers at once, else the client retransmits
            // what nobody acknowledged; a quiet server that was asked something else may just be holding a long poll
            Monitor.SessionOutcome.Stalled when f.Retransmissions > 0 || f.ClientHellos.Count > 0
                || f.AppProtocol is Packets.AppProtocol.Tls or Packets.AppProtocol.Http or Packets.AppProtocol.Mtproto => FlowHealth.Stalled,
            Monitor.SessionOutcome.Stalled when f.Rsts.Any(r => r.FromServer) => FlowHealth.Reset,
            _ => f.Protocol == "tcp" && f.BytesIn == 0 && f.Rsts.Any(r => r.FromServer) ? FlowHealth.Reset : FlowHealth.Unknown,
        };
    }
}
