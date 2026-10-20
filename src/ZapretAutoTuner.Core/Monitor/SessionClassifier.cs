using System.Net;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Core.Monitor;

/// <summary>How one real session to a domain of the strategy went (dpi-diagnostics §9).</summary>
public enum SessionOutcome
{
    /// <summary>Too little traffic to judge (a connection that never got data and is still young).</summary>
    Unknown,
    Ok,

    /// <summary>A RST that did not come from the server.</summary>
    Reset,

    /// <summary>Data stopped at 8–32 KB and the connection hung: the 16 KB cut-off.</summary>
    Stalled16k,

    /// <summary>A handshake and no data at all.</summary>
    Stalled,

    /// <summary>UDP (QUIC): the client keeps sending, nothing comes back.</summary>
    NoReply,
}

public sealed record SessionSample(string Domain, L4Kind L4, DateTime Time, SessionOutcome Outcome, long BytesIn, int Retransmissions)
{
    public bool Failed => Outcome is not (SessionOutcome.Ok or SessionOutcome.Unknown);
}

/// <summary>
/// Turns captured flows into session samples for the live monitor: only headers and the ClientHello are looked at,
/// never the content. A flow belongs to a domain by its SNI, else by the DNS answer for its server address.
/// </summary>
public static class SessionClassifier
{
    public const long Stall16kMin = 8 * 1024;
    public const long Stall16kMax = 32 * 1024;

    /// <summary>A flow with no incoming data for this long, while the client was still there, hung.</summary>
    public static TimeSpan StallGap { get; } = TimeSpan.FromSeconds(4);

    /// <param name="captureEnd">The end of the capture window: a flow younger than <see cref="StallGap"/> there is not judged.</param>
    /// <param name="nameOf">The name of a server address from DNS, when the flow has no SNI.</param>
    public static SessionSample? Classify(Flow f, DateTime captureEnd, Func<IPAddress, string?>? nameOf = null)
    {
        var name = f.ClientHello?.Sni;
        if (string.IsNullOrEmpty(name))
            name = nameOf?.Invoke(f.Server.Address);
        if (string.IsNullOrEmpty(name))
            return null;
        var l4 = f.Protocol == "udp" ? L4Kind.Udp : L4Kind.Tcp;
        return new SessionSample(name.TrimEnd('.').ToLowerInvariant(), l4, f.FirstSeen, Outcome(f, captureEnd), f.BytesIn, f.Retransmissions);
    }

    public static SessionOutcome Outcome(Flow f, DateTime captureEnd)
    {
        if (f.Protocol == "udp")
        {
            if (f.PacketsIn >= 2)
                return SessionOutcome.Ok;
            return f.PacketsOut >= Diagnostics.FlowVerdict.UdpMinOut && f.PacketsIn <= 1 ? SessionOutcome.NoReply : SessionOutcome.Unknown;
        }
        if (f.Rsts.Any(r => r.FromServer && r.Origin == RstOrigin.Injected))
            return SessionOutcome.Reset;
        // the client went on after the last incoming byte (retransmits, keep-alives) for a while: the data hung
        bool hung = f.LastDataIn is { } last ? f.LastSeen - last >= StallGap : captureEnd - f.FirstSeen >= StallGap && f.LastSeen - f.FirstSeen >= StallGap;
        if (f.BytesIn == 0)
            return f.SynAckTime is not null && f.BytesOut > 0 && hung ? SessionOutcome.Stalled : SessionOutcome.Unknown;
        if (f.BytesIn is >= Stall16kMin and <= Stall16kMax && hung && f.Retransmissions > 0)
            return SessionOutcome.Stalled16k;
        return SessionOutcome.Ok;
    }

    /// <summary>Whether <paramref name="name"/> is <paramref name="domain"/> or its subdomain (hostlist semantics).</summary>
    public static bool Matches(string name, string domain) =>
        name.Equals(domain, StringComparison.OrdinalIgnoreCase)
        || (name.Length > domain.Length && name.EndsWith(domain, StringComparison.OrdinalIgnoreCase) && name[^(domain.Length + 1)] == '.');

    /// <summary>The domain of the strategy a session name belongs to (the longest match), or null.</summary>
    public static string? DomainOf(string name, IEnumerable<string> domains) =>
        domains.Where(d => Matches(name, d)).OrderByDescending(d => d.Length).FirstOrDefault();
}
