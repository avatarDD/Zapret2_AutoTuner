namespace ZapretAutoTuner.Core.Diagnostics;

public enum QuicOutcome
{
    /// <summary>A server Initial with a ServerHello came back: QUIC with this SNI passes.</summary>
    ServerHello,

    /// <summary>Datagrams came back, but no readable ServerHello (Retry, version negotiation, coalesced 1-RTT only).</summary>
    Responded,

    /// <summary>Version Negotiation: the server does not speak this QUIC version.</summary>
    VersionNegotiation,

    /// <summary>Nothing came back (QUIC_BLOCK, or no HTTP/3 on this address).</summary>
    NoResponse,

    /// <summary>ICMP port unreachable.</summary>
    Unreachable,
}

public sealed record QuicProbeResult
{
    public required string Address { get; init; }

    public int Port { get; init; }

    public string? Sni { get; init; }

    public QuicOutcome Outcome { get; init; }

    /// <summary>Datagrams sent (a kyber hello needs two).</summary>
    public int Sent { get; init; }

    public int Received { get; init; }

    public long BytesReceived { get; init; }

    public TimeSpan? FirstReply { get; init; }

    public TimeSpan Duration { get; init; }

    /// <summary>Versions offered in a Version Negotiation packet.</summary>
    public IReadOnlyList<uint> OfferedVersions { get; init; } = [];

    public bool PassedDpi => Outcome is QuicOutcome.ServerHello or QuicOutcome.Responded or QuicOutcome.VersionNegotiation;

    public override string ToString() => $"QUIC {Sni} @ {Address}:{Port} → {Outcome} ({Received} datagrams)";
}
