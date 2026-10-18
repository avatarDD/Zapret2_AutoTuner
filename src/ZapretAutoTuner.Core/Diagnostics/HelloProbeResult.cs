namespace ZapretAutoTuner.Core.Diagnostics;

/// <summary>What came back for a crafted ClientHello.</summary>
public enum HelloOutcome
{
    ServerHello,
    HelloRetryRequest,

    /// <summary>A TLS alert from the server: the hello passed the DPI, the server did not like it.</summary>
    Alert,

    /// <summary>RST after the hello (typical SNI or fingerprint block).</summary>
    Reset,

    /// <summary>No answer (DPI drop).</summary>
    Timeout,

    /// <summary>FIN without a TLS answer.</summary>
    Closed,

    /// <summary>The answer is not TLS (a block page, a proxy).</summary>
    NotTls,

    /// <summary>TCP connect failed; see <see cref="HelloProbeResult.ConnectError"/>.</summary>
    ConnectFailed,
}

public sealed record HelloProbeResult
{
    public required string Address { get; init; }

    public int Port { get; init; }

    public string? Sni { get; init; }

    public required string Spec { get; init; }

    public HelloOutcome Outcome { get; init; }

    public ProbeError ConnectError { get; init; }

    /// <summary>TLS alert description when <see cref="Outcome"/> is Alert.</summary>
    public int? AlertCode { get; init; }

    /// <summary>Negotiated version (0x0304 from supported_versions, else the legacy version).</summary>
    public int? ServerVersion { get; init; }

    public int? CipherSuite { get; init; }

    /// <summary>Size of the ClientHello handshake message.</summary>
    public int HelloBytes { get; init; }

    public string? Ja4 { get; init; }

    /// <summary>The hello carried a post-quantum key share (bigger than one MSS).</summary>
    public bool Kyber { get; init; }

    /// <summary>The hello carried an ECH extension.</summary>
    public bool Ech { get; init; }

    public TimeSpan Duration { get; init; }

    public TimeSpan? Ttfb { get; init; }

    public bool RstSeen => Outcome == HelloOutcome.Reset || ConnectError == ProbeError.ConnectRefused;

    /// <summary>The server answered as TLS: whatever filters this flow let the hello through.</summary>
    public bool PassedDpi => Outcome is HelloOutcome.ServerHello or HelloOutcome.HelloRetryRequest or HelloOutcome.Alert;

    public override string ToString() => $"{Spec} {Sni ?? "(no SNI)"} @ {Address}:{Port} → {Outcome}{(AlertCode is { } a ? $" alert {a}" : "")}";
}
