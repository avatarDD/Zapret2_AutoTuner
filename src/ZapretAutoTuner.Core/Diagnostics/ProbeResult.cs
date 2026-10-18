namespace ZapretAutoTuner.Core.Diagnostics;

/// <summary>Where a probe attempt broke (dpi-diagnostics §3). <see cref="None"/> means it ran to the end.</summary>
public enum ProbeError
{
    None,

    /// <summary>SYN unanswered: IP or port drop.</summary>
    ConnectTimeout,

    /// <summary>RST in reply to SYN: closed port or an injected reset.</summary>
    ConnectRefused,

    /// <summary>ICMP unreachable or no route.</summary>
    Unreachable,

    /// <summary>TCP is up, the ClientHello got no answer (DPI drop).</summary>
    TlsTimeout,

    /// <summary>RST during the handshake (typical SNI block).</summary>
    TlsReset,

    /// <summary>The peer closed the connection during the handshake (FIN).</summary>
    TlsClosed,

    /// <summary>The handshake failed with a TLS alert or protocol error.</summary>
    TlsFailed,

    /// <summary>No HTTP response in time after the request.</summary>
    HttpTimeout,

    /// <summary>RST after the handshake (while sending or receiving HTTP).</summary>
    HttpReset,

    /// <summary>No incoming bytes for the stall timeout: the 16 KB cut-off looks like this.</summary>
    Stalled,

    /// <summary>The connection closed before the response was complete.</summary>
    Truncated,

    /// <summary>The response is not HTTP.</summary>
    BadResponse,

    /// <summary>The overall time limit was reached while data was still flowing.</summary>
    TimeLimit,

    /// <summary>Any other local failure (see <see cref="ProbeResult.ErrorDetail"/>).</summary>
    Other,
}

/// <summary>Who sent the reset that broke the attempt, judged from a capture (FlowAnalyzer).</summary>
public enum RstOrigin
{
    Unknown,
    Server,
    Injected,
}

/// <summary>
/// One probe attempt (dpi-diagnostics §3): <c>{connect_ok, tls_ok, http_status, bytes_in, ttfb, duration,
/// stalled_at, rst_seen, rst_origin_guess, alpn, tls_version, error}</c> plus what the classifier needs as evidence.
/// </summary>
public sealed record ProbeResult
{
    public required string Host { get; init; }

    public required string Address { get; init; }

    public int Port { get; init; } = 443;

    /// <summary>The attempt used TLS (false for plain HTTP).</summary>
    public bool Tls { get; init; } = true;

    /// <summary>SNI sent; null when the hello carried none.</summary>
    public string? Sni { get; init; }

    public bool ConnectOk { get; init; }

    public bool TlsOk { get; init; }

    public int? HttpStatus { get; init; }

    /// <summary>Response bytes after the TLS layer (headers and body).</summary>
    public long BytesIn { get; init; }

    /// <summary>Request bytes sent on the wire, TLS included (a padded request is large).</summary>
    public long BytesOut { get; init; }

    /// <summary>Response body bytes.</summary>
    public long BodyBytes { get; init; }

    /// <summary>Content-Length of the response, if given.</summary>
    public long? ContentLength { get; init; }

    /// <summary>The whole body arrived (Content-Length reached, last chunk, or close after a body without length).</summary>
    public bool Complete { get; init; }

    public TimeSpan? ConnectTime { get; init; }

    public TimeSpan? TlsTime { get; init; }

    /// <summary>From sending the request to the first response byte.</summary>
    public TimeSpan? Ttfb { get; init; }

    public TimeSpan Duration { get; init; }

    /// <summary>Response bytes received when the flow stalled; null if it did not.</summary>
    public long? StalledAt { get; init; }

    public bool RstSeen { get; init; }

    public RstOrigin RstOrigin { get; init; }

    public string? Alpn { get; init; }

    /// <summary>"1.2" or "1.3".</summary>
    public string? TlsVersion { get; init; }

    /// <summary>The certificate is valid for <see cref="Host"/> and chains to a trusted root.</summary>
    public bool CertValid { get; init; }

    public string? CertSubject { get; init; }

    public string? CertIssuer { get; init; }

    /// <summary>DNS names of the certificate (SAN): the real host name of an IP probed without SNI.</summary>
    public IReadOnlyList<string> CertNames { get; init; } = [];

    /// <summary>Why the certificate was rejected (name mismatch, untrusted chain…).</summary>
    public string? CertError { get; init; }

    /// <summary>Location header of a redirect.</summary>
    public string? Location { get; init; }

    public ProbeError Error { get; init; }

    public string? ErrorDetail { get; init; }

    /// <summary>
    /// Success at the given level (dpi-diagnostics §3). 4xx/5xx count as success: the server answered. L2 needs
    /// <paramref name="minBytes"/> of body or the whole resource, without a stall. L3 is decided by the browser probe.
    /// </summary>
    public bool Passes(ProbeLevel level, long minBytes = 64 * 1024)
    {
        bool l1 = ConnectOk && HttpStatus is not null && (!Tls || (TlsOk && CertValid));
        return level switch
        {
            ProbeLevel.L1Handshake => l1,
            ProbeLevel.L2Body => l1 && StalledAt is null && (BodyBytes >= minBytes || Complete),
            _ => false,
        };
    }

    public override string ToString()
    {
        var what = Error == ProbeError.None ? $"HTTP {HttpStatus} {BodyBytes} B" : $"{Error}{(StalledAt is { } s ? $" at {s} B" : "")}";
        return $"{Host} @ {Address}:{Port} {what} in {Duration.TotalMilliseconds:F0} ms";
    }
}
