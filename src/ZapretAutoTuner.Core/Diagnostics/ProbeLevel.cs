namespace ZapretAutoTuner.Core.Diagnostics;

/// <summary>Verification levels from dpi-diagnostics §3.</summary>
public enum ProbeLevel
{
    /// <summary>TLS handshake and an HTTP response with a valid certificate.</summary>
    L1Handshake = 1,

    /// <summary>A large resource is received in full (≥ 64 KB, ≥ 128 KB for the 16 KB block).</summary>
    L2Body = 2,

    /// <summary>The page loads in a real browser.</summary>
    L3Page = 3,
}
