namespace ZapretAutoTuner.Core.Model;

/// <summary>How a client is exercised: a real browser, curl or a TLS fingerprint impersonator.</summary>
public enum ClientEngine
{
    Curl,
    Impersonate,
    Chromium,
    Firefox,
}

/// <summary>
/// A browser or device whose ClientHello and TCP behaviour the strategy must survive
/// (dpi-diagnostics §5).
/// </summary>
public sealed record ClientProfile
{
    public required string Id { get; init; }

    public required string NameRu { get; init; }

    public required string NameEn { get; init; }

    public ClientEngine Engine { get; init; } = ClientEngine.Curl;

    /// <summary>Impersonation target (curl-impersonate name, e.g. <c>chrome131</c>) when Engine is Impersonate.</summary>
    public string? ImpersonateAs { get; init; }

    public string? Ja4 { get; init; }

    public bool Kyber { get; init; }

    public bool Ech { get; init; }

    public bool Quic { get; init; }

    public bool Ipv6 { get; init; } = true;

    /// <summary>Whether the client sends TCP timestamps. Windows does not by default, so <c>tcp_ts</c> fooling is useless there.</summary>
    public bool TcpTimestamps { get; init; }

    public int Mss { get; init; } = 1460;

    public int TtlBase { get; init; } = 64;

    public bool Tls12Only { get; init; }

    public static IReadOnlyList<ClientProfile> BuiltIn { get; } =
    [
        new() { Id = "curl", NameRu = "curl (эталон blockcheck2)", NameEn = "curl (blockcheck2 reference)", Engine = ClientEngine.Curl, Kyber = false, TcpTimestamps = !OperatingSystem.IsWindows(), TtlBase = OperatingSystem.IsWindows() ? 128 : 64 },
        new() { Id = "chrome", NameRu = "Chrome / Edge", NameEn = "Chrome / Edge", Engine = ClientEngine.Chromium, Kyber = true, Ech = true, Quic = true, TcpTimestamps = !OperatingSystem.IsWindows(), TtlBase = OperatingSystem.IsWindows() ? 128 : 64 },
        new() { Id = "firefox", NameRu = "Firefox", NameEn = "Firefox", Engine = ClientEngine.Firefox, Kyber = true, Ech = true, Quic = true, TcpTimestamps = !OperatingSystem.IsWindows(), TtlBase = OperatingSystem.IsWindows() ? 128 : 64 },
        new() { Id = "safari_ios", NameRu = "Safari / iPhone", NameEn = "Safari / iPhone", Engine = ClientEngine.Impersonate, ImpersonateAs = "safari18_0_ios", Kyber = true, Quic = true, TcpTimestamps = true, TtlBase = 64 },
        new() { Id = "android_chrome", NameRu = "Android Chrome", NameEn = "Android Chrome", Engine = ClientEngine.Impersonate, ImpersonateAs = "chrome131_android", Kyber = true, Quic = true, TcpTimestamps = true, TtlBase = 64 },
        new() { Id = "smart_tv", NameRu = "Smart TV и старые клиенты", NameEn = "Smart TV and legacy clients", Engine = ClientEngine.Impersonate, ImpersonateAs = "chrome99_android", Kyber = false, Quic = false, TcpTimestamps = true, TtlBase = 64 },
    ];
}
