namespace ZapretAutoTuner.Core.Model;

/// <summary>A pinned address for a domain (hosts entry), dpi-diagnostics §2a.</summary>
public sealed record HostPin(string Domain, IReadOnlyList<string> Ips);

public sealed class SolutionMeta
{
    public DateTimeOffset Created { get; set; } = DateTimeOffset.UtcNow;

    public string AutotunerVersion { get; set; } = AppInfo.Version;

    public string Zapret2Version { get; set; } = AppInfo.Zapret2Version;

    public List<string> TestedProfiles { get; set; } = [];

    public List<string> Targets { get; set; } = [];

    public string? ReportRef { get; set; }

    public string? Title { get; set; }
}

/// <summary>
/// Everything an exporter needs (strategy-export: "Solution"): ordered profiles, the lists and blobs they
/// reference, extra Lua files and pinned addresses.
/// </summary>
public sealed class Solution
{
    public List<Profile> Profiles { get; set; } = [];

    public SortedDictionary<string, List<string>> Hostlists { get; set; } = new(StringComparer.Ordinal);

    public SortedDictionary<string, List<string>> Ipsets { get; set; } = new(StringComparer.Ordinal);

    /// <summary>Custom blobs only (built-in ones are never stored). Key is a Lua identifier.</summary>
    public SortedDictionary<string, byte[]> Blobs { get; set; } = new(StringComparer.Ordinal);

    /// <summary>Lua files beyond the standard ones (rare: zapret-autotuner.lua).</summary>
    public SortedDictionary<string, string> LuaFiles { get; set; } = new(StringComparer.Ordinal);

    public List<HostPin> HostPins { get; set; } = [];

    public SolutionMeta Meta { get; set; } = new();

    public string TcpPorts => PortList.Union(Profiles.Select(p => p.TcpPorts));

    public string UdpPorts => PortList.Union(Profiles.Select(p => p.UdpPorts));
}
