using System.Net;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Engine;

/// <summary>Everything needed to build one engine command line.</summary>
public sealed class EngineLaunch
{
    public EnginePlatform Platform { get; init; } = OperatingSystem.IsWindows() ? EnginePlatform.Windows : EnginePlatform.Linux;

    /// <summary>Directory with the bundled lua; <c>--lua-init=@dir/file</c>.</summary>
    public required string LuaDir { get; init; }

    /// <summary>Lua files in load order. Null — the standard set (lib, antidpi, auto).</summary>
    public IReadOnlyList<string>? LuaFiles { get; init; }

    /// <summary>Extra lua files with absolute paths, loaded after the standard ones.</summary>
    public IReadOnlyList<string> ExtraLuaPaths { get; init; } = [];

    /// <summary>Blob name → file path (written as <c>@path</c>) or literal <c>0x…</c>.</summary>
    public IReadOnlyDictionary<string, string> Blobs { get; init; } = new Dictionary<string, string>();

    public IReadOnlyList<Profile> Profiles { get; init; } = [];

    /// <summary>Maps list references to file paths for <c>--hostlist=</c> / <c>--ipset=</c>.</summary>
    public Func<ListRef, bool, string>? ListPath { get; init; }

    /// <summary>Linux NFQUEUE number; must equal the firewall rule (nfqws2-engine §0.9).</summary>
    public int QueueNum { get; init; } = 300;

    /// <summary><c>--fwmark</c> for generated packets on Linux; firewall skips packets with this bit.</summary>
    public uint FwMark { get; init; } = 0x40000000;

    /// <summary><c>--debug</c> value: null (off), <c>1</c> (stdout) or <c>@file</c>.</summary>
    public string? Debug { get; init; }

    /// <summary>
    /// Windows: limit interception to these addresses with <c>--wf-raw-filter</c> (one test instance per target).
    /// Linux: the same addresses go into the nft sets.
    /// </summary>
    public IReadOnlyList<IPAddress> TargetAddresses { get; init; } = [];

    /// <summary><c>--wf-tcp-empty=1</c> like blockcheck2, so the packet counter <c>n</c> is exact.</summary>
    public bool WinDivertTcpEmpty { get; init; }

    /// <summary><c>--ipcache-hostname</c>, needed for phase 0 techniques in hostlist profiles.</summary>
    public bool IpcacheHostname { get; init; }

    /// <summary><c>--writable</c> directory for lua (pcap function etc.).</summary>
    public string? Writable { get; init; }

    /// <summary>Additional global options, each <c>--opt=value</c>.</summary>
    public IReadOnlyList<string> ExtraGlobalOptions { get; init; } = [];
}
