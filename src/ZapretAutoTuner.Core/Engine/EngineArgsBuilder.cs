using System.Net;
using System.Net.Sockets;
using System.Text;
using ZapretAutoTuner.Core.Catalog;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Engine;

/// <summary>
/// Builds nfqws2 / winws2 argv following nfqws2-engine: values always via <c>=</c>, global options (<c>--lua-init</c>
/// in lib → antidpi → auto order, <c>--blob</c>) before the first profile, profiles separated by <c>--new</c>, and on
/// Windows the <c>--wf-*</c> interception filter derived from the profiles' ports.
/// </summary>
public static class EngineArgsBuilder
{
    public const int WinDivertMaxFilter = 65536;
    public const int WinDivertMaxPortFilter = 4096;

    public static IReadOnlyList<string> StandardLuaFiles => LuaCatalog.Default.Data.LuaInitOrder.Take(3).ToList();

    public static List<string> Build(EngineLaunch l)
    {
        if (l.Profiles.Count == 0)
            throw new ArgumentException("no profiles to run", nameof(l));
        var a = new List<string>();
        bool win = l.Platform == EnginePlatform.Windows;

        if (win)
            a.AddRange(WinDivertOptions(l));
        else
        {
            a.Add($"--qnum={l.QueueNum}");
            a.Add($"--fwmark=0x{l.FwMark:X8}");
        }

        if (l.Debug is not null)
            a.Add("--debug=" + l.Debug);
        if (l.IpcacheHostname)
            a.Add("--ipcache-hostname");
        if (l.Writable is not null)
            a.Add("--writable=" + PathArg(l.Writable, win));
        a.AddRange(l.ExtraGlobalOptions);

        foreach (var f in l.LuaFiles ?? StandardLuaFiles)
            a.Add("--lua-init=@" + PathArg(l.LuaDir.TrimEnd('/', '\\') + "/" + f, win)); // the target platform's separator, not the host's
        foreach (var f in l.ExtraLuaPaths)
            a.Add("--lua-init=@" + PathArg(f, win));

        foreach (var (name, src) in l.Blobs.OrderBy(b => b.Key, StringComparer.Ordinal))
        {
            if (!Identifiers.IsLuaIdentifier(name))
                throw new ArgumentException($"blob name '{name}' is not a Lua identifier");
            a.Add($"--blob={name}:" + (src.StartsWith("0x", StringComparison.Ordinal) ? src : "@" + PathArg(src, win)));
        }

        Func<ListRef, bool, string> listPath = l.ListPath is null
            ? (r, _) => PathArg(r.ToString(), win)
            : (r, isIpset) => PathArg(l.ListPath(r, isIpset), win);
        for (int i = 0; i < l.Profiles.Count; i++)
        {
            if (i > 0)
                a.Add("--new");
            a.AddRange(l.Profiles[i].ToArgs(listPath));
        }
        return a;
    }

    /// <summary>
    /// <c>--wf-tcp-out</c>/<c>--wf-udp-out</c> from the union of profile ports, <c>--wf-tcp-in</c>/<c>--wf-udp-in</c>
    /// when a profile needs incoming packets (circular, autohostlist, detectors), and <c>--wf-raw-filter</c>
    /// restricting interception to the test target addresses.
    /// </summary>
    public static List<string> WinDivertOptions(EngineLaunch l)
    {
        var a = new List<string>();
        var tcp = PortList.Union(l.Profiles.Select(p => p.TcpPorts));
        var udp = PortList.Union(l.Profiles.Select(p => p.UdpPorts));
        if (tcp.Length > WinDivertMaxPortFilter || udp.Length > WinDivertMaxPortFilter)
            throw new ArgumentException("port filter is longer than WinDivert allows (4096)");
        bool incoming = l.Profiles.Any(NeedsIncoming);
        if (l.WinDivertTcpEmpty)
            a.Add("--wf-tcp-empty=1");
        if (l.TargetAddresses.Count > 0)
        {
            bool v4 = l.TargetAddresses.Any(x => x.AddressFamily == AddressFamily.InterNetwork);
            bool v6 = l.TargetAddresses.Any(x => x.AddressFamily == AddressFamily.InterNetworkV6);
            if (v4 != v6)
                a.Add("--wf-l3=" + (v4 ? "ipv4" : "ipv6"));
        }
        if (tcp.Length > 0)
        {
            a.Add("--wf-tcp-out=" + tcp);
            if (incoming)
                a.Add("--wf-tcp-in=" + tcp);
        }
        if (udp.Length > 0)
        {
            a.Add("--wf-udp-out=" + udp);
            if (incoming)
                a.Add("--wf-udp-in=" + udp);
        }
        if (l.TargetAddresses.Count > 0)
        {
            var filter = TargetFilter(l.TargetAddresses);
            if (filter.Length > WinDivertMaxFilter / 2)
                throw new ArgumentException("too many target addresses for one WinDivert filter");
            a.Add("--wf-raw-filter=" + filter);
        }
        return a;
    }

    /// <summary>WinDivert expression matching packets to or from any of the addresses.</summary>
    public static string TargetFilter(IEnumerable<IPAddress> addresses)
    {
        var sb = new StringBuilder("(");
        bool first = true;
        foreach (var ip in addresses.Distinct())
        {
            var prefix = ip.AddressFamily == AddressFamily.InterNetworkV6 ? "ipv6" : "ip";
            if (!first)
                sb.Append(" or ");
            sb.Append(prefix).Append(".DstAddr==").Append(ip).Append(" or ").Append(prefix).Append(".SrcAddr==").Append(ip);
            first = false;
        }
        return sb.Append(')').ToString();
    }

    /// <summary>Does the profile react to incoming packets (detectors need them, nfqws2-engine §10)?</summary>
    public static bool NeedsIncoming(Profile p) =>
        p.HostlistAuto is not null
        || p.Strategy.Actions.OfType<InRange>().Any(r => r.Range != "x")
        || p.Strategy.Calls.Any(c => LuaCatalog.Default.Find(c.Function) is { NeedsIncoming: true });

    /// <summary>Paths for the engine: forward slashes on Windows (Cygwin understands <c>C:/…</c>).</summary>
    public static string PathArg(string path, bool windows) => windows ? path.Replace('\\', '/') : path;

    /// <summary>Formats argv as one line for logs and copy-paste, quoting where a shell would need it.</summary>
    public static string ToCommandLine(IEnumerable<string> argv) => string.Join(' ', argv.Select(ArgTokenizer.Quote));

    /// <summary>
    /// Formats argv as an @config file (nfqws2-engine §2): one option per line, never <c>#</c> comments,
    /// single quotes around values with spaces. Throws if the result exceeds 16384 bytes.
    /// </summary>
    public static string ToConfigFile(IEnumerable<string> argv)
    {
        var sb = new StringBuilder();
        foreach (var arg in argv)
        {
            if (arg.Contains('`', StringComparison.Ordinal) || arg.Contains("$(", StringComparison.Ordinal))
                throw new ArgumentException($"@config cannot contain command substitution: {arg}");
            var q = ArgTokenizer.Quote(arg);
            if (q.StartsWith('#'))
                throw new ArgumentException($"@config cannot have a word starting with #: {arg}");
            sb.Append(q).Append('\n');
        }
        var text = sb.ToString();
        if (Encoding.UTF8.GetByteCount(text) > StrategyValidator.MaxConfigFileSize)
            throw new ArgumentException("@config is larger than 16384 bytes");
        return text;
    }
}
