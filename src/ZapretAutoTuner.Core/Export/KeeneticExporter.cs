using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Unify;

namespace ZapretAutoTuner.Core.Export;

/// <summary>
/// nfqws2-keenetic 1.3.x (strategy-export §2): <c>nfqws2.conf</c> with the solution spread over the package's
/// variables in the order its init script assembles them (§2.2). The widest TCP profile becomes <c>NFQWS_ARGS</c> and
/// its domains go to <c>lists/user.list</c> (<c>MODE_LIST</c>); a QUIC profile for the same domains becomes
/// <c>NFQWS_ARGS_QUIC</c>; every other profile goes to <c>NFQWS_ARGS_CUSTOM</c>, which runs first, with its own list.
/// The package's <c>NFQWS_ARGS_UDP</c> (STUN, WireGuard, Discord) stays, and its ports stay in <c>UDP_PORTS</c>.
/// </summary>
public static partial class KeeneticExporter
{
    public const string Root = "/opt/etc/nfqws2";

    public static string ListFile(string name) => $"lists/zt-{name}.list";

    public static string IpsetFile(string name) => $"lists/zt-{name}-ipset.list";

    public static string BlobFile(string name) => $"blobs/{name}.bin";

    /// <summary>The package's default nfqws2.conf (1.3.1), the base of the full file.</summary>
    public static string DefaultConf { get; } = ReadDefault();

    /// <param name="mode">NFQWS_EXTRA_ARGS: MODE_LIST (only the user.list domains), MODE_AUTO or MODE_ALL.</param>
    public static ExportPackage Build(Solution s, string mode = "MODE_LIST")
    {
        ExportCommon.CheckSolution(s);
        if (mode is not ("MODE_LIST" or "MODE_AUTO" or "MODE_ALL"))
            throw new ArgumentException("mode: MODE_LIST, MODE_AUTO or MODE_ALL", nameof(mode));
        var pkg = new ExportPackage { Format = "keenetic" };

        // the main profile: the last (widest) TCP profile with a hostlist
        var main = s.Profiles.LastOrDefault(p => p.TcpPorts is not null && p.UdpPorts is null && p.Hostlists.Count == 1 && p.Ipsets.Count == 0);
        var mainDomains = main is null ? null : s.Hostlists[main.Hostlists[0].Name];
        var quic = main is null ? null : s.Profiles.FirstOrDefault(p => p.UdpPorts is not null && p.TcpPorts is null && p.Hostlists.Count == 1 && p.Ipsets.Count == 0
            && s.Hostlists[p.Hostlists[0].Name].ToHashSet(StringComparer.Ordinal).SetEquals(mainDomains!));

        string Path(ListRef r, bool ipset) => $"{Root}/{(ipset ? IpsetFile(r.Name) : ListFile(r.Name))}";
        string Line(Profile p, bool own) => string.Join(' ', (own ? p : WithoutLists(p)).ToArgs(Path));

        var custom = s.Profiles.Where(p => p != main && p != quic).Select(p => Line(p, true)).ToList();
        var vars = new Dictionary<string, string>(StringComparer.Ordinal);
        var bases = new List<string> { "--fastpath-workaround=auto" };
        bases.AddRange(new[] { "zapret-lib", "zapret-antidpi", "zapret-auto" }.Select(f => $"--lua-init=@{Root}/lua/{f}.lua"));
        if (Unifier.NeedsIpcacheHostname(s))
            bases.Add("--ipcache-hostname");
        bases.Add($"--blob=quic_initial:@{Root}/blobs/quic_initial.bin");
        bases.Add($"--blob=tls_clienthello:@{Root}/blobs/tls_clienthello.bin");
        bases.AddRange(s.Blobs.Keys.Select(n => $"--blob={n}:@{Root}/{BlobFile(n)}"));
        vars["NFQWS_BASE_ARGS"] = string.Join("\n", bases);
        vars["NFQWS_ARGS"] = main is null ? "" : Line(main, false);
        vars["NFQWS_ARGS_QUIC"] = quic is null ? "" : Line(quic, false);
        vars["NFQWS_ARGS_CUSTOM"] = string.Join(" --new\n", custom);
        foreach (var (k, v) in vars)
        {
            ExportCommon.CheckShellValue(k, v);
            if (k != "NFQWS_ARGS_CUSTOM" && v.Contains("--new", StringComparison.Ordinal))
                throw new ExportException($"{k}: --new разрешён только в NFQWS_ARGS_CUSTOM");
        }
        vars["NFQWS_EXTRA_ARGS"] = "$" + mode;

        var defaults = ParseVars(DefaultConf);
        var tcp = ToIptables(PortList.Union(s.Profiles.Select(p => p.TcpPorts)));
        // the package UDP profile stays, so do its ports
        var udp = ToIptables(PortList.Union(s.Profiles.Select(p => p.UdpPorts).Append(UdpFilter(defaults.GetValueOrDefault("NFQWS_ARGS_UDP", "")))));

        // the kept package UDP profile is the user's business, but say when it is broken
        var udpCheck = new Validation.StrategyValidator(new Validation.ValidationContext()).ValidateArgv(
            StrategyImporter.KeeneticArgv(new Dictionary<string, string> { ["NFQWS_ARGS_UDP"] = defaults.GetValueOrDefault("NFQWS_ARGS_UDP", "") }));
        foreach (var e in udpCheck.Errors)
            pkg.Warnings.Add($"NFQWS_ARGS_UDP пакета (оставлен как есть) / the package's NFQWS_ARGS_UDP (kept): {e}");

        var fragment = new StringBuilder();
        foreach (var name in new[] { "NFQWS_BASE_ARGS", "NFQWS_ARGS", "NFQWS_ARGS_QUIC", "NFQWS_EXTRA_ARGS", "NFQWS_ARGS_CUSTOM" })
            fragment.Append($"{name}=\"{vars[name]}\"\n");
        fragment.Append($"TCP_PORTS={tcp}\nUDP_PORTS={udp}\n");
        pkg.Text = fragment.ToString();
        pkg.AddText("nfqws2.conf.fragment", pkg.Text);

        var full = DefaultConf;
        foreach (var (name, value) in vars)
            full = ReplaceVar(full, name, $"\"{value}\"");
        full = ReplaceVar(full, "TCP_PORTS", tcp);
        full = ReplaceVar(full, "UDP_PORTS", udp);
        pkg.AddText("nfqws2.conf", full);

        if (main is not null)
            pkg.AddText("lists/user.list", ExportCommon.ListLines(mainDomains!));
        // every list a line refers to: the main and QUIC hostlists are user.list, their excludes are not
        var hostlists = s.Profiles.SelectMany(p => (p == main || p == quic ? [] : p.Hostlists).Concat(p.HostlistExcludes)).Select(r => r.Name).Distinct();
        var ipsets = s.Profiles.SelectMany(p => p.Ipsets.Concat(p.IpsetExcludes)).Select(r => r.Name).Distinct();
        foreach (var name in hostlists)
            pkg.AddText(ListFile(name), ExportCommon.ListLines(s.Hostlists[name]));
        foreach (var name in ipsets)
            pkg.AddText(IpsetFile(name), ExportCommon.ListLines(s.Ipsets[name]));
        foreach (var (name, bytes) in s.Blobs)
            pkg.Files[BlobFile(name)] = bytes;
        if (mode == "MODE_ALL" && main is not null)
            pkg.Warnings.Add("MODE_ALL: основной профиль применяется ко всем доменам, кроме exclude.list / the main profile applies to every domain but exclude.list");

        pkg.AddText("README.txt", ExportCommon.Header(s) + $"""

            Экспорт для nfqws2-keenetic 1.3.x.
            Вариант 1 (файлы): скопируйте nfqws2.conf, lists/ и blobs/ в {Root}/ и выполните
              /opt/etc/init.d/S51nfqws2 restart
            nfqws2.conf — полный файл пакета с нашими переменными. Проверьте ISP_INTERFACE (у вас он свой).
            lists/user.list заменит ваш список: если в нём есть свои домены, допишите наши к ним.
            Вариант 2 (фрагмент): в существующем {Root}/nfqws2.conf замените только строки из
            nfqws2.conf.fragment, положите lists/ и blobs/ и перезапустите сервис.

            Export for nfqws2-keenetic 1.3.x.
            Option 1 (files): copy nfqws2.conf, lists/ and blobs/ into {Root}/ and restart S51nfqws2.
            nfqws2.conf is the package's full file with our variables; check ISP_INTERFACE.
            lists/user.list replaces yours: append our domains if you keep your own.
            Option 2 (fragment): replace only the lines of nfqws2.conf.fragment in your nfqws2.conf.

            """ + ExportCommon.PinsSection(s, "keenetic"));
        return pkg;
    }

    private static Profile WithoutLists(Profile p)
    {
        var c = p.Clone();
        c.Hostlists = [];
        return c;
    }

    /// <summary>nfqws2 port syntax (<c>a-b</c>) to iptables multiport (<c>a:b</c>).</summary>
    public static string ToIptables(string ports) => ports.Replace('-', ':');

    private static string? UdpFilter(string args) =>
        Regex.Match(args, "--filter-udp=(\\S+)") is { Success: true } m ? m.Groups[1].Value : null;

    [GeneratedRegex("^([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|[^\\s#]*)", RegexOptions.Multiline)]
    private static partial Regex AssignRe();

    /// <summary>The shell assignments of a conf, quotes removed (no expansion).</summary>
    public static Dictionary<string, string> ParseVars(string conf)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match m in AssignRe().Matches(conf))
        {
            var v = m.Groups[2].Value;
            d[m.Groups[1].Value] = v.Length >= 2 && v[0] is '"' or '\'' ? v[1..^1] : v;
        }
        return d;
    }

    /// <summary>
    /// Replaces the value of the last assignment of <paramref name="name"/>, the one the shell keeps (quoted values may
    /// span lines); appends one if there is none.
    /// </summary>
    public static string ReplaceVar(string conf, string name, string value)
    {
        var m = AssignRe().Matches(conf).LastOrDefault(m => m.Groups[1].Value == name);
        return m is null
            ? conf.TrimEnd('\n') + $"\n{name}={value}\n"
            : conf[..m.Groups[2].Index] + value + conf[(m.Groups[2].Index + m.Groups[2].Length)..];
    }

    private static string ReadDefault()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("ZapretAutoTuner.Core.Export.keenetic-nfqws2.conf")
            ?? throw new InvalidOperationException("keenetic-nfqws2.conf resource missing");
        using var r = new StreamReader(s);
        return r.ReadToEnd().ReplaceLineEndings("\n");
    }
}
