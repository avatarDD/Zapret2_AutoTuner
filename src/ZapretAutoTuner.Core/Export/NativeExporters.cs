using System.Text;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Export;

/// <summary>zapret2 on Linux: the variables of <c>/opt/zapret2/config</c> (strategy-export §1.1).</summary>
public static class Zapret2Exporter
{
    public const string Root = "/opt/zapret2";

    public static string HostlistFile(string name) => $"ipset/zt-{name}.txt";

    public static string IpsetFile(string name) => $"ipset/zt-{name}.txt";

    public static string BlobFile(string name) => $"files/fake/{(name.StartsWith("zt_", StringComparison.Ordinal) ? name : "zt_" + name)}.bin";

    /// <param name="modeFilter">MODE_FILTER: the profiles carry their own lists, so "hostlist" does not change them.</param>
    public static ExportPackage Build(Solution s, string modeFilter = "hostlist")
    {
        ExportCommon.CheckSolution(s);
        var pkg = new ExportPackage { Format = "zapret2" };
        var opt = new StringBuilder("\n");
        foreach (var name in s.Blobs.Keys)
            opt.Append($"--blob={name}:@{Root}/{BlobFile(name)}\n");
        if (Unify.Unifier.NeedsIpcacheHostname(s))
            opt.Append("--ipcache-hostname\n");
        for (int i = 0; i < s.Profiles.Count; i++)
        {
            var args = s.Profiles[i].ToArgs((r, ipset) => $"{Root}/{(ipset ? IpsetFile(r.Name) : HostlistFile(r.Name))}");
            opt.Append(string.Join(' ', args));
            opt.Append(i < s.Profiles.Count - 1 ? " --new\n" : "\n");
        }
        var value = opt.ToString();
        ExportCommon.CheckShellValue("NFQWS2_OPT", value);
        var text = new StringBuilder();
        text.Append("NFQWS2_ENABLE=1\n");
        text.Append($"NFQWS2_PORTS_TCP={s.TcpPorts}\n");
        text.Append($"NFQWS2_PORTS_UDP={s.UdpPorts}\n");
        text.Append($"MODE_FILTER={modeFilter}\n");
        text.Append($"NFQWS2_OPT=\"{value}\"\n");
        pkg.Text = text.ToString();
        pkg.AddText("config.fragment", pkg.Text);
        foreach (var (name, domains) in s.Hostlists)
            pkg.AddText(HostlistFile(name), ExportCommon.ListLines(domains));
        foreach (var (name, cidrs) in s.Ipsets)
            pkg.AddText(IpsetFile(name), ExportCommon.ListLines(cidrs));
        foreach (var (name, bytes) in s.Blobs)
            pkg.Files[BlobFile(name)] = bytes;
        pkg.AddText("README.txt", ExportCommon.Header(s) + $"""

            Экспорт для zapret2 (Linux).
            1. Скопируйте ipset/ и files/ в {Root}/ (сохраняя пути).
            2. В {Root}/config замените только переменные из config.fragment:
               NFQWS2_ENABLE, NFQWS2_PORTS_TCP, NFQWS2_PORTS_UDP, MODE_FILTER, NFQWS2_OPT.
               --user, --qnum, --fwmark и --lua-init добавит сам zapret2.
            3. Перезапустите: {Root}/init.d/sysv/zapret2 restart (или systemctl restart zapret2).

            Export for zapret2 (Linux).
            1. Copy ipset/ and files/ into {Root}/ keeping the paths.
            2. In {Root}/config replace only the variables from config.fragment.
            3. Restart zapret2.

            """ + ExportCommon.PinsSection(s, "hosts") + ExportCommon.PinsSection(s, "dnsmasq"));
        return pkg;
    }
}

/// <summary>winws2 on Windows: an @config file and a .cmd next to the engine (strategy-export §1.2).</summary>
public static class WinwsExporter
{
    public const int MaxConfigBytes = 16 * 1024;

    public static string HostlistFile(string name) => $"lists/zt-{name}.txt";

    public static string BlobFile(string name) => $"files/{name}.bin";

    public static ExportPackage Build(Solution s)
    {
        ExportCommon.CheckSolution(s);
        var pkg = new ExportPackage { Format = "winws2" };
        var launch = new EngineLaunch
        {
            Platform = EnginePlatform.Windows,
            LuaDir = "lua",
            Blobs = s.Blobs.Keys.ToDictionary(n => n, BlobFile, StringComparer.Ordinal),
            Profiles = s.Profiles,
            ListPath = (r, _) => HostlistFile(r.Name),
            IpcacheHostname = Unify.Unifier.NeedsIpcacheHostname(s),
        };
        var argv = EngineArgsBuilder.Build(launch);
        // one line per group: interception, lua, blobs, then one profile per line ending with --new
        var lines = new List<string>();
        var head = argv.TakeWhile(a => !IsProfileStart(a)).ToList();
        lines.Add(string.Join(' ', head.Where(a => a.StartsWith("--wf-", StringComparison.Ordinal))));
        lines.Add(string.Join(' ', head.Where(a => a == "--ipcache-hostname")));
        lines.Add(string.Join(' ', head.Where(a => a.StartsWith("--lua-init=", StringComparison.Ordinal))));
        if (s.Blobs.Count > 0)
            lines.Add(string.Join(' ', head.Where(a => a.StartsWith("--blob=", StringComparison.Ordinal))));
        var profiles = string.Join(' ', argv.Skip(head.Count).Select(Quote)).Split(" --new ");
        for (int i = 0; i < profiles.Length; i++)
            lines.Add(profiles[i] + (i < profiles.Length - 1 ? " --new" : ""));
        var config = ExportCommon.ListLines(lines.Where(l => l.Length > 0));
        if (config.Contains('#', StringComparison.Ordinal))
            throw new ExportException("@config winws2 не может содержать «#»");
        if (Encoding.UTF8.GetByteCount(config) > MaxConfigBytes)
            throw new ExportException("@config длиннее 16 KB");
        pkg.Text = config;
        pkg.AddText("zt-config.txt", config);
        pkg.AddText("zt-start.cmd", "@echo off\r\ncd /d \"%~dp0\"\r\nwinws2.exe @\"%~dp0zt-config.txt\"\r\n");
        foreach (var (name, domains) in s.Hostlists)
            pkg.AddText(HostlistFile(name), ExportCommon.ListLines(domains));
        foreach (var (name, bytes) in s.Blobs)
            pkg.Files[BlobFile(name)] = bytes;
        pkg.AddText("README.txt", ExportCommon.Header(s) + """

            Экспорт для winws2 (Windows).
            Положите файлы в папку zapret2 рядом с winws2.exe, cygwin1.dll, WinDivert.dll,
            WinDivert64.sys и lua\. Запуск: zt-start.cmd от имени администратора.
            Установить как службу можно из AutoTuner (кнопка «Служба Windows»).

            Export for winws2 (Windows).
            Put the files into the zapret2 folder next to winws2.exe and lua\.
            Run zt-start.cmd as Administrator, or install the service from AutoTuner.

            """ + ExportCommon.PinsSection(s, "hosts"));
        return pkg;
    }

    private static bool IsProfileStart(string a) =>
        a != "--ipcache-hostname" && !a.StartsWith("--wf-", StringComparison.Ordinal) && !a.StartsWith("--lua-init=", StringComparison.Ordinal) && !a.StartsWith("--blob=", StringComparison.Ordinal);

    /// <summary>@config words: a value with spaces goes in single quotes.</summary>
    private static string Quote(string a) => a.Contains(' ', StringComparison.Ordinal) ? "'" + a + "'" : a;
}

/// <summary>A one-line argv to copy (strategy-export §1.3): globals first, profiles joined by --new.</summary>
public static class ArgvExporter
{
    /// <param name="luaDir">Where the engine's lua files are on the target.</param>
    public static ExportPackage Build(Solution s, EnginePlatform platform = EnginePlatform.Linux, string luaDir = "/opt/zapret2/lua")
    {
        ExportCommon.CheckSolution(s);
        var launch = new EngineLaunch
        {
            Platform = platform,
            LuaDir = luaDir,
            // inline hex: the line stands alone, no files to carry
            Blobs = s.Blobs.ToDictionary(b => b.Key, b => "0x" + Convert.ToHexString(b.Value), StringComparer.Ordinal),
            Profiles = s.Profiles.Select(p =>
            {
                var c = p.Clone();
                c.HostlistDomains.AddRange(p.Hostlists.SelectMany(l => s.Hostlists[l.Name]));
                c.Hostlists = [];
                c.IpsetIps.AddRange(p.Ipsets.SelectMany(l => s.Ipsets[l.Name]));
                c.Ipsets = [];
                return c;
            }).ToList(),
            IpcacheHostname = Unify.Unifier.NeedsIpcacheHostname(s),
        };
        var argv = EngineArgsBuilder.Build(launch);
        // the engine's runner adds the queue; a copied line carries only what the strategy needs
        argv.RemoveAll(a => a.StartsWith("--qnum=", StringComparison.Ordinal) || a.StartsWith("--fwmark=", StringComparison.Ordinal));
        var pkg = new ExportPackage { Format = "argv", Text = EngineArgsBuilder.ToCommandLine(argv) };
        pkg.AddText("args.txt", pkg.Text + "\n");
        pkg.AddText("README.txt", ExportCommon.Header(s) + "\nСтрока аргументов nfqws2/winws2 / nfqws2/winws2 argument line.\n" + ExportCommon.PinsSection(s, "hosts"));
        return pkg;
    }
}
