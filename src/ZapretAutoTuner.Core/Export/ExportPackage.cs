using System.IO.Compression;
using System.Text;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Export;

/// <summary>
/// What an exporter produces: the files (path → bytes, '/' separators), the text the user copies, and warnings. Every
/// package carries a README.txt (strategy-export rule 3).
/// </summary>
public sealed class ExportPackage
{
    public required string Format { get; init; }

    public SortedDictionary<string, byte[]> Files { get; } = new(StringComparer.Ordinal);

    /// <summary>The main text: a config fragment, an argv line or a JSON document.</summary>
    public string Text { get; set; } = "";

    public List<string> Warnings { get; } = [];

    /// <summary>UTF-8 without BOM; LF line ends, CRLF for Windows batch files.</summary>
    public void AddText(string path, string text) => Files[path] = new UTF8Encoding(false).GetBytes(
        text.ReplaceLineEndings(path.EndsWith(".cmd", StringComparison.Ordinal) || path.EndsWith(".bat", StringComparison.Ordinal) ? "\r\n" : "\n"));

    public string TextOf(string path) => Encoding.UTF8.GetString(Files[path]);

    /// <summary>A zip with the files in a fixed order and a fixed time, so the same solution gives the same bytes.</summary>
    public byte[] ToZip()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (path, bytes) in Files)
            {
                var e = zip.CreateEntry(path, CompressionLevel.Optimal);
                e.LastWriteTime = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
                using var s = e.Open();
                s.Write(bytes);
            }
        }
        return ms.ToArray();
    }
}

/// <summary>Exporter failure that the user must fix (a name or value the target platform rejects).</summary>
public sealed class ExportException(string message) : Exception(message);

/// <summary>Shared pieces of the exporters.</summary>
internal static partial class ExportCommon
{
    public const int MaxBlobBytes = 16 * 1024;

    /// <summary>The checks of strategy-export §5 that hold for every target.</summary>
    public static void CheckSolution(Solution s)
    {
        if (s.Profiles.Count == 0)
            throw new ExportException("нет профилей для экспорта");
        foreach (var p in s.Profiles)
        {
            if (!Identifiers.IsListName(p.Name))
                throw new ExportException($"имя профиля «{p.Name}» должно быть [a-zA-Z0-9_-]{{1,64}}");
            foreach (var l in p.Hostlists.Concat(p.HostlistExcludes))
            {
                if (!s.Hostlists.ContainsKey(l.Name))
                    throw new ExportException($"профиль {p.Name}: нет списка «{l.Name}»");
            }
            foreach (var l in p.Ipsets.Concat(p.IpsetExcludes))
            {
                if (!s.Ipsets.ContainsKey(l.Name))
                    throw new ExportException($"профиль {p.Name}: нет ipset «{l.Name}»");
            }
        }
        foreach (var name in s.Hostlists.Keys.Concat(s.Ipsets.Keys))
        {
            if (!Identifiers.IsListName(name))
                throw new ExportException($"имя списка «{name}» должно быть [a-zA-Z0-9_-]{{1,64}}");
        }
        foreach (var (name, bytes) in s.Blobs)
        {
            if (!Identifiers.IsLuaIdentifier(name))
                throw new ExportException($"имя блоба «{name}» должно быть идентификатором Lua");
            if (bytes.Length is 0 or > MaxBlobBytes)
                throw new ExportException($"блоб {name}: {bytes.Length} байт, допустимо 1…16384");
        }
        foreach (var file in s.LuaFiles.Keys)
        {
            if (!LuaFileRe().IsMatch(file) || Catalog.LuaCatalog.Default.Data.LuaInitOrder.Contains(file))
                throw new ExportException($"Lua-файл «{file}»: нужно имя вида zt-имя.lua (латиница, цифры, _ - .), не совпадающее с файлами zapret2");
        }
    }

    [System.Text.RegularExpressions.GeneratedRegex("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,123}\\.lua$")]
    private static partial System.Text.RegularExpressions.Regex LuaFileRe();

    /// <summary>The <c>--lua-init</c> of the solution's own Lua files, after the standard ones, in name order.</summary>
    public static IEnumerable<string> LuaInits(Solution s, string dir) => s.LuaFiles.Keys.Select(f => $"--lua-init=@{dir}/{f}");

    /// <summary>The solution's Lua files into the package under <c>lua/</c>.</summary>
    public static void AddLuaFiles(ExportPackage pkg, Solution s)
    {
        foreach (var (file, text) in s.LuaFiles)
            pkg.AddText($"lua/{file}", text);
    }

    /// <summary>Shell double-quoted values (zapret2 config, keenetic conf) must not hold ", $ or `.</summary>
    public static void CheckShellValue(string variable, string value)
    {
        if (value.IndexOfAny(['"', '$', '`', '\\']) >= 0)
            throw new ExportException($"{variable}: значение содержит \", $, ` или \\ — shell их раскроет");
    }

    public static string ListLines(IEnumerable<string> items) => string.Concat(items.Select(i => i + "\n"));

    /// <summary>The pinned addresses for each kind of target (strategy-export §4a): hosts, keenetic or dnsmasq.</summary>
    public static string PinsSection(Solution s, string kind)
    {
        if (s.HostPins.Count == 0)
            return "";
        var lines = s.HostPins.SelectMany(pin => pin.Ips.Select(ip => kind switch
        {
            "keenetic" => $"ip host {pin.Domain} {ip}",
            "dnsmasq" => $"address=/{pin.Domain}/{ip}",
            _ => $"{ip} {pin.Domain}",
        })).ToList();
        if (kind == "hosts")
            lines = [Hosts.HostsFile.Begin, .. lines, Hosts.HostsFile.End];
        else if (kind == "keenetic")
            lines.Add("system configuration save");
        return "\nЗакреплённые IP / pinned addresses\n"
            + "Адреса CDN меняются: закрепления надо перепроверять (AutoTuner делает это в мониторинге).\n"
            + "CDN addresses change: re-check the pins (AutoTuner does it in monitoring).\n\n"
            + ListLines(lines);
    }

    public static string Header(Solution s) =>
        $"Zapret2_AutoTuner {s.Meta.AutotunerVersion}, zapret2 {s.Meta.Zapret2Version}, {s.Meta.Created:yyyy-MM-dd}\n"
        + (s.Meta.Targets.Count > 0 ? "Цели / targets: " + string.Join(", ", s.Meta.Targets) + "\n" : "")
        + (s.Meta.TestedProfiles.Count > 0 ? "Проверено на / tested with: " + string.Join(", ", s.Meta.TestedProfiles) + "\n" : "");
}
