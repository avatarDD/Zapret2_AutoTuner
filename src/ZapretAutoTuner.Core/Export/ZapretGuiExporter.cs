using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Unify;

namespace ZapretAutoTuner.Core.Export;

/// <summary>
/// zapret-gui (strategy-export §3-4): the import text (§3.1), the strategy JSON for the REST API (§3.2), the backup
/// file (§3.3) and the AutoTuner bundle (§4). Hostlists become GUI lists named <c>zt-&lt;name&gt;</c>, ipsets
/// <c>zt-&lt;name&gt;-ipset</c>. Custom blobs are not declared in the JSON: the GUI's blob registry declares an
/// uploaded blob by its name.
/// </summary>
public static partial class ZapretGuiExporter
{
    public const string Root = "/opt/zapret2";

    private static readonly string[] BuiltinLists = ["other", "other2", "netrogat"];

    [GeneratedRegex("^(?:ipset-.*|my-ipset.*|.*-ipset)$")]
    private static partial Regex IpsetNamespaceRe();

    [GeneratedRegex("[^a-zA-Z0-9_-]")]
    private static partial Regex IdBadChars();

    public static string GuiHostlist(string name) => "zt-" + name;

    public static string GuiIpset(string name) => $"zt-{name}-ipset";

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>The checks of §5 for zapret-gui on top of the common ones.</summary>
    public static void Check(Solution s)
    {
        ExportCommon.CheckSolution(s);
        foreach (var name in s.Hostlists.Keys)
        {
            var gui = GuiHostlist(name);
            if (gui.Length > 64 || BuiltinLists.Contains(gui) || IpsetNamespaceRe().IsMatch(gui))
                throw new ExportException($"список «{name}»: имя {gui} zapret-gui не примет");
        }
        foreach (var name in s.Ipsets.Keys)
        {
            if (GuiIpset(name).Length > 64)
                throw new ExportException($"ipset «{name}»: имя {GuiIpset(name)} длиннее 64");
        }
    }

    /// <summary>The <c>args</c> of one GUI profile: GUI placeholders for the lists, no --name, no --new.</summary>
    public static string ProfileArgs(Profile p) => string.Join(' ', ProfileTokens(p, (r, ipset) => ipset ? $"lists/{GuiIpset(r.Name)}.txt" : $"lists/{GuiHostlist(r.Name)}.txt"));

    private static IEnumerable<string> ProfileTokens(Profile p, Func<ListRef, bool, string> path) =>
        p.ToArgs(path).Where(a => !a.StartsWith("--name=", StringComparison.Ordinal));

    /// <summary>Global options the strategy needs inside its first profile (the GUI has no other place for them).</summary>
    private static List<string> Globals(Solution s) => Unifier.NeedsIpcacheHostname(s) ? ["--ipcache-hostname"] : [];

    public static string StrategyId(Solution s, string? title = null)
    {
        var basis = title ?? s.Meta.Title ?? s.Meta.Targets.FirstOrDefault() ?? "strategy";
        var id = IdBadChars().Replace($"zt_{basis}_{s.Meta.Created:yyyy_MM_dd}", "_");
        return id.Length > 64 ? id[..64] : id;
    }

    /// <summary>§3.1: an NFQWS2_OPT text whose paths the GUI's import maps to <c>lists/</c> and <c>@bin/</c>.</summary>
    public static string BuildText(Solution s)
    {
        Check(s);
        var sb = new StringBuilder("NFQWS2_OPT=\"\n");
        foreach (var name in s.Blobs.Keys)
            sb.Append($"--blob={name}:@{Root}/files/fake/{name}.bin\n");
        var globals = Globals(s);
        for (int i = 0; i < s.Profiles.Count; i++)
        {
            var tokens = ProfileTokens(s.Profiles[i], (r, ipset) => ipset ? $"{Root}/ipset/{GuiIpset(r.Name)}.txt" : $"{Root}/lists/{GuiHostlist(r.Name)}.txt");
            sb.Append(string.Join(' ', (i == 0 ? globals : []).Concat(tokens)));
            sb.Append(i < s.Profiles.Count - 1 ? " --new\n" : "\n");
        }
        sb.Append("\"\n");
        var text = sb.ToString();
        ExportCommon.CheckShellValue("NFQWS2_OPT", text["NFQWS2_OPT=\"".Length..^2]);
        return text;
    }

    /// <summary>§3.2: the strategy for <c>POST /api/strategies</c>.</summary>
    public static JsonObject StrategyJson(Solution s, string? id = null, string? title = null)
    {
        Check(s);
        var globals = Globals(s);
        var profiles = new JsonArray();
        for (int i = 0; i < s.Profiles.Count; i++)
        {
            var p = s.Profiles[i];
            var args = string.Join(' ', (i == 0 ? globals : []).Append(ProfileArgs(p)));
            profiles.Add((JsonNode)new JsonObject
            {
                ["id"] = $"p{i + 1}",
                ["name"] = ProfileTitle(p),
                ["enabled"] = true,
                ["args"] = args,
            });
        }
        var name = title ?? s.Meta.Title ?? "AutoTuner: " + string.Join(", ", s.Meta.Targets.Take(3)) + (s.Meta.Targets.Count > 3 ? "…" : "");
        return new JsonObject
        {
            ["id"] = id ?? StrategyId(s, title),
            ["name"] = name,
            ["description"] = $"Подобрано {AppInfo.Name} {s.Meta.AutotunerVersion} {s.Meta.Created:yyyy-MM-dd}, zapret2 {s.Meta.Zapret2Version}",
            ["version"] = 1,
            ["type"] = "combined",
            ["profiles"] = profiles,
        };
    }

    private static string ProfileTitle(Profile p)
    {
        var proto = p.L7.Count > 0 ? string.Join('+', p.L7).ToUpperInvariant() : p.UdpPorts is not null ? "UDP" : "TCP";
        var lists = string.Join(',', p.Hostlists.Select(l => l.Name).Concat(p.Ipsets.Select(l => l.Name)));
        return lists.Length > 0 ? $"{proto} {lists}" : proto;
    }

    private static JsonArray Hostlists(Solution s) =>
        [.. s.Hostlists.Select(kv => (JsonNode)new JsonObject { ["name"] = GuiHostlist(kv.Key), ["domains"] = new JsonArray([.. kv.Value.Select(d => (JsonNode)d!)]) })];

    /// <summary>§3.3: a zapret-gui backup with the strategies and hostlists sections only.</summary>
    public static JsonObject Backup(Solution s, string? id = null, string? title = null) => new()
    {
        ["format"] = "zapret-gui-backup",
        ["format_version"] = 1,
        ["created_at"] = s.Meta.Created.ToUnixTimeSeconds(),
        ["app_version"] = $"{AppInfo.Name} {s.Meta.AutotunerVersion}",
        ["strategies"] = new JsonArray(StrategyJson(s, id, title)),
        ["hostlists"] = Hostlists(s),
    };

    /// <summary>§4: the bundle with everything the strategy needs, for the GUI's bundle import.</summary>
    public static JsonObject Bundle(Solution s, string? id = null, string? title = null) => new()
    {
        ["format"] = "zapret-autotuner-bundle",
        ["format_version"] = 1,
        ["generator"] = new JsonObject { ["name"] = AppInfo.Name, ["version"] = s.Meta.AutotunerVersion },
        ["zapret2_compat"] = AppInfo.LuaCompatVersion,
        ["strategy"] = StrategyJson(s, id, title),
        ["hostlists"] = Hostlists(s),
        ["ipsets"] = new JsonArray([.. s.Ipsets.Select(kv => (JsonNode)new JsonObject { ["name"] = GuiIpset(kv.Key), ["cidrs"] = new JsonArray([.. kv.Value.Select(d => (JsonNode)d!)]) })]),
        ["blobs"] = new JsonArray([.. s.Blobs.Select(kv => (JsonNode)new JsonObject { ["name"] = kv.Key, ["base64"] = System.Convert.ToBase64String(kv.Value) })]),
        ["lua"] = new JsonArray([.. s.LuaFiles.Select(kv => (JsonNode)new JsonObject { ["name"] = kv.Key, ["text"] = kv.Value })]),
        ["hosts_pins"] = new JsonArray([.. s.HostPins.Select(p => (JsonNode)new JsonObject { ["domain"] = p.Domain, ["ips"] = new JsonArray([.. p.Ips.Select(ip => (JsonNode)ip.ToString()!)]) })]),
        ["report"] = new JsonObject
        {
            ["tested_at"] = s.Meta.Created.ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture),
            ["targets"] = new JsonArray([.. s.Meta.Targets.Select(t => (JsonNode)t!)]),
            ["client_profiles"] = new JsonArray([.. s.Meta.TestedProfiles.Select(t => (JsonNode)t!)]),
        },
    };

    public static string ToJson(JsonNode node) => node.ToJsonString(Json) + "\n";

    public static ExportPackage Build(Solution s, string? id = null, string? title = null)
    {
        Check(s);
        var pkg = new ExportPackage { Format = "zapret-gui", Text = BuildText(s) };
        pkg.AddText("zapret-gui-import.txt", pkg.Text);
        pkg.AddText("strategy.json", ToJson(StrategyJson(s, id, title)));
        pkg.AddText("zapret-gui-backup.json", ToJson(Backup(s, id, title)));
        pkg.AddText("zapret-autotuner-bundle.json", ToJson(Bundle(s, id, title)));
        foreach (var (name, domains) in s.Hostlists)
            pkg.AddText($"lists/{GuiHostlist(name)}.txt", ExportCommon.ListLines(domains));
        foreach (var (name, cidrs) in s.Ipsets)
            pkg.AddText($"ipset/{GuiIpset(name)}.txt", ExportCommon.ListLines(cidrs));
        foreach (var (name, bytes) in s.Blobs)
            pkg.Files[$"blobs/{name}.bin"] = bytes;

        var todo = new StringBuilder();
        foreach (var name in s.Hostlists.Keys)
            todo.Append($"  - список / hostlist {GuiHostlist(name)} (lists/{GuiHostlist(name)}.txt)\n");
        foreach (var name in s.Ipsets.Keys)
            todo.Append($"  - ipset {GuiIpset(name)} (ipset/{GuiIpset(name)}.txt)\n");
        foreach (var name in s.Blobs.Keys)
            todo.Append($"  - блоб / blob {name} (blobs/{name}.bin)\n");
        if (s.Ipsets.Count > 0 || s.Blobs.Count > 0)
            pkg.Warnings.Add("в бэкапе zapret-gui нет блобов и ipset: создайте их вручную / the zapret-gui backup has no blobs or ipsets: create them by hand");
        pkg.AddText("README.txt", ExportCommon.Header(s) + $"""

            Экспорт для zapret-gui. Ничего не применяется само: стратегию сохраняете и включаете вы.
            Способ 1: «Стратегии → Импорт», вставьте zapret-gui-import.txt.
            Способ 2: «Бэкап → Восстановить» файлом zapret-gui-backup.json (секции strategies и hostlists).
            Способ 3: импорт бандла zapret-autotuner-bundle.json (если ваша версия zapret-gui его умеет).
            Перед способами 1 и 2 создайте в GUI:

            Export for zapret-gui. Nothing is applied by itself: you save and enable the strategy.
            1: Strategies → Import, paste zapret-gui-import.txt.
            2: Backup → Restore with zapret-gui-backup.json (strategies and hostlists sections).
            3: bundle import of zapret-autotuner-bundle.json, if your zapret-gui supports it.
            Before 1 and 2 create in the GUI:
            {todo}
            """ + ExportCommon.PinsSection(s, "dnsmasq"));
        return pkg;
    }
}
