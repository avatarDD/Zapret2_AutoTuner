using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Export;

/// <summary>What an import produced: the solution, what kind of text it was, and what could not be carried over.</summary>
public sealed record ImportResult(string Kind, Solution Solution, IReadOnlyList<string> Warnings);

/// <summary>
/// Imports a strategy from any format the exporters write (PLAN 5.2): a zapret2 config (<c>NFQWS2_OPT</c>), an
/// nfqws2-keenetic conf (assembled in the init script's order, §2.2), a winws2 @config or .cmd, an argv line, a
/// zapret-gui strategy JSON, backup or AutoTuner bundle. Files next to the text (lists, blobs, lua; e.g. the export
/// zip) are looked up by path, then by file name; what is missing becomes a warning, not a failure.
/// </summary>
public static partial class StrategyImporter
{
    private static readonly string[] StandardLua = ["zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"];

    /// <summary>Blobs the packages ship (keenetic blobs/, zapret2 files/fake/) that are not built into nfqws2.</summary>
    private static readonly string[] PackageBlobs = ["quic_initial", "tls_clienthello"];

    /// <summary>Global options the runner or the exporter sets; they are not part of a strategy.</summary>
    private static readonly string[] RunnerOptions =
        ["qnum", "user", "uid", "fwmark", "daemon", "pidfile", "debug", "dry-run", "fastpath-workaround", "bind-fix4", "bind-fix6", "ipcache-hostname", "intercept", "writable", "writeable"];

    public static ImportResult Import(string text, IReadOnlyDictionary<string, byte[]>? files = null)
    {
        files ??= new Dictionary<string, byte[]>();
        var warnings = new List<string>();
        text ??= "";
        var trimmed = text.TrimStart('\uFEFF', ' ', '\t', '\r', '\n');
        if (trimmed.StartsWith('{'))
        {
            try
            {
                return ImportJson(trimmed, files, warnings);
            }
            catch (Exception e) when (e is InvalidOperationException or FormatException)
            {
                // a section of the wrong type (AsArray on an object, a string where a number is) or bad base64
                return Fail("json", "JSON неверной формы / malformed JSON: " + e.Message, warnings);
            }
        }

        string kind;
        List<string> argv;
        var cmd = WinwsCmdRe().Match(text);
        if (cmd.Success && !text.Contains("--lua-desync", StringComparison.Ordinal))
        {
            kind = "winws2";
            var config = cmd.Groups[1].Value.Replace("%~dp0", "", StringComparison.Ordinal);
            if (Find(files, config) is not { } bytes)
                return Fail("winws2", $"нет файла {config} / {config} is missing", warnings);
            argv = Tokens(StripComments(Encoding.UTF8.GetString(bytes)));
        }
        else
        {
            kind = ZapretGuiConvert.Detect(text);
            switch (kind)
            {
                case "zapret2":
                    var opt = KeeneticExporter.ParseVars(text).GetValueOrDefault("NFQWS2_OPT", "");
                    if (opt.Contains("<HOSTLIST", StringComparison.Ordinal))
                        warnings.Add("маркеры <HOSTLIST> пропущены: их раскрывает init zapret2 / <HOSTLIST> markers skipped, the zapret2 init expands them");
                    argv = Tokens(StripComments(MarkerRe().Replace(opt, " ")));
                    break;
                case "keenetic":
                    argv = KeeneticArgv(KeeneticExporter.ParseVars(text));
                    break;
                case "args":
                    var body = Regex.Replace(text, "^\\s*(?:\\S*[/\\\\])?(?:nfqws2?|winws2?)(?:\\.exe)?(?:\\s|$)", "", RegexOptions.Multiline | RegexOptions.IgnoreCase);
                    argv = Tokens(StripComments(body.Replace("\\\n", " ", StringComparison.Ordinal).Replace("^\r\n", " ", StringComparison.Ordinal)));
                    break;
                case "zapret1":
                    return Fail(kind, "это конфиг zapret v1 (--dpi-desync), в nfqws2 его надо переписать / a zapret v1 config, it must be rewritten for nfqws2", warnings);
                default:
                    return Fail(kind, "текст не распознан / unrecognised text", warnings);
            }
        }
        return new ImportResult(kind, FromArgv(argv, files, warnings), warnings);
    }

    private static ImportResult Fail(string kind, string why, List<string> warnings)
    {
        warnings.Add(why);
        return new ImportResult(kind, new Solution(), warnings);
    }

    [GeneratedRegex("winws2(?:\\.exe)?\\s+@\"?([^\"\\s]+)\"?", RegexOptions.IgnoreCase)]
    private static partial Regex WinwsCmdRe();

    [GeneratedRegex("<[A-Z_]+>")]
    private static partial Regex MarkerRe();

    [GeneratedRegex("\\$\\{?([A-Za-z_][A-Za-z0-9_]*)\\}?")]
    private static partial Regex VarRefRe();

    /// <summary>Whole-line and trailing <c># comments</c>, the way the keenetic conf and @config files carry them.</summary>
    private static string StripComments(string s) =>
        string.Join("\n", s.ReplaceLineEndings("\n").Split('\n').Select(l => Regex.Replace(l, "(?:^|\\s)#.*$", "")));

    private static List<string> Tokens(string s) => ArgTokenizer.Split(s);

    /// <summary>The argv the keenetic init assembles (<c>_startup_args</c> in etc/init.d/common, strategy-export §2.2).</summary>
    internal static List<string> KeeneticArgv(Dictionary<string, string> vars)
    {
        // a fragment leans on the package's list modes
        vars = new Dictionary<string, string>(vars, StringComparer.Ordinal);
        foreach (var mode in new[] { "MODE_LIST", "MODE_ALL", "MODE_AUTO" })
        {
            if (!vars.ContainsKey(mode))
                vars[mode] = KeeneticExporter.ParseVars(KeeneticExporter.DefaultConf)[mode];
        }
        string Expand(string v, int depth = 0) => depth > 5 ? v : VarRefRe().Replace(StripComments(v), m => Expand(vars.GetValueOrDefault(m.Groups[1].Value, ""), depth + 1));
        string V(string name) => Expand(vars.GetValueOrDefault(name, "")).Trim();
        var argv = new List<string>();
        void Add(string s) => argv.AddRange(Tokens(s));
        Add(V("NFQWS_BASE_ARGS"));
        var parts = new List<string>();
        if (V("NFQWS_ARGS_CUSTOM") is { Length: > 0 } custom)
            parts.Add(custom);
        if (V("NFQWS_ARGS_UDP") is { Length: > 0 } udp)
            parts.Add(udp);
        var ipset = V("NFQWS_ARGS_IPSET");
        var extra = V("NFQWS_EXTRA_ARGS");
        if (V("NFQWS_ARGS_QUIC") is { Length: > 0 } quic)
        {
            if (ipset.Length > 0)
                parts.Add($"{quic} {ipset} --ipset-ip=0.0.0.0");
            parts.Add($"{quic} {extra}");
        }
        if (V("NFQWS_ARGS") is { Length: > 0 } main)
        {
            if (ipset.Length > 0)
                parts.Add($"{main} {ipset} --ipset-ip=0.0.0.0");
            parts.Add($"{main} {extra}");
        }
        Add(string.Join(" --new ", parts));
        return argv;
    }

    private static ImportResult ImportJson(string text, IReadOnlyDictionary<string, byte[]> files, List<string> warnings)
    {
        JsonObject root;
        try
        {
            root = JsonNode.Parse(text) as JsonObject ?? throw new JsonException("not an object");
        }
        catch (JsonException e)
        {
            return Fail("json", "JSON не разобран / JSON parse error: " + e.Message, warnings);
        }
        var format = (string?)root["format"];
        JsonObject? strategy = format switch
        {
            "zapret-gui-backup" => root["strategies"]?.AsArray().FirstOrDefault() as JsonObject,
            "zapret-autotuner-bundle" => root["strategy"] as JsonObject,
            _ => root["profiles"] is JsonArray ? root : null,
        };
        if (format == "zapret-gui-backup" && root["strategies"]?.AsArray().Count > 1)
            warnings.Add("в бэкапе несколько стратегий, взята первая / several strategies in the backup, the first is taken");
        if (strategy?["profiles"] is not JsonArray profiles)
            return Fail(format ?? "json", "в JSON нет стратегии / no strategy in the JSON", warnings);

        // the GUI's files as an export zip would hold them: lists/<name>.txt, bin/<blob>.bin
        var all = new Dictionary<string, byte[]>(files, StringComparer.Ordinal);
        foreach (var key in new[] { "hostlists", "ipsets" })
        {
            foreach (var l in root[key]?.AsArray().OfType<JsonObject>() ?? [])
            {
                var items = (l["domains"] ?? l["cidrs"])?.AsArray().Select(x => (string?)x).OfType<string>() ?? [];
                all[$"lists/{(string?)l["name"]}.txt"] = Encoding.UTF8.GetBytes(ExportCommon.ListLines(items));
            }
        }
        var argv = new List<string>();
        var blobs = root["blobs"]?.AsArray().OfType<JsonObject>().ToList() ?? [];
        foreach (var b in blobs)
        {
            all[$"bin/{(string?)b["name"]}.bin"] = Convert.FromBase64String((string?)b["base64"] ?? "");
            argv.Add($"--blob={(string?)b["name"]}:@bin/{(string?)b["name"]}.bin");
        }
        foreach (var l in root["lua"]?.AsArray().OfType<JsonObject>() ?? [])
        {
            all[$"lua/{(string?)l["name"]}"] = Encoding.UTF8.GetBytes((string?)l["text"] ?? "");
            argv.Add($"--lua-init=@lua/{(string?)l["name"]}");
        }
        var enabled = profiles.OfType<JsonObject>().Where(p => (bool?)p["enabled"] != false).ToList();
        for (int i = 0; i < enabled.Count; i++)
        {
            if (i > 0)
                argv.Add("--new");
            argv.AddRange(Tokens((string?)enabled[i]["args"] ?? ""));
        }
        // the GUI's blob registry declares an uploaded blob by its name, so the args may use it undeclared
        var s = FromArgv(argv, all, warnings, registryBlobs: true);
        s.Meta.Title = (string?)strategy["name"];
        foreach (var pin in root["hosts_pins"]?.AsArray().OfType<JsonObject>() ?? [])
            s.HostPins.Add(new HostPin((string?)pin["domain"] ?? "", [.. pin["ips"]?.AsArray().Select(x => (string?)x).OfType<string>() ?? []]));
        if (root["report"]?["targets"] is JsonArray targets)
            s.Meta.Targets = [.. targets.Select(x => (string?)x).OfType<string>()];
        return new ImportResult(format ?? "zapret-gui-strategy", s, warnings);
    }

    /// <summary>The argv in the model: profiles, the lists and blobs they use read from the files.</summary>
    private static Solution FromArgv(List<string> argv, IReadOnlyDictionary<string, byte[]> files, List<string> warnings, bool registryBlobs = false)
    {
        var parsed = EngineArgsParser.Parse(argv);
        if (registryBlobs)
        {
            foreach (var name in parsed.Profiles.SelectMany(p => p.Strategy.Calls).SelectMany(c => c.Args)
                .Where(a => a.Name is "blob" or "pattern" or "seqovl_pattern" && Identifiers.IsLuaIdentifier(a.Value) && !a.Value!.StartsWith("fake_default_", StringComparison.Ordinal))
                .Select(a => a.Value!).Distinct().Where(n => !parsed.Blobs.ContainsKey(n)).ToList())
                parsed.Blobs[name] = $"@{name}.bin";
        }
        foreach (var (tok, why) in parsed.Problems)
            warnings.Add($"{tok}: {why}");
        var s = new Solution();
        foreach (var g in parsed.Globals)
        {
            var key = ArgTokenizer.SplitOption(g).Name[2..];
            if (!RunnerOptions.Contains(key) && !key.StartsWith("wf-", StringComparison.Ordinal))
                warnings.Add($"глобальная опция {g} не перенесена / global option {g} not carried over");
        }
        foreach (var init in parsed.LuaInits)
        {
            var file = init.StartsWith('@') ? Basename(init[1..]) : null;
            if (file is not null && StandardLua.Contains(file))
                continue;
            if (file is not null && Find(files, init[1..]) is { } lua)
                s.LuaFiles[file] = Encoding.UTF8.GetString(lua);
            else
                warnings.Add($"--lua-init={init}: файл не найден / file not found");
        }
        var used = parsed.Profiles.SelectMany(p => p.Strategy.Calls).SelectMany(c => c.Args).Select(a => a.Value).OfType<string>().ToHashSet(StringComparer.Ordinal);
        foreach (var (name, source) in parsed.Blobs)
        {
            byte[]? bytes = null;
            if (source.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    bytes = Convert.FromHexString(source[2..]);
                }
                catch (FormatException)
                {
                    warnings.Add($"блоб {name}: неверный hex / bad hex");
                }
            }
            else if (source.IndexOf('@') is int at and >= 0)
                bytes = Find(files, source[(at + 1)..]);
            if (bytes is not null)
            {
                if (used.Contains(name))
                    s.Blobs[name] = bytes;
            }
            else if (used.Contains(name))
                warnings.Add($"блоб {name}: файл {source} не найден / blob file not found" + (PackageBlobs.Contains(name) ? " (он есть в пакете роутера / the router package has it)" : ""));
        }

        for (int i = 0; i < parsed.Profiles.Count; i++)
        {
            var p = parsed.Profiles[i];
            if (!Identifiers.IsListName(p.Name))
                p.Name = $"p{i + 1}";
            p.Hostlists = [.. p.Hostlists.Select(r => Load(r, s.Hostlists, files, warnings))];
            p.HostlistExcludes = [.. p.HostlistExcludes.Select(r => Load(r, s.Hostlists, files, warnings))];
            p.Ipsets = [.. p.Ipsets.Select(r => Load(r, s.Ipsets, files, warnings))];
            p.IpsetExcludes = [.. p.IpsetExcludes.Select(r => Load(r, s.Ipsets, files, warnings))];
            s.Profiles.Add(p);
        }
        // names must be unique for the exporters; the last profile keeps it (keenetic puts the ipset copies first)
        foreach (var g in s.Profiles.GroupBy(p => p.Name).Where(g => g.Count() > 1).ToList())
        {
            int n = 1;
            foreach (var p in g.SkipLast(1))
                p.Name = Identifiers.ToListName($"{p.Name}_{++n}");
        }
        s.Meta.Targets = [.. s.Hostlists.Values.SelectMany(d => d).Distinct(StringComparer.Ordinal)];
        return s;
    }

    /// <summary>A list file into the solution under its name (export prefixes and suffixes removed).</summary>
    private static ListRef Load(ListRef r, SortedDictionary<string, List<string>> into, IReadOnlyDictionary<string, byte[]> files, List<string> warnings)
    {
        if (r.Path is null)
            return r;
        if (Find(files, r.Path) is not { } bytes)
        {
            warnings.Add($"список {r.Path} не найден, ссылка оставлена как есть / list {r.Path} not found, kept as a path");
            return r;
        }
        var name = r.Name;
        if (name.StartsWith("zt-", StringComparison.Ordinal) && name.Length > 3)
            name = name[3..];
        if (name.EndsWith("-ipset", StringComparison.Ordinal) && name.Length > 6)
            name = name[..^6];
        name = Identifiers.ToListName(name);
        var items = Encoding.UTF8.GetString(bytes).ReplaceLineEndings("\n").Split('\n')
            .Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList();
        if (into.TryGetValue(name, out var existing) && !existing.SequenceEqual(items))
        {
            int n = 2;
            while (into.ContainsKey($"{name}_{n}"))
                n++;
            name = $"{name}_{n}";
        }
        into[name] = items;
        return new ListRef(name);
    }

    private static string Basename(string path) => path.Replace('\\', '/').Split('/')[^1];

    /// <summary>A file by its path (the longest matching tail wins), or by its name.</summary>
    private static byte[]? Find(IReadOnlyDictionary<string, byte[]> files, string path)
    {
        var norm = path.Trim('\'', '"').Replace('\\', '/');
        if (files.TryGetValue(norm, out var exact))
            return exact;
        var tail = files.Keys.Where(k => norm.EndsWith("/" + k, StringComparison.Ordinal)).OrderByDescending(k => k.Length).FirstOrDefault();
        if (tail is not null)
            return files[tail];
        var file = Basename(norm);
        var byName = files.Keys.Where(k => Basename(k) == file).ToList();
        return byName.Count == 1 ? files[byName[0]] : null;
    }

}
