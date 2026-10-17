using System.Text;
using System.Text.RegularExpressions;

namespace ZapretAutoTuner.Core.Export;

/// <summary>The paths and checks of the router zapret-gui runs on (<c>profile_import.import_text</c>).</summary>
public sealed record ZapretGuiEnv
{
    public string LuaPath { get; init; } = "/opt/zapret2/lua";

    public string BinPath { get; init; } = "/opt/zapret2/files/fake";

    public string ListsPath { get; init; } = "/opt/zapret2/lists";

    public string IpsetPath { get; init; } = "/opt/zapret2/ipset";

    /// <summary>Whether a file exists on the router; by default every file does.</summary>
    public Func<string, bool> Exists { get; init; } = _ => true;

    public Func<string, bool>? IfaceExists { get; init; }
}

public sealed record ZapretGuiProfile(string Id, string Name, bool Enabled, string Args);

public sealed record ZapretGuiConvertResult(bool Ok, string Kind, string KindTitle, IReadOnlyList<ZapretGuiProfile> Profiles,
    IReadOnlyList<string> Warnings, IReadOnlyList<string> Dropped, string? Error);

/// <summary>
/// A line-for-line port of zapret-gui <c>core/profile_import.convert</c> (strategy-export §3.1, rule 4): what the GUI
/// makes of a pasted text. The exporter's round-trip test runs its text through this, and golden tests keep the port
/// equal to the Python on the GUI's own examples.
/// </summary>
public static partial class ZapretGuiConvert
{
    [GeneratedRegex("^[ \\t]*(?:export[ \\t]+)?([A-Za-z_][A-Za-z0-9_]*)=(?:\"([^\"]*)\"|'([^']*)'|([^\\s#]*))", RegexOptions.Multiline)]
    private static partial Regex VarRe();

    [GeneratedRegex("^<[A-Z_]+>$")]
    private static partial Regex MarkerRe();

    private static readonly string[] IfaceVars = ["ISP_INTERFACE", "IFACE_WAN", "IFACE_WAN6", "WAN_IFACE"];
    private static readonly string[] ListOpts = ["--hostlist", "--hostlist-exclude", "--hostlist-auto", "--ipset", "--ipset-exclude"];
    private static readonly string[] IpsetOpts = ["--ipset", "--ipset-exclude"];
    private static readonly string[] PathOpts = [.. ListOpts, "--lua-init", "--blob"];
    private static readonly string[] Decl = ["--blob=", "--lua-init="];

    /// <summary>core/strategy_lint.ENGINE_OWNED_OPTIONS and TAKES_VALUE.</summary>
    private static readonly string[] EngineOwned = ["--user", "--uid", "--qnum", "--fwmark", "--daemon", "--pidfile", "--writable", "--writeable", "--intercept", "--dry-run"];
    private static readonly string[] TakesValue = ["--user", "--uid", "--qnum", "--fwmark", "--pidfile"];

    public static readonly IReadOnlyDictionary<string, string> KindTitles = new Dictionary<string, string>
    {
        ["zapret2"] = "конфиг zapret2 (NFQWS2_OPT)",
        ["keenetic"] = "конфиг nfqws2-keenetic",
        ["zapret1"] = "конфиг zapret v1 (NFQWS_OPT)",
        ["args"] = "строка аргументов nfqws2",
        ["unknown"] = "не распознано",
    };

    public static string Detect(string text)
    {
        var names = VarRe().Matches(text ?? "").Select(m => m.Groups[1].Value).ToHashSet(StringComparer.Ordinal);
        if (names.Contains("NFQWS2_OPT"))
            return "zapret2";
        if (names.Overlaps(["NFQWS_ARGS", "NFQWS_ARGS_QUIC", "NFQWS_ARGS_UDP", "NFQWS_EXTRA_ARGS", "NFQWS_BASE_ARGS", "ISP_INTERFACE"]))
            return "keenetic";
        if (names.Contains("NFQWS_OPT"))
            return "zapret1";
        if (Regex.IsMatch(text ?? "", "--(?:lua-desync|dpi-desync|filter-)"))
            return "args";
        return "unknown";
    }

    /// <summary>core/models.tokenize_args: whitespace splits, quotes group and stay in the token.</summary>
    public static List<string> Tokenize(string text)
    {
        var result = new List<string>();
        if (string.IsNullOrEmpty(text))
            return result;
        var cur = new StringBuilder();
        char quote = '\0';
        foreach (char c in text)
        {
            if (c is '"' or '\'' && quote == '\0')
            {
                quote = c;
                cur.Append(c);
            }
            else if (c == quote)
            {
                quote = '\0';
                cur.Append(c);
            }
            else if (c is ' ' or '\t' or '\r' or '\n' && quote == '\0')
            {
                if (cur.Length > 0)
                {
                    result.Add(cur.ToString());
                    cur.Clear();
                }
            }
            else
                cur.Append(c);
        }
        if (cur.Length > 0)
            result.Add(cur.ToString());
        return result;
    }

    private static (List<(string Var, string Value)> Found, List<(string Var, string Value)> Ifaces) Sources(string text, string kind)
    {
        var found = new List<(string, string)>();
        var ifaces = new List<(string Var, string Value)>();
        foreach (Match m in VarRe().Matches(text ?? ""))
        {
            var name = m.Groups[1].Value;
            var value = new[] { m.Groups[2], m.Groups[3], m.Groups[4] }.FirstOrDefault(g => g.Success)?.Value ?? "";
            value = value.Replace("\\\n", " ", StringComparison.Ordinal);
            if (IfaceVars.Contains(name))
            {
                int i = ifaces.FindIndex(x => x.Var == name);
                if (i >= 0)
                    ifaces[i] = (name, value);
                else
                    ifaces.Add((name, value));
            }
            else if (Regex.IsMatch(value, "(?:^|\\s)--[a-z]"))
                found.Add((name, value));
        }
        if (kind == "args" || found.Count == 0)
        {
            var body = Regex.Replace(text ?? "", "^\\s*(?:\\S*/)?(?:nfqws2?|winws2?)(?:\\s|$)", "", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            body = string.Join("\n", SplitLines(body.Replace("\\\n", " ", StringComparison.Ordinal)).Select(l => Regex.Replace(l, "(?:^|\\s)#.*$", "")));
            found = [("", body.Replace("\\\n", " ", StringComparison.Ordinal))];
        }
        return (found, ifaces);
    }

    /// <summary>Python str.splitlines for the separators a config can hold.</summary>
    private static IEnumerable<string> SplitLines(string s)
    {
        var lines = s.Split(["\r\n", "\n", "\r"], StringSplitOptions.None).ToList();
        if (lines.Count > 0 && lines[^1].Length == 0)
            lines.RemoveAt(lines.Count - 1);
        return lines;
    }

    private static List<string> MergeSplitValues(List<string> tokens)
    {
        var o = new List<string>();
        for (int i = 0; i < tokens.Count; i++)
        {
            var t = tokens[i];
            if (PathOpts.Contains(t) && i + 1 < tokens.Count && !tokens[i + 1].StartsWith('-'))
            {
                o.Add($"{t}={tokens[i + 1]}");
                i++;
                continue;
            }
            o.Add(t);
        }
        return o;
    }

    private static List<string> StripOwned(List<string> tokens, List<string> dropped, List<string> notes)
    {
        var skip = new HashSet<int>();
        for (int i = 0; i < tokens.Count; i++)
        {
            var text = tokens[i];
            var name = text.Split('=', 2)[0];
            string? reason = null;
            if (EngineOwned.Contains(name))
            {
                reason = $"{name} задаёт GUI, а не стратегия";
                dropped.Add(text);
                skip.Add(i);
                if (TakesValue.Contains(text) && i + 1 < tokens.Count)
                {
                    dropped.Add(tokens[i + 1]);
                    skip.Add(i + 1);
                }
            }
            else if (text.StartsWith("--debug=@", StringComparison.Ordinal))
            {
                reason = "--debug в файл: nfqws2 обнуляет его от root; лог движка и так приходит в журнал GUI";
                dropped.Add(text);
                skip.Add(i);
            }
            if (reason is not null && !notes.Contains(reason))
                notes.Add(reason);
        }
        return [.. tokens.Where((_, i) => !skip.Contains(i))];
    }

    private static List<List<string>> SplitNew(List<string> tokens)
    {
        var o = new List<List<string>>();
        var cur = new List<string>();
        foreach (var t in tokens)
        {
            if (t == "--new")
            {
                o.Add(cur);
                cur = [];
            }
            else
                cur.Add(t);
        }
        o.Add(cur);
        return [.. o.Where(p => p.Count > 0)];
    }

    private static bool IsListsOnly(List<string> tokens) =>
        tokens.Count > 0 && tokens.All(t => ListOpts.Contains(t.Split('=', 2)[0]) || t.StartsWith("--hostlist-domains", StringComparison.Ordinal));

    private static string Basename(string path) => path[(path.LastIndexOf('/') + 1)..];

    private static string Join(string dir, string name) => dir.EndsWith('/') ? dir + name : dir + "/" + name;

    /// <summary>adapt_token: the token with the GUI's own paths, and a note when the file is missing there.</summary>
    public static (string Token, string Note) AdaptToken(string tok, ZapretGuiEnv env)
    {
        int eqAt = tok.IndexOf('=', StringComparison.Ordinal);
        var opt = eqAt < 0 ? tok : tok[..eqAt];
        bool eq = eqAt >= 0;
        var val = eqAt < 0 ? "" : tok[(eqAt + 1)..];
        if (opt == "--lua-init" && val.StartsWith('@') && val.Contains('/', StringComparison.Ordinal))
        {
            var name = Basename(val[1..]);
            var note = env.Exists(Join(env.LuaPath, name)) ? "" : $"lua-скрипта {name} здесь нет — загрузите его в «Lua-скрипты»";
            return ($"--lua-init=@lua/{name}", note);
        }
        if (opt == "--blob" && val.Contains(":@", StringComparison.Ordinal))
        {
            int at = val.IndexOf(":@", StringComparison.Ordinal);
            var bname = val[..at];
            var path = val[(at + 2)..];
            if (path.Contains('/', StringComparison.Ordinal))
            {
                var fname = Basename(path);
                var note = env.Exists(Join(env.BinPath, fname)) ? "" : $"файла блоба {fname} здесь нет — загрузите его в «Блобы»";
                return ($"--blob={bname}:@bin/{fname}", note);
            }
        }
        if (ListOpts.Contains(opt) && eq && val.Contains('/', StringComparison.Ordinal))
        {
            var fname = Basename(val);
            var dir = IpsetOpts.Contains(opt) ? env.IpsetPath : env.ListsPath;
            var note = env.Exists(Join(dir, fname)) ? "" : $"списка {fname} здесь нет — создайте его или уберите {opt}";
            return ($"{opt}=lists/{fname}", note);
        }
        return (tok, "");
    }

    public static ZapretGuiConvertResult Convert(string text, ZapretGuiEnv? env = null)
    {
        env ??= new ZapretGuiEnv();
        var kind = Detect(text);
        var warnings = new List<string>();
        var dropped = new List<string>();
        var (sources, ifaces) = Sources(text, kind);
        foreach (var (var, value) in ifaces)
        {
            var missing = value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Where(i => env.IfaceExists is not null && !env.IfaceExists(i)).ToList();
            if (missing.Count > 0)
                warnings.Add($"интерфейса {string.Join(", ", missing)} ({var}) на этом роутере нет — внешний интерфейс GUI берёт из своих настроек");
        }

        var groups = new List<(string Var, List<string> Part)>();
        var extra = new List<string>();
        var notes = new List<string>();
        bool hasMarker = false;
        foreach (var (var, value) in sources)
        {
            var tokens = MergeSplitValues(Tokenize(value));
            if (tokens.Any(t => MarkerRe().IsMatch(t)))
                hasMarker = true;
            tokens = [.. tokens.Where(t => !MarkerRe().IsMatch(t))];
            tokens = StripOwned(tokens, dropped, notes);
            if (IsListsOnly(tokens))
            {
                extra.AddRange(tokens);
                continue;
            }
            foreach (var part in SplitNew(tokens))
                groups.Add((var, part));
        }

        var profiles = new List<ZapretGuiProfile>();
        var carry = new List<string>();
        static bool IsDecl(string t) => Decl.Any(d => t.StartsWith(d, StringComparison.Ordinal));
        foreach (var (var, group) in groups)
        {
            var part = group;
            if (part.Any(t => t.StartsWith("--dpi-desync", StringComparison.Ordinal)))
            {
                warnings.Add($"{(var.Length > 0 ? var + ": " : "")}стратегия nfqws v1 (--dpi-desync) — для nfqws2 её надо переписать на --lua-desync");
                carry.AddRange(part.Where(IsDecl));
                continue;
            }
            if (!part.Any(t => t.StartsWith("--lua-desync=", StringComparison.Ordinal)))
            {
                carry.AddRange(part.Where(IsDecl));
                var rest = part.Where(t => !IsDecl(t)).ToList();
                if (rest.Count > 0)
                    warnings.Add("часть без --lua-desync пропущена: " + Cut(string.Join(' ', rest), 120));
                continue;
            }
            part = [.. carry, .. part];
            carry = [];
            part.AddRange(extra.Where(t => !part.Contains(t)).ToList());
            var args = new List<string>();
            foreach (var t in part)
            {
                var (tok, note) = AdaptToken(t, env);
                if (note.Length > 0 && !notes.Contains(note))
                    notes.Add(note);
                args.Add(tok);
            }
            int n = profiles.Count + 1;
            profiles.Add(new ZapretGuiProfile($"import{n}", ProfileName(args, n, var), true, string.Join(' ', args)));
        }
        if (carry.Count > 0)
        {
            if (profiles.Count > 0)
            {
                var decl = new List<string>();
                foreach (var t in carry)
                {
                    var (tok, note) = AdaptToken(t, env);
                    if (note.Length > 0 && !notes.Contains(note))
                        notes.Add(note);
                    decl.Add(tok);
                }
                profiles[0] = profiles[0] with { Args = string.Join(' ', [.. decl, profiles[0].Args]) };
            }
            else
                warnings.Add("объявления без профиля пропущены: " + Cut(string.Join(' ', carry), 120));
        }
        if (hasMarker)
            notes.Add("маркеры <HOSTLIST> убраны: списки подставит режим фильтра GUI (Настройки → nfqws)");
        warnings.AddRange(notes);
        string? error = profiles.Count > 0 ? null
            : kind != "zapret1" ? "не нашлось ни одного профиля nfqws2 с --lua-desync" : "это конфиг zapret v1 — стратегии nfqws2 в нём нет";
        return new ZapretGuiConvertResult(profiles.Count > 0, kind, KindTitles.GetValueOrDefault(kind, kind), profiles, warnings,
            [.. dropped.Distinct().Order(StringComparer.Ordinal)], error);
    }

    private static string Cut(string s, int n) => s.Length <= n ? s : s[..n];

    private static string ProfileName(List<string> args, int n, string var)
    {
        foreach (var a in args)
        {
            if (a.StartsWith("--filter-tcp=", StringComparison.Ordinal))
                return "TCP " + a.Split('=', 2)[1];
            if (a.StartsWith("--filter-udp=", StringComparison.Ordinal))
                return "UDP " + a.Split('=', 2)[1];
        }
        return var.Length > 0 ? var : $"Профиль {n}";
    }
}
