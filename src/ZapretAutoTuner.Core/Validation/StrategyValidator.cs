using System.Globalization;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core.Catalog;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Validation;

/// <summary>Where a strategy is going to run: decides which options are allowed and how strict some checks are.</summary>
public enum EnginePlatform
{
    Linux,
    Windows,
    Keenetic,
}

/// <summary>What the validator knows besides the strategy itself.</summary>
public sealed class ValidationContext
{
    public LuaCatalog Catalog { get; init; } = LuaCatalog.Default;

    public EnginePlatform Platform { get; init; } = OperatingSystem.IsWindows() ? EnginePlatform.Windows : EnginePlatform.Linux;

    /// <summary>Blobs declared with <c>--blob</c>: name → size in bytes (null if the file is not readable yet).</summary>
    public IReadOnlyDictionary<string, long?> DeclaredBlobs { get; init; } = new Dictionary<string, long?>();

    /// <summary>
    /// Functions defined by the lua files that will be loaded (parsed with <see cref="LuaSourceIndex"/>).
    /// Null means "the standard library of the catalog".
    /// </summary>
    public IReadOnlySet<string>? LoadedFunctions { get; init; }

    /// <summary>The client the strategy is meant for; used for the tcp_ts check.</summary>
    public ClientProfile? Client { get; init; }

    /// <summary><c>--ipcache-hostname</c> is on, so hostlist profiles can match from the first packet.</summary>
    public bool IpcacheHostname { get; init; }

    /// <summary>
    /// Functions of the user's <b>approved</b> Lua scripts (PLAN 4a.5): function → script file (<c>zt-name.lua</c>).
    /// <c>--lua-desync</c> calls to them are accepted; their argument names are unknown to the catalog and are not
    /// checked, everything else (blobs, substitutions, ranges, payloads, profile rules) is.
    /// </summary>
    public IReadOnlyDictionary<string, string> UserFunctions { get; init; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>
    /// Functions defined only by user scripts that are not approved yet: function → script name. Calls to them are
    /// refused with a message that says to approve the script in AutoTuner first.
    /// </summary>
    public IReadOnlyDictionary<string, string> DraftFunctions { get; init; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>Approved user functions whose file the argv does not load (set by <see cref="StrategyValidator.ValidateArgv"/>).</summary>
    internal IReadOnlyDictionary<string, string> UnloadedUserFunctions { get; init; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>A copy with the user's Lua functions: approved ones by file, drafts by script name.</summary>
    public ValidationContext WithUserLua(IReadOnlyDictionary<string, string> approved, IReadOnlyDictionary<string, string> drafts) => new()
    {
        Catalog = Catalog,
        Platform = Platform,
        DeclaredBlobs = DeclaredBlobs,
        LoadedFunctions = LoadedFunctions,
        Client = Client,
        IpcacheHostname = IpcacheHostname,
        UserFunctions = approved,
        DraftFunctions = drafts,
    };
}

/// <summary>
/// Checks strategies and full argv before anything runs (AGENTS.md rule 4): rules of nfqws2-engine §9 and the
/// generator invariants of nfqws2-lua §10. Every message is shown to the user, so it says what is wrong in plain words.
/// </summary>
public sealed partial class StrategyValidator
{
    public const int MaxConfigFileSize = 16384;
    public const int MaxBlobSize = 16384;

    private static readonly HashSet<string> Resenders = new(StringComparer.Ordinal)
    {
        "multisplit", "multidisorder", "multidisorder_legacy", "fakedsplit", "fakeddisorder", "hostfakesplit", "tcpseg",
    };

    private static readonly HashSet<string> TcpFlags = new(StringComparer.Ordinal) { "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR" };

    private readonly ValidationContext _ctx;

    public StrategyValidator(ValidationContext? context = null)
    {
        _ctx = context ?? new ValidationContext();
    }

    private LuaCatalog Cat => _ctx.Catalog;

    [GeneratedRegex("^0x([0-9A-Fa-f]{2})+$")]
    private static partial Regex HexBlobRegex();

    [GeneratedRegex("^([0-9A-Fa-f]{2})*$")]
    private static partial Regex HexRegex();

    [GeneratedRegex(@"^-?\d+,\d+-\d+$|^-?\d+$")]
    private static partial Regex AutoTtlRegex();

    [GeneratedRegex(@"(?<!\\)([%#])([A-Za-z_][A-Za-z0-9_]*)")]
    private static partial Regex SubstitutionRegex();

    /// <summary>Validates one profile: filters, ordered actions and the invariants between instances.</summary>
    public ValidationResult ValidateProfile(Profile profile, string? where = null)
    {
        var r = new ValidationResult();
        ValidateProfile(profile, r, where ?? (profile.Name.Length > 0 ? profile.Name : null));
        return r;
    }

    public ValidationResult ValidateStrategy(Strategy strategy, L4Kind l4 = L4Kind.Tcp)
    {
        var p = new Profile { Strategy = strategy };
        if (l4 == L4Kind.Tcp)
            p.TcpPorts = "443";
        else
            p.UdpPorts = "443";
        return ValidateProfile(p);
    }

    /// <summary>
    /// Validates a full engine command line: option names and platform, value syntax, global option placement,
    /// lua load order, blob declarations and sizes, WinDivert coverage of profile ports, and every profile.
    /// <paramref name="fileExists"/> and <paramref name="fileSize"/> resolve blob paths (null skips file checks).
    /// </summary>
    /// <param name="luaFunctions">
    /// The functions a <c>--lua-init=@file</c> outside the zapret2 library defines (the Agent indexes the file it is
    /// about to load); null leaves such files to <see cref="ValidationContext.UserFunctions"/>.
    /// </param>
    public ValidationResult ValidateArgv(IReadOnlyList<string> argv, Func<string, long?>? fileSize = null, Func<string, IReadOnlyCollection<string>?>? luaFunctions = null)
    {
        var r = new ValidationResult();
        var parsed = Engine.EngineArgsParser.Parse(argv, Cat);
        foreach (var (tok, reason) in parsed.Problems)
            r.Error("argv.parse", $"{tok}: {reason}", $"{tok}: cannot be used ({reason})");

        foreach (var tok in argv.Where(t => t.StartsWith("--", StringComparison.Ordinal)))
        {
            var key = Model.ArgTokenizer.SplitOption(tok).Name[2..];
            if (!Cat.EngineOptions.TryGetValue(key, out var spec))
                continue;
            bool allowed = spec.Platform switch
            {
                "all" => true,
                "linux" => _ctx.Platform is EnginePlatform.Linux or EnginePlatform.Keenetic,
                "posix" => _ctx.Platform != EnginePlatform.Windows,
                "windows" => _ctx.Platform == EnginePlatform.Windows,
                "keenetic" => _ctx.Platform == EnginePlatform.Keenetic,
                _ => false,
            };
            if (!allowed)
                r.Error("argv.platform", $"--{key} не поддерживается движком для {PlatformName(_ctx.Platform)}", $"--{key} is not supported on {_ctx.Platform}", tok);
        }

        foreach (var late in parsed.LateGlobals.Where(t => t.StartsWith("--blob=", StringComparison.Ordinal) || t.StartsWith("--lua-init=", StringComparison.Ordinal)))
            r.Warn("argv.late_global", "--blob и --lua-init должны стоять до первого профиля", "--blob and --lua-init must come before the first profile", late);

        var order = Cat.Data.LuaInitOrder;
        int lastRank = -1;
        // functions available at runtime: known only when every --lua-init is a bundled file
        var loadedFiles = new HashSet<string>(StringComparer.Ordinal);
        bool loadedKnown = true;
        var userFiles = _ctx.UserFunctions.Values.ToHashSet(StringComparer.Ordinal);
        var resolvedUser = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var init in parsed.LuaInits)
        {
            var file = init.TrimStart('@').Replace('\\', '/').Split('/')[^1];
            if (file.EndsWith(".gz", StringComparison.Ordinal))
                file = file[..^3];
            if (!init.StartsWith('@') || !Cat.Functions.Any(f => f.File == file))
            {
                // a user script: known by its file name, or indexed by the caller (the Agent); anything else is opaque
                if (init.StartsWith('@') && userFiles.Contains(file))
                {
                }
                else if (init.StartsWith('@') && luaFunctions?.Invoke(init[1..]) is { } defined)
                {
                    foreach (var fn in defined.Where(fn => Cat.Find(fn) is null))
                        resolvedUser[fn] = file;
                }
                else
                    loadedKnown = false;
            }
            loadedFiles.Add(file);
            int rank = order.IndexOf(file);
            if (rank < 0)
                rank = order.Count;
            if (rank < lastRank)
                r.Error("argv.lua_order", $"порядок --lua-init нарушен: {file} должен грузиться раньше (нужно {string.Join(" → ", order.Take(3))} → остальные)", $"--lua-init order is wrong at {file}", init);
            lastRank = Math.Max(lastRank, rank);
        }
        if (parsed.LuaInits.Count > 0 && !parsed.LuaInits[0].Replace('\\', '/').EndsWith("zapret-lib.lua", StringComparison.Ordinal))
            r.Error("argv.lua_lib_first", "первым --lua-init должен быть zapret-lib.lua", "zapret-lib.lua must be the first --lua-init");

        var declared = new Dictionary<string, long?>(_ctx.DeclaredBlobs, StringComparer.Ordinal);
        foreach (var (name, src) in parsed.Blobs)
        {
            if (!Identifiers.IsLuaIdentifier(name))
                r.Error("blob.name", $"имя блоба «{name}» должно быть идентификатором Lua (латиница, цифры, _; не с цифры): движок выйдет с bad identifier", $"blob name '{name}' must be a Lua identifier", "--blob=" + name);
            long? size = null;
            if (src.StartsWith("0x", StringComparison.Ordinal))
                size = (src.Length - 2) / 2;
            else if (fileSize is not null)
            {
                var at = src.IndexOf('@', StringComparison.Ordinal);
                var path = at >= 0 ? src[(at + 1)..] : src;
                size = fileSize(path);
                if (size is null)
                    r.Error("blob.file", $"файл блоба {path} не найден", $"blob file {path} not found", "--blob=" + name);
            }
            if (size > MaxBlobSize)
                r.Error("blob.size", $"блоб {name} больше 16 KB ({size} байт)", $"blob {name} exceeds 16 KB", "--blob=" + name);
            declared[name] = size;
        }

        if (_ctx.Platform == EnginePlatform.Windows && !argv.Any(t => t.StartsWith("--wf-raw=", StringComparison.Ordinal)))
        {
            string Wf(string opt) => PortsOf(argv, opt);
            var tcpOut = Wf("--wf-tcp-out");
            var udpOut = Wf("--wf-udp-out");
            foreach (var p in parsed.Profiles)
            {
                CheckCovered(p.TcpPorts, tcpOut, "--wf-tcp-out", r, p.Name);
                CheckCovered(p.UdpPorts, udpOut, "--wf-udp-out", r, p.Name);
            }
        }

        var inner = new StrategyValidator(new ValidationContext
        {
            Catalog = Cat,
            Platform = _ctx.Platform,
            DeclaredBlobs = declared,
            LoadedFunctions = _ctx.LoadedFunctions
                ?? (loadedKnown ? Cat.Functions.Where(f => loadedFiles.Contains(f.File)).Select(f => f.Name).ToHashSet(StringComparer.Ordinal) : null),
            Client = _ctx.Client,
            IpcacheHostname = _ctx.IpcacheHostname || argv.Any(t => t is "--ipcache-hostname" or "--ipcache-hostname=1"),
            UserFunctions = _ctx.UserFunctions.Where(kv => loadedFiles.Contains(kv.Value)).Concat(resolvedUser)
                .GroupBy(kv => kv.Key, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First().Value, StringComparer.Ordinal),
            DraftFunctions = _ctx.DraftFunctions,
            UnloadedUserFunctions = _ctx.UserFunctions.Where(kv => !loadedFiles.Contains(kv.Value)).ToDictionary(StringComparer.Ordinal),
        });
        for (int i = 0; i < parsed.Profiles.Count; i++)
            inner.ValidateProfile(parsed.Profiles[i], r, parsed.Profiles[i].Name.Length > 0 ? parsed.Profiles[i].Name : $"профиль {i + 1}");

        var total = argv.Sum(a => System.Text.Encoding.UTF8.GetByteCount(Model.ArgTokenizer.Quote(a)) + 1);
        if (total > MaxConfigFileSize)
            r.Warn("argv.config_size", $"командная строка {total} байт не влезет в @config (максимум 16384)", $"command line of {total} bytes exceeds the @config limit", null);
        return r;
    }

    private static string PortsOf(IReadOnlyList<string> argv, string opt)
    {
        var values = argv.Where(t => t.StartsWith(opt + "=", StringComparison.Ordinal)).Select(t => t[(opt.Length + 1)..]);
        return string.Join(',', values);
    }

    private static void CheckCovered(string? ports, string wf, string opt, ValidationResult r, string where)
    {
        if (ports is null || ports.Contains('~', StringComparison.Ordinal))
            return;
        HashSet<int> covered;
        try
        {
            covered = wf.Length == 0 ? [] : PortList.Parse(wf).ToHashSet();
        }
        catch (FormatException)
        {
            return;
        }
        var missing = PortList.ParseRanges(ports).Where(rg => !Enumerable.Range(rg.From, rg.To - rg.From + 1).All(covered.Contains)).ToList();
        if (missing.Count > 0)
            r.Error("wf.uncovered", $"порты {PortList.Format(missing)} профиля не перехватываются: добавьте их в {opt}", $"profile ports {PortList.Format(missing)} are not intercepted, add them to {opt}", where.Length > 0 ? where : null);
    }

    private static string PlatformName(EnginePlatform p) => p switch
    {
        EnginePlatform.Windows => "Windows (winws2)",
        EnginePlatform.Keenetic => "Keenetic",
        _ => "Linux (nfqws2)",
    };

    private void ValidateProfile(Profile p, ValidationResult r, string? where)
    {
        foreach (var l7 in p.L7)
        {
            if (!Cat.L7.Contains(l7))
                r.Error("l7.unknown", $"неизвестный протокол --filter-l7={l7}", $"unknown --filter-l7 protocol {l7}", where);
        }
        if (p.Name.Length > 0 && !Identifiers.IsListName(p.Name))
            r.Error("profile.name", $"имя профиля «{p.Name}» должно состоять из латиницы, цифр, _ и -", $"profile name '{p.Name}' must be [A-Za-z0-9_-]", where);
        CheckPorts(p.TcpPorts, "--filter-tcp", r, where);
        CheckPorts(p.UdpPorts, "--filter-udp", r, where);
        if (p.TcpPorts is null && p.UdpPorts is null && !p.ExtraOptions.Any(o => o.StartsWith("--filter-", StringComparison.Ordinal)))
            r.Warn("profile.nofilter", "у профиля нет фильтра портов: он поймает весь трафик", "the profile has no port filter and matches all traffic", where);

        bool tcp = p.TcpPorts is not null;
        bool udpOnly = !tcp && p.UdpPorts is not null;
        var producedBlobs = new HashSet<string>(StringComparer.Ordinal);
        string inRange = "x";
        bool payloadFiltered = false;
        var calls = new List<(LuaCall Call, int Index)>();
        int idx = 0;
        foreach (var action in p.Strategy.Actions)
        {
            switch (action)
            {
                case PayloadFilter pf:
                    foreach (var t in pf.Types)
                    {
                        if (!Cat.Payloads.Contains(t))
                            r.Error("payload.unknown", $"неизвестный тип пейлоада --payload={t}", $"unknown payload type --payload={t}", where);
                    }
                    payloadFiltered = !(pf.Types.Count == 1 && pf.Types[0] == "all");
                    break;
                case InRange ir:
                    if (!PacketRange.IsValid(ir.Range))
                        r.Error("range.bad", $"неверный диапазон --in-range={ir.Range}", $"invalid --in-range={ir.Range}", where);
                    inRange = ir.Range;
                    break;
                case OutRange or_:
                    if (!PacketRange.IsValid(or_.Range))
                        r.Error("range.bad", $"неверный диапазон --out-range={or_.Range}", $"invalid --out-range={or_.Range}", where);
                    break;
                case LuaDesync ld:
                    ValidateCall(ld.Call, p, r, where, producedBlobs, udpOnly, inRange, payloadFiltered);
                    calls.Add((ld.Call, idx));
                    break;
            }
            idx++;
        }

        if (calls.Count == 0)
            r.Warn("profile.empty", "в профиле нет ни одного --lua-desync", "the profile has no --lua-desync", where);

        // nfqws2-lua §10.4: oob must not be combined with resenders in the same profile
        if (calls.Any(c => c.Call.Function == "oob") && calls.Any(c => Resenders.Contains(c.Call.Function)))
            r.Error("oob.resender", "oob нельзя сочетать с multisplit и другими ресендерами в одном профиле", "oob cannot be combined with multisplit and other resenders in one profile", where);

        // nfqws2-lua §10.5: http_methodeol goes last among the http functions
        int methodeol = calls.FindIndex(c => c.Call.Function == "http_methodeol");
        if (methodeol >= 0 && calls.Skip(methodeol + 1).Any(c => Cat.Find(c.Call.Function)?.Category == "http"))
            r.Error("http.methodeol.order", "http_methodeol должна идти последней из http-функций", "http_methodeol must be the last http function", where);

        // tcpseg sends a piece without a verdict: without drop the original goes out too
        int tcpseg = calls.FindIndex(c => c.Call.Function == "tcpseg");
        if (tcpseg >= 0 && !calls.Skip(tcpseg + 1).Any(c => c.Call.Function == "drop"))
            r.Warn("tcpseg.nodrop", "после tcpseg нет drop: оригинал тоже уйдёт", "no drop after tcpseg: the original packet is sent too", where);

        // nfqws2-lua §10.7 and nfqws2-engine §6.4: phase 0 techniques never fire in a hostlist-only profile
        if (p.HasHostFilter && !p.HasIpFilter && !_ctx.IpcacheHostname)
        {
            foreach (var (call, _) in calls)
            {
                if (Cat.Find(call.Function) is { Phase0: true })
                    r.Error("phase0.hostlist", $"{call.Function} работает до появления имени хоста, а профиль выбирается по hostlist: техника не сработает (нужен профиль без hostlist или --ipcache-hostname)", $"{call.Function} acts before the hostname is known but the profile is selected by hostlist; it never fires", where);
            }
        }

        ValidateCircular(calls.Select(c => c.Call).ToList(), r, where);
    }

    private void ValidateCall(LuaCall call, Profile p, ValidationResult r, string? where, HashSet<string> producedBlobs, bool udpOnly, string inRange, bool payloadFiltered)
    {
        var at = where is null ? call.Function : $"{where}: {call.Function}";
        var spec = Cat.Find(call.Function);
        if (spec is null)
        {
            if (_ctx.UserFunctions.ContainsKey(call.Function))
            {
                ValidateUserCall(call, r, at, producedBlobs);
                return;
            }
            if (_ctx.DraftFunctions.TryGetValue(call.Function, out var draft))
            {
                r.Error("func.unapproved", $"функция {call.Function} из Lua-скрипта «{draft}», который не подтверждён: откройте скрипт в AutoTuner, проверьте текст и нажмите «Подтвердить»",
                    $"function {call.Function} comes from the Lua script '{draft}', which is not approved: open it in AutoTuner, review the text and press Approve", at);
                return;
            }
            if (_ctx.UnloadedUserFunctions.TryGetValue(call.Function, out var file))
            {
                r.Error("func.user_notloaded", $"функция {call.Function} из своего скрипта {file}, но --lua-init для него нет", $"function {call.Function} is from the user script {file}, but there is no --lua-init for it", at);
                return;
            }
            if (_ctx.LoadedFunctions is { } loaded && loaded.Contains(call.Function))
                return; // custom function from an extra lua file: arguments are unknown to us
            r.Error("func.unknown", $"функция {call.Function} не определена в загружаемых lua", $"function {call.Function} is not defined in the loaded lua", at);
            return;
        }
        if (_ctx.LoadedFunctions is { } fs && !fs.Contains(call.Function))
            r.Error("func.notloaded", $"функция {call.Function} есть в каталоге, но файл {spec.File} не загружается", $"{call.Function} is in the catalog but {spec.File} is not loaded", at);
        if (spec.TwoSided)
            r.Warn("func.twosided", $"{call.Function} нужна вторая сторона с тем же zapret2, для обхода DPI на ПК не подходит", $"{call.Function} needs a peer running zapret2", at);
        if (spec.ServerSide)
            r.Warn("func.server", $"{call.Function} — серверная техника, клиенту не нужна", $"{call.Function} is a server-side technique", at);

        foreach (var req in spec.Args.Where(a => a.Required))
        {
            if (!call.Has(req.Name))
                r.Error("arg.required", $"не указан обязательный аргумент {req.Name}", $"required argument {req.Name} is missing", at);
        }

        foreach (var arg in call.Args)
        {
            var aspec = Cat.FindArg(spec, arg.Name);
            if (aspec is null)
            {
                r.Error("arg.unknown", $"аргумент {arg.Name} функция не принимает (Lua молча его проигнорирует)", $"argument {arg.Name} is not accepted by the function and would be ignored", at);
                continue;
            }
            ValidateArgValue(aspec, arg, call, r, at, producedBlobs);
        }

        // %var / #var substitutions resolve to desync fields or globals (blobs); unresolved ones cancel the whole plan
        foreach (var arg in call.Args.Where(a => a.Value is not null))
        {
            foreach (Match m in SubstitutionRegex().Matches(arg.Value!))
            {
                var name = m.Groups[2].Value;
                if (!BlobAvailable(name, producedBlobs))
                    r.Error("blob.subst", $"подстановка {m.Value} в {arg.Name} не разрешится: блоб {name} не объявлен (движок отменит весь план профиля)", $"substitution {m.Value} in {arg.Name} cannot resolve: blob {name} is not declared", at);
            }
        }

        if (spec.Payloads is { } onlyPayloads && call["payload"] is { } payloadArg && !payloadArg.StartsWith('~'))
        {
            if (!payloadArg.Split(',').Any(onlyPayloads.Contains))
                r.Warn("payload.mismatch", $"{call.Function} работает только с {string.Join(", ", onlyPayloads)}", $"{call.Function} only acts on {string.Join(", ", onlyPayloads)}", at);
        }

        // nfqws2-lua §10.1: fakes need fooling, otherwise the server accepts the fake and the connection breaks
        if (spec.NeedsFooling && !udpOnly && !call.Args.Any(a => Cat.FoolingKeys.Contains(a.Name)))
            r.Error("fake.nofooling", $"{call.Function} без fooling: фейк дойдёт до сервера и сломает соединение (добавьте tcp_md5, tcp_seq, badsum, ip_ttl…)", $"{call.Function} has no fooling: the fake reaches the server and breaks the connection", at);

        // nfqws2-lua §10.2: tcp_ts does nothing when the client does not send timestamps (Windows by default)
        if (call.Has("tcp_ts") && _ctx.Client is { TcpTimestamps: false } c)
            r.Warn("fooling.tcp_ts", $"tcp_ts бесполезен: клиент «{c.NameRu}» не отправляет TCP timestamps", $"tcp_ts is useless: client '{c.NameEn}' sends no TCP timestamps", at);

        if (udpOnly && (call.Has("ip_ttl") || call.Has("ip_autottl") || call.Has("ip6_ttl") || call.Has("ip6_autottl")))
            r.Warn("fooling.udp_ttl", "TTL-fooling на UDP опасен: ICMP time-exceeded закрывает сокет у Safari и iOS", "TTL fooling on UDP is risky: ICMP time-exceeded closes sockets on Safari/iOS", at);

        switch (call.Function)
        {
            case "multidisorder" or "fakeddisorder" or "multidisorder_legacy":
                CheckSeqovlBeforePos(call, r, at);
                break;
            case "oob":
                if (inRange != "-s1")
                    r.Error("oob.inrange", "oob требует --in-range=-s1 перед собой", "oob requires --in-range=-s1 before it", at);
                if (payloadFiltered || p.HasHostFilter)
                    r.Warn("oob.filter", "oob нельзя фильтровать по payload и hostlist: он действует на handshake", "oob cannot be filtered by payload or hostlist; it acts on the handshake", at);
                if (call.Has("char") && call.Has("byte"))
                    r.Warn("oob.charbyte", "указаны и char, и byte: возьмётся только один", "both char and byte given; only one is used", at);
                break;
            case "circular":
                if (inRange == "x")
                    r.Warn("circular.inrange", "circular без входящих пакетов (--in-range=x): детектор неудач ничего не увидит, нужен --in-range=-s5556", "circular without incoming packets: the failure detector is blind, use --in-range=-s5556", at);
                break;
            case "synack":
                r.Warn("synack.nat", "synack ломает NAT", "synack breaks NAT", at);
                break;
        }

        if (call.Function == "tls_client_hello_clone" && call["blob"] is { } produced)
            producedBlobs.Add(produced);
    }

    /// <summary>
    /// A call to a function of an approved user script: its own argument names are unknown, but the orchestrator's
    /// instance arguments, blob names and <c>%var</c>/<c>#var</c> substitutions follow the same rules as everywhere.
    /// </summary>
    private void ValidateUserCall(LuaCall call, ValidationResult r, string at, HashSet<string> producedBlobs)
    {
        foreach (var arg in call.Args)
        {
            // the orchestrator's instance args and the standard dir/payload filters mean the same for every function
            var standard = Cat.Data.InstanceArgs
                .Concat(Cat.Data.Blocks.GetValueOrDefault("direction") ?? [])
                .Concat(Cat.Data.Blocks.GetValueOrDefault("payload") ?? []);
            if (standard.FirstOrDefault(a => a.Name == arg.Name) is { } instance)
            {
                ValidateArgValue(instance, arg, call, r, at, producedBlobs);
                continue;
            }
            if (arg.Value is { Length: > 0 } v && Resources.ResourceRefs.BlobArgs.Contains(arg.Name) && v[0] is not ('%' or '#') && !HexBlobRegex().IsMatch(v))
            {
                if (!Identifiers.IsLuaIdentifier(v))
                    r.Error("blob.name", $"имя блоба «{v}» не идентификатор Lua", $"blob name '{v}' is not a Lua identifier", at);
                else if (!BlobAvailable(v, producedBlobs))
                    r.Error("blob.missing", $"блоб «{v}» в {arg.Name} не объявлен: движок оборвёт план профиля до Lua (нужен --blob={v}:@файл)", $"blob '{v}' in {arg.Name} is not declared: the engine aborts the profile plan", at);
            }
            if (arg.Value is { Length: > 2 } hx && hx.StartsWith("0x", StringComparison.Ordinal) && HexBlobRegex().IsMatch(hx) && (hx.Length - 2) / 2 > MaxBlobSize)
                r.Error("blob.size", $"hex-блоб в {arg.Name} больше 16 KB", $"hex blob in {arg.Name} exceeds 16 KB", at);
        }
        foreach (var arg in call.Args.Where(a => a.Value is not null))
        {
            foreach (Match m in SubstitutionRegex().Matches(arg.Value!))
            {
                var name = m.Groups[2].Value;
                if (!BlobAvailable(name, producedBlobs))
                    r.Error("blob.subst", $"подстановка {m.Value} в {arg.Name} не разрешится: блоб {name} не объявлен (движок отменит весь план профиля)", $"substitution {m.Value} in {arg.Name} cannot resolve: blob {name} is not declared", at);
            }
        }
    }

    private void ValidateArgValue(ArgSpec spec, LuaArg arg, LuaCall call, ValidationResult r, string at, HashSet<string> producedBlobs)
    {
        var v = arg.Value;
        string Bad(string what) => $"{arg.Name}={v}: {what}";
        switch (spec.Kind)
        {
            case ArgKind.Flag:
                if (v is { Length: > 0 })
                    r.Warn("arg.flagvalue", $"{arg.Name} — флаг, значение «{v}» не учитывается", $"{arg.Name} is a flag, the value is ignored", at);
                return;
            case ArgKind.HexOptional:
                if (v is { Length: > 0 } && !HexRegex().IsMatch(v.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? v[2..] : v))
                    r.Error("arg.hex", Bad("ожидается hex"), Bad("hex expected"), at);
                return;
            case ArgKind.FunctionOptional:
                if (v is { Length: > 0 } && !Identifiers.IsLuaIdentifier(v))
                    r.Error("arg.func", Bad("ожидается имя функции"), Bad("function name expected"), at);
                return;
        }

        if (v is null)
        {
            r.Error("arg.novalue", $"у аргумента {arg.Name} должно быть значение", $"argument {arg.Name} needs a value", at);
            return;
        }

        switch (spec.Kind)
        {
            case ArgKind.Int or ArgKind.IntSigned:
                if (!long.TryParse(v, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n))
                {
                    r.Error("arg.int", Bad("ожидается число"), Bad("number expected"), at);
                    return;
                }
                if (spec.Kind == ArgKind.Int && n < 0 && spec.Min is null)
                    r.Error("arg.int", Bad("число не может быть отрицательным"), Bad("must not be negative"), at);
                if (spec.Min is { } min && n < min)
                    r.Error("arg.range", Bad($"меньше минимума {min}"), Bad($"below minimum {min}"), at);
                if (spec.Max is { } max && n > max)
                    r.Error("arg.range", Bad($"больше максимума {max}"), Bad($"above maximum {max}"), at);
                if (spec.MultipleOf is { } mul && n % mul != 0)
                    r.Error("arg.multiple", Bad($"должно быть кратно {mul}"), Bad($"must be a multiple of {mul}"), at);
                break;
            case ArgKind.String:
                if (spec.Length is { } len && v.Length != len)
                    r.Error("arg.length", Bad($"нужно ровно {len} символа"), Bad($"exactly {len} characters required"), at);
                break;
            case ArgKind.Enum:
                if (spec.Values is { } vals && !vals.Contains(v))
                    r.Error("arg.enum", Bad($"допустимо: {string.Join(", ", vals)}"), Bad($"allowed: {string.Join(", ", vals)}"), at);
                break;
            case ArgKind.Blob:
                if (v.Length > 1 && v[0] is '%' or '#')
                    break; // substitution, checked below for every argument
                if (!HexBlobRegex().IsMatch(v) && !BlobAvailable(v, producedBlobs) && !call.Has("optional"))
                    r.Error("blob.missing", $"блоб «{v}» в {arg.Name} не объявлен: движок оборвёт план профиля до Lua (нужен --blob={v}:@файл)", $"blob '{v}' in {arg.Name} is not declared: the engine aborts the profile plan", at);
                else if (!HexBlobRegex().IsMatch(v) && !Identifiers.IsLuaIdentifier(v))
                    r.Error("blob.name", $"имя блоба «{v}» не идентификатор Lua", $"blob name '{v}' is not a Lua identifier", at);
                else if (v.StartsWith("0x", StringComparison.Ordinal) && (v.Length - 2) / 2 > MaxBlobSize)
                    r.Error("blob.size", $"hex-блоб в {arg.Name} больше 16 KB", $"hex blob in {arg.Name} exceeds 16 KB", at);
                break;
            case ArgKind.BlobNameOut:
                if (!Identifiers.IsLuaIdentifier(v))
                    r.Error("blob.name", $"имя блоба «{v}» не идентификатор Lua", $"blob name '{v}' is not a Lua identifier", at);
                break;
            case ArgKind.Marker:
                if (!PositionMarker.TryParse(v, Cat.PositionMarkers, out _))
                    r.Error("arg.marker", Bad("неверный маркер позиции (пример: 1, -1, midsld, host+2)"), Bad("invalid position marker"), at);
                break;
            case ArgKind.MarkerOptional:
                if (v.Length > 0 && !PositionMarker.TryParse(v, Cat.PositionMarkers, out _))
                    r.Error("arg.marker", Bad("неверный маркер позиции"), Bad("invalid position marker"), at);
                break;
            case ArgKind.MarkerOrBe:
                if (v is not ("b" or "e") && !PositionMarker.TryParse(v, Cat.PositionMarkers, out _))
                    r.Error("arg.marker", Bad("ожидается маркер, b или e"), Bad("marker, b or e expected"), at);
                break;
            case ArgKind.MarkerList:
                if (!PositionMarker.TryParseList(v, Cat.PositionMarkers, out var list) || list.Count == 0)
                    r.Error("arg.marker", Bad("неверный список маркеров (пример: 1,midsld)"), Bad("invalid marker list"), at);
                else if (spec.Count is { } cnt && list.Count != cnt)
                    r.Error("arg.count", Bad($"нужно ровно {cnt} маркера"), Bad($"exactly {cnt} markers required"), at);
                break;
            case ArgKind.PayloadList:
                foreach (var t in (v.StartsWith('~') ? v[1..] : v).Split(','))
                {
                    if (!Cat.Payloads.Contains(t))
                        r.Error("payload.unknown", Bad($"неизвестный тип пейлоада {t}"), Bad($"unknown payload type {t}"), at);
                }
                break;
            case ArgKind.TlsMod:
                foreach (var mod in v.Split(','))
                {
                    var name = mod.Split('=')[0];
                    if (!Cat.TlsMods.Contains(name) || (spec.Values is { } allowed && !allowed.Contains(name) && name != "none"))
                        r.Error("tlsmod.unknown", Bad($"tls_mod «{name}» не поддерживается этой функцией"), Bad($"tls_mod '{name}' is not supported here"), at);
                    else if (name == "sni" && !mod.Contains('=', StringComparison.Ordinal))
                        r.Error("tlsmod.sni", Bad("у sni нужно значение: sni=домен"), Bad("sni needs a value: sni=domain"), at);
                }
                break;
            case ArgKind.TcpFlags:
                foreach (var f in v.Split(','))
                {
                    if (!TcpFlags.Contains(f.ToUpperInvariant()))
                        r.Error("arg.tcpflag", Bad($"неизвестный флаг {f}"), Bad($"unknown flag {f}"), at);
                }
                break;
            case ArgKind.AutoTtl:
                if (!AutoTtlRegex().IsMatch(v))
                    r.Error("arg.autottl", Bad("ожидается delta,min-max (например -1,3-20)"), Bad("delta,min-max expected"), at);
                break;
            case ArgKind.Function:
                if (!Identifiers.IsLuaIdentifier(v))
                    r.Error("arg.func", Bad("ожидается имя функции"), Bad("function name expected"), at);
                break;
            case ArgKind.Iff:
                if (!Cat.Data.IffFunctions.Contains(v) && _ctx.LoadedFunctions?.Contains(v) != true)
                    r.Error("arg.iff", Bad($"неизвестная iff-функция (есть: {string.Join(", ", Cat.Data.IffFunctions)})"), Bad("unknown iff function"), at);
                break;
        }
    }

    private bool BlobAvailable(string name, HashSet<string> produced) =>
        Cat.BuiltinBlobs.Contains(name) || _ctx.DeclaredBlobs.ContainsKey(name) || produced.Contains(name);

    private void CheckSeqovlBeforePos(LuaCall call, ValidationResult r, string at)
    {
        // nfqws2-lua §10.3: seqovl must be less than the first split position
        if (call["seqovl"] is not { } so || call["pos"] is not { } pos)
            return;
        if (!PositionMarker.TryParse(so, Cat.PositionMarkers, out var seq) || !PositionMarker.TryParseList(pos, Cat.PositionMarkers, out var list) || list.Count == 0)
            return;
        // the engine sorts the resolved positions, so the first split is the smallest one, wherever it is written:
        // any position of the same kind at or below seqovl already breaks the rule
        var first = list
            .Where(m => seq!.Name == m.Name && (!seq.IsAbsolute || (seq.Offset >= 0 && m.Offset >= 0)))
            .MinBy(m => m.Offset);
        if (first is not null && seq!.Offset >= first.Offset)
            r.Error("seqovl.pos", $"seqovl={so} должен быть меньше первой позиции pos={first}", $"seqovl={so} must be less than the first split position {first}", at);
    }

    private static void ValidateCircular(List<LuaCall> calls, ValidationResult r, string? where)
    {
        int ci = calls.FindIndex(c => c.Function == "circular");
        if (ci < 0)
            return;
        var numbers = new List<int>();
        foreach (var c in calls.Skip(ci + 1))
        {
            if (c["strategy"] is { } s)
            {
                if (!int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n < 1)
                    r.Error("circular.number", $"strategy={s} должно быть положительным числом", $"strategy={s} must be a positive number", where);
                else
                    numbers.Add(n);
            }
        }
        if (numbers.Count == 0)
        {
            r.Error("circular.empty", "после circular нет инстансов со strategy=N", "no instances with strategy=N follow circular", where);
            return;
        }
        var distinct = numbers.Distinct().Order().ToList();
        if (distinct[0] != 1 || distinct[^1] != distinct.Count)
            r.Error("circular.gap", $"номера strategy должны идти с 1 без пропусков, сейчас: {string.Join(",", distinct)}", $"strategy numbers must start at 1 without gaps: {string.Join(",", distinct)}", where);
    }

    private static void CheckPorts(string? ports, string opt, ValidationResult r, string? where)
    {
        if (ports is null)
            return;
        foreach (var raw in ports.Split(','))
        {
            var p = raw.StartsWith('~') ? raw[1..] : raw;
            if (p == "*")
                continue;
            var parts = p.Split('-');
            bool ok = parts.Length is 1 or 2 && parts.All(x => int.TryParse(x, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n is >= 0 and <= 65535);
            if (!ok)
                r.Error("ports.bad", $"неверный порт «{raw}» в {opt}", $"invalid port '{raw}' in {opt}", where);
        }
    }
}
