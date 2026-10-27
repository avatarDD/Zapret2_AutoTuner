using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using ZapretAutoTuner.Agent.Firewall;
using ZapretAutoTuner.Agent.Os;
using ZapretAutoTuner.Core.Catalog;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Agent.Engine;

internal sealed record CheckResult(bool Ok, string Stage, IReadOnlyList<string> Output);

/// <summary>
/// Starts and stops engine instances (PLAN 1.2). Every argv passes the Validator and the Agent policy before it
/// runs (AGENTS.md rule 4); on Linux each instance gets its queue rule in the firewall, removed when it stops.
/// </summary>
internal sealed class EngineManager : IDisposable
{
    public const uint FwMark = 0x40000000;

    private readonly ConcurrentDictionary<string, EngineInstance> _engines = new();
    private readonly ConcurrentDictionary<string, int> _queues = new();
    private readonly ConcurrentDictionary<string, string[]> _copies = new();
    private readonly AgentOptions _options;
    private readonly FirewallManager? _firewall;
    private readonly AgentStateStore _state;
    private readonly WindowsJob? _job;
    private int _seq;

    public EngineManager(AgentOptions options, AgentStateStore state, FirewallManager? firewall)
    {
        _options = options;
        _state = state;
        _firewall = firewall;
        // under pkexec only the engine next to the Agent binary: ZT_ZAPRET2_DIR is the caller's to set
        _originalEnginePath = options.Engine ?? (options.Pkexec ? new Tools.Zapret2Bundle(Path.Combine(AppContext.BaseDirectory, "zapret2")) : Tools.Zapret2Bundle.Locate()).EnginePath;
        EnginePath = _originalEnginePath;
        // the bundle (next to the Agent, or ZT_ZAPRET2_DIR) run with rights: copied and verified if others can write it
        _guarded = Environment.IsPrivilegedProcess && IsBundled(_originalEnginePath, options.Pkexec);
        if (OperatingSystem.IsWindows())
            _job = new WindowsJob();
        Lua = new LuaStore(options.LuaDir ?? LuaStore.DefaultRoot(options.DataDir!), Path.GetDirectoryName(Path.GetFullPath(EnginePath)) ?? options.DataDir!,
            () => [.. _copies.Values.SelectMany(c => c)]);
    }

    private readonly string _originalEnginePath;
    private readonly bool _guarded;
    private readonly Lock _prepareLock = new();
    private bool _prepared;

    /// <summary>The engine that runs: the bundled one, or the Agent's verified copy of it (<see cref="PrepareEngine"/>).</summary>
    public string EnginePath { get; private set; }

    private static bool IsBundled(string enginePath, bool pkexec)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(enginePath));
        var roots = new List<string> { Path.Combine(AppContext.BaseDirectory, "zapret2") };
        if (!pkexec)
            roots.Add(Tools.Zapret2Bundle.Locate().Root);
        var cmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return roots.Any(r => string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(r)), dir, cmp));
    }

    /// <summary>
    /// Before the engine runs with the Agent's rights (final review 9): a bundle that a non-administrator could change
    /// (a portable archive in the user's folder) is copied into the protected store and verified against bundle.json;
    /// from then on <see cref="EnginePath"/> is the copy. Throws <see cref="EngineStartException"/> "engine" when the copy
    /// does not verify. Nothing happens for an installed bundle, an unprivileged Agent or an engine named explicitly.
    /// </summary>
    public string PrepareEngine()
    {
        lock (_prepareLock)
        {
            if (_prepared || !_guarded || !File.Exists(_originalEnginePath))
                return EnginePath;
            var root = Path.GetDirectoryName(Path.GetFullPath(_originalEnginePath))!;
            var name = Path.GetFileName(_originalEnginePath);
            if (ProtectedBundle.WritableByOthers(root, name).Count == 0)
            {
                _prepared = true;
                return EnginePath;
            }
            var copy = Lua.NewEngineFolder();
            try
            {
                ProtectedBundle.CopyAndVerify(root, copy, name);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw new EngineStartException("engine", [$"не удалось скопировать движок в защищённый каталог / could not copy the engine: {e.Message}"]);
            }
            EnginePath = Path.Combine(copy, name);
            Lua.EngineDir = copy;
            _bundleRoot = root;
            _prepared = true;
            return EnginePath;
        }
    }

    private string? _bundleRoot;

    /// <summary>Where the capture loads WinDivert.dll from: the folder of the prepared engine, null when it did not verify.</summary>
    internal static Func<string?>? CaptureBundleRoot { get; set; }

    /// <summary>The UI names the bundle's own files (lua, files/fake) where it found them: they are loaded from the copy.</summary>
    internal List<string> FromCopy(IReadOnlyList<string> argv)
    {
        if (_bundleRoot is not { } from)
            return [.. argv];
        var to = Path.GetDirectoryName(EnginePath)!;
        var cmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var prefixes = new[] { from + Path.DirectorySeparatorChar, from + Path.AltDirectorySeparatorChar }.Distinct().ToList();
        return [.. argv.Select(t =>
        {
            foreach (var p in prefixes)
                if (t.Contains(p, cmp))
                    return t.Replace(p, to + Path.DirectorySeparatorChar, cmp);
            return t;
        })];
    }

    /// <summary>The Agent's protected copies of the Lua files the UI sends (user Lua, PLAN 4a.5).</summary>
    public LuaStore Lua { get; }

    public EnginePlatform Platform => OperatingSystem.IsWindows() ? EnginePlatform.Windows : EnginePlatform.Linux;

    public IReadOnlyList<string> Running => _engines.Values.Where(e => !e.HasExited).Select(e => e.Id).ToList();

    public IReadOnlyList<string> WriteRoots => [_options.DataDir!];

    /// <summary>
    /// Where blob files may come from: the engine's own directory (files/fake) and the Agent's copies. nfqws2 reads
    /// blobs as root before dropping privileges, so a blob is never read from the user-writable data directory (a
    /// symlink there could point at a root-only file): the UI sends its content and <see cref="LuaStore"/> copies it.
    /// </summary>
    public IReadOnlyList<string> ReadRoots => [Path.GetDirectoryName(EnginePath) ?? _options.DataDir!, Lua.Root];

    public EngineInstance? Find(string id) => _engines.GetValueOrDefault(id);

    /// <summary>Validator + policy problems, or null if the argv may run.</summary>
    /// <param name="extraReadRoots">More directories the argv may read from (the winws2 service directory).</param>
    public CheckResult? Precheck(IReadOnlyList<string> argv, IReadOnlyList<string>? extraReadRoots = null)
    {
        var policy = EngineArgvPolicy.Check(argv, WriteRoots, [.. ReadRoots, .. extraReadRoots ?? []], luaRoots: [.. Lua.AllowedRoots, .. extraReadRoots ?? []]);
        policy.AddRange(LinkProblems(argv, WriteRoots));
        if (policy.Count > 0)
            return new CheckResult(false, "policy", policy);
        var ctx = new ValidationContext { Catalog = LuaCatalog.Default, Platform = Platform };
        var result = new StrategyValidator(ctx).ValidateArgv(argv, f => File.Exists(f) ? new FileInfo(f).Length : null, UserLuaFunctions);
        if (!result.Ok)
            return new CheckResult(false, "validator", result.Errors.Select(e => e.ToString()).ToList());
        return null;
    }

    /// <summary>
    /// The engine opens and chowns the files of <c>--debug=@</c>, <c>--hostlist-auto</c> and <c>--hostlist-auto-debug</c>
    /// as root before dropping privileges (nfqws.c: <c>ensure_file_access</c>), and they lie in the user-writable data
    /// directory: a symlink (or a junction) on the way would hand any file to the engine's user. Such a path is refused.
    /// The check runs before the start, so it narrows the window rather than closing it (the user's own folder).
    /// </summary>
    internal static List<string> LinkProblems(IReadOnlyList<string> argv, IReadOnlyList<string> roots)
    {
        var problems = new List<string>();
        foreach (var tok in argv)
        {
            if (!tok.StartsWith("--", StringComparison.Ordinal))
                continue;
            var (name, value) = Core.Model.ArgTokenizer.SplitOption(tok);
            var key = name[2..];
            string? path = key == "debug" && value is { Length: > 1 } && value[0] == '@' ? value[1..]
                : EngineArgvPolicy.WrittenPaths.Contains(key) ? value : null;
            if (path is null || !Path.IsPathFullyQualified(path))
                continue;
            var full = Path.GetFullPath(path);
            var root = roots.Select(r => Path.TrimEndingDirectorySeparator(Path.GetFullPath(r))).FirstOrDefault(r => EngineArgvPolicy.IsUnder(full, [r]));
            if (root is null)
                continue;
            for (var p = full; p.Length > root.Length; p = Path.GetDirectoryName(p)!)
            {
                FileSystemInfo info = Directory.Exists(p) ? new DirectoryInfo(p) : new FileInfo(p);
                if (info.Exists && info.LinkTarget is not null)
                {
                    problems.Add($"{name}: {p} — символическая ссылка, движок не пишет через неё");
                    break;
                }
            }
        }
        return problems;
    }

    /// <summary>
    /// The desync functions of a user Lua file (PLAN 4a.5) the argv loads, so the Validator accepts calls to them. The
    /// user approved the script in the UI; the Agent only reads which functions its own copy (the file it will load,
    /// <see cref="LuaStore"/>) defines.
    /// </summary>
    private static IReadOnlyCollection<string>? UserLuaFunctions(string path)
    {
        if (!path.EndsWith(".lua", StringComparison.Ordinal) || !File.Exists(path) || new FileInfo(path).Length > Core.Resources.ResourceRules.MaxLuaBytes)
            return null;
        return Core.Resources.LuaScriptCheck.FindDesyncFunctions(File.ReadAllText(path));
    }

    /// <summary><c>--dry-run</c>, then <c>--intercept=0</c> (catches lua-init errors), nfqws2-engine §9.</summary>
    public async Task<CheckResult> CheckAsync(IReadOnlyList<string> argv, IReadOnlyDictionary<string, byte[]> luaFiles, CancellationToken ct)
    {
        try
        {
            PrepareEngine();
            argv = Lua.Prepare(FromCopy(argv), luaFiles);
        }
        catch (EngineStartException e)
        {
            return new CheckResult(false, e.Stage, e.Problems);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new CheckResult(false, "engine", [e.Message]);
        }
        if (Precheck(argv) is { } bad)
            return bad;
        foreach (var (stage, extra) in new[] { ("dry-run", "--dry-run"), ("intercept=0", "--intercept=0") })
        {
            // nfqws2 refuses to start without --qnum even for --dry-run; nothing is intercepted here
            var full = WithManaged(argv, queueNum: 0).Append(extra).ToList();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(20));
            CmdResult r;
            try
            {
                r = await Cmd.RunAsync(EnginePath, full, ct: cts.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return new CheckResult(false, stage, ["движок не завершился за 20 с"]);
            }
            var lines = (r.Stdout + r.Stderr).Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
            if (!r.Ok)
                return new CheckResult(false, stage, lines);
            if (lines.Select(EngineLogParser.Parse).Any(e => e is not null && EngineLogParser.IsFatal(e)))
                return new CheckResult(false, stage, lines);
        }
        return new CheckResult(true, "", []);
    }

    /// <summary>Starts an instance. Throws <see cref="EngineStartException"/> with Russian text on refusal.</summary>
    /// <param name="luaFiles">The content of the <c>--lua-init=@file</c> files outside the engine's directory, by path.</param>
    public EngineInstance Start(IReadOnlyList<string> argv, IReadOnlyDictionary<string, byte[]> luaFiles, NftQueueRule? queue, string tag)
    {
        PrepareEngine();
        argv = Lua.Prepare(FromCopy(argv), luaFiles);
        if (Precheck(argv) is { } bad)
            throw new EngineStartException(bad.Stage, bad.Output);
        if (!File.Exists(EnginePath))
            throw new EngineStartException("engine", [$"не найден движок {EnginePath}"]);

        var id = "e" + Interlocked.Increment(ref _seq).ToString(CultureInfo.InvariantCulture);
        if (Platform == EnginePlatform.Linux)
        {
            if (queue is null)
                throw new EngineStartException("firewall", ["на Linux нужно правило очереди (queue)"]);
            if (_engines.Values.Any(e => !e.HasExited && _queues.TryGetValue(e.Id, out var q) && q == queue.QueueNum))
                throw new EngineStartException("firewall", [$"очередь {queue.QueueNum} уже занята другим экземпляром"]);
            if (_firewall is null)
                throw new EngineStartException("firewall", ["firewall недоступен"]);
            var err = _firewall.Set(id, queue);
            if (err is not null)
                throw new EngineStartException("firewall", [err]);
            _queues[id] = queue.QueueNum;
        }

        EngineInstance inst;
        try
        {
            inst = EngineInstance.Start(id, tag, EnginePath, WithManaged(argv, queue?.QueueNum), _job);
        }
        catch
        {
            _firewall?.Unset(id);
            _queues.TryRemove(id, out _);
            throw;
        }
        _engines[id] = inst;
        _copies[id] = [.. Protocol.LuaFiles.Paths(argv).Where(p => EngineArgvPolicy.IsUnder(p, [Lua.Root]))];
        _state.Update(s => s.Engines.Add(new AgentState.EngineRecord(inst.Pid, EnginePath, inst.StartTimeUtc)));
        _ = inst.Exited.ContinueWith(_ => OnExited(inst), TaskScheduler.Default);
        return inst;
    }

    private void OnExited(EngineInstance inst)
    {
        _firewall?.Unset(inst.Id);
        _queues.TryRemove(inst.Id, out _);
        _copies.TryRemove(inst.Id, out _);
        _state.Update(s => s.Engines.RemoveAll(e => e.Pid == inst.Pid));
    }

    public async Task<(bool WasRunning, int ExitCode)> StopAsync(string id)
    {
        if (!_engines.TryRemove(id, out var inst))
            return (false, 0);
        bool wasRunning = !inst.HasExited;
        int code = await inst.StopAsync(TimeSpan.FromSeconds(3));
        OnExited(inst);
        inst.Dispose();
        return (wasRunning, code);
    }

    public async Task StopAllAsync()
    {
        await Task.WhenAll(_engines.Keys.ToList().Select(StopAsync));
    }

    /// <summary>Adds the Agent-managed options: <c>--qnum</c> and <c>--fwmark</c> on Linux.</summary>
    private List<string> WithManaged(IReadOnlyList<string> argv, int? queueNum)
    {
        var a = new List<string>();
        if (Platform == EnginePlatform.Linux)
        {
            if (queueNum is not null)
                a.Add($"--qnum={queueNum}");
            a.Add($"--fwmark=0x{FwMark:X8}");
        }
        a.AddRange(argv);
        return a;
    }

    public static NftQueueRule ToRule(ZapretAutoTuner.Protocol.QueueRule q) => new()
    {
        QueueNum = q.QueueNum,
        TcpPorts = q.TcpPorts,
        UdpPorts = q.UdpPorts,
        Targets = q.Targets.Select(IPAddress.Parse).ToList(),
        Incoming = q.Incoming,
    };

    public void Dispose()
    {
        foreach (var e in _engines.Values)
            e.Dispose();
        if (OperatingSystem.IsWindows())
            _job?.Dispose();
    }
}

internal sealed class EngineStartException : Exception
{
    public EngineStartException(string stage, IReadOnlyList<string> problems)
        : base(stage + ": " + string.Join("; ", problems))
    {
        Stage = stage;
        Problems = problems;
    }

    public string Stage { get; }

    public IReadOnlyList<string> Problems { get; }
}
