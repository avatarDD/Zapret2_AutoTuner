using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Agent.Engine;
using ZapretAutoTuner.Agent.Firewall;
using ZapretAutoTuner.Agent.Os;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Protocol;
using ZapretAutoTuner.Tools;

namespace ZapretAutoTuner.Agent.Geneva;

internal sealed class GenevaStartException(string message) : Exception(message);

/// <summary>
/// geneva_c in the Agent (skill <c>geneva</c>): at most one <c>geneva run</c> (the bypass) and one <c>geneva evolve</c>
/// (the search). The UI names only typed settings; the command line, the queues (330/331, apart from zapret2's),
/// the control token and the files are the Agent's. A strategy passes <c>geneva check</c> before it runs (AGENTS.md
/// rule 4). The search's checkpoint and the strategy database live in a protected folder that survives restarts,
/// so a search continues where it stopped. Cleanup stops both and removes geneva's firewall rules.
/// </summary>
internal sealed class GenevaManager : IDisposable
{
    private readonly ConcurrentDictionary<string, GenevaInstance> _running = new();
    private readonly AgentOptions _options;
    private readonly AgentStateStore _state;
    private readonly LuaStore _store;
    private readonly WindowsJob? _job;
    private readonly FirewallManager? _firewall;
    private readonly SemaphoreSlim _autoGate = new(1, 1);
    private readonly Dictionary<string, GenevaInstance> _auto = new(StringComparer.Ordinal);
    private readonly Dictionary<int, string> _autoFilters = [];
    private GenevaInstance? _host;
    private string _hostSignature = "";
    private string _hostFilter = "";
    private readonly Lock _prepareLock = new();
    private readonly string _original;
    private string? _prepared;
    private int _seq;

    public GenevaManager(AgentOptions options, AgentStateStore state, LuaStore store, FirewallManager? firewall = null)
    {
        _options = options;
        _state = state;
        _store = store;
        _firewall = firewall;
        // under pkexec only the copy next to the Agent binary: ZT_GENEVA_DIR is the caller's to set
        _original = options.Pkexec ? Path.Combine(AppContext.BaseDirectory, "geneva") : GenevaBundle.Locate().Root;
        if (OperatingSystem.IsWindows())
            _job = new WindowsJob();
    }

    /// <summary>The bundle the Agent found (before the protected copy).</summary>
    public GenevaBundle Bundle => new(_original);

    public IReadOnlyList<string> Running => [.. _running.Values.Where(i => !i.HasExited).Select(i => i.Id)];

    public GenevaInstance? Find(string id) => _running.GetValueOrDefault(id);

    /// <summary>
    /// The geneva that runs: the bundled one, or the verified copy in the protected store when others can write the
    /// bundle's folder (final review 9, as for nfqws2). Throws <see cref="GenevaStartException"/> when it is missing or
    /// does not verify.
    /// </summary>
    public string Prepare()
    {
        lock (_prepareLock)
        {
            if (_prepared is not null && File.Exists(_prepared))
                return _prepared;
            var bundle = Bundle;
            if (!bundle.Exists)
                throw new GenevaStartException($"geneva не найдена в {bundle.Root} / geneva is missing (tools/bundle/bundle_geneva.py)");
            var check = bundle.Verify();
            if (!check.Ok)
                throw new GenevaStartException("geneva: " + string.Join("; ", check.Problems));
            if (!Environment.IsPrivilegedProcess || ProtectedBundle.WritableByOthers(bundle.Root, GenevaBundle.FileName).Count == 0)
                return _prepared = bundle.EnginePath;
            var copy = _store.NewToolFolder(LuaStore.GenevaFolderName);
            try
            {
                ProtectedBundle.CopyAndVerify(bundle.Root, copy, GenevaBundle.FileName, dir => new GenevaBundle(dir).Verify());
            }
            catch (EngineStartException e)
            {
                throw new GenevaStartException(string.Join("; ", e.Problems));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw new GenevaStartException($"не удалось скопировать geneva в защищённый каталог / could not copy geneva: {e.Message}");
            }
            return _prepared = Path.Combine(copy, GenevaBundle.FileName);
        }
    }

    /// <summary>
    /// Where the searches and the database are kept between runs: written by geneva with the Agent's rights, so never
    /// in the user's folder (a link there could point anywhere). Windows: ProgramData with an admin-only ACL; Linux:
    /// /var/lib (root only). An unprivileged Agent (tests) keeps them in its data directory.
    /// </summary>
    public string StateDir
    {
        get
        {
            if (_stateDir is not null)
                return _stateDir;
            string dir;
            if (!Environment.IsPrivilegedProcess)
            {
                dir = Path.Combine(_options.DataDir!, "geneva");
                Directory.CreateDirectory(dir);
            }
            else if (OperatingSystem.IsWindows())
            {
                dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ZapretAutoTuner-geneva");
                WinwsService.CreateProtected(dir);
            }
            else
            {
                const string parent = "/var/lib/zapret-autotuner";
                dir = parent + "/geneva";
                foreach (var (d, mode) in new[] { (parent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute), (dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute) })
                {
                    if (new DirectoryInfo(d).LinkTarget is not null)
                        throw new GenevaStartException($"{d}: символическая ссылка вместо каталога / a symlink");
                    Directory.CreateDirectory(d, mode);
                    File.SetUnixFileMode(d, mode);
                }
            }
            return _stateDir = dir;
        }
    }

    private string? _stateDir;

    public string DbPath => Path.Combine(StateDir, "db.jsonl");

    /// <summary>The folder of one target's search: its checkpoint and seeds.</summary>
    public string SearchDir(string targetKey) =>
        Path.Combine(StateDir, "searches", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(targetKey)))[..16]);

    public async Task<GenevaStartReply> StartAsync(GenevaStartRequest r, CancellationToken ct)
    {
        var geneva = Prepare();
        if (r.Mode == "run")
            return await StartRunAsync(geneva, r, ct);
        if (r.Mode == "evolve")
            return await StartSearchAsync(geneva, r, ct);
        throw new GenevaStartException($"неизвестный режим {r.Mode} / unknown mode");
    }

    private async Task<GenevaStartReply> StartRunAsync(string geneva, GenevaStartRequest r, CancellationToken ct)
    {
        if (_running.Values.Any(i => i.Mode == "run" && !i.HasExited))
            throw new GenevaStartException("geneva уже работает: сначала остановите её / geneva already runs");
        if (_running.Values.Any(i => i.Mode == "auto" && !i.HasExited))
            throw new GenevaStartException("включён режим «Авто»: сначала выключите его / the \"Auto\" mode is on");
        var settings = new GenevaRunSettings
        {
            Strategy = r.Strategy,
            Ports = string.IsNullOrWhiteSpace(r.Ports) ? "80,443" : r.Ports,
            ExcludeSubnets = [.. r.ExcludeSubnets],
            ExcludeDomains = [.. r.ExcludeDomains],
        };
        if (settings.Problems() is { Count: > 0 } bad)
            throw new GenevaStartException(string.Join("; ", bad));
        var features = await FeaturesAsync(geneva, ct);
        if (GenevaStrategyText.NeedsExt(settings.Strategy) && !features.Contains("ext_xact"))
            throw new GenevaStartException("стратегия с x-действиями требует geneva_c 2.0 / x-actions need geneva_c 2.0");
        bool lists = features.Contains("ext_lists");
        // the user's "never touch" list (a VPN, a proxy) is a promise: without ext_lists it cannot be kept, so the
        // run does not start rather than going over that traffic too
        if (!lists && (settings.ExcludeSubnets.Count > 0 || settings.ExcludeDomains.Count > 0))
            throw new GenevaStartException("исключения требуют geneva_c 2.0: обновите geneva или очистите список «Не трогать» / the exclusions need geneva_c 2.0");
        var check = (await new GenevaBundle(Path.GetDirectoryName(geneva)!).CheckAsync([settings.Strategy], ct, features.Contains("ext_xact"))) is { Count: > 0 } checks ? checks[0] : null;
        if (check is not { Ok: true, Strategy: { } canonical })
            throw new GenevaStartException("стратегия не разбирается / the strategy does not parse: " + (check?.Error ?? "?"));
        settings = settings with { Strategy = canonical };
        int port = FreeLoopbackPort();
        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var argv = GenevaArgv.Run(settings, port, lists);
        if (OperatingSystem.IsLinux())
            await FirewallDownAsync(geneva, GenevaArgv.RunQueue);
        var inst = Launch("run", geneva, argv, new Dictionary<string, string> { ["GENEVA_CONTROL_TOKEN"] = token }, supervise: true,
            port, token, GenevaArgv.NormalizePorts(settings.Ports), GenevaArgv.RunQueue);
        return new GenevaStartReply { Id = inst.Id, Pid = inst.Pid, Strategy = canonical };
    }

    private async Task<GenevaStartReply> StartSearchAsync(string geneva, GenevaStartRequest r, CancellationToken ct)
    {
        if (_running.Values.Any(i => i.Mode == "evolve" && !i.HasExited))
            throw new GenevaStartException("подбор geneva уже идёт / a geneva search is already running");
        var settings = new GenevaSearchSettings
        {
            Host = r.Host.Trim().TrimEnd('.').ToLowerInvariant(),
            Port = r.Port == 0 ? 443 : r.Port,
            Population = r.Population == 0 ? 30 : r.Population,
            Generations = r.Generations == 0 ? 15 : r.Generations,
            Resume = r.Resume,
            Seeds = [.. r.Seeds],
            Protos = string.IsNullOrEmpty(r.Protos) ? "TCP" : r.Protos,
            Probe = string.IsNullOrEmpty(r.Probe) ? GenevaArgv.WebProbe : r.Probe,
            Workers = Math.Max(1, r.Workers),
        };
        if (settings.Problems() is { Count: > 0 } bad)
            throw new GenevaStartException(string.Join("; ", bad));
        // an older geneva_c refuses --probe external with several workers: it gets one
        if (settings.Workers > 1 && !(await FeaturesAsync(geneva, ct)).Contains(GenevaBundle.ExternalWorkersFeature))
            settings = settings with { Workers = 1 };
        var dir = SearchDir(settings.TargetKey);
        CreateOwnDir(Path.GetDirectoryName(dir)!);
        CreateOwnDir(dir);
        var checkpoint = Path.Combine(dir, "search.ckpt");
        if (settings.Resume && !File.Exists(checkpoint))
            settings = settings with { Resume = false };
        // a search started with the extensions may hold x-actions in its checkpoint: it goes on with them
        var extMark = Path.Combine(dir, "ext");
        bool ext = (await FeaturesAsync(geneva, ct)).Contains("ext_xact");
        settings = settings with { ResumeExt = ext && settings.Resume && File.Exists(extMark) };
        await File.WriteAllTextAsync(Path.Combine(dir, "target.txt"), settings.TargetKey, ct);
        string? seedsFile = null;
        if (settings.Seeds.Count > 0 && !settings.Resume)
        {
            var good = (await new GenevaBundle(Path.GetDirectoryName(geneva)!).CheckAsync(settings.Seeds, ct, ext)).Where(c => c.Ok).Select(c => c.Strategy!).ToList();
            settings = settings with { Seeds = good };
            if (good.Count > 0)
            {
                seedsFile = Path.Combine(dir, "seeds.txt");
                await File.WriteAllLinesAsync(seedsFile, good, ct);
            }
        }
        else if (!settings.Resume)
        {
            settings = settings with { Seeds = [] };
        }
        if (settings.Ext)
            await File.WriteAllTextAsync(extMark, "x-actions\n", ct);
        else if (!settings.Resume && File.Exists(extMark))
            File.Delete(extMark);
        var argv = GenevaArgv.Evolve(settings, checkpoint, DbPath, seedsFile);
        if (OperatingSystem.IsLinux())
            await FirewallDownAsync(geneva, GenevaArgv.EvalQueue);
        var inst = Launch("evolve", geneva, argv, new Dictionary<string, string>(), supervise: false, queue: GenevaArgv.EvalQueue);
        return new GenevaStartReply { Id = inst.Id, Pid = inst.Pid };
    }

    private GenevaInstance Launch(string mode, string geneva, List<string> argv, Dictionary<string, string> env, bool supervise,
        int controlPort = 0, string token = "", string ports = "", int queue = 0)
    {
        var id = "g" + Interlocked.Increment(ref _seq).ToString(CultureInfo.InvariantCulture);
        var inst = GenevaInstance.Start(id, mode, geneva, argv, env, supervise, _job, controlPort, token, ports, queue);
        _running[id] = inst;
        _state.Update(s =>
        {
            s.Engines.Add(new AgentState.EngineRecord(inst.Pid, geneva, inst.StartTimeUtc));
            if (!s.GenevaQueues.Contains(queue))
                s.GenevaQueues.Add(queue);
        });
        int pid = inst.Pid;
        _ = inst.Exited.ContinueWith(_ => _state.Update(s => s.Engines.RemoveAll(e => e.Pid == pid)), TaskScheduler.Default);
        return inst;
    }

    private static void CreateOwnDir(string dir)
    {
        if (new DirectoryInfo(dir).LinkTarget is not null)
            throw new GenevaStartException($"{dir}: символическая ссылка вместо каталога / a symlink");
        if (OperatingSystem.IsWindows())
            Directory.CreateDirectory(dir);
        else
            Directory.CreateDirectory(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private static int FreeLoopbackPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    /// <summary>The answer to an eval_request: <c>{"id":N,"fitness":F,"detail":"..."}</c> on geneva's stdin.</summary>
    public async Task AnswerAsync(string id, long requestId, int fitness, string detail, CancellationToken ct)
    {
        var inst = Find(id) ?? throw new GenevaStartException("нет такого подбора / no such search");
        if (inst.Mode != "evolve" || inst.HasExited)
            throw new GenevaStartException("подбор не идёт / the search is not running");
        var line = new JsonObject
        {
            ["id"] = requestId,
            ["fitness"] = Math.Clamp(fitness, -1000, 1000),
            ["detail"] = detail.Length > 200 ? detail[..200] : detail,
        }.ToJsonString();
        await inst.WriteLineAsync(line, ct);
    }

    /// <summary>The commands the UI may send to a run (the control socket also has stop and log_level: those are the Agent's).</summary>
    public static readonly IReadOnlySet<string> ControlCommands = new HashSet<string>(StringComparer.Ordinal) { "status", "stats", "pause", "resume", "reset_stats", "set_strategy" };

    /// <summary>What may be asked of a group of the "Авто" mode: its counters only.</summary>
    public static readonly IReadOnlySet<string> AutoControlCommands = new HashSet<string>(StringComparer.Ordinal) { "status", "stats" };

    public async Task<(bool Ok, string Json)> ControlAsync(string id, string cmd, string? strategy, CancellationToken ct)
    {
        var inst = Find(id) ?? throw new GenevaStartException("нет такого экземпляра / no such instance");
        if (inst.Mode is not ("run" or "auto") || inst.HasExited)
            throw new GenevaStartException("geneva не работает / geneva is not running");
        if (!ControlCommands.Contains(cmd))
            throw new GenevaStartException($"команда {cmd} не разрешена / command not allowed");
        // the "Авто" mode's groups are named by their strategy and managed by AutoApply: a strategy changed or a group
        // paused from outside would leave the mode applying something else than it shows
        if (inst.Mode == "auto" && !AutoControlCommands.Contains(cmd))
            throw new GenevaStartException($"режимом «Авто» управляет он сам: команда {cmd} недоступна / the \"Auto\" mode manages its groups itself");
        var req = new JsonObject { ["id"] = 2, ["cmd"] = cmd };
        if (cmd == "set_strategy")
        {
            if (GenevaStrategyText.Problem(strategy) is { } bad)
                throw new GenevaStartException(bad);
            // a new strategy passes geneva check like one at the start (AGENTS.md rule 4)
            var check = (await new GenevaBundle(Path.GetDirectoryName(Prepare())!).CheckAsync([strategy!], ct, (await FeaturesAsync(Prepare(), ct)).Contains("ext_xact"))) is { Count: > 0 } checks ? checks[0] : null;
            if (check is not { Ok: true, Strategy: { } canonical })
                throw new GenevaStartException("стратегия не разбирается / the strategy does not parse: " + (check?.Error ?? "?"));
            req["strategy"] = canonical;
        }
        var answer = await SendControlAsync(inst, req, ct);
        return ((bool?)answer["ok"] ?? false, answer.ToJsonString());
    }

    private static async Task<JsonObject> SendControlAsync(GenevaInstance inst, JsonObject req, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(5));
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, inst.ControlPort, cts.Token);
        using var stream = client.GetStream();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var writer = new StreamWriter(stream, new UTF8Encoding(false)) { NewLine = "\n", AutoFlush = true };
        await writer.WriteLineAsync(new JsonObject { ["id"] = 1, ["cmd"] = "auth", ["token"] = inst.ControlToken }.ToJsonString().AsMemory(), cts.Token);
        await writer.WriteLineAsync(req.ToJsonString().AsMemory(), cts.Token);
        var want = (int?)req["id"];
        while (await reader.ReadLineAsync(cts.Token) is { } line)
        {
            JsonObject? o;
            try
            {
                o = JsonNode.Parse(line) as JsonObject;
            }
            catch (JsonException)
            {
                continue;
            }
            if (o is null || o["ok"] is null)
                continue;
            if ((int?)o["id"] == 1 && !((bool?)o["ok"] ?? false))
                throw new GenevaStartException("geneva отклонила токен / geneva refused the token");
            if ((int?)o["id"] == want)
                return o;
        }
        throw new GenevaStartException("geneva закрыла управляющее соединение / geneva closed the control connection");
    }

    public async Task<(bool WasRunning, int ExitCode)> StopAsync(string id)
    {
        if (!_running.TryRemove(id, out var inst))
            return (false, 0);
        bool was = !inst.HasExited;
        if (was && inst.Mode is "run" or "auto")
        {
            try
            {
                // a clean exit removes the rules; on Linux the supervisor's SIGTERM would do the same
                await SendControlAsync(inst, new JsonObject { ["id"] = 2, ["cmd"] = "stop" }, CancellationToken.None);
            }
            catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or GenevaStartException)
            {
            }
        }
        // a search saves its checkpoint after the current step: give it time
        int code = await inst.StopAsync(TimeSpan.FromSeconds(inst.Mode == "evolve" ? 15 : 5));
        if (OperatingSystem.IsLinux() && _prepared is { } geneva)
            await FirewallDownAsync(geneva, inst.Queue);
        _state.Update(s => s.Engines.RemoveAll(e => e.Pid == inst.Pid));
        inst.Dispose();
        return (was, code);
    }

    public async Task StopAllAsync()
    {
        // an AutoApply under way finishes first: else it could start a group after everything stopped
        bool gate = await _autoGate.WaitAsync(TimeSpan.FromSeconds(30));
        try
        {
            await Task.WhenAll(_running.Keys.ToList().Select(StopAsync));
            _auto.Clear();
            _autoFilters.Clear();
            _host = null;
            _hostSignature = "";
            _hostFilter = "";
            _firewall?.Replace(AutoOwner, new Dictionary<string, NftQueueRule>());
        }
        finally
        {
            if (gate)
                _autoGate.Release();
        }
    }

    // ---- the "Авто" mode (skill geneva, §9)

    /// <summary>The queues of the "Авто" mode's groups: apart from zapret2's (300–321) and geneva's own (310, 311, 330, 331).</summary>
    public const int AutoQueueBase = 340;

    /// <summary>The owner prefix of the "Авто" mode's rules in the engine firewall.</summary>
    public const string AutoOwner = "geneva-auto/";

    /// <summary>geneva's own packets (raw sends) carry this mark and must not come back to its queue.</summary>
    public const uint GenevaMark = 0x20000000;

    private IReadOnlySet<string>? _features;

    /// <summary>The <c>features</c> of <c>geneva version --json</c> (Windows: "filter" and "set_filter" turn the mode on).</summary>
    private async Task<IReadOnlySet<string>> FeaturesAsync(string geneva, CancellationToken ct)
    {
        if (_features is not null)
            return _features;
        var set = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            var v = await Cmd.RunAsync(geneva, ["version", "--json"], ct: cts.Token);
            if (JsonNode.Parse(v.Stdout.Trim()) is JsonObject o && o["features"] is JsonArray a)
            {
                foreach (var f in a)
                {
                    if (f is JsonValue fv && fv.TryGetValue<string>(out var name))
                        set.Add(name);
                }
                // only an answer is kept: a timeout or a broken start is asked again next time
                _features = set;
            }
        }
        catch (Exception e) when (e is JsonException or OperationCanceledException or InvalidOperationException or IOException)
        {
        }
        return set;
    }

    /// <summary>
    /// Makes the running groups match <paramref name="r"/>: a strategy that stays keeps its process (its targets are
    /// replaced), a new one starts on a free queue, a dropped one stops. Linux: the targets become rules in the engine
    /// firewall (addresses, ports, the first packets of each connection, geneva's own packets skipped) and geneva runs
    /// with <c>--firewall none</c>. Windows: geneva_c with <c>--filter</c> (features "filter", "set_filter") gets the
    /// targets as its WinDivert filter; an older geneva cannot aim at addresses, and nothing is applied.
    /// </summary>
    public async Task<GenevaAutoApplyReply> AutoApplyAsync(GenevaAutoApplyRequest r, CancellationToken ct)
    {
        await _autoGate.WaitAsync(ct);
        try
        {
            return await AutoApplyLockedAsync(r, ct);
        }
        finally
        {
            _autoGate.Release();
        }
    }

    private async Task<GenevaAutoApplyReply> AutoApplyLockedAsync(GenevaAutoApplyRequest r, CancellationToken ct)
    {
        var reply = new GenevaAutoApplyReply();
        if (r.Groups.Count > 0 && _running.Values.Any(i => i.Mode == "run" && !i.HasExited))
            throw new GenevaStartException("включён обход geneva с одной стратегией: сначала выключите его / the single-strategy geneva bypass is on");
        if (r.Groups.Count > AutoRules.MaxGroups)
            throw new GenevaStartException($"больше {AutoRules.MaxGroups} групп / more than {AutoRules.MaxGroups} groups");
        var geneva = r.Groups.Count > 0 ? Prepare() : _prepared;
        bool windows = OperatingSystem.IsWindows();
        if (r.Groups.Count > 0 && windows)
        {
            var f = await FeaturesAsync(geneva!, ct);
            if (!f.Contains("filter") || !f.Contains("set_filter"))
            {
                await StopAutoAsync(_auto.Keys.ToList());
                reply.Limited = true;
                reply.Problems.Add("эта geneva_c на Windows не умеет фильтр по адресам (--filter): обход не применён, нужна geneva_c 1.1 / this geneva_c cannot filter by address on Windows (--filter): nothing applied, geneva_c 1.1 is needed");
                return reply;
            }
        }
        else if ((r.Groups.Count > 0 || r.Hosts.Count > 0) && _firewall is null)
        {
            throw new GenevaStartException("нет firewall для правил очереди / no firewall for the queue rules");
        }

        // the canonical form names a group: the same strategy in two spellings is one process
        var wanted = new Dictionary<string, List<AutoTarget>>(StringComparer.Ordinal);
        var spellings = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        if (r.Groups.Count > 0)
        {
            var checks = await new GenevaBundle(Path.GetDirectoryName(geneva!)!).CheckAsync([.. r.Groups.Select(g => g.Strategy)], ct, (await FeaturesAsync(geneva!, ct)).Contains("ext_xact"));
            for (int i = 0; i < r.Groups.Count; i++)
            {
                var g = r.Groups[i];
                var check = i < checks.Count ? checks[i] : null;
                if (GenevaStrategyText.Problem(g.Strategy) is { } bad)
                {
                    reply.Problems.Add(bad);
                    continue;
                }
                if (check is not { Ok: true, Strategy: { } canonical })
                {
                    reply.Problems.Add("стратегия не разбирается / the strategy does not parse: " + (check?.Error ?? "?"));
                    continue;
                }
                var targets = g.Targets.Select(ToTarget).Where(t => t is not null).Select(t => t!).ToList();
                if (targets.Count == 0)
                    continue;
                if (!wanted.TryGetValue(canonical, out var list))
                {
                    wanted[canonical] = list = [];
                    spellings[canonical] = [];
                }
                list.AddRange(targets);
                if (!spellings[canonical].Contains(g.Strategy))
                    spellings[canonical].Add(g.Strategy);
            }
        }

        var gone = _auto.Where(a => !wanted.ContainsKey(a.Key) || a.Value.HasExited).Select(a => a.Key).ToList();
        await StopAutoAsync(gone);

        var rules = new Dictionary<string, NftQueueRule>(StringComparer.Ordinal);
        foreach (var (strategy, targets) in wanted)
        {
            if (windows && _auto.TryGetValue(strategy, out var running))
            {
                var filter = AutoPlan.WinDivertFilter(targets);
                if (_autoFilters.GetValueOrDefault(running.Queue) != filter && !await SetFilterAsync(running, filter, ct))
                {
                    // a process still on its old filter would miss the new targets (and a trial would be judged
                    // without its strategy): it starts again with the new one
                    await StopAutoAsync([strategy]);
                }
            }
            if (!_auto.TryGetValue(strategy, out var inst))
            {
                int queue = Enumerable.Range(AutoQueueBase, AutoRules.MaxGroups).FirstOrDefault(q => _auto.Values.All(i => i.Queue != q));
                if (queue == 0)
                {
                    reply.Problems.Add("нет свободной очереди / no free queue");
                    continue;
                }
                try
                {
                    inst = await StartAutoAsync(geneva!, strategy, queue, targets, ct);
                }
                catch (Exception e) when (e is GenevaStartException or IOException or InvalidOperationException or global::System.ComponentModel.Win32Exception)
                {
                    reply.Problems.Add($"{strategy}: {e.Message}");
                    continue;
                }
                _auto[strategy] = inst;
            }
            if (!windows)
            {
                for (int i = 0; i < targets.Count; i++)
                    rules[$"{AutoOwner}{inst.Queue.ToString(CultureInfo.InvariantCulture)}/{i.ToString(CultureInfo.InvariantCulture)}"] = Rule(targets[i], inst.Queue);
            }
            var state = new GenevaAutoGroupState { Strategy = strategy, Id = inst.Id, Queue = inst.Queue, Pid = inst.Pid };
            state.Requested.AddRange(spellings[strategy]);
            reply.Groups.Add(state);
        }
        // asked even for an empty request: the mode learns from it whether x-actions and by-name are there before
        // anything is applied (an empty book would otherwise search without them)
        IReadOnlySet<string> feats;
        try
        {
            feats = await FeaturesAsync(geneva ?? Prepare(), ct);
        }
        catch (Exception e) when (e is GenevaStartException or IOException or UnauthorizedAccessException)
        {
            feats = new HashSet<string>();
        }
        reply.Ext = feats.Contains("ext_xact");
        reply.ByName = HostFeatures.All(feats.Contains) && (!windows || feats.Contains("filter"));
        if (r.Hosts.Count > 0 && reply.ByName)
        {
            // the groups' addresses stay theirs: the name-based process leaves them alone (Windows hands a packet on to
            // the next handle, and two strategies on one packet would judge neither)
            var groupAddresses = wanted.Values.SelectMany(t => t).SelectMany(t => t.Addresses).Select(a => a.ToString()).Distinct(StringComparer.Ordinal);
            try
            {
                await ApplyHostAsync((geneva ?? Prepare())!, r, [.. groupAddresses], reply, ct);
            }
            catch (Exception e) when (e is GenevaStartException or IOException or InvalidOperationException or UnauthorizedAccessException or global::System.ComponentModel.Win32Exception)
            {
                reply.Problems.Add("по имени / by name: " + e.Message);
                await StopHostAsync();
            }
            if (_host is not null && !windows)
                rules[$"{AutoOwner}~host"] = HostRule(r.Hosts.Any(h => h.Udp));
        }
        else
        {
            await StopHostAsync();
        }
        if (_firewall is not null && !windows && _firewall.Replace(AutoOwner, rules) is { } err)
        {
            // without the rules nothing reaches geneva: better stopped than shown as working
            await StopAutoAsync(_auto.Keys.ToList());
            await StopHostAsync();
            reply.Groups.Clear();
            reply.Host = null;
            reply.Problems.Add("firewall: " + err);
        }
        return reply;
    }

    /// <summary>geneva's <c>set_filter</c> on a running group (Windows); false when it refused or did not answer.</summary>
    private async Task<bool> SetFilterAsync(GenevaInstance inst, string filter, CancellationToken ct)
    {
        try
        {
            var answer = await SendControlAsync(inst, new JsonObject { ["id"] = 2, ["cmd"] = "set_filter", ["filter"] = filter }, ct);
            if ((bool?)answer["ok"] ?? false)
            {
                _autoFilters[inst.Queue] = filter;
                return true;
            }
            Console.Error.WriteLine($"geneva set_filter: {(string?)answer["error"]}");
        }
        catch (Exception e) when (e is IOException or SocketException or GenevaStartException || (e is OperationCanceledException && !ct.IsCancellationRequested))
        {
            Console.Error.WriteLine($"geneva set_filter: {e.Message}");
        }
        return false;
    }

    private static AutoTarget? ToTarget(GenevaAutoTarget t)
    {
        var addresses = t.Addresses.Select(a => IPAddress.TryParse(a, out var ip) ? ip : null).Where(a => a is not null).Select(a => a!).ToList();
        string Ports(string p)
        {
            if (string.IsNullOrWhiteSpace(p))
                return "";
            try
            {
                return GenevaArgv.NormalizePorts(p);
            }
            catch (FormatException)
            {
                return "";
            }
        }
        var tcp = Ports(t.TcpPorts);
        var udp = Ports(t.UdpPorts);
        if (tcp.Length == 0 && udp.Length == 0)
            return null;
        // aimed at nothing would mean everything: a target is addresses, or a program's local ports
        if (!t.ByLocalPort && addresses.Count == 0)
            return null;
        return new AutoTarget { Addresses = t.ByLocalPort ? [] : addresses, TcpPorts = tcp, UdpPorts = udp, ByLocalPort = t.ByLocalPort };
    }

    private static NftQueueRule Rule(AutoTarget t, int queue) => new()
    {
        QueueNum = queue,
        Targets = t.Addresses,
        TcpPorts = t.TcpPorts,
        UdpPorts = t.UdpPorts,
        BySourcePort = t.ByLocalPort,
        Incoming = true,
        SkipMark = GenevaMark,
        TcpOutPackets = AutoRules.OutPackets,
        UdpOutPackets = AutoRules.OutPackets,
        TcpInPackets = AutoRules.InPackets,
        UdpInPackets = AutoRules.InPackets,
    };

    private async Task<GenevaInstance> StartAutoAsync(string geneva, string strategy, int queue, IReadOnlyList<AutoTarget> targets, CancellationToken ct)
    {
        int port = FreeLoopbackPort();
        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var q = queue.ToString(CultureInfo.InvariantCulture);
        // -p and --proto only name the traffic for geneva's events; what reaches it is decided by the rules (Linux) or
        // the filter (Windows)
        var argv = new List<string> { "run" };
        if (GenevaStrategyText.NeedsExt(strategy))
            argv.Add("--ext");
        argv.AddRange(new[]
        {
            "-s", strategy, "-p", "1-65535", "--proto", "tcp,udp",
            "-c", "tcp:" + port.ToString(CultureInfo.InvariantCulture),
            "-e", "-", "--stats-interval", "5", "--quiet",
        });
        if (OperatingSystem.IsWindows())
        {
            var file = Path.Combine(StateDir, $"auto-{q}.filter");
            var filter = AutoPlan.WinDivertFilter(targets);
            await File.WriteAllTextAsync(file, filter, ct);
            argv.AddRange(["--filter-file", file]);
            if ((await FeaturesAsync(geneva, ct)).Contains("first"))
                argv.AddRange(["--first", AutoRules.OutPackets.ToString(CultureInfo.InvariantCulture)]);
            _autoFilters[queue] = filter;
        }
        else
        {
            argv.AddRange(["-q", q, "--firewall", "none"]);
        }
        return Launch("auto", geneva, argv, new Dictionary<string, string> { ["GENEVA_CONTROL_TOKEN"] = token }, supervise: true, port, token, "1-65535", queue);
    }

    /// <summary>What applying by name needs from geneva_c (2.0): profiles, host lists, the name from the ClientHello.</summary>
    public static readonly IReadOnlyList<string> HostFeatures = ["ext", "ext_profile", "ext_lists", "ext_l7"];

    /// <summary>
    /// The name-based process (geneva_c 2.0, <c>run --ext</c>): one profile per strategy, each with a host list file.
    /// New names in a list need no restart (geneva reads a changed list within a second, and <c>reload_lists</c> is
    /// sent too); a new set of strategies starts the process again. Its traffic is the first packets of every TLS,
    /// HTTP (and QUIC) connection except the groups' addresses and the user's exclusions; a connection to a name in no
    /// list goes through untouched.
    /// </summary>
    private async Task ApplyHostAsync(string geneva, GenevaAutoApplyRequest r, IReadOnlyList<string> groupAddresses, GenevaAutoApplyReply reply, CancellationToken ct)
    {
        bool windows = OperatingSystem.IsWindows();
        var feats = await FeaturesAsync(geneva, ct);
        var hosts = r.Hosts.Where(h => h.Domains.Count > 0 && GenevaStrategyText.Problem(h.Strategy) is null).Take(AutoRules.MaxHostProfiles).ToList();
        if (!feats.Contains("ext_crypto"))
            hosts.RemoveAll(h => h.Udp);   // QUIC's name needs its Initial decrypted
        var checks = await new GenevaBundle(Path.GetDirectoryName(geneva)!).CheckAsync([.. hosts.Select(h => h.Strategy)], ct, feats.Contains("ext_xact"));
        var good = new List<(string Strategy, bool Udp, List<string> Domains)>();
        for (int i = 0; i < hosts.Count; i++)
        {
            if (i < checks.Count && checks[i] is { Ok: true, Strategy: { } canonical })
            {
                var domains = hosts[i].Domains.Select(d => d.Trim().TrimEnd('.').ToLowerInvariant())
                    .Where(d => AutoNameList.Problem(d) is null && d.Contains('.', StringComparison.Ordinal) && !d.Contains('/', StringComparison.Ordinal))
                    .Distinct(StringComparer.Ordinal).ToList();
                if (domains.Count > 0)
                    good.Add((canonical, hosts[i].Udp, domains));
            }
            else
            {
                reply.Problems.Add("по имени, стратегия не разбирается / by name, the strategy does not parse: " + (i < checks.Count ? checks[i].Error : "?"));
            }
        }
        if (good.Count == 0)
        {
            await StopHostAsync();
            return;
        }
        var dir = Path.Combine(StateDir, "auto-host");
        CreateOwnDir(dir);
        // an empty host list would take every name (geneva, as zapret2): every list has at least one name, and each is
        // written beside and moved over, so geneva never reads half a file
        var exclude = groupAddresses.Concat(new AutoNameList(r.ExcludeSubnets).Subnets).Distinct(StringComparer.Ordinal).ToList();
        await WriteAtomicAsync(Path.Combine(dir, "exclude-ip.txt"), "# geneva-auto: the groups' addresses and the user's exclusions\n" + string.Join("\n", exclude) + "\n", ct);
        var excludeHosts = r.ExcludeDomains.Select(d => d.Trim().TrimEnd('.').ToLowerInvariant()).Where(d => d.Length > 0 && AutoNameList.Problem(d) is null).Distinct(StringComparer.Ordinal);
        await WriteAtomicAsync(Path.Combine(dir, "exclude-hosts.txt"), "# geneva-auto: never touched\n" + string.Join("\n", excludeHosts) + "\n", ct);
        var ini = new StringBuilder("# geneva-auto: strategies by the site's name, written by ZapretAutoTuner's Agent\n");
        for (int i = 0; i < good.Count; i++)
        {
            var (strategy, udp, domains) = good[i];
            var n = i.ToString(CultureInfo.InvariantCulture);
            await WriteAtomicAsync(Path.Combine(dir, $"hosts-{n}.txt"), string.Join("\n", domains) + "\n", ct);
            await WriteAtomicAsync(Path.Combine(dir, $"strategy-{n}.txt"), strategy + "\n", ct);
            ini.Append($"[profile p{n}]\n");
            ini.Append(udp ? $"filter-udp = {AutoRules.HostUdpPorts}\nfilter-l7 = quic\n" : $"filter-tcp = {AutoRules.HostTcpPorts}\nfilter-l7 = tls,http\n");
            ini.Append($"hostlist = {Path.Combine(dir, $"hosts-{n}.txt")}\n");
            ini.Append($"hostlist-exclude = {Path.Combine(dir, "exclude-hosts.txt")}\n");
            ini.Append($"ipset-exclude = {Path.Combine(dir, "exclude-ip.txt")}\n");
            ini.Append($"strategy-file = {Path.Combine(dir, $"strategy-{n}.txt")}\n");
        }
        var signature = string.Join("\n", good.Select(g => (g.Udp ? "udp " : "tcp ") + g.Strategy));
        bool udpAny = good.Any(g => g.Udp);
        var filter = HostFilter(udpAny);
        if (_host is { HasExited: false } running && signature == _hostSignature && (!windows || filter == _hostFilter))
        {
            // the lists changed at most: geneva rereads them; the command makes it at once
            try
            {
                await SendControlAsync(running, new JsonObject { ["id"] = 3, ["cmd"] = "reload_lists" }, ct);
            }
            catch (Exception e) when (e is IOException or SocketException or GenevaStartException || (e is OperationCanceledException && !ct.IsCancellationRequested))
            {
                Console.Error.WriteLine($"geneva reload_lists: {e.Message}");
            }
        }
        else
        {
            await StopHostAsync();
            var profiles = Path.Combine(dir, "profiles.ini");
            await WriteAtomicAsync(profiles, ini.ToString(), ct);
            int port = FreeLoopbackPort();
            var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
            var q = AutoRules.HostQueue.ToString(CultureInfo.InvariantCulture);
            var argv = new List<string>
            {
                "run", "--ext", "--ext-profile", profiles, "-p", udpAny ? "80,443" : AutoRules.HostTcpPorts, "--proto", udpAny ? "tcp,udp" : "tcp",
                "-c", "tcp:" + port.ToString(CultureInfo.InvariantCulture),
                "-e", "-", "--stats-interval", "5", "--quiet",
                // a new connection to an address whose name an earlier one showed gets its profile from the first packet
                "--ext-ipcache-hostname",
            };
            if (windows)
            {
                var file = Path.Combine(dir, "host.filter");
                await File.WriteAllTextAsync(file, filter, ct);
                // after the groups' handles: a packet a group handed on comes here, and its address is excluded
                argv.AddRange(["--filter-file", file, "--priority", "-100"]);
                if (feats.Contains("first"))
                    argv.AddRange(["--first", AutoRules.OutPackets.ToString(CultureInfo.InvariantCulture)]);
            }
            else
            {
                argv.AddRange(["-q", q, "--firewall", "none"]);
            }
            _host = Launch("auto", geneva, argv, new Dictionary<string, string> { ["GENEVA_CONTROL_TOKEN"] = token }, supervise: true, port, token,
                udpAny ? "80,443" : AutoRules.HostTcpPorts, AutoRules.HostQueue);
            _hostSignature = signature;
            _hostFilter = filter;
        }
        var state = new GenevaAutoGroupState { Strategy = "", Id = _host!.Id, Queue = _host.Queue, Pid = _host.Pid };
        state.Requested.AddRange(r.Hosts.Select(h => h.Strategy));
        reply.Host = state;
    }

    /// <summary>The WinDivert filter of the name-based process: TLS and HTTP (and QUIC) both ways.</summary>
    public static string HostFilter(bool udp)
    {
        var outs = "(tcp and (tcp.DstPort == 80 or tcp.DstPort == 443))" + (udp ? " or (udp and udp.DstPort == 443)" : "");
        var ins = "(tcp and (tcp.SrcPort == 80 or tcp.SrcPort == 443))" + (udp ? " or (udp and udp.SrcPort == 443)" : "");
        return $"(outbound and ({outs})) or (inbound and ({ins}))";
    }

    /// <summary>The name-based process's rule (Linux): every address, after the groups' rules (its key sorts last).</summary>
    public static NftQueueRule HostRule(bool udp) => new()
    {
        QueueNum = AutoRules.HostQueue,
        TcpPorts = AutoRules.HostTcpPorts,
        UdpPorts = udp ? AutoRules.HostUdpPorts : "",
        Incoming = true,
        SkipMark = GenevaMark,
        TcpOutPackets = AutoRules.OutPackets,
        UdpOutPackets = AutoRules.OutPackets,
        TcpInPackets = AutoRules.InPackets,
        UdpInPackets = AutoRules.InPackets,
    };

    private async Task StopHostAsync()
    {
        if (_host is not { } h)
            return;
        _host = null;
        _hostSignature = "";
        _hostFilter = "";
        await StopAsync(h.Id);
    }

    private static async Task WriteAtomicAsync(string path, string text, CancellationToken ct)
    {
        var tmp = path + ".tmp";
        await File.WriteAllTextAsync(tmp, text, new UTF8Encoding(false), ct);
        File.Move(tmp, path, overwrite: true);
    }

    private async Task StopAutoAsync(IReadOnlyList<string> strategies)
    {
        foreach (var s in strategies)
        {
            if (!_auto.Remove(s, out var inst))
                continue;
            _autoFilters.Remove(inst.Queue);
            await StopAsync(inst.Id);
        }
    }

    /// <summary>geneva's rules of a queue, gone even if geneva was killed (<c>geneva fw down</c>: the rules are named by queue).</summary>
    public static async Task FirewallDownAsync(string geneva, int queue)
    {
        if (queue == 0 || !File.Exists(geneva))
            return;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await Cmd.RunAsync(geneva, ["fw", "down", "-p", "1", "-q", queue.ToString(CultureInfo.InvariantCulture)], ct: cts.Token);
        }
        catch (Exception e) when (e is OperationCanceledException or InvalidOperationException or global::System.ComponentModel.Win32Exception)
        {
        }
    }

    /// <summary>After a crash: the rules of the queues an earlier Agent used.</summary>
    public void RecoverFirewall(IReadOnlyList<int> queues)
    {
        if (!OperatingSystem.IsLinux() || queues.Count == 0)
            return;
        string geneva;
        try
        {
            geneva = Prepare();
        }
        catch (GenevaStartException)
        {
            return;
        }
        foreach (var q in queues)
            FirewallDownAsync(geneva, q).GetAwaiter().GetResult();
    }

    public async Task<GenevaInfoReply> InfoAsync(CancellationToken ct)
    {
        var reply = new GenevaInfoReply();
        reply.Running.AddRange(Running);
        string geneva;
        try
        {
            geneva = Prepare();
        }
        catch (GenevaStartException e)
        {
            reply.Problems.Add(e.Message);
            return reply;
        }
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            var v = await Cmd.RunAsync(geneva, ["version", "--json"], ct: cts.Token);
            reply.VersionJson = v.Stdout.Trim();
            if (File.Exists(DbPath))
            {
                var top = await Cmd.RunAsync(geneva, ["db", "--db", DbPath, "list", "--json"], ct: cts.Token);
                reply.Best.AddRange(ParseDb(top.Stdout).OrderByDescending(e => e.Ok * 1.0 / Math.Max(1, e.Runs)).ThenByDescending(e => e.AvgFitness).Take(100));
            }
        }
        catch (Exception e) when (e is OperationCanceledException or InvalidOperationException or IOException)
        {
            reply.Problems.Add("geneva: " + e.Message);
        }
        var searches = Path.Combine(StateDir, "searches");
        if (Directory.Exists(searches))
        {
            foreach (var d in new DirectoryInfo(searches).GetDirectories())
            {
                var ckpt = new FileInfo(Path.Combine(d.FullName, "search.ckpt"));
                var target = Path.Combine(d.FullName, "target.txt");
                if (ckpt.Exists && File.Exists(target))
                    reply.Searches.Add(new GenevaSavedSearch { Target = File.ReadAllText(target).Trim(), SavedMs = new DateTimeOffset(ckpt.LastWriteTimeUtc).ToUnixTimeMilliseconds() });
            }
        }
        return reply;
    }

    /// <summary>The database's JSON Lines (<c>docs/EVOLVE.md</c>): one record per strategy and target.</summary>
    internal static IEnumerable<GenevaDbEntry> ParseDb(string jsonl)
    {
        foreach (var line in jsonl.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            JsonObject? o;
            try
            {
                o = JsonNode.Parse(line) as JsonObject;
            }
            catch (JsonException)
            {
                continue;
            }
            if (o is null || (string?)o["s"] is not { Length: > 0 } s)
                continue;
            int runs = (int?)o["runs"] ?? 0;
            yield return new GenevaDbEntry
            {
                Strategy = s,
                Target = (string?)o["t"] ?? "",
                Runs = runs,
                Ok = (int?)o["ok"] ?? 0,
                BestFitness = (double?)o["fit_best"] ?? 0,
                AvgFitness = runs > 0 ? ((double?)o["fit_sum"] ?? 0) / runs : 0,
                LastOkMs = (long?)o["last_ok"] ?? 0,
            };
        }
    }

    public void Dispose()
    {
        _autoGate.Dispose();
        foreach (var i in _running.Values)
            i.Dispose();
        if (OperatingSystem.IsWindows())
            _job?.Dispose();
    }
}
