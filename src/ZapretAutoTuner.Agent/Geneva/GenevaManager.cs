using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Agent.Engine;
using ZapretAutoTuner.Agent.Os;
using ZapretAutoTuner.Core.Geneva;
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
    private readonly Lock _prepareLock = new();
    private readonly string _original;
    private string? _prepared;
    private int _seq;

    public GenevaManager(AgentOptions options, AgentStateStore state, LuaStore store)
    {
        _options = options;
        _state = state;
        _store = store;
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
        var settings = new GenevaRunSettings { Strategy = r.Strategy, Ports = string.IsNullOrWhiteSpace(r.Ports) ? "80,443" : r.Ports };
        if (settings.Problems() is { Count: > 0 } bad)
            throw new GenevaStartException(string.Join("; ", bad));
        var check = (await new GenevaBundle(Path.GetDirectoryName(geneva)!).CheckAsync([settings.Strategy], ct)) is { Count: > 0 } checks ? checks[0] : null;
        if (check is not { Ok: true, Strategy: { } canonical })
            throw new GenevaStartException("стратегия не разбирается / the strategy does not parse: " + (check?.Error ?? "?"));
        settings = settings with { Strategy = canonical };
        int port = FreeLoopbackPort();
        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var argv = GenevaArgv.Run(settings, port);
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
        };
        if (settings.Problems() is { Count: > 0 } bad)
            throw new GenevaStartException(string.Join("; ", bad));
        var dir = SearchDir(settings.TargetKey);
        CreateOwnDir(Path.GetDirectoryName(dir)!);
        CreateOwnDir(dir);
        var checkpoint = Path.Combine(dir, "search.ckpt");
        if (settings.Resume && !File.Exists(checkpoint))
            settings = settings with { Resume = false };
        await File.WriteAllTextAsync(Path.Combine(dir, "target.txt"), settings.TargetKey, ct);
        string? seedsFile = null;
        if (settings.Seeds.Count > 0 && !settings.Resume)
        {
            var good = (await new GenevaBundle(Path.GetDirectoryName(geneva)!).CheckAsync(settings.Seeds, ct)).Where(c => c.Ok).Select(c => c.Strategy!).ToList();
            if (good.Count > 0)
            {
                seedsFile = Path.Combine(dir, "seeds.txt");
                await File.WriteAllLinesAsync(seedsFile, good, ct);
            }
        }
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

    public async Task<(bool Ok, string Json)> ControlAsync(string id, string cmd, string? strategy, CancellationToken ct)
    {
        var inst = Find(id) ?? throw new GenevaStartException("нет такого экземпляра / no such instance");
        if (inst.Mode != "run" || inst.HasExited)
            throw new GenevaStartException("geneva не работает / geneva is not running");
        if (!ControlCommands.Contains(cmd))
            throw new GenevaStartException($"команда {cmd} не разрешена / command not allowed");
        var req = new JsonObject { ["id"] = 2, ["cmd"] = cmd };
        if (cmd == "set_strategy")
        {
            if (GenevaStrategyText.Problem(strategy) is { } bad)
                throw new GenevaStartException(bad);
            // a new strategy passes geneva check like one at the start (AGENTS.md rule 4)
            var check = (await new GenevaBundle(Path.GetDirectoryName(Prepare())!).CheckAsync([strategy!], ct)) is { Count: > 0 } checks ? checks[0] : null;
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
        if (was && inst.Mode == "run")
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
        await Task.WhenAll(_running.Keys.ToList().Select(StopAsync));
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
        foreach (var i in _running.Values)
            i.Dispose();
        if (OperatingSystem.IsWindows())
            _job?.Dispose();
    }
}
