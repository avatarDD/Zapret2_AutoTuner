using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Tuning.Geneva;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// geneva_c, the second bypass engine (skill <c>geneva</c>), over MCP: the engine choice, Geneva's library and check,
/// the genetic search (judged by the program's full-download probe) and the bypass with its live counters. The search
/// and the bypass run in the Agent like everything privileged; turning the bypass on waits for the user's yes.
/// </summary>
public sealed class GenevaTools(McpSession session)
{
    public const string PortsPattern = "^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?){0,15}$";

    private static JsonObject Strategy() =>
        S.Str("A strategy in Geneva's language (geneva_c docs/STRATEGY.md), e.g. [TCP:flags:PA]-fragment{tcp:8:True}-| \\/. Checked by geneva itself before anything runs.", GenevaStrategyText.MaxLength);

    private static JsonObject Target() => S.Str("A target from targets_list (a host name, never a URL)", 253, McpTools.HostPattern);

    public static IReadOnlyList<McpToolDefinition> Definitions { get; } =
    [
        new("geneva_status", McpScope.Read,
            "The bypass engine in use (nfqws2 or geneva) and geneva's state: whether the bundled geneva is ready, the running or last search (generation, strategies checked, best fitness, baseline), the saved searches that can be continued, the strategies found, and the bypass with its live counters (packets, how often each tree fired).",
            S.Empty()),
        new("geneva_library", McpScope.Read,
            "Geneva's library of published strategies with their success rate against the censors of China, India and Kazakhstan. A starting point, not a promise for another DPI.",
            S.Obj([
                ("country", S.Str("Only this country's censor", values: ["china", "india", "kazakhstan"])),
                ("limit", S.Int("Rows at most (default 20)", 1, 60)),
            ])),
        new("geneva_check", McpScope.Read,
            "Parses Geneva strategies with geneva itself: the canonical form and the number of actions, or why one does not parse. Nothing runs.",
            S.Obj([("strategies", S.Arr("Strategies", Strategy(), 10, 1))], "strategies")),
        new("engine_select", McpScope.Control,
            "Chooses which engine bypasses on this PC: nfqws2 (zapret2: the wizard, the monitor, exports) or geneva. Only the choice: nothing starts or stops.",
            S.Obj([("engine", S.Str("The engine", values: ["nfqws2", "geneva"]))], "engine")),
        new("geneva_search_start", McpScope.Control,
            "Starts geneva's genetic search for a blocked target: the site is first checked without a bypass (a search only makes sense when it is blocked), then every strategy geneva breeds is judged by the program's full download of the page. Progress is saved; resume=true continues the saved search of the target. Long: poll geneva_status.",
            S.Obj([
                ("target", Target()),
                ("port", S.Int("Service port (default 443; 80 means plain HTTP)", 1, 65535)),
                ("population", S.Int("Population size (default 30)", 4, 200)),
                ("generations", S.Int("Generations (default 15)", 1, 100)),
                ("resume", S.Bool("Continue the saved search of this target")),
                ("seeds", S.Arr("Strategies the population starts from (found ones, the library's)", Strategy(), GenevaArgv.MaxSeeds)),
            ], "target")),
        new("geneva_search_stop", McpScope.Control,
            "Stops geneva's search; geneva saves its progress, and geneva_search_start with resume=true continues it.",
            S.Empty()),
        new("geneva_run_start", McpScope.Control,
            "Turns the bypass with geneva on: the strategy applies to every connection of this PC to the ports. Needs the user's yes in the AutoTuner window; the answer is pending until then. zapret2's protection must be off.",
            S.Obj([
                ("strategy", Strategy()),
                ("ports", S.Str("Service ports (default 80,443)", 100, PortsPattern)),
                ("auto_start", S.Bool("Turn it on again when the program starts")),
            ], "strategy"), Confirms: true),
        new("geneva_run_pause", McpScope.Control,
            "Pauses the geneva bypass (packets pass unchanged, the interception stays) or resumes it with resume=true.",
            S.Obj([("resume", S.Bool("Resume a paused bypass"))])),
        new("geneva_run_stop", McpScope.Control,
            "Turns the geneva bypass off and removes its interception rules.",
            S.Empty()),
    ];

    public IEnumerable<KeyValuePair<string, Func<JsonObject, CancellationToken, Task<JsonObject>>>> Handlers() =>
        new Dictionary<string, Func<JsonObject, CancellationToken, Task<JsonObject>>>(StringComparer.Ordinal)
        {
            ["geneva_status"] = (a, ct) => Task.FromResult(Status()),
            ["geneva_library"] = LibraryAsync,
            ["geneva_check"] = CheckAsync,
            ["engine_select"] = (a, ct) => Task.FromResult(Select((string)a["engine"]!)),
            ["geneva_search_start"] = SearchStartAsync,
            ["geneva_search_stop"] = (a, ct) => WithGeneva(async g =>
            {
                if (!g.SearchRunning)
                    return McpErrors.Error("no geneva search is running / подбор geneva не идёт");
                await g.StopSearchAsync(ct).ConfigureAwait(false);
                return new JsonObject { ["ok"] = true, ["status"] = "stopped", ["hint"] = "geneva_search_start with resume=true continues it" };
            }),
            ["geneva_run_start"] = (a, ct) => Task.FromResult(RunStart(a)),
            ["geneva_run_pause"] = (a, ct) => WithGeneva(async g =>
            {
                bool resume = (bool?)a["resume"] ?? false;
                await g.PauseRunAsync(!resume, ct).ConfigureAwait(false);
                return new JsonObject { ["ok"] = true, ["status"] = resume ? "running" : "paused" };
            }),
            ["geneva_run_stop"] = (a, ct) => WithGeneva(async g =>
            {
                if (!g.RunRunning)
                    return McpErrors.Error("the geneva bypass is off / обход geneva выключен");
                await g.StopRunAsync(forget: true, ct).ConfigureAwait(false);
                return new JsonObject { ["ok"] = true, ["status"] = "stopped" };
            }),
        };

    private static JsonObject NoGeneva() => McpErrors.Error("geneva is not available in this program / geneva недоступна");

    private async Task<JsonObject> WithGeneva(Func<GenevaController, Task<JsonObject>> f)
    {
        if (session.Host.Geneva is not { } g)
            return NoGeneva();
        try
        {
            return await f(g).ConfigureAwait(false);
        }
        catch (GenevaRefusedException e)
        {
            return McpErrors.Error(e.Message);
        }
    }

    private JsonObject Status()
    {
        if (session.Host.Geneva is not { } g)
            return NoGeneva();
        var state = g.State;
        var s = g.Search;
        var r = g.Run;
        var o = new JsonObject
        {
            ["ok"] = true,
            ["engine"] = state.Engine == BypassEngine.Geneva ? "geneva" : "nfqws2",
            ["geneva_ready"] = session.Host.GenevaBundle is { Exists: true } b && b.Verify().Ok,
            ["search"] = s.Host.Length == 0 ? null : new JsonObject
            {
                ["running"] = s.Running,
                ["target"] = s.Host,
                ["port"] = s.Port,
                ["generation"] = s.Generation + 1,
                ["generations"] = s.Generations,
                ["population"] = s.Population,
                ["percent"] = Math.Round(s.Percent * 100, 1),
                ["checked"] = s.Evaluated,
                ["loaded"] = s.Succeeded,
                ["blocked_without_bypass"] = s.Blocked,
                ["baseline"] = s.BaselineOutcome,
                ["best_fitness"] = s.BestFitness,
                ["best"] = s.Best,
                ["ended"] = s.Ended?.En,
                ["recent"] = new JsonArray([.. g.Trials.Take(8).Select(t => (JsonNode)new JsonObject
                {
                    ["strategy"] = t.Strategy,
                    ["fitness"] = t.Fitness,
                    ["outcome"] = t.Outcome,
                })]),
            },
            ["saved_searches"] = new JsonArray([.. state.Searches.Take(10).Select(p => (JsonNode)new JsonObject
            {
                ["target"] = p.Host,
                ["port"] = p.Port,
                ["generation"] = p.Generation + 1,
                ["generations"] = p.Generations,
                ["best_fitness"] = p.BestFitness,
                ["finished"] = p.Finished,
                ["can_resume"] = !p.Finished && p.Generation >= 0,
            })]),
            ["found"] = new JsonArray([.. state.Found.Take(20).Select(f => (JsonNode)new JsonObject
            {
                ["target"] = f.Host,
                ["port"] = f.Port,
                ["strategy"] = f.Strategy,
                ["fitness"] = f.Fitness,
                ["runs"] = f.Runs,
            })]),
            ["bypass"] = new JsonObject
            {
                ["running"] = r.Running,
                ["ready"] = r.Ready,
                ["strategy"] = r.Strategy.Length > 0 ? r.Strategy : state.Active?.Strategy,
                ["ports"] = r.Ports.Length > 0 ? r.Ports : state.Active?.Ports,
                ["auto_start"] = state.Active?.AutoStart ?? false,
                ["ended"] = r.Running ? null : r.Ended?.En,
                ["stats"] = r.Stats is not { } st ? null : new JsonObject
                {
                    ["uptime_sec"] = st.UptimeMs / 1000,
                    ["paused"] = st.Paused,
                    ["packets_out"] = st.PktsOut,
                    ["packets_in"] = st.PktsIn,
                    ["triggered"] = st.Triggered,
                    ["modified"] = st.Modified,
                    ["injected"] = st.Injected,
                    ["dropped"] = st.Dropped,
                    ["errors"] = st.Errors + st.Overruns,
                    ["idle"] = st.Idle,
                    ["trees"] = new JsonArray([.. st.Trees.Select(t => (JsonNode)new JsonObject { ["tree"] = t.Tree, ["fired"] = t.Fired })]),
                },
            },
        };
        return o;
    }

    private async Task<JsonObject> LibraryAsync(JsonObject a, CancellationToken ct)
    {
        if (session.Host.GenevaBundle is not { Exists: true } b)
            return NoGeneva();
        var country = (string?)a["country"];
        int limit = (int?)a["limit"] ?? 20;
        var all = await b.LibraryAsync(ct).ConfigureAwait(false);
        var rows = all.Where(e => !e.ServerSide && (country is null || e.Country == country)).OrderByDescending(e => e.Rate).Take(limit);
        return new JsonObject
        {
            ["ok"] = true,
            ["strategies"] = new JsonArray([.. rows.Select(e => (JsonNode)new JsonObject
            {
                ["strategy"] = e.Strategy,
                ["rate_percent"] = e.Rate,
                ["country"] = e.Country,
                ["test"] = e.Test,
                ["description"] = e.Description,
            })]),
        };
    }

    private async Task<JsonObject> CheckAsync(JsonObject a, CancellationToken ct)
    {
        if (session.Host.GenevaBundle is not { Exists: true } b)
            return NoGeneva();
        var list = ((JsonArray)a["strategies"]!).Select(n => (string?)n ?? "").ToList();
        var bad = list.Select(GenevaStrategyText.Problem).ToList();
        var toCheck = list.Where((s, i) => bad[i] is null).ToList();
        var checks = await b.CheckAsync(toCheck, ct).ConfigureAwait(false);
        var result = new JsonArray();
        int k = 0;
        for (int i = 0; i < list.Count; i++)
        {
            if (bad[i] is { } why)
            {
                result.Add((JsonNode)new JsonObject { ["ok"] = false, ["error"] = why });
                continue;
            }
            var c = k < checks.Count ? checks[k++] : new Tools.GenevaCheck(false, null, 0, "no answer from geneva");
            result.Add((JsonNode)new JsonObject { ["ok"] = c.Ok, ["canonical"] = c.Strategy, ["actions"] = c.Ok ? c.Actions : null, ["error"] = c.Error });
        }
        return new JsonObject { ["ok"] = true, ["results"] = result };
    }

    private JsonObject Select(string engine)
    {
        if (session.Host.Geneva is not { } g)
            return NoGeneva();
        var e = engine == "geneva" ? BypassEngine.Geneva : BypassEngine.Nfqws2;
        if (e == BypassEngine.Nfqws2 && g.RunRunning)
            return McpErrors.Error("the geneva bypass is on: geneva_run_stop first / сначала выключите обход geneva");
        g.Engine = e;
        return new JsonObject { ["ok"] = true, ["engine"] = engine };
    }

    private Task<JsonObject> SearchStartAsync(JsonObject a, CancellationToken ct) => WithGeneva(async g =>
    {
        var target = (string)a["target"]!;
        if (!session.IsTarget(target))
            return McpErrors.NotATarget(target);
        if (session.Host.ProtectionActive)
            return McpErrors.Error("zapret2's protection is on: geneva would fight it for the traffic / работает защита nfqws2");
        int port = (int?)a["port"] ?? 443;
        var settings = new GenevaSearchSettings
        {
            Host = target.ToLowerInvariant(),
            Port = port,
            Tls = port != 80,
            Population = (int?)a["population"] ?? 30,
            Generations = (int?)a["generations"] ?? 15,
            Resume = (bool?)a["resume"] ?? false,
            Seeds = [.. ((a["seeds"] as JsonArray) ?? []).Select(n => (string?)n ?? "")],
        };
        await g.StartSearchAsync(settings, ct).ConfigureAwait(false);
        return new JsonObject
        {
            ["ok"] = true,
            ["status"] = "started",
            ["target"] = settings.Host,
            ["resume"] = settings.Resume,
            ["hint"] = "poll geneva_status; a strategy is kept in found when the page loaded fully with it",
        };
    });

    private JsonObject RunStart(JsonObject a)
    {
        if (session.Host.Geneva is not { } g)
            return NoGeneva();
        var strategy = ((string)a["strategy"]!).Trim();
        var ports = (string?)a["ports"] ?? "80,443";
        bool auto = (bool?)a["auto_start"] ?? false;
        var key = "geneva_run_start:" + a.ToJsonString();
        if (session.Confirmations.Report(key) is { } known)
            return known;
        var problems = new GenevaRunSettings { Strategy = strategy, Ports = ports }.Problems();
        if (problems.Count > 0)
            return McpErrors.Error(string.Join("; ", problems));
        if (session.Host.ProtectionActive)
            return McpErrors.Error("zapret2's protection is on: turn it off in the Monitor first / сначала выключите защиту nfqws2");
        if (g.RunRunning)
            return McpErrors.Error("the geneva bypass is already on: geneva_run_stop first / обход geneva уже включён");
        var request = new ConfirmRequest("geneva_run_start",
            "Внешний агент хочет включить обход geneva", "An external agent wants to turn the geneva bypass on",
            $"geneva будет применять стратегию ко всем соединениям этого ПК на порты {ports}" + (auto ? " и включаться при запуске программы" : "") + $":\n{strategy}",
            $"geneva will apply the strategy to every connection of this PC to ports {ports}" + (auto ? " and turn on when the program starts" : "") + $":\n{strategy}");
        return session.Confirmations.Request(key, request, async ct =>
        {
            try
            {
                await g.StartRunAsync(strategy, ports, auto, ct).ConfigureAwait(false);
            }
            catch (GenevaRefusedException e)
            {
                return McpErrors.Error(e.Message);
            }
            return new JsonObject { ["ok"] = true, ["status"] = "running", ["strategy"] = g.Run.Strategy, ["ports"] = ports, ["hint"] = "geneva_status shows the live counters" };
        });
    }
}
