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
        new("geneva_auto_status", McpScope.Read,
            "geneva's \"Авто\" mode: whether it is on, what it does now, every service it watches (sites, QUIC, DNS, WireGuard, OpenVPN, DHT, any endpoint) with its state (watching, suspected, blocked, searching, applied, degraded, not_found, ip_blocked, ...), the strategy applied to it, the running strategies with their counters, and the mode's log.",
            S.Obj([("all", S.Bool("Also the services that work fine (default: only those with a problem or a bypass)"))])),
        new("geneva_auto_enable", McpScope.Control,
            "Turns the \"Авто\" mode on: AutoTuner watches all of this PC's traffic, confirms each block without a bypass first, finds a geneva strategy for each blocked service and applies it to that service's traffic only. It stays on across restarts. Needs the user's yes in the AutoTuner window; the answer is pending until then.",
            S.Empty(), Confirms: true),
        new("geneva_auto_disable", McpScope.Control,
            "Turns the \"Авто\" mode off: every strategy it applied stops and its interception rules go; what it learned stays for the next time.",
            S.Empty()),
        new("geneva_auto_reset", McpScope.Control,
            "Forgets what the \"Авто\" mode knows about one service (its key from geneva_auto_status): its bypass goes and watching starts over.",
            S.Obj([("key", S.Str("The service's key", 300))], "key")),
        new("geneva_auto_check_now", McpScope.Control,
            "Checks one service of the \"Авто\" mode now, pauses included: an applied one with its bypass on (searched again if it fails), any other without a bypass (searched if blocked), one that found nothing is searched again.",
            S.Obj([("key", S.Str("The service's key from geneva_auto_status", 300))], "key")),
        new("geneva_auto_priority", McpScope.Control,
            "Sets how much a service matters to the \"Авто\" mode: important ones are confirmed and searched first and interrupt a search for less important ones; unimportant ones go last (background). auto: the program decides (sites and DNS normal, YouTube, Discord, Telegram, WhatsApp, Instagram, X important, bare peers background).",
            S.Obj([("key", S.Str("The service's key", 300)), ("priority", S.Str("important, auto or unimportant", values: ["important", "auto", "unimportant"]))], "key", "priority")),
        new("geneva_auto_pin", McpScope.Control,
            "Pins (or unpins) the strategy applied to a service: a pinned strategy stays even when the service fails again, and no new search replaces it.",
            S.Obj([("key", S.Str("The service's key", 300)), ("pinned", S.Bool("true pins, false unpins"))], "key", "pinned")),
        new("geneva_auto_lists", McpScope.Control,
            "Reads or replaces the user's lists for geneva: important and unimportant services of the \"Авто\" mode, no_search — services no bypass is looked for (they leave the problems; an applied strategy stays), and excluded — never touched by any geneva bypass (a VPN or proxy server). important, unimportant and no_search take domains (with subdomains), zones (*.ru), patterns (*google*), addresses, subnets and AS numbers (AS12389, its announced prefixes are fetched from RIPEstat, only the number is sent); excluded takes domains, addresses and subnets only. A list left out stays as it is. Also whether site strategies are applied by name (geneva_c 2.0), and whether the search threads are split between several services searched at once.",
            S.Obj([
                ("important", S.Arr("Important services", S.Str("A domain, an address or a subnet", 260), 200)),
                ("unimportant", S.Arr("Unimportant services", S.Str("A domain, an address or a subnet", 260), 200)),
                ("excluded", S.Arr("Never touched by geneva", S.Str("A domain, an address or a subnet", 260), 200)),
                ("no_search", S.Arr("Not searched for", S.Str("A domain, a zone, a pattern, an address, a subnet or an AS", 260), 200)),
                ("known_important", S.Bool("YouTube, Discord, Telegram, WhatsApp, Instagram and X count as important (default true)")),
                ("by_name", S.Bool("Apply site strategies by name too (geneva_c 2.0; default true)")),
                ("split_workers", S.Bool("Split the search threads between up to 4 services searched at once (true), or give them all to one service at a time (false, default)")),
            ])),
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
            ["geneva_auto_status"] = (a, ct) => Task.FromResult(AutoStatus((bool?)a["all"] ?? false)),
            ["geneva_auto_enable"] = (a, ct) => Task.FromResult(AutoEnable()),
            ["geneva_auto_disable"] = async (a, ct) =>
            {
                if (session.Host.GenevaAuto is not { } auto)
                    return NoGeneva();
                if (!auto.Running && !auto.Enabled)
                    return McpErrors.Error("the Auto mode is off / режим «Авто» выключен");
                await auto.DisableAsync(ct).ConfigureAwait(false);
                return new JsonObject { ["ok"] = true, ["status"] = "off" };
            },
            ["geneva_auto_check_now"] = (a, ct) => Task.FromResult(WithService(a, (auto, key) =>
            {
                auto.CheckNow(key);
                return new JsonObject { ["ok"] = true, ["key"] = key, ["hint"] = "geneva_auto_status shows the result after the next slice" };
            })),
            ["geneva_auto_priority"] = (a, ct) => Task.FromResult(WithService(a, (auto, key) =>
            {
                var p = (string?)a["priority"] switch
                {
                    "important" => Core.Geneva.Auto.AutoUserPriority.Important,
                    "unimportant" => Core.Geneva.Auto.AutoUserPriority.Unimportant,
                    _ => Core.Geneva.Auto.AutoUserPriority.None,
                };
                auto.SetPriority(key, p);
                return new JsonObject { ["ok"] = true, ["key"] = key, ["priority"] = (string?)a["priority"] };
            })),
            ["geneva_auto_pin"] = (a, ct) => Task.FromResult(WithService(a, (auto, key) =>
            {
                bool pinned = (bool?)a["pinned"] ?? true;
                return auto.Pin(key, pinned)
                    ? new JsonObject { ["ok"] = true, ["key"] = key, ["pinned"] = pinned }
                    : McpErrors.Error("the service has no applied strategy to pin / у сервиса нет применённой стратегии");
            })),
            ["geneva_auto_lists"] = (a, ct) => ListsAsync(a, ct),
            ["geneva_auto_reset"] = async (a, ct) =>
            {
                if (session.Host.GenevaAuto is not { } auto)
                    return NoGeneva();
                var key = (string)a["key"]!;
                if (auto.View.Services.All(x => x.Key != key))
                    return McpErrors.Error($"no such service: {key} (geneva_auto_status lists them) / нет такого сервиса");
                await auto.ResetServiceAsync(key, ct).ConfigureAwait(false);
                return new JsonObject { ["ok"] = true, ["key"] = key, ["status"] = "watching" };
            },
        };

    private static string Snake(Core.Geneva.Auto.AutoStatus s) => s switch
    {
        Core.Geneva.Auto.AutoStatus.NotBlocked => "not_blocked",
        Core.Geneva.Auto.AutoStatus.IpBlocked => "ip_blocked",
        Core.Geneva.Auto.AutoStatus.NotFound => "not_found",
        _ => s.ToString().ToLowerInvariant(),
    };

    private JsonObject AutoStatus(bool all)
    {
        if (session.Host.GenevaAuto is not { } auto)
            return NoGeneva();
        var v = auto.View;
        var services = new JsonArray();
        foreach (var x in v.Services.Where(x => all || x.Status is not (Core.Geneva.Auto.AutoStatus.Watching or Core.Geneva.Auto.AutoStatus.NotBlocked)).Take(200))
        {
            services.Add((JsonNode)new JsonObject
            {
                ["key"] = x.Key,
                ["name"] = x.Name,
                ["kind"] = x.Kind.ToString().ToLowerInvariant(),
                ["protocol"] = x.App,
                ["status"] = Snake(x.Status),
                ["why"] = x.Why.Length > 0 ? x.Why : null,
                ["strategy"] = x.Strategy,
                ["priority"] = x.Priority.ToString().ToLowerInvariant(),
                ["user_priority"] = x.UserPriority == Core.Geneva.Auto.AutoUserPriority.None ? null : x.UserPriority.ToString().ToLowerInvariant(),
                ["pinned"] = x.Pinned ? true : null,
                ["addresses"] = x.Addresses.Count,
                ["since"] = x.Since == default ? null : new DateTimeOffset(x.Since, TimeSpan.Zero).ToString("o"),
            });
        }
        var groups = new JsonArray();
        foreach (var g in v.Groups)
        {
            groups.Add((JsonNode)new JsonObject
            {
                ["strategy"] = g.Strategy,
                ["services"] = new JsonArray([.. g.Services.Select(n => (JsonNode)n)]),
                ["packets"] = g.Stats is { } st ? st.PktsOut + st.PktsIn : null,
                ["triggered"] = g.Stats?.Triggered,
                ["rate"] = Math.Round(g.Rate, 1),
                ["by_name"] = g.ByName ? true : null,
                ["trial"] = g.Trial ? true : null,
            });
        }
        return new JsonObject
        {
            ["ok"] = true,
            ["enabled"] = v.Enabled,
            ["running"] = v.Running,
            ["phase"] = v.Phase.En,
            ["slices"] = v.Slices,
            ["flows_last_slice"] = v.Flows,
            ["services_total"] = v.Services.Count,
            ["searching"] = v.Current,
            ["trying"] = v.Trying,
            ["searches"] = new JsonArray([.. v.Searches.Select(w => (JsonNode)new JsonObject { ["service"] = w.Name, ["key"] = w.Key, ["trying"] = w.Trying })]),
            ["split_workers"] = session.Host.Geneva?.AutoSplit,
            ["searches_at_once"] = session.Host.Geneva?.AutoSearches,
            ["by_name"] = v.ByName,
            ["x_actions"] = v.Ext,
            ["limited"] = v.Limited ? "Windows with geneva_c older than 1.1: strategies are found but not applied" : null,
            ["problems"] = new JsonArray([.. v.Problems.Select(p => (JsonNode)p)]),
            ["services"] = services,
            ["groups"] = groups,
            ["log"] = new JsonArray([.. auto.Log.TakeLast(30).Select(l => (JsonNode)l)]),
        };
    }

    private JsonObject WithService(JsonObject a, Func<Tuning.Geneva.GenevaAuto, string, JsonObject> act)
    {
        if (session.Host.GenevaAuto is not { } auto)
            return NoGeneva();
        var key = (string?)a["key"] ?? "";
        if (auto.View.Services.All(x => x.Key != key))
            return McpErrors.Error($"no such service: {key} (geneva_auto_status lists them) / нет такого сервиса");
        return act(auto, key);
    }

    private async Task<JsonObject> ListsAsync(JsonObject a, CancellationToken ct)
    {
        if (session.Host.Geneva is not { } g)
            return NoGeneva();
        List<string>? Read(string name)
        {
            if (a[name] is not JsonArray arr)
                return null;
            return [.. arr.Select(x => ((string?)x ?? "").Trim()).Where(x => x.Length > 0)];
        }
        var before = g.Lists;
        var lists = before;
        var changed = false;
        foreach (var (name, apply, masks) in new (string, Func<List<string>, Core.Geneva.Auto.AutoLists>, bool)[]
        {
            ("important", l => lists with { Important = l }, true),
            ("unimportant", l => lists with { Unimportant = l }, true),
            ("excluded", l => lists with { Excluded = l }, false),
            ("no_search", l => lists with { NoSearch = l }, true),
        })
        {
            if (Read(name) is not { } l)
                continue;
            Func<string, string?> check = masks ? Core.Geneva.Auto.AutoNameList.MaskProblem : Core.Geneva.Auto.AutoNameList.Problem;
            if (l.Select(check).FirstOrDefault(p => p is not null) is { } bad)
                return McpErrors.Error($"{name}: {bad}");
            lists = apply(l);
            changed = true;
        }
        if ((bool?)a["known_important"] is { } known)
        {
            lists = lists with { KnownImportant = known };
            changed = true;
        }
        var problems = new List<string>();
        if (changed)
        {
            (lists, problems) = await Tuning.Geneva.AsnPrefixes.RefreshAsync(lists, Tuning.Geneva.AsnPrefixes.DefaultGet, DateTime.UtcNow, ct).ConfigureAwait(false);
            // the fetch takes a while: what the page saved meanwhile is kept
            lists = Tuning.Geneva.AsnPrefixes.Merge(lists, before, g.Lists);
            g.Lists = lists;
        }
        if ((bool?)a["by_name"] is { } byName)
            g.ByName = byName;
        if ((bool?)a["split_workers"] is { } split)
            g.AutoSplit = split;
        return new JsonObject
        {
            ["ok"] = true,
            ["important"] = new JsonArray([.. lists.Important.Select(x => (JsonNode)x)]),
            ["unimportant"] = new JsonArray([.. lists.Unimportant.Select(x => (JsonNode)x)]),
            ["excluded"] = new JsonArray([.. lists.Excluded.Select(x => (JsonNode)x)]),
            ["no_search"] = new JsonArray([.. lists.NoSearch.Select(x => (JsonNode)x)]),
            ["asn_networks"] = lists.AsnPrefixes.Count == 0 ? null : new JsonObject(lists.AsnPrefixes.Select(kv => KeyValuePair.Create("AS" + kv.Key, (JsonNode?)kv.Value.Count))),
            ["problems"] = problems.Count == 0 ? null : new JsonArray([.. problems.Select(x => (JsonNode)x)]),
            ["known_important"] = lists.KnownImportant,
            ["by_name"] = g.ByName,
            ["split_workers"] = g.AutoSplit,
        };
    }

    private JsonObject AutoEnable()
    {
        if (session.Host.GenevaAuto is not { } auto)
            return NoGeneva();
        const string key = "geneva_auto_enable";
        if (session.Confirmations.Report(key) is { } known)
            return known;
        if (auto.Running)
            return new JsonObject { ["ok"] = true, ["status"] = "running" };
        if (session.Host.ProtectionActive)
            return McpErrors.Error("zapret2's protection is on: turn it off in the Monitor first / сначала выключите защиту nfqws2");
        if (session.Host.Geneva is { RunRunning: true })
            return McpErrors.Error("the single-strategy geneva bypass is on: geneva_run_stop first / сначала выключите обход geneva");
        var request = new ConfirmRequest("geneva_auto_enable",
            "Внешний агент хочет включить режим «Авто» geneva", "An external agent wants to turn geneva's Auto mode on",
            "AutoTuner будет следить за всем трафиком этого ПК, проверять блокировки, подбирать стратегии geneva и применять их к заблокированным сервисам. Режим остаётся включённым после перезапуска.",
            "AutoTuner will watch all of this PC's traffic, check blocks, find geneva strategies and apply them to the blocked services. The mode stays on across restarts.");
        return session.Confirmations.Request(key, request, async ct =>
        {
            try
            {
                await auto.EnableAsync(ct).ConfigureAwait(false);
            }
            catch (GenevaRefusedException e)
            {
                return McpErrors.Error(e.Message);
            }
            return new JsonObject { ["ok"] = true, ["status"] = "running", ["hint"] = "geneva_auto_status shows what it finds" };
        });
    }

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
