using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Mcp;

/// <summary>One tool: its name, permission group and argument schema. <see cref="Confirms"/>: the user says yes in the AutoTuner window.</summary>
public sealed record McpToolDefinition(string Name, McpScope Scope, string Description, JsonObject InputSchema, bool Confirms = false);

/// <summary>
/// Every tool of the server (MCP design, "Инструменты"). Only functions of the program: no shell, no paths, no URLs,
/// no engine options, no Lua code beyond the typed drafts of resource_create (which only the user can approve), no OS. Objects are named by program ids (target host, s-… strategy, tr-… trial). The list
/// and the schemas are pinned by a golden test: a new tool or argument does not appear without editing it.
/// </summary>
public static class McpTools
{
    public const string HostPattern = "^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$";
    public const string StrategyIdPattern = "^s-[0-9a-f]{12}$";
    public const string TrialIdPattern = "^tr-[0-9]{1,6}$";

    private static JsonObject Target(string what = "A target from targets_list (a host name, never a URL)") => S.Str(what, 253, HostPattern);

    private static JsonObject StrategyText() =>
        S.Str("A strategy in nfqws2 syntax: only --payload=, --in-range=, --out-range= and --lua-desync= with catalog functions. Checked by the Validator before anything runs.", 2048);

    private static JsonObject StrategyId() => S.Str("A strategy id (s-…) from another answer of this server", 14, StrategyIdPattern);

    private static JsonObject Profile() => S.Str("Client profile the strategy must survive", values: ClientProfile.BuiltIn.Select(p => p.Id));

    public static IReadOnlyList<McpToolDefinition> All { get; } =
    [
        // read: always
        new("targets_list", McpScope.Read,
            "The targets the user put in AutoTuner, with the last diagnosis. Probes go only to these; a new one is added by the user (target_add asks).",
            S.Empty()),
        new("diagnose", McpScope.Read,
            "The block classifier's verdict for a target with its evidence (DNS, IP, SNI, 16 KB cut-off, QUIC…). refresh=true probes the target again and needs the probes permission.",
            S.Obj([("target", Target()), ("refresh", S.Bool("Run the classifier again (probes the target; needs the probes permission)"))], "target")),
        new("trials_history", McpScope.Read,
            "What was tried: the knowledge base's results per strategy (successes/attempts) and this session's trials.",
            S.Obj([("target", Target("Only this target")), ("limit", S.Int("Rows at most", 1, 50))])),
        new("catalog_functions", McpScope.Read,
            "The --lua-desync functions a strategy may use, with their arguments, ranges and defaults (the bundled zapret2 catalog).",
            S.Obj([
                ("category", S.Str("Only this category", values: ["basic", "http", "handshake", "window", "fake", "split", "faked", "oob", "udp", "orchestrator"])),
                ("name", S.Str("Only this function", 40, "^[a-z0-9_]+$")),
            ])),
        new("strategy_validate", McpScope.Read,
            "Checks a strategy without running it: the Validator's errors and warnings and its id. Nothing is sent anywhere.",
            S.Obj([("strategy", StrategyText()), ("l4", S.Str("Transport", values: ["tcp", "udp"])), ("client", Profile())], "strategy")),
        new("kb_query", McpScope.Read,
            "The local knowledge base: what worked for a target and what worked on a provider (ASN) for anyone's targets here.",
            S.Obj([("target", Target("Results for this target")), ("asn", S.Int("Provider's AS number", 1, int.MaxValue)), ("l4", S.Str("Transport", values: ["tcp", "udp"])), ("limit", S.Int("Rows at most", 1, 50))])),

        // probes
        new("target_add", McpScope.Probes,
            "Asks the user to add a target. The AutoTuner window shows a dialog; the answer is pending until the user decides. Call again with the same arguments to see the decision.",
            S.Obj([("target", Target("The host name to add")), ("reason", S.Str("Why, shown to the user", 300))], "target"), Confirms: true),
        new("trial_run", McpScope.Probes,
            "Runs one strategy against a blocked target: the engine (through the privileged Agent) for the target's addresses, then the probe. Returns a compact observation: L0-L3, bytes, time, successes/attempts against the baseline, what went out and what came back, the classifier's reading. Never page content.",
            S.Obj([
                ("target", Target()),
                ("strategy", StrategyText()),
                ("strategy_id", StrategyId()),
                ("client", Profile()),
                ("level", S.Str("L1 handshake, L2 full download (default), L3 page in a browser", values: ["L1", "L2", "L3"])),
                ("attempts", S.Int("Attempts in the series (default 3)", 1, 5)),
            ], "target")),

        // control
        new("search_start", McpScope.Control,
            "Starts the AutoTuner search for a blocked target (the Runner: families in order, refinement, punishment pauses). Strategies put in the queue with search_enqueue go first. Long: poll search_status.",
            S.Obj([("target", Target()), ("mode", S.Str("Search depth", values: ["quick", "standard", "full"]))], "target")),
        new("search_status", McpScope.Control,
            "Progress of the search: stage, percent, tried, found strategies with ids and efficiency, the best partial one, the queue.",
            S.Empty()),
        new("search_pause", McpScope.Control,
            "Pauses the search between trials (resume=true continues it).",
            S.Obj([("resume", S.Bool("Continue a paused search"))])),
        new("search_stop", McpScope.Control,
            "Stops the search; what was found stays in search_status.",
            S.Empty()),
        new("search_enqueue", McpScope.Control,
            "Puts your candidate strategies in the Runner's queue: before the next trial of a running search, or first in the next search. Each passes the Validator; results are stored with source llm.",
            S.Obj([("strategies", S.Arr("Candidates", StrategyText(), 10, 1)), ("note", S.Str("Why these, kept with them", 200))], "strategies")),
        new("search_prune_family", McpScope.Control,
            "Skips a strategy family for the rest of the search (search_status lists the families).",
            S.Obj([("family", S.Str("Family id", 64, "^[a-z0-9_]+$")), ("reason", S.Str("Why", 200))], "family")),

        // experiments: live traffic on this PC, with zapret-gui's names and semantics
        new("strategy_experiment_start", McpScope.Experiments,
            "Runs strategy variants one by one on this PC's live traffic to the targets and measures each against a baseline; everything is reverted by itself after ttl_sec unless committed. Starting needs the user's yes in the AutoTuner window. Returns run_id; poll strategy_experiment_status.",
            S.Obj([
                ("variants", S.Arr("Variants", S.Obj([("label", S.Str("Variant name", 32, "^[A-Za-z0-9_-]+$")), ("strategy", StrategyText()), ("strategy_id", StrategyId())], "label"), 5, 1)),
                ("targets", S.Arr("Targets from targets_list (default: all, at most 10)", Target(), 10)),
                ("repeats", S.Int("Probes per target and variant (default 3)", 1, 5)),
                ("baseline", S.Bool("Measure the targets without a strategy first (default true)")),
                ("ttl_sec", S.Int("Automatic revert after this many seconds (default 300)", 30, 900)),
                ("keep_best", S.Bool("Keep the best variant applied until the deadline (still not committed)")),
            ], "variants"), Confirms: true),
        new("strategy_experiment_status", McpScope.Experiments,
            "The experiment's state (awaiting_confirmation, running, finished, failed, reverted, committed), phase, variant, seconds left before the revert, awaiting_commit.",
            S.Empty()),
        new("strategy_experiment_result", McpScope.Experiments,
            "The report: per variant and target the probes, success rate, score, delta to the baseline (fixed, broken, unchanged); the best variant.",
            S.Obj([("run_id", S.Str("The run (default: the last)", 40, "^exp-[0-9a-z-]+$"))])),
        new("strategy_experiment_commit", McpScope.Experiments,
            "Keeps a variant: it becomes this PC's active protection. Needs the user's yes in the AutoTuner window; the answer is pending until then.",
            S.Obj([("label", S.Str("The variant (default: best)", 32, "^[A-Za-z0-9_-]+$"))]), Confirms: true),
        new("strategy_experiment_rollback", McpScope.Experiments,
            "Reverts at once: stops the experiment's engine (a kept variant too).",
            S.Empty()),

        // export: dry run only
        new("export_preview", McpScope.Export,
            "Builds an export without applying anything: the files and the main config text. save=true asks the user to save it to AutoTuner's export folder; applying to a router or zapret-gui is always done by the user.",
            S.Obj([
                ("format", S.Str("Export format", values: ["zapret2", "winws2", "keenetic", "zapret_gui", "argv"])),
                ("items", S.Arr("Target and strategy pairs (default: the best known strategy of each target)", S.Obj([("target", Target()), ("strategy_id", StrategyId())], "target", "strategy_id"), 20)),
                ("save", S.Bool("Ask the user to save the package")),
            ], "format"), Confirms: true),

        // router: zapret-gui's experiments on the router, with the address and token the user entered in AutoTuner
        new("router_experiment_start", McpScope.Router,
            "Tries strategy variants on the router through zapret-gui: the router measures the targets without bypass first, then applies each variant (the router's current strategy profiles stay after it) and probes the targets from the router; everything reverts by itself after ttl_sec unless committed. Each strategy passes the Validator for Linux. Starting needs the user's yes in the AutoTuner window. Poll router_experiment_status.",
            S.Obj([
                ("variants", S.Arr("Variants", S.Obj([("label", S.Str("Variant name", 32, "^[A-Za-z0-9_-]+$")), ("strategy", StrategyText()), ("strategy_id", StrategyId()), ("l4", S.Str("Transport", values: ["tcp", "udp"]))], "label"), 5, 1)),
                ("targets", S.Arr("Targets from targets_list (default: all, at most 10)", Target(), 10)),
                ("repeats", S.Int("Probes per target and variant (default 3)", 1, 5)),
                ("ttl_sec", S.Int("Automatic revert on the router after this many seconds (default 300)", 60, 900)),
                ("keep_best", S.Bool("Keep the best variant applied on the router until the deadline (still not committed)")),
            ], "variants"), Confirms: true),
        new("router_experiment_status", McpScope.Router,
            "The router experiment's state (awaiting_confirmation, running, finished, failed, reverted, committed), the router's phase, awaiting_commit, and whether zapret-gui is set up in AutoTuner.",
            S.Empty()),
        new("router_experiment_result", McpScope.Router,
            "The router's report: targets open without bypass, per variant and target the probes from the router, success rate, score, zapret-gui's hints; the best variant. The results are stored with source router.",
            S.Obj([("run_id", S.Str("The run (default: the last)", 64, "^[A-Za-z0-9_.:-]+$"))])),
        new("router_experiment_commit", McpScope.Router,
            "Keeps a variant on the router: it becomes zapret-gui's strategy (save=true also saves it as a user strategy and makes it active). Needs the user's yes in the AutoTuner window; the answer is pending until then.",
            S.Obj([("label", S.Str("The variant (default: best)", 32, "^[A-Za-z0-9_-]+$")), ("save", S.Bool("Also save it as a user strategy on the router and make it active"))]), Confirms: true),
        new("router_experiment_rollback", McpScope.Router,
            "Reverts the router at once to its state before the experiment (a kept variant too). A committed variant stays.",
            S.Empty()),
        // bug report draft (read) and strategy resources (PLAN 4a.5, 4a.6)
        BugReportTool.Definition,
        .. ResourceTools.Definitions,
    ];

    public static McpToolDefinition? Find(string name) => All.FirstOrDefault(t => t.Name == name);
}
