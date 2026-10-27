using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Bench;

/// <summary>The benchmark's tables: Markdown for people, JSON for scripts.</summary>
public static class BenchFormat
{
    public static string Name(BenchArm a) => a switch
    {
        BenchArm.Static => "static",
        BenchArm.Bandit => "bandit",
        BenchArm.Model => "model",
        _ => "bandit+model",
    };

    private static string N(int? v, int budget) => v is { } x ? x.ToString(CultureInfo.InvariantCulture) : $"> {budget}";

    public static string Markdown(BenchReport r)
    {
        var o = r.Options;
        var sb = new StringBuilder();
        sb.AppendLine("# Замер подбора / Search benchmark (PLAN 4a.3, MCP M6)");
        sb.AppendLine();
        var models = r.ModelName is null ? "; model arms off (no provider given)." : $", model seeds {o.ModelSeeds}, model {r.ModelName}.";
        sb.AppendLine(CultureInfo.InvariantCulture, $"Simulated DPI, mode {o.Mode.ToString().ToLowerInvariant()}, budget {o.Budget} strategies, seeds {o.Seeds}{models}");
        sb.AppendLine("Trials to success = distinct strategies run up to and including the first one that passed a full series (3/3 probes, L2).");
        sb.AppendLine("A failed run (no success within the budget or the set) counts as more than the budget in the percentiles.");
        Table(sb, "All scenarios / все сценарии", r.Summaries(), o.Budget);
        Table(sb, "Warm scenarios (a sibling on the same provider) / тёплые", r.Summaries(x => x.Warm), o.Budget);
        Table(sb, "Cold scenarios / холодные", r.Summaries(x => !x.Warm), o.Budget);

        sb.AppendLine();
        sb.AppendLine("## Per scenario: median trials to success / по сценариям");
        sb.AppendLine();
        var arms = r.Arms;
        sb.AppendLine("| Scenario | ASN | Warm | " + string.Join(" | ", arms.Select(Name)) + " |");
        sb.AppendLine("|---|---|---|" + string.Concat(arms.Select(_ => "---|")));
        foreach (var g in r.Runs.GroupBy(x => x.Scenario))
        {
            var first = g.First();
            var cells = arms.Select(a =>
            {
                var runs = g.Where(x => x.Arm == a).ToList();
                if (runs.Count == 0)
                    return "–";
                int ok = runs.Count(x => x.Success);
                return N(BenchReport.Percentile(runs, 0.5, x => x.Strategies), o.Budget) + (ok == runs.Count ? "" : $" ({ok}/{runs.Count} ok)");
            });
            sb.AppendLine(CultureInfo.InvariantCulture, $"| {first.Scenario} | {first.Asn} | {(first.Warm ? "yes" : "no")} | {string.Join(" | ", cells)} |");
        }

        sb.AppendLine();
        sb.AppendLine("## Verdict / вывод");
        sb.AppendLine();
        foreach (var line in Verdict(r))
            sb.AppendLine("- " + line);
        return sb.ToString();
    }

    private static void Table(StringBuilder sb, string title, IReadOnlyList<ArmSummary> rows, int budget)
    {
        if (rows.Count == 0)
            return;
        sb.AppendLine();
        sb.AppendLine("## " + title);
        sb.AppendLine();
        sb.AppendLine("| Arm | Runs | Success | Failed | Median | p90 | Mean (successful) | Median probes | Tokens |");
        sb.AppendLine("|---|---|---|---|---|---|---|---|---|");
        foreach (var s in rows)
        {
            sb.AppendLine(CultureInfo.InvariantCulture,
                $"| {Name(s.Arm)} | {s.Runs} | {s.Successes} | {s.Failures} | {N(s.Median, budget)} | {N(s.P90, budget)} | {s.MeanSuccessStrategies.ToString("0.0", CultureInfo.InvariantCulture)} | {N(s.MedianAttempts, budget * 5)} | {s.Tokens} |");
        }
    }

    /// <summary>The comparisons PLAN 4a.3 asks for, in words: the bandit against the static order, the model against both.</summary>
    public static IReadOnlyList<string> Verdict(BenchReport r)
    {
        var lines = new List<string>();
        var warm = r.Summaries(x => x.Warm).ToDictionary(s => s.Arm);
        if (warm.TryGetValue(BenchArm.Static, out var st) && warm.TryGetValue(BenchArm.Bandit, out var bd))
        {
            lines.Add(Compare("bandit", bd, "static", st, r.Options.Budget, "warm scenarios"));
        }
        var all = r.Summaries().ToDictionary(s => s.Arm);
        if (all.TryGetValue(BenchArm.Model, out var m))
        {
            var best = new[] { BenchArm.Bandit, BenchArm.Static }.Where(all.ContainsKey).Select(a => all[a]).First();
            lines.Add(Compare("model", m, Name(best.Arm), best, r.Options.Budget, "all scenarios"));
            if (all.TryGetValue(BenchArm.BanditModel, out var bm))
                lines.Add(Compare("bandit+model", bm, Name(best.Arm), best, r.Options.Budget, "all scenarios"));
            bool wins = Better(m, best) || (all.TryGetValue(BenchArm.BanditModel, out var bm2) && Better(bm2, best));
            lines.Add(wins
                ? "The model shortens the search here: keep it in the search loop (measure again on the stand before relying on it)."
                : "The model does not beat the search here: it stays a tool for explaining failures, not for searching (PLAN 4a.3, M6).");
        }
        else
        {
            lines.Add("Model arms not run: pass --provider (and a key or an endpoint) to measure them.");
        }
        return lines;
    }

    /// <summary>Fewer failures first, then a lower median, then a lower p90 (null is worse than any number).</summary>
    public static bool Better(ArmSummary a, ArmSummary b) =>
        a.Failures != b.Failures ? a.Failures < b.Failures : Cmp(a.Median, b.Median) is var c && c != 0 ? c < 0 : Cmp(a.P90, b.P90) < 0;

    /// <summary>Not worse: no more failures, and median and p90 no higher.</summary>
    public static bool NoWorse(ArmSummary a, ArmSummary b) => a.Failures <= b.Failures && Cmp(a.Median, b.Median) <= 0 && Cmp(a.P90, b.P90) <= 0;

    private static int Cmp(int? a, int? b) => (a ?? int.MaxValue).CompareTo(b ?? int.MaxValue);

    private static string Compare(string an, ArmSummary a, string bn, ArmSummary b, int budget, string scope) =>
        $"{scope}: {an} median {N(a.Median, budget)}, p90 {N(a.P90, budget)}, failed {a.Failures}/{a.Runs} vs {bn} median {N(b.Median, budget)}, p90 {N(b.P90, budget)}, failed {b.Failures}/{b.Runs}"
        + (Better(a, b) ? $" — {an} is better" : NoWorse(a, b) ? " — the same" : $" — {an} is worse");

    public static string Json(BenchReport r)
    {
        JsonObject Summary(ArmSummary s) => new()
        {
            ["arm"] = Name(s.Arm),
            ["runs"] = s.Runs,
            ["successes"] = s.Successes,
            ["failures"] = s.Failures,
            ["median"] = s.Median,
            ["p90"] = s.P90,
            ["median_probes"] = s.MedianAttempts,
            ["mean_successful"] = s.MeanSuccessStrategies,
            ["tokens"] = s.Tokens,
        };
        var o = r.Options;
        var root = new JsonObject
        {
            ["mode"] = o.Mode.ToString().ToLowerInvariant(),
            ["budget"] = o.Budget,
            ["seeds"] = o.Seeds,
            ["model_seeds"] = o.ModelSeeds,
            ["model"] = r.ModelName,
            ["scenarios"] = new JsonArray([.. o.Scenarios.Select(s => (JsonNode)new JsonObject
            {
                ["id"] = s.Id,
                ["asn"] = s.Asn,
                ["label"] = s.Label,
                ["warm"] = BenchScenarios.Warm(s, o.Scenarios),
                ["hidden_rule"] = s.Hidden,
            })]),
            ["summary"] = new JsonObject
            {
                ["all"] = new JsonArray([.. r.Summaries().Select(s => (JsonNode)Summary(s))]),
                ["warm"] = new JsonArray([.. r.Summaries(x => x.Warm).Select(s => (JsonNode)Summary(s))]),
                ["cold"] = new JsonArray([.. r.Summaries(x => !x.Warm).Select(s => (JsonNode)Summary(s))]),
            },
            ["verdict"] = new JsonArray([.. Verdict(r).Select(v => (JsonNode)JsonValue.Create(v))]),
            ["runs"] = new JsonArray([.. r.Runs.Select(x => (JsonNode)new JsonObject
            {
                ["scenario"] = x.Scenario,
                ["arm"] = Name(x.Arm),
                ["seed"] = x.Seed,
                ["warm"] = x.Warm,
                ["success"] = x.Success,
                ["strategies"] = x.Strategies,
                ["probes"] = x.Attempts,
                ["winner"] = x.Winner,
                ["note"] = x.Note,
                ["turns"] = x.Turns,
                ["tool_calls"] = x.ToolCalls,
                ["tokens"] = x.Tokens,
            })]),
        };
        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }
}
