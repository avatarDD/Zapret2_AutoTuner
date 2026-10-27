using System.Text;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Unify;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// export_preview (M5): the export as a dry run, built by the same exporters as the "Экспорт" step. Saving the package
/// to the program's export folder needs the user's yes; delivering it to a router or zapret-gui is never a tool, the
/// user does it in the window (AGENTS.md rule 7).
/// </summary>
internal static class ExportPreview
{
    public const int MaxText = 4000;

    public static JsonObject Build(McpSession session, JsonObject a)
    {
        var format = (string)a["format"]!;
        var results = new List<DomainResult>();
        if (a["items"] is JsonArray items && items.Count > 0)
        {
            foreach (var item in items.Cast<JsonObject>())
            {
                var target = (string)item["target"]!;
                if (!session.IsTarget(target))
                    return McpErrors.NotATarget(target);
                if (session.Strategy((string)item["strategy_id"]!) is not { } s)
                    return McpErrors.Error($"{item["strategy_id"]} is unknown in this session");
                var c = StrategyPolicy.Check(s.Strategy.ToString(), s.L4);
                if (!c.Ok)
                    return StrategyPolicy.Refusal(c);
                var eff = session.Host.Kb.Results(target).FirstOrDefault(r => r.Args == s.Strategy.ToString())?.Efficiency ?? default;
                results.Add(new DomainResult(target, s.L4, s.Strategy, eff, StrategyScore.Compute(s.Strategy, eff).Total));
            }
        }
        else
        {
            foreach (var target in session.Host.Targets)
            {
                var best = session.Host.Kb.Results(target).FirstOrDefault(r => r.Status == "working");
                if (best is null)
                    continue;
                Strategy s;
                try
                {
                    s = Strategy.Parse(best.Args);
                }
                catch (FormatException)
                {
                    continue;
                }
                session.Remember(s);
                results.Add(new DomainResult(target, L4Kind.Tcp, s, best.Efficiency, best.Score ?? StrategyScore.Compute(s, best.Efficiency).Total));
            }
        }
        if (results.Count == 0)
            return McpErrors.Error("nothing to export: no working strategy for the targets yet / экспортировать нечего");

        var solution = Unifier.ToSolution(Unifier.Plan(results));
        var pkg = format switch
        {
            "zapret2" => Zapret2Exporter.Build(solution),
            "winws2" => WinwsExporter.Build(solution),
            "keenetic" => KeeneticExporter.Build(solution),
            "zapret_gui" => ZapretGuiExporter.Build(solution),
            _ => ArgvExporter.Build(solution, OperatingSystem.IsWindows() ? EnginePlatform.Windows : EnginePlatform.Linux, session.Host.TrialOptions.LuaDir),
        };
        var preview = new JsonObject
        {
            ["ok"] = true,
            ["dry_run"] = true,
            ["format"] = format,
            ["profiles"] = new JsonArray([.. solution.Profiles.Select(p => (JsonNode)new JsonObject
            {
                ["name"] = p.Name,
                ["domains"] = new JsonArray([.. p.HostlistDomains.Concat(p.Hostlists.SelectMany(l => solution.Hostlists.GetValueOrDefault(l.Name) ?? [])).Take(20).Select(d => (JsonNode)JsonValue.Create(d))]),
                ["strategy"] = p.Strategy.ToString(),
            })]),
            ["files"] = new JsonArray([.. pkg.Files.Select(f => (JsonNode)new JsonObject { ["name"] = f.Key, ["bytes"] = f.Value.Length })]),
            ["text"] = pkg.Text.Length > MaxText ? pkg.Text[..MaxText] + "…" : pkg.Text,
            ["warnings"] = new JsonArray([.. pkg.Warnings.Select(w => (JsonNode)JsonValue.Create(w))]),
            ["apply"] = "applying to a router or zapret-gui is done by the user in the AutoTuner window / применяет пользователь",
        };
        if ((bool?)a["save"] != true)
            return preview;

        var name = $"autotuner-mcp-{format}-{session.Time.GetUtcNow().UtcDateTime:yyyyMMdd-HHmmss}.zip";
        var key = "export_preview:save:" + format + ":" + string.Join(";", results.Select(r => r.Domain + "=" + r.Strategy));
        var zip = pkg.ToZip();
        var summary = new StringBuilder();
        foreach (var p in solution.Profiles)
            summary.Append("• ").Append(string.Join(", ", p.HostlistDomains)).Append(": ").AppendLine(p.Strategy.ToString());
        var request = new ConfirmRequest("export_preview",
            "Внешний агент предлагает сохранить экспорт", "An external agent proposes to save an export",
            $"Сохранить пакет {format} ({pkg.Files.Count} файлов) в папку экспорта AutoTuner? Ничего не применяется.\n{summary}",
            $"Save the {format} package ({pkg.Files.Count} files) to AutoTuner's export folder? Nothing is applied.\n{summary}");
        var answer = session.Confirmations.Request(key, request, async ct =>
        {
            var saved = await session.Host.SaveExportAsync(name, zip, ct).ConfigureAwait(false);
            return new JsonObject { ["ok"] = true, ["status"] = "saved", ["saved_as"] = saved, ["dry_run"] = false };
        });
        answer["preview"] = preview;
        return answer;
    }
}
