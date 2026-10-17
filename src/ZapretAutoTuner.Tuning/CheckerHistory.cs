using System.Text.Json;
using System.Text.Json.Serialization;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Probes.Diagnostics;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.Tuning;

/// <summary>One row of a stored checker run: enough to draw the history, without addresses.</summary>
public sealed record CheckerHistoryRow(string Id, string Kind, BlockLabel Primary, TrafficLight Light);

/// <summary>History of the "check blocks" button in the knowledge base (PLAN 2.5b): what was blocked and when.</summary>
public static class CheckerHistory
{
    public static void Save(KnowledgeBase kb, CheckerReport report, long? networkId = null)
    {
        var rows = report.Rows.Select(r => new CheckerHistoryRow(r.Resource.Id, r.Resource.Kind, r.Primary, r.Light)).ToList();
        kb.AddCheckerRun(report.Started, report.Duration, report.NetworkProblem, JsonSerializer.Serialize(rows, CheckerHistoryJson.Default.ListCheckerHistoryRow), networkId);
    }

    public static List<(DateTimeOffset Started, TimeSpan Duration, bool NetworkProblem, IReadOnlyList<CheckerHistoryRow> Rows)> Load(KnowledgeBase kb, int limit = 50) =>
        [.. kb.CheckerRuns(limit).Select(r => (r.Started, r.Duration, r.NetworkProblem,
            (IReadOnlyList<CheckerHistoryRow>)(JsonSerializer.Deserialize(r.Report, CheckerHistoryJson.Default.ListCheckerHistoryRow) ?? [])))];
}

[JsonSourceGenerationOptions(UseStringEnumConverter = true)]
[JsonSerializable(typeof(List<CheckerHistoryRow>))]
internal sealed partial class CheckerHistoryJson : JsonSerializerContext;
