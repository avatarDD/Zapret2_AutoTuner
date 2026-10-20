using System.Globalization;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Search;

/// <summary>Where a strategy will be exported: limits what counts as portable (dpi-diagnostics §6.3).</summary>
[Flags]
public enum ExportTargets
{
    None = 0,
    Pc = 1,
    Keenetic = 2,
    ZapretGui = 4,
}

/// <summary>A score with the reasons that made it, so the UI can say why one strategy ranks above another.</summary>
public sealed record ScoreBreakdown(double Total, IReadOnlyList<(string Ru, string En, double Points)> Parts)
{
    public override string ToString() => Total.ToString("0.##", CultureInfo.InvariantCulture);
}

/// <summary>
/// Ranking of working strategies (PLAN 3.3a, dpi-diagnostics §6.3). Less is better: fewer instances, no TTL fooling
/// (depends on the route), no wssize or synack, no custom blobs, no --in-range, fewer repeats, 100% stability, all
/// client profiles, and fit for the export targets.
/// </summary>
public static class StrategyScore
{
    public static ScoreBreakdown Compute(Strategy s, Efficiency eff, int profilesPassed = 1, int profilesTotal = 1,
        ExportTargets targets = ExportTargets.Pc, IReadOnlyCollection<string>? customBlobs = null)
    {
        var parts = new List<(string, string, double)>();
        void Add(string ru, string en, double p)
        {
            if (p != 0)
                parts.Add((ru, en, p));
        }

        var calls = s.Calls.ToList();
        Add($"инстансов: {calls.Count}", $"instances: {calls.Count}", calls.Count);
        if (calls.Any(c => c.Has("ip_ttl") || c.Has("ip6_ttl")))
            Add("фиксированный TTL зависит от маршрута", "fixed TTL depends on the route", 3);
        else if (calls.Any(c => c.Has("ip_autottl") || c.Has("ip6_autottl")))
            Add("autottl зависит от маршрута", "autottl depends on the route", 1.5);
        if (calls.Any(c => c.Function is "wssize" or "wsize"))
            Add("wssize режет скорость", "wssize cuts the speed", 5);
        if (calls.Any(c => c.Function is "synack" or "synack_split"))
            Add("synack ломает NAT", "synack breaks NAT", 5);
        var blobs = calls.SelectMany(c => c.Args).Where(a => a.Name is "blob" or "seqovl_pattern" or "pattern").Select(a => a.Value).ToList();
        if (customBlobs is not null && blobs.Any(b => b is not null && customBlobs.Contains(b)))
            Add("свой блоб: нужен файл при экспорте", "custom blob: a file must be exported", 1);
        if (s.Actions.OfType<InRange>().Any())
            Add("нужен --in-range", "needs --in-range", 1);
        int repeats = calls.Select(c => int.TryParse(c["repeats"], CultureInfo.InvariantCulture, out var r) ? r : 1).DefaultIfEmpty(1).Max();
        if (repeats > 1)
            Add($"repeats={repeats}", $"repeats={repeats}", Math.Log2(repeats));
        if (!eff.Working)
            Add($"стабильность {eff.Rate:P0}", $"stability {eff.Rate:P0}", 10 * (1 - eff.Rate));
        if (profilesTotal > 0 && profilesPassed < profilesTotal)
            Add($"работает на {profilesPassed} из {profilesTotal} профилей", $"works on {profilesPassed} of {profilesTotal} profiles", 4.0 * (profilesTotal - profilesPassed) / profilesTotal);
        if (targets.HasFlag(ExportTargets.Keenetic) && calls.Any(c => c.Function == "oob"))
            Add("oob на роутере требует --in-range на каждый профиль", "oob on the router needs --in-range per profile", 1);
        if (targets.HasFlag(ExportTargets.ZapretGui) && calls.Any(c => !StandardFunctions.Contains(c.Function)))
            Add("в zapret-gui только штатные функции", "zapret-gui runs the stock functions only", 10);
        return new ScoreBreakdown(parts.Sum(p => p.Item3), parts);
    }

    /// <summary>Functions of the stock lua files (zapret-antidpi and zapret-auto).</summary>
    private static readonly HashSet<string> StandardFunctions = Catalog.LuaCatalog.Default.Data.Functions
        .Where(f => f.File is "zapret-antidpi.lua" or "zapret-auto.lua" or "zapret-lib.lua")
        .Select(f => f.Name)
        .ToHashSet(StringComparer.Ordinal);
}
