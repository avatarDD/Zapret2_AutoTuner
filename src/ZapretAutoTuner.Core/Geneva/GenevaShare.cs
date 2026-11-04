using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Core.Geneva;

/// <summary>A strategy shared between users: the strategy and the services (domains, protocol names) it worked for.</summary>
public sealed record GenevaSharedStrategy
{
    public required string Strategy { get; init; }

    public IReadOnlyList<string> Services { get; init; } = [];

    public double? Fitness { get; init; }
}

/// <summary>
/// The exchange file of found geneva strategies, the same as zapret-gui's (<c>core/geneva_share.py</c>):
/// <code>
/// {"format": "zapret-gui/geneva-strategies", "version": 1, "exported_at": "2026-11-04T09:40:00Z",
///  "items": [{"strategy": "...", "transport": "tcp", "services": ["youtube.com", ...], "fitness": 396.0}]}
/// </code>
/// Only strategies, their transport and service names go into the file: no device addresses, keys or logs. An import
/// takes the same file or plain text with one strategy per line (<c>#</c> starts a comment). Imported strategies are
/// candidates: the "Авто" mode tries each on the service's own traffic before it applies one (AGENTS.md rules 4, 5).
/// </summary>
public static class GenevaShare
{
    public const string Format = "zapret-gui/geneva-strategies";
    public const int Version = 1;
    public const int MaxItems = 200;
    public const int MaxBytes = 512 * 1024;
    public const int MaxServices = 20;

    /// <summary>"tcp", "udp" or "tcp,udp" by the trees' protocols, as zapret-gui says it.</summary>
    public static string Transport(string strategy)
    {
        bool tcp = strategy.Contains("[TCP:", StringComparison.OrdinalIgnoreCase);
        bool udp = strategy.Contains("[UDP:", StringComparison.OrdinalIgnoreCase) || strategy.Contains("[DNS", StringComparison.OrdinalIgnoreCase);
        return tcp && udp ? "tcp,udp" : udp ? "udp" : "tcp";
    }

    /// <summary>A service name as the file keeps it: printable, at most 120 characters; empty when it is not one.</summary>
    public static string CleanName(string? v)
    {
        v = (v ?? "").Trim();
        if (v.Length == 0 || v.Any(char.IsControl))
            return "";
        return v.Length > 120 ? v[..120] : v;
    }

    /// <summary>The export document: one item per strategy (the services that share it together), as JSON text.</summary>
    public static string Build(IEnumerable<GenevaSharedStrategy> items, DateTimeOffset now)
    {
        var list = new JsonArray();
        var byStrategy = new Dictionary<string, (List<string> Services, double? Fitness)>(StringComparer.Ordinal);
        var order = new List<string>();
        foreach (var it in items)
        {
            var s = it.Strategy.Trim();
            if (s.Length == 0)
                continue;
            if (!byStrategy.TryGetValue(s, out var cur))
            {
                cur = ([], null);
                order.Add(s);
            }
            foreach (var n in it.Services.Select(CleanName).Where(n => n.Length > 0))
            {
                if (!cur.Services.Contains(n, StringComparer.OrdinalIgnoreCase) && cur.Services.Count < MaxServices)
                    cur.Services.Add(n);
            }
            if (it.Fitness is { } f && (cur.Fitness is null || f > cur.Fitness))
                cur.Fitness = f;
            byStrategy[s] = cur;
        }
        foreach (var s in order.Take(MaxItems))
        {
            var (services, fitness) = byStrategy[s];
            var o = new JsonObject
            {
                ["strategy"] = s,
                ["transport"] = Transport(s),
                ["services"] = new JsonArray([.. services.Select(x => (JsonNode)x)]),
            };
            if (fitness is { } f)
                o["fitness"] = f;
            list.Add((JsonNode)o);
        }
        var doc = new JsonObject
        {
            ["format"] = Format,
            ["version"] = Version,
            ["exported_at"] = now.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
            ["items"] = list,
        };
        return doc.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    /// <summary>
    /// An export document or plain text (one strategy per line) → the strategies that pass the shape check
    /// (<see cref="GenevaStrategyText.Problem"/>), without repeats, and what was wrong, in Russian and English. The
    /// real parse (<c>geneva check</c>) is the caller's.
    /// </summary>
    public static (List<GenevaSharedStrategy> Items, List<string> Errors) Parse(string text)
    {
        var rows = new List<GenevaSharedStrategy>();
        var errors = new List<string>();
        if (Encoding.UTF8.GetByteCount(text) > MaxBytes)
            return (rows, [$"файл больше {MaxBytes / 1024} КБ / the file is over {MaxBytes / 1024} KB"]);
        text = text.Trim().TrimStart('﻿');
        var raw = new List<(string Strategy, List<string> Services, double? Fitness)>();
        if (text.StartsWith('{'))
        {
            JsonNode? doc;
            try
            {
                doc = JsonNode.Parse(text);
            }
            catch (JsonException e)
            {
                return (rows, ["не JSON / not JSON: " + e.Message]);
            }
            if (doc is not JsonObject o)
                return (rows, ["ожидался объект с items / an object with items expected"]);
            if (o["format"] is { } fmt && (fmt.GetValueKind() != JsonValueKind.String || (string?)fmt != Format))
                return (rows, [$"чужой формат / another format: {Short(fmt.ToJsonString())}"]);
            if (o["items"] is not JsonArray items)
                return (rows, ["нет списка items / no items list"]);
            if (items.Count > MaxItems)
                errors.Add($"взяты первые {MaxItems} из {items.Count} / the first {MaxItems} of {items.Count} taken");
            foreach (var it in items.Take(MaxItems))
            {
                switch (it)
                {
                    case JsonObject io:
                    {
                        var s = io["strategy"] is JsonValue sv && sv.GetValueKind() == JsonValueKind.String ? (string?)sv ?? "" : "";
                        var services = new List<string>();
                        if (io["services"] is JsonArray sa)
                        {
                            foreach (var name in sa.OfType<JsonValue>().Where(v => v.GetValueKind() == JsonValueKind.String).Select(v => CleanName((string?)v)))
                            {
                                if (name.Length > 0 && !services.Contains(name, StringComparer.OrdinalIgnoreCase) && services.Count < MaxServices)
                                    services.Add(name);
                            }
                        }
                        double? fit = io["fitness"] is JsonValue fv && fv.GetValueKind() == JsonValueKind.Number && double.TryParse(fv.ToJsonString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var f) && double.IsFinite(f) ? f : null;
                        raw.Add((s.Trim(), services, fit));
                        break;
                    }
                    case JsonValue v when v.GetValueKind() == JsonValueKind.String:
                        raw.Add((((string?)v ?? "").Trim(), [], null));
                        break;
                }
            }
        }
        else
        {
            var lines = text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList();
            if (lines.Count > MaxItems)
                errors.Add($"взяты первые {MaxItems} из {lines.Count} / the first {MaxItems} of {lines.Count} taken");
            raw.AddRange(lines.Take(MaxItems).Select(l => (l, new List<string>(), (double?)null)));
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        int n = 0;
        foreach (var (s, services, fit) in raw)
        {
            n++;
            if (s.Length == 0)
                continue;
            if (GenevaStrategyText.Problem(s) is { } bad)
            {
                errors.Add($"{n}: {bad}");
                continue;
            }
            if (!seen.Add(s))
                continue;
            rows.Add(new GenevaSharedStrategy { Strategy = s, Services = services, Fitness = fit });
        }
        return (rows, errors);
    }

    private static string Short(string s) => s.Length > 60 ? s[..60] : s;

    /// <summary>
    /// The starting set that comes with the program: strategies the "Авто" mode found and checked for real users
    /// (<c>Data/geneva-preset.json</c>, in the exchange format). New users try them first and wait less for their first
    /// bypass; each is still checked on the service's own traffic before it is applied.
    /// </summary>
    public static IReadOnlyList<GenevaSharedStrategy> Preset => _preset ??= LoadPreset();

    private static IReadOnlyList<GenevaSharedStrategy>? _preset;

    private static List<GenevaSharedStrategy> LoadPreset()
    {
        using var s = typeof(GenevaShare).Assembly.GetManifestResourceStream("ZapretAutoTuner.Core.Geneva.geneva-preset.json")
            ?? throw new InvalidOperationException("geneva-preset.json is not embedded");
        using var r = new StreamReader(s, Encoding.UTF8);
        return Parse(r.ReadToEnd()).Items;
    }

    /// <summary>
    /// Whether a shared strategy names the service: the same domain, a subdomain of it (www.youtube.com for
    /// youtube.com), or a name that contains the shared one as a word (STUN stun.l.google.com).
    /// </summary>
    public static bool Names(GenevaSharedStrategy shared, string name, string host = "")
    {
        foreach (var raw in shared.Services)
        {
            var n = raw.Trim().TrimEnd('.').ToLowerInvariant();
            if (n.Length == 0)
                continue;
            foreach (var mine in new[] { name, host })
            {
                var m = mine.Trim().TrimEnd('.').ToLowerInvariant();
                if (m.Length == 0)
                    continue;
                if (m == n || m.EndsWith("." + n, StringComparison.Ordinal))
                    return true;
                // "STUN stun.l.google.com (74.125.0.1:19302)": the endpoint's name holds the host as a word
                if (m.Split(' ', '(', ')').Contains(n, StringComparer.Ordinal))
                    return true;
            }
        }
        return false;
    }
}
