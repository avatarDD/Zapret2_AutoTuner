using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Core.Geneva;

/// <summary>
/// One event of geneva's JSON Lines stream (<c>docs/PROTOCOL.md</c> of geneva_c, proto 1). Unknown events and fields
/// are kept as they are: geneva may add them without changing the protocol version.
/// </summary>
public sealed record GenevaEvent(string Ev, long Ts, JsonObject Data)
{
    /// <summary>The protocol this program speaks; a binary with another one is refused.</summary>
    public const int Proto = 1;

    /// <summary>A line of geneva's stdout, or null when it is not an event (the final "fitness TAB strategy" lines).</summary>
    public static GenevaEvent? Parse(string? line)
    {
        if (string.IsNullOrWhiteSpace(line) || line[0] != '{')
            return null;
        try
        {
            if (JsonNode.Parse(line) is not JsonObject o || o["ev"] is not JsonValue ev || ev.GetValueKind() != JsonValueKind.String)
                return null;
            long ts = o["ts"] is JsonValue t && t.TryGetValue<long>(out var v) ? v : 0;
            return new GenevaEvent((string)ev!, ts, o);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public DateTimeOffset Time => Ts > 0 ? DateTimeOffset.FromUnixTimeMilliseconds(Ts) : DateTimeOffset.UtcNow;

    public string? Str(string name) => Data[name] is JsonValue v && v.GetValueKind() == JsonValueKind.String ? (string?)v : null;

    public long Long(string name) => Data[name] is JsonValue v && v.GetValueKind() == JsonValueKind.Number ? (long)Math.Round(v.GetValue<double>()) : 0;

    public double Num(string name) => Data[name] is JsonValue v && v.GetValueKind() == JsonValueKind.Number ? v.GetValue<double>() : 0;

    public bool Bool(string name) => Data[name] is JsonValue v && v.GetValueKind() == JsonValueKind.True;
}

/// <summary>The counters of <c>geneva run</c> (the <c>stats</c> event and command).</summary>
public sealed record GenevaStats
{
    public long UptimeMs { get; init; }

    public bool Paused { get; init; }

    public long PktsOut { get; init; }

    public long PktsIn { get; init; }

    public long Triggered { get; init; }

    public long Modified { get; init; }

    public long Dropped { get; init; }

    public long Injected { get; init; }

    public long Errors { get; init; }

    public long Overruns { get; init; }

    /// <summary>Each tree with how often it fired: "does the strategy act at all".</summary>
    public IReadOnlyList<(string Tree, long Fired)> Trees { get; init; } = [];

    public static GenevaStats From(GenevaEvent e) => new()
    {
        UptimeMs = e.Long("uptime_ms"),
        Paused = e.Bool("paused"),
        PktsOut = e.Long("pkts_out"),
        PktsIn = e.Long("pkts_in"),
        Triggered = e.Long("triggered"),
        Modified = e.Long("modified"),
        Dropped = e.Long("dropped"),
        Injected = e.Long("injected"),
        Errors = e.Long("send_errors") + e.Long("verdict_errors") + e.Long("parse_errors"),
        Overruns = e.Long("overruns"),
        Trees = [.. ReadTrees(e, "out_trees"), .. ReadTrees(e, "in_trees")],
    };

    private static IEnumerable<(string, long)> ReadTrees(GenevaEvent e, string name)
    {
        if (e.Data[name] is not JsonArray a)
            yield break;
        foreach (var t in a.OfType<JsonObject>())
        {
            var tree = t["tree"] is JsonValue s && s.GetValueKind() == JsonValueKind.String ? (string)s! : "";
            long fired = t["fired"] is JsonValue f && f.GetValueKind() == JsonValueKind.Number ? (long)f.GetValue<double>() : 0;
            yield return (tree, fired);
        }
    }

    /// <summary>A strategy that runs for a while and never fires does nothing: the page says so.</summary>
    public bool Idle => UptimeMs > 30_000 && PktsOut > 100 && Triggered == 0;
}

/// <summary>One strategy geneva found good, as the search reports it (<c>result</c>, <c>generation</c>).</summary>
public sealed record GenevaFound(string Strategy, double Fitness, int Runs);

/// <summary>Geneva's event outcomes and exit reasons in the UI's two languages.</summary>
public static class GenevaText
{
    public static (string Ru, string En) Outcome(string? outcome) => outcome switch
    {
        "ok" => ("загрузилось", "loaded"),
        "reset" => ("сброс (RST)", "reset"),
        "injected" => ("подмена ответа", "forged answer"),
        "connect_timeout" => ("соединение не установилось", "no connection"),
        "timeout" => ("нет ответа", "no answer"),
        "broken" => ("ответ неполный", "incomplete answer"),
        _ => ("ошибка", "failed"),
    };

    /// <summary>Exit codes of <c>docs/PROTOCOL.md</c>.</summary>
    public static (string Ru, string En) Exit(int code, string? reason) => (code, reason) switch
    {
        (0, "signal" or "control") => ("остановлено", "stopped"),
        (0, _) => ("завершено", "finished"),
        (7, _) or (_, "not_blocked") => ("сайт открывается и без обхода: подбирать нечего", "the site opens without a bypass: nothing to search"),
        (2, _) => ("geneva отклонила параметры (подробности в журнале)", "geneva refused the options (see the log)"),
        (3, _) => ("стратегия не разбирается", "the strategy does not parse"),
        (4, _) => ("нет прав или модулей ядра (NFQUEUE, raw-сокеты)", "no rights or kernel modules (NFQUEUE, raw sockets)"),
        (5, _) => ("правила firewall не применились", "the firewall rules did not apply"),
        (6, _) => ("ошибка ввода-вывода", "I/O error"),
        _ => ($"ошибка (код {code.ToString(CultureInfo.InvariantCulture)})", $"error (code {code.ToString(CultureInfo.InvariantCulture)})"),
    };
}
