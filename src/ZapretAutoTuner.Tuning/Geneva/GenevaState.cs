using System.Text.Json;
using System.Text.Json.Serialization;
using ZapretAutoTuner.Core.Geneva;

namespace ZapretAutoTuner.Tuning.Geneva;

/// <summary>A strategy that loaded the target in geneva's search (the UI's full-download probe said yes).</summary>
public sealed record GenevaFoundStrategy
{
    public string Host { get; init; } = "";

    public int Port { get; init; } = 443;

    public string Strategy { get; init; } = "";

    public double Fitness { get; init; }

    public int Runs { get; init; }

    public DateTimeOffset Found { get; init; }
}

/// <summary>How far a target's search got: shown after a restart, and "Продолжить" resumes from geneva's checkpoint.</summary>
public sealed record GenevaSearchProgress
{
    public string Host { get; init; } = "";

    public int Port { get; init; } = 443;

    public int Population { get; init; }

    /// <summary>The last generation geneva finished (0-based), -1 before the first.</summary>
    public int Generation { get; init; } = -1;

    public int Generations { get; init; }

    public double BestFitness { get; init; }

    public string? Best { get; init; }

    public DateTimeOffset Updated { get; init; }

    /// <summary>The search ran to its end (geneva's "done"); a stopped one can be continued.</summary>
    public bool Finished { get; init; }
}

/// <summary>The bypass with geneva the user turned on: brought back after a restart when <see cref="AutoStart"/> is set.</summary>
public sealed record GenevaActiveRun
{
    public string Strategy { get; init; } = "";

    public string Ports { get; init; } = "80,443";

    public bool AutoStart { get; init; }
}

/// <summary>
/// What is kept between runs (the user's "сохранять прогресс и рабочие настройки"): the chosen engine, the last search
/// settings, each target's search progress, the strategies found and the strategy that bypasses. The search itself
/// (population, hall of fame) is geneva's checkpoint in the Agent's protected folder.
/// </summary>
public sealed record GenevaState
{
    public BypassEngine Engine { get; init; } = BypassEngine.Nfqws2;

    public string LastHost { get; init; } = "";

    public int LastPort { get; init; } = 443;

    public int Population { get; init; } = 30;

    public int Generations { get; init; } = 15;

    public List<GenevaSearchProgress> Searches { get; init; } = [];

    public List<GenevaFoundStrategy> Found { get; init; } = [];

    public GenevaActiveRun? Active { get; init; }

    public const int MaxFound = 200;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    public string Serialize() => JsonSerializer.Serialize(this, Json);

    /// <summary>The saved state, or a fresh one when there is none or it is unreadable.</summary>
    public static GenevaState Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new GenevaState();
        try
        {
            return JsonSerializer.Deserialize<GenevaState>(json, Json) ?? new GenevaState();
        }
        catch (JsonException)
        {
            return new GenevaState();
        }
    }

    /// <summary>The found strategies with one more: the same strategy for the same target keeps its best result.</summary>
    public GenevaState WithFound(IEnumerable<GenevaFoundStrategy> found)
    {
        var list = Found.ToList();
        foreach (var f in found)
        {
            int i = list.FindIndex(x => x.Strategy == f.Strategy && string.Equals(x.Host, f.Host, StringComparison.OrdinalIgnoreCase) && x.Port == f.Port);
            if (i < 0)
                list.Add(f);
            else
                list[i] = list[i] with { Fitness = Math.Max(list[i].Fitness, f.Fitness), Runs = Math.Max(list[i].Runs, f.Runs) };
        }
        return this with { Found = [.. list.OrderByDescending(x => x.Fitness).ThenByDescending(x => x.Runs).Take(MaxFound)] };
    }

    public GenevaState WithProgress(GenevaSearchProgress p)
    {
        var list = Searches.Where(x => !(string.Equals(x.Host, p.Host, StringComparison.OrdinalIgnoreCase) && x.Port == p.Port)).ToList();
        list.Insert(0, p);
        return this with { Searches = [.. list.Take(50)] };
    }

    public GenevaSearchProgress? ProgressOf(string host, int port) =>
        Searches.FirstOrDefault(x => string.Equals(x.Host, host, StringComparison.OrdinalIgnoreCase) && x.Port == port);
}

/// <summary>Where <see cref="GenevaState"/> is kept (the App: the knowledge base's settings).</summary>
public interface IGenevaStore
{
    string? Load();

    void Save(string json);
}
