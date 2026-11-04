using System.Text.Json;
using System.Text.Json.Serialization;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Core.Geneva.Auto;

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

    /// <summary>The layers it searched (<c>--protos</c>); empty in a progress saved before they were kept: TCP.</summary>
    public string Protos { get; init; } = "";
}

/// <summary>A strategy imported from another user's file (zapret-gui's format): tried by the "Авто" mode, never applied as is.</summary>
public sealed record GenevaImportedStrategy
{
    public string Strategy { get; init; } = "";

    public List<string> Services { get; init; } = [];

    public DateTimeOffset Imported { get; init; }
}

/// <summary>The bypass with geneva the user turned on: brought back after a restart when <see cref="AutoStart"/> is set.</summary>
public sealed record GenevaActiveRun
{
    public string Strategy { get; init; } = "";

    public string Ports { get; init; } = "80,443";

    public bool AutoStart { get; init; }
}

/// <summary>The "Авто" mode between runs: whether it is on, and every service with its status and strategy.</summary>
public sealed record GenevaAutoState
{
    public bool Enabled { get; init; }

    public List<AutoService> Services { get; init; } = [];

    /// <summary>Timestamps kept per list in the saved state: the window needs a few, not hundreds.</summary>
    public const int SavedTimes = 20;

    /// <summary>The book as it is saved: the windows' timestamps trimmed to the last <see cref="SavedTimes"/>.</summary>
    public static List<AutoService> Trimmed(IEnumerable<AutoService> services) => [.. services.Select(s =>
    {
        var c = s.Clone();
        c.Fails = [.. c.Fails.TakeLast(SavedTimes)];
        c.Oks = [.. c.Oks.TakeLast(SavedTimes)];
        c.NoConnections = [.. c.NoConnections.TakeLast(SavedTimes)];
        return c;
    })];
}

/// <summary>
/// What is kept between runs (the user's "сохранять прогресс и рабочие настройки"): the chosen engine, the last search
/// settings, each target's search progress, the strategies found and the strategy that bypasses. The search itself
/// (population, hall of fame) is geneva's checkpoint in the Agent's protected folder.
/// </summary>
public sealed record GenevaState
{
    /// <summary>geneva by default: its "Авто" mode is the program's main mode (a saved choice stays as it was).</summary>
    public BypassEngine Engine { get; init; } = BypassEngine.Geneva;

    public string LastHost { get; init; } = "";

    public int LastPort { get; init; } = 443;

    public int Population { get; init; } = 30;

    public int Generations { get; init; } = 15;

    public List<GenevaSearchProgress> Searches { get; init; } = [];

    public List<GenevaFoundStrategy> Found { get; init; } = [];

    public GenevaActiveRun? Active { get; init; }

    public GenevaAutoState Auto { get; init; } = new();

    /// <summary>Strategies judged at once by a search (geneva's workers), manual and "Авто": 1 to 8.</summary>
    public int Workers { get; init; } = 1;

    /// <summary>Imported strategies, oldest first: added next to the working ones, never replacing them.</summary>
    public List<GenevaImportedStrategy> Imported { get; init; } = [];

    public const int MaxFound = 200;

    public const int MaxImported = 200;

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

    /// <summary>
    /// The imported strategies with more: a new strategy is added, a known one only gains the new services' names
    /// (nothing that works is replaced or removed). Returns the state and how many strategies were new.
    /// </summary>
    public (GenevaState State, int Added) WithImported(IEnumerable<GenevaSharedStrategy> rows, DateTimeOffset now)
    {
        var list = Imported.Select(x => x with { Services = [.. x.Services] }).ToList();
        int added = 0;
        foreach (var r in rows)
        {
            var cur = list.FirstOrDefault(x => x.Strategy == r.Strategy);
            if (cur is null)
            {
                cur = new GenevaImportedStrategy { Strategy = r.Strategy, Imported = now };
                list.Add(cur);
                added++;
            }
            foreach (var n in r.Services)
            {
                if (!cur.Services.Contains(n, StringComparer.OrdinalIgnoreCase) && cur.Services.Count < GenevaShare.MaxServices)
                    cur.Services.Add(n);
            }
        }
        return (this with { Imported = [.. list.TakeLast(MaxImported)] }, added);
    }

    /// <summary>The imported strategies and the program's starting set, as the "Авто" mode's candidates take them.</summary>
    public IEnumerable<GenevaSharedStrategy> Shared() =>
        Imported.Select(x => new GenevaSharedStrategy { Strategy = x.Strategy, Services = x.Services }).Concat(GenevaShare.Preset);

    /// <summary>
    /// This state with what an older copy of it holds (the data folder of an earlier version): its found and imported
    /// strategies, the searches and the "Авто" services this one does not know. What this one has is kept as it is.
    /// </summary>
    public GenevaState MergedWith(GenevaState old, DateTimeOffset now)
    {
        var merged = WithFound(old.Found);
        merged = merged.WithImported(old.Imported.Select(x => new GenevaSharedStrategy { Strategy = x.Strategy, Services = x.Services }), now).State;
        var searches = Searches.ToList();
        foreach (var p in old.Searches)
        {
            if (merged.ProgressOf(p.Host, p.Port) is null && searches.All(x => !(string.Equals(x.Host, p.Host, StringComparison.OrdinalIgnoreCase) && x.Port == p.Port)))
                searches.Add(p);
        }
        var services = Auto.Services.ToList();
        foreach (var s in old.Auto.Services)
        {
            if (services.All(x => x.Key != s.Key))
                services.Add(s);
        }
        return merged with
        {
            Searches = [.. searches.Take(50)],
            Auto = Auto with { Enabled = Auto.Enabled || old.Auto.Enabled, Services = services },
            Active = Active ?? old.Active,
        };
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
