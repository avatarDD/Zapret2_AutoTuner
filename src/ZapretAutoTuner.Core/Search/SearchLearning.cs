namespace ZapretAutoTuner.Core.Search;

/// <summary>Where a candidate came from; stored with every trial so it can be seen whether outside sources help.</summary>
public static class CandidateSource
{
    /// <summary>Expanded from <c>families.yaml</c>.</summary>
    public const string Generator = "generator";

    /// <summary>A refinement or repair child of another strategy (§6.2a).</summary>
    public const string Mutation = "mutation";

    /// <summary>Worked for other targets on this provider (knowledge base, §6.2 adaptive search).</summary>
    public const string Prior = "prior";

    /// <summary>Suggested by a language model (LLM advisor, MCP search_enqueue).</summary>
    public const string Llm = "llm";

    /// <summary>
    /// Measured on the router through zapret-gui's experiments (PLAN 7.6), whatever proposed it. Those trials are also
    /// stored with the <c>router</c> client profile, so the router's own results form the narrowest learning level.
    /// </summary>
    public const string Router = "router";
}

/// <summary>The context a search runs in: the user's provider, the block and the client.</summary>
public sealed record LearningContext(int? Asn = null, string? Label = null, string ClientProfile = "default");

/// <summary>Trials of one strategy in one context on one day, as the knowledge base stores them.</summary>
public sealed record ArmStat(string Strategy, string? Family, string Source, int? Asn, string? Label, string ClientProfile, DateTimeOffset Day, int Successes, int Attempts);

/// <summary>
/// Local self-learning of the search order (PLAN 4a.1): what worked for this user on this provider goes first. Built
/// from the knowledge base's own trials; nothing leaves the machine. Null in <see cref="SearchOptions.Learning"/> is the
/// static order.
/// </summary>
public sealed record SearchLearning
{
    public IReadOnlyList<ArmStat> History { get; init; } = [];

    public LearningContext Context { get; init; } = new();

    /// <summary>A result this old weighs half; zero or less turns the decay off.</summary>
    public TimeSpan HalfLife { get; init; } = TimeSpan.FromDays(30);

    /// <summary>Pseudo-attempts a broader context lends to a narrower one: how much data a sparse context needs to stand on its own.</summary>
    public double Strength { get; init; } = 4;

    /// <summary>Prior success rate of outside sources before any of their results are known.</summary>
    public IReadOnlyDictionary<string, double> SourcePriors { get; init; } = new Dictionary<string, double>(StringComparer.Ordinal)
    {
        [CandidateSource.Prior] = 0.7,
        [CandidateSource.Llm] = 0.5,
    };

    /// <summary>Fixed seed for reproducible orders (tests); null draws from the shared generator.</summary>
    public int? Seed { get; init; }

    /// <summary>The clock for the decay; null is now.</summary>
    public DateTimeOffset? Now { get; init; }
}

/// <summary>A Beta posterior of a success rate.</summary>
public readonly record struct BetaPosterior(double Alpha, double Beta)
{
    public double Mean => Alpha / (Alpha + Beta);

    public double Sample(Random rnd)
    {
        double x = Gamma(rnd, Alpha), y = Gamma(rnd, Beta);
        return x + y > 0 ? x / (x + y) : Mean;
    }

    /// <summary>Marsaglia–Tsang; shapes below 1 are boosted by U^(1/a).</summary>
    private static double Gamma(Random rnd, double shape)
    {
        if (shape < 1)
            return Gamma(rnd, shape + 1) * Math.Pow(rnd.NextDouble(), 1 / shape);
        double d = shape - 1.0 / 3, c = 1 / Math.Sqrt(9 * d);
        while (true)
        {
            double x, v;
            do
            {
                x = Normal(rnd);
                v = 1 + c * x;
            }
            while (v <= 0);
            v = v * v * v;
            double u = rnd.NextDouble();
            if (u < 1 - 0.0331 * x * x * x * x || Math.Log(u) < 0.5 * x * x + d * (1 - v + Math.Log(v)))
                return d * v;
        }
    }

    private static double Normal(Random rnd) =>
        Math.Sqrt(-2 * Math.Log(1 - rnd.NextDouble())) * Math.Cos(2 * Math.PI * rnd.NextDouble());
}

/// <summary>
/// Thompson sampling over the search's arms. Level one: the generated families and the outside sources (one block per
/// source). Level two: the strategies inside a block. An arm's posterior walks nested contexts from broad to narrow
/// (global → block label → ASN + label → ASN + label + client profile; an unknown part is left out): each level starts
/// from the previous level's mean with <see cref="SearchLearning.Strength"/> pseudo-attempts and adds its own decayed
/// counts, so a sparse context leans on the broader ones and a rich one speaks for itself. Arms without any history keep
/// the generator's order (cheap first, label-first): they share the "unexplored" prior, so one draw of it splits the
/// known arms into those tried before the unexplored ones and those tried after. Nothing is dropped: the result is a
/// permutation of the input.
/// </summary>
public sealed class ThompsonOrder
{
    private const double SeenAttempts = 0.05;

    private readonly SearchLearning _l;
    private readonly List<Func<ArmStat, bool>> _levels = [];
    private readonly ILookup<string, (ArmStat R, double W)> _byStrategy;
    private readonly ILookup<string, (ArmStat R, double W)> _byFamily;
    private readonly ILookup<string, (ArmStat R, double W)> _bySource;
    private readonly List<(ArmStat R, double W)> _all;

    public ThompsonOrder(SearchLearning learning)
    {
        _l = learning;
        var now = learning.Now ?? DateTimeOffset.UtcNow;
        _all = [.. learning.History.Select(r => (r, Weight(r.Day, now))).Where(x => x.Item2 > 1e-4 && x.r.Attempts > 0)];
        _byStrategy = _all.ToLookup(x => x.R.Strategy, StringComparer.Ordinal);
        _byFamily = _all.Where(x => x.R.Family is not null).ToLookup(x => x.R.Family!, StringComparer.Ordinal);
        _bySource = _all.ToLookup(x => x.R.Source, StringComparer.Ordinal);

        // nested levels, broad to narrow: each one's counts are a subset of the previous one's
        var c = learning.Context;
        Func<ArmStat, bool> narrow = _ => true;
        _levels.Add(narrow);
        if (c.Label is { } label)
            _levels.Add(narrow = r => r.Label == label);
        if (c.Asn is { } asn)
        {
            var broader = narrow;
            _levels.Add(narrow = r => r.Asn == asn && broader(r));
        }
        if (c.ClientProfile != "default")
        {
            var broader = narrow;
            _levels.Add(r => r.ClientProfile == c.ClientProfile && broader(r));
        }
        Pool = Chain(_all, 0.5);
    }

    /// <summary>All arms together: the success rate expected of an arm nothing is known about, in this context.</summary>
    public BetaPosterior Pool { get; }

    /// <summary>Weight of a result of <paramref name="day"/>: halves every <see cref="SearchLearning.HalfLife"/>.</summary>
    public double Weight(DateTimeOffset day, DateTimeOffset now)
    {
        if (_l.HalfLife <= TimeSpan.Zero)
            return 1;
        double age = Math.Max(0, (now - day).TotalDays);
        return Math.Pow(0.5, age / _l.HalfLife.TotalDays);
    }

    public BetaPosterior Family(string family) => Chain(_byFamily[family], Pool.Mean);

    public BetaPosterior Source(string source) => Chain(_bySource[source], SourcePrior(source) ?? Pool.Mean);

    /// <summary>
    /// A strategy's posterior. It starts from the pool, not from its family: the family's success may be one variant's
    /// (a TTL that fits this route), and a family's own results already decide where the family stands.
    /// </summary>
    public BetaPosterior Strategy(string key) => Chain(_byStrategy[key], Pool.Mean);

    /// <summary>
    /// The search plan: blocks (outside sources and generated families) ordered by a draw from their posteriors, and
    /// the strategies inside each block likewise.
    /// </summary>
    public List<StrategyCandidate> Arrange(IReadOnlyList<StrategyCandidate> external, IReadOnlyList<StrategyCandidate> generated)
    {
        var rnd = _l.Seed is { } seed ? new Random(seed) : Random.Shared;
        var blocks = new List<(List<StrategyCandidate> Items, BetaPosterior Post, bool Seen)>();
        foreach (var g in external.GroupBy(c => c.Source == CandidateSource.Generator ? CandidateSource.Prior : c.Source, StringComparer.Ordinal))
        {
            var rows = _bySource[g.Key];
            blocks.Add(([.. g], Source(g.Key), SourcePrior(g.Key) is not null || Seen(rows)));
        }
        foreach (var g in generated.GroupBy(c => c.Family, StringComparer.Ordinal))
            blocks.Add(([.. g], Family(g.Key), Seen(_byFamily[g.Key])));

        var plan = new List<StrategyCandidate>();
        foreach (var (items, _, _) in Split(blocks, b => b.Seen, b => b.Post, Unexplored(Pool.Mean), rnd))
        {
            var arms = items.Select(c => (C: c, Post: Strategy(c.Key), Seen: Seen(_byStrategy[c.Key]))).ToList();
            plan.AddRange(Split(arms, a => a.Seen, a => a.Post, Unexplored(Pool.Mean), rnd).Select(a => a.C));
        }
        return plan;
    }

    /// <summary>Known arms that beat a draw of the unexplored prior, then the unexplored in input order, then the rest.</summary>
    private static List<T> Split<T>(List<T> arms, Func<T, bool> seen, Func<T, BetaPosterior> post, BetaPosterior unexplored, Random rnd)
    {
        double bar = unexplored.Sample(rnd);
        var known = arms.Where(seen).Select(a => (A: a, Theta: post(a).Sample(rnd))).OrderByDescending(x => x.Theta).ToList();
        return [.. known.Where(x => x.Theta > bar).Select(x => x.A), .. arms.Where(a => !seen(a)), .. known.Where(x => x.Theta <= bar).Select(x => x.A)];
    }

    private BetaPosterior Unexplored(double mean) => new(_l.Strength * Clamp(mean), _l.Strength * (1 - Clamp(mean)));

    private BetaPosterior Chain(IEnumerable<(ArmStat R, double W)> rows, double start)
    {
        var list = rows as IReadOnlyCollection<(ArmStat R, double W)> ?? [.. rows];
        double mean = Clamp(start), a = 0, b = 0;
        foreach (var level in _levels)
        {
            double s = 0, n = 0;
            foreach (var (r, w) in list)
            {
                if (!level(r))
                    continue;
                s += w * r.Successes;
                n += w * r.Attempts;
            }
            a = _l.Strength * mean + s;
            b = _l.Strength * (1 - mean) + (n - s);
            mean = a / (a + b);
        }
        return new BetaPosterior(a, b);
    }

    private static bool Seen(IEnumerable<(ArmStat R, double W)> rows) => rows.Sum(x => x.W * x.R.Attempts) >= SeenAttempts;

    private double? SourcePrior(string source) => _l.SourcePriors.TryGetValue(source, out var p) ? p : null;

    private static double Clamp(double p) => Math.Clamp(p, 0.01, 0.99);
}
