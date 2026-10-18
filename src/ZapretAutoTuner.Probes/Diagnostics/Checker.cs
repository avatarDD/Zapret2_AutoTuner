using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Probes.Diagnostics;

public sealed class CheckerTarget
{
    public string Host { get; set; } = "";

    public string Path { get; set; } = "/";

    public bool Quic { get; set; }
}

/// <summary>One row of the checker (data, <c>Data/checker.json</c>).</summary>
public sealed class CheckerResource
{
    public string Id { get; set; } = "";

    /// <summary><c>service</c>, <c>provider</c> or <c>control</c>.</summary>
    public string Kind { get; set; } = "service";

    public string NameRu { get; set; } = "";

    public string NameEn { get; set; } = "";

    public List<CheckerTarget> Targets { get; set; } = [];

    public bool IsControl => Kind == "control";

    public override string ToString() => Id;
}

public sealed class CheckerData
{
    public List<CheckerResource> Resources { get; set; } = [];

    private static readonly Lazy<CheckerData> DefaultLazy = new(() =>
    {
        using var s = typeof(CheckerData).Assembly.GetManifestResourceStream("ZapretAutoTuner.Probes.Data.checker.json")
            ?? throw new InvalidOperationException("checker.json is missing");
        return JsonSerializer.Deserialize(s, CheckerJsonContext.Default.CheckerData) ?? new CheckerData();
    });

    public static CheckerData Default => DefaultLazy.Value;
}

/// <summary>Traffic light of a row (§4b).</summary>
public enum TrafficLight
{
    /// <summary>Opens.</summary>
    Green,

    /// <summary>Blocked, but a strategy (or DoH) can fix it.</summary>
    Yellow,

    /// <summary>Blocked by IP/port or nothing works: VPN or another IP.</summary>
    Red,
}

public sealed record CheckerTargetResult(CheckerTarget Target, ClassifierVerdict Verdict, TimeSpan Duration, bool Retried);

public sealed record CheckerRow
{
    public required CheckerResource Resource { get; init; }

    public IReadOnlyList<CheckerTargetResult> Targets { get; init; } = [];

    /// <summary>The worst target decides the row.</summary>
    public BlockLabel Primary { get; init; }

    public TrafficLight Light { get; init; }

    public string SummaryRu => Texts.Ru(Primary);

    public string SummaryEn => Texts.En(Primary);
}

public sealed record CheckerReport
{
    public DateTimeOffset Started { get; init; }

    public TimeSpan Duration { get; init; }

    public IReadOnlyList<CheckerRow> Rows { get; init; } = [];

    /// <summary>Even the control resources fail: the network is down, not blocked (§4b).</summary>
    public bool NetworkProblem { get; init; }
}

public sealed record CheckerOptions
{
    public int Parallel { get; init; } = 8;

    /// <summary>Per-target classifier settings on top of the quick defaults (tests point targets at local servers).</summary>
    public Func<CheckerTarget, ClassifierOptions, ClassifierOptions>? Tweak { get; init; }
}

/// <summary>
/// The "check blocks" button (PLAN 2.5b, dpi-diagnostics §4b): quick probes without the engine on a set of resources,
/// one attempt per step and a retry only on failure, giving a traffic light with the block type in plain words.
/// </summary>
public static class Checker
{
    public static async Task<CheckerReport> RunAsync(IReadOnlyList<CheckerResource> resources, CheckerOptions? options = null,
        IProgress<ClassifierStep>? progress = null, CancellationToken ct = default)
    {
        var o = options ?? new CheckerOptions();
        var started = DateTimeOffset.Now;
        var sw = Stopwatch.StartNew();
        using var gate = new SemaphoreSlim(Math.Max(1, o.Parallel));
        var rows = await Task.WhenAll(resources.Select(async res =>
        {
            var targets = await Task.WhenAll(res.Targets.Select(async t =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    progress?.Report(new ClassifierStep("checker", null, $"{res.NameRu}: {t.Host}", $"{res.NameEn}: {t.Host}"));
                    return await CheckTargetAsync(t, o, ct).ConfigureAwait(false);
                }
                finally
                {
                    gate.Release();
                }
            })).ConfigureAwait(false);
            var primary = Worst(targets.Select(t => t.Verdict.Primary));
            return new CheckerRow { Resource = res, Targets = targets, Primary = primary, Light = LightOf(primary) };
        })).ConfigureAwait(false);

        var controls = rows.Where(r => r.Resource.IsControl).ToList();
        return new CheckerReport
        {
            Started = started,
            Duration = sw.Elapsed,
            Rows = rows,
            NetworkProblem = controls.Count > 0 && controls.All(r => r.Light == TrafficLight.Red),
        };
    }

    private static async Task<CheckerTargetResult> CheckTargetAsync(CheckerTarget t, CheckerOptions o, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var co = new ClassifierOptions
        {
            Path = t.Path,
            BaselineAttempts = 1,
            MaxAddresses = 2,
            Profiles = [],
            CheckHttp = false,
            CheckQuic = t.Quic,
            Pause = TimeSpan.FromMilliseconds(200),
        };
        co = o.Tweak?.Invoke(t, co) ?? co;
        var run = await ClassifierRunner.RunAsync(t.Host, co, null, ct).ConfigureAwait(false);
        bool retried = false;
        if (run.Verdict.Primary != BlockLabel.Open)
        {
            // one retry only on failure: a lost packet must not paint a row red
            retried = true;
            var again = await ClassifierRunner.RunAsync(t.Host, co, null, ct).ConfigureAwait(false);
            if (again.Verdict.Primary == BlockLabel.Open)
                run = again;
        }
        return new CheckerTargetResult(t, run.Verdict, sw.Elapsed, retried);
    }

    public static TrafficLight LightOf(BlockLabel l) => l switch
    {
        BlockLabel.Open => TrafficLight.Green,
        BlockLabel.IpBlock or BlockLabel.PortBlock or BlockLabel.Unknown or BlockLabel.Punish => TrafficLight.Red,
        _ => TrafficLight.Yellow,
    };

    private static BlockLabel Worst(IEnumerable<BlockLabel> labels)
    {
        var list = labels.ToList();
        if (list.Count == 0)
            return BlockLabel.Unknown;
        // red beats yellow beats green; within a colour, the first target (the main site) speaks
        return list.OrderByDescending(LightOf).First();
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true)]
[JsonSerializable(typeof(CheckerData))]
internal sealed partial class CheckerJsonContext : JsonSerializerContext;
