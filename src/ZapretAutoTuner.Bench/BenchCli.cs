using System.Globalization;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Mcp.Advisor;

namespace ZapretAutoTuner.Bench;

/// <summary>The command line of <c>ztuner-bench</c>. The model arms are on only when a provider is named explicitly.</summary>
public sealed record BenchCli
{
    public const string KeyEnv = "ZT_BENCH_API_KEY";

    public BenchOptions Options { get; init; } = new();

    /// <summary>The provider of the model arms; null runs only the static and bandit arms and sends nothing anywhere.</summary>
    public AdvisorOptions? Model { get; init; }

    public AdvisorLimits Limits { get; init; } = new(MaxTurns: 40, MaxToolCalls: 120, MaxTokens: 2_000_000);

    public bool IncludeSkills { get; init; } = true;

    public string? JsonPath { get; init; }

    public string? MarkdownPath { get; init; }

    public bool List { get; init; }

    public bool Help { get; init; }

    public const string Usage = """
        ztuner-bench — trials to success of the static order, the bandit, the model and bandit+model on simulated DPIs
        (PLAN 4a.3, MCP M6). No network and no rights for the static and bandit arms.

          --seeds N            seeds per scenario for static and bandit (default 5)
          --budget N           distinct strategies per run (default 200)
          --mode M             quick | standard | full (default standard)
          --scenarios a,b      only these scenarios (--list shows them)
          --md PATH            write the Markdown table there (it is always printed)
          --json PATH          write the JSON report there
          --list               list the scenarios and exit

        Model arms (off unless a provider is given; then the advisor's requests go to that provider only):
          --provider P         claude | openai (an OpenAI-compatible endpoint, e.g. a local model)   [ZT_BENCH_PROVIDER]
          --model NAME         model name (default claude-opus-5-5 / qwen2.5:14b)                    [ZT_BENCH_MODEL]
          --endpoint URL       OpenAI-compatible endpoint, e.g. http://127.0.0.1:11434/v1             [ZT_BENCH_ENDPOINT]
          --api-key-env VAR    environment variable that holds the key (default ZT_BENCH_API_KEY)
          --model-seeds N      seeds per scenario for the model arms (default 1)
          --no-skills          leave the skills out of the system prompt (small local models)
          --max-turns N, --max-tool-calls N, --max-tokens N   bounds of one advisor session
        """;

    /// <summary>Parses the arguments; <paramref name="env"/> reads the environment (tests pass their own).</summary>
    public static BenchCli Parse(IReadOnlyList<string> args, Func<string, string?> env)
    {
        var cli = new BenchCli();
        var o = cli.Options;
        string? provider = env("ZT_BENCH_PROVIDER"), model = env("ZT_BENCH_MODEL"), endpoint = env("ZT_BENCH_ENDPOINT"), keyEnv = KeyEnv;
        var limits = cli.Limits;
        for (int i = 0; i < args.Count; i++)
        {
            string Value() => i + 1 < args.Count ? args[++i] : throw new ArgumentException($"{args[i]} needs a value");
            int Int() => int.TryParse(Value(), NumberStyles.None, CultureInfo.InvariantCulture, out var v) && v > 0 ? v : throw new ArgumentException($"{args[i - 1]} needs a positive number");
            switch (args[i])
            {
                case "--seeds": o = o with { Seeds = Int() }; break;
                case "--model-seeds": o = o with { ModelSeeds = Int() }; break;
                case "--budget": o = o with { Budget = Int() }; break;
                case "--mode":
                    o = o with { Mode = Enum.TryParse<SearchMode>(Value(), true, out var m) ? m : throw new ArgumentException("--mode: quick, standard or full") };
                    break;
                case "--scenarios": o = o with { Scenarios = BenchScenarios.Select(Value().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) }; break;
                case "--json": cli = cli with { JsonPath = Value() }; break;
                case "--md": cli = cli with { MarkdownPath = Value() }; break;
                case "--list": cli = cli with { List = true }; break;
                case "--help" or "-h": cli = cli with { Help = true }; break;
                case "--provider": provider = Value(); break;
                case "--model": model = Value(); break;
                case "--endpoint": endpoint = Value(); break;
                case "--api-key-env": keyEnv = Value(); break;
                case "--no-skills": cli = cli with { IncludeSkills = false }; break;
                case "--max-turns": limits = limits with { MaxTurns = Int() }; break;
                case "--max-tool-calls": limits = limits with { MaxToolCalls = Int() }; break;
                case "--max-tokens": limits = limits with { MaxTokens = Int() }; break;
                default: throw new ArgumentException($"unknown argument {args[i]}");
            }
        }
        cli = cli with { Options = o, Limits = limits };
        if (string.IsNullOrWhiteSpace(provider))
            return cli;
        var p = provider.Trim().ToLowerInvariant() switch
        {
            "claude" or "anthropic" => AdvisorProvider.Claude,
            "openai" or "local" => AdvisorProvider.OpenAiCompatible,
            _ => throw new ArgumentException("--provider: claude or openai"),
        };
        var options = new AdvisorOptions(p,
            string.IsNullOrWhiteSpace(model) ? p == AdvisorProvider.Claude ? AdvisorOptions.DefaultClaudeModel : AdvisorOptions.DefaultLocalModel : model.Trim(),
            p == AdvisorProvider.OpenAiCompatible ? endpoint : null,
            env(keyEnv) ?? "");
        return options.Problem() switch
        {
            null => cli with { Model = options },
            "key" => throw new ArgumentException($"--provider claude needs the key in the environment variable {keyEnv}"),
            "endpoint" => throw new ArgumentException("--provider openai needs --endpoint http(s)://host:port/v1"),
            var problem => throw new ArgumentException($"model options: {problem} is missing"),
        };
    }

    /// <summary>The model arms for this command line, over <paramref name="http"/>; null when no provider was named.</summary>
    public ModelArms? Arms(HttpClient http) =>
        Model is { } m ? new ModelArms($"{m.Provider} {m.Model}", AdvisorChats.For(m, Limits, http), Limits, IncludeSkills) : null;
}
