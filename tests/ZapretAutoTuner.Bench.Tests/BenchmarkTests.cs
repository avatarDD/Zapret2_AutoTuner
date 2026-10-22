using System.Text.Json.Nodes;
using Xunit.Abstractions;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Mcp.Advisor;
using ZapretAutoTuner.Mcp.Tests;

namespace ZapretAutoTuner.Bench.Tests;

public sealed class BenchmarkTests(ITestOutputHelper output)
{
    /// <summary>Three providers with two DPIs each: every scenario is warm.</summary>
    private static readonly string[] Small = ["a-split-midsld", "a-disorder", "b-fake-md5", "b-fake-md5-white", "c-ttl", "c-ttl-white"];

    private static BenchOptions SmallOptions => new() { Scenarios = BenchScenarios.Select(Small), Seeds = 3, Budget = 200 };

    [Fact]
    public void TheDpiIsReproducibleAndEndsAtTheFirstFullSeries()
    {
        var flaky = new BenchScenario("flaky", 1, BlockLabel.SniBlock, [BlockLabel.SniBlock], SimFailure.Reset, "", "half", _ => 0.5);
        var s = Strategy.Parse("--lua-desync=multisplit:pos=1");
        List<bool> Draw(int seed)
        {
            using var dpi = new SimulatedDpi(flaky, seed, 10, confirmAttempts: 100);
            dpi.Begin(s);
            return [.. Enumerable.Range(0, 40).Select(_ => dpi.Probe())];
        }
        Assert.Equal(Draw(1), Draw(1));
        Assert.NotEqual(Draw(1), Draw(2));
        Assert.InRange(Draw(1).Count(x => x), 10, 30);

        var rule = BenchScenarios.Select(["b-fake-md5"])[0];
        using var run = new SimulatedDpi(rule, 1, budget: 2);
        Assert.False(run.Probe()); // no engine: the baseline is blocked
        run.Begin(Strategy.Parse("--lua-desync=multisplit:pos=1"));
        Assert.False(run.Probe());
        run.End();
        run.Begin(Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5"));
        Assert.True(run.Probe() & run.Probe());
        Assert.Null(run.FirstSuccess);
        Assert.True(run.Probe());
        Assert.Equal((2, 4), (run.FirstSuccess!.Value.Strategies, run.FirstSuccess.Value.Attempts));
        Assert.True(run.Done.IsCancellationRequested);
    }

    [Fact]
    public void TheBudgetRefusesANewStrategy()
    {
        using var dpi = new SimulatedDpi(BenchScenarios.Select(["e-none"])[0], 1, budget: 1);
        dpi.Begin(Strategy.Parse("--lua-desync=multisplit:pos=1"));
        dpi.End();
        dpi.Begin(Strategy.Parse("--lua-desync=multisplit:pos=1")); // the same strategy again costs nothing new
        dpi.End();
        Assert.Throws<OperationCanceledException>(() => dpi.Begin(Strategy.Parse("--lua-desync=multisplit:pos=2")));
        Assert.True(dpi.OverBudget);
        Assert.True(dpi.Done.IsCancellationRequested);
    }

    /// <summary>Every scenario but the hopeless one has a passing strategy in the standard set: a failure is the order's, not the rule's.</summary>
    [Fact]
    public void EveryScenarioButTheHopelessOneIsSolvable()
    {
        foreach (var s in BenchScenarios.All)
        {
            var set = StrategyGenerator.Generate(s.Generator(SearchMode.Standard)).Candidates;
            Assert.True(set.Any(c => s.Rule(c.Strategy) >= 1) == (s.Id != "e-none"), s.Id);
        }
    }

    [Fact]
    public async Task StaticAndBanditAreDeterministic()
    {
        var a = await new SearchBenchmark(SmallOptions with { Seeds = 2 }).RunAsync();
        var b = await new SearchBenchmark(SmallOptions with { Seeds = 2 }).RunAsync();
        Assert.Equal(a.Runs, b.Runs);
        Assert.Equal([BenchArm.Static, BenchArm.Bandit], a.Arms);
        // the static order tries the families in order: the midsld split is the third multisplit candidate
        var first = a.Runs.First(r => r.Scenario == "a-split-midsld" && r.Arm == BenchArm.Static);
        Assert.True(first.Success);
        Assert.Equal(3, first.Strategies);
        Assert.Contains("midsld", first.Winner, StringComparison.Ordinal);
    }

    /// <summary>
    /// PLAN 4a.3 / M6: on warm scenarios (a sibling DPI on the same provider was searched before) the learned order must
    /// not be worse than the static one. Per scenario it can be: see the printed table (provider A, where the static
    /// order already starts with the right family, is where the bandit loses).
    /// </summary>
    [Fact]
    public async Task TheBanditIsNoWorseThanStaticOnWarmScenarios()
    {
        var report = await new SearchBenchmark(SmallOptions).RunAsync();
        output.WriteLine(BenchFormat.Markdown(report));
        var warm = report.Summaries(r => r.Warm).ToDictionary(s => s.Arm);
        Assert.Equal(Small.Length * 3, warm[BenchArm.Static].Runs);
        Assert.True(BenchFormat.NoWorse(warm[BenchArm.Bandit], warm[BenchArm.Static]),
            string.Join("\n", BenchFormat.Verdict(report)));
    }

    [Fact]
    public async Task TheReportHasTheTablesAndTheJson()
    {
        var report = await new SearchBenchmark(new BenchOptions { Scenarios = BenchScenarios.Select(["a-split-midsld", "a-disorder", "e-wssize"]), Seeds = 1, Budget = 50 }).RunAsync();
        var md = BenchFormat.Markdown(report);
        Assert.Contains("| static | 3 |", md, StringComparison.Ordinal);
        Assert.Contains("| e-wssize | 64505 | no |", md, StringComparison.Ordinal);
        Assert.Contains("> 50", md, StringComparison.Ordinal);
        Assert.Contains("Model arms not run", md, StringComparison.Ordinal);
        var json = JsonNode.Parse(BenchFormat.Json(report))!;
        Assert.Equal(6, json["runs"]!.AsArray().Count);
        Assert.Equal(["static", "bandit"], json["summary"]!["all"]!.AsArray().Select(s => (string?)s!["arm"]));
        Assert.Null((int?)json["summary"]!["cold"]![0]!["median"]);
    }

    [Fact]
    public void WithoutAProviderNoModelArmRuns()
    {
        var env = new Dictionary<string, string> { ["ANTHROPIC_API_KEY"] = "sk-ant-x", [BenchCli.KeyEnv] = "sk-ant-y", ["ZT_BENCH_ENDPOINT"] = "http://127.0.0.1:1/v1" };
        var cli = BenchCli.Parse(["--seeds", "2", "--scenarios", "c-ttl,c-ttl-white"], env.GetValueOrDefault);
        Assert.Null(cli.Model);
        Assert.Null(cli.Arms(new HttpClient()));
        Assert.Equal(2, cli.Options.Seeds);
        Assert.Equal(["c-ttl", "c-ttl-white"], cli.Options.Scenarios.Select(s => s.Id));

        var claude = BenchCli.Parse(["--provider", "claude"], env.GetValueOrDefault);
        Assert.Equal((AdvisorProvider.Claude, "sk-ant-y", AdvisorOptions.DefaultClaudeModel), (claude.Model!.Provider, claude.Model.ApiKey, claude.Model.Model));
        Assert.Throws<ArgumentException>(() => BenchCli.Parse(["--provider", "claude", "--api-key-env", "NOPE"], env.GetValueOrDefault));
        var local = BenchCli.Parse(["--provider", "openai", "--model", "qwen3"], env.GetValueOrDefault);
        Assert.Equal(("http://127.0.0.1:1/v1", "qwen3"), (local.Model!.Endpoint, local.Model.Model));
        Assert.Throws<ArgumentException>(() => BenchCli.Parse(["--provider", "openai", "--endpoint", "file:///etc/passwd"], env.GetValueOrDefault));
        Assert.Throws<ArgumentException>(() => BenchCli.Parse(["--scenarios", "no-such"], env.GetValueOrDefault));
        Assert.Throws<ArgumentException>(() => BenchCli.Parse(["--budget", "0"], env.GetValueOrDefault));
    }

    private static ModelArms Scripted(FakeLlm llm)
    {
        var options = new AdvisorOptions(AdvisorProvider.Claude, AdvisorOptions.DefaultClaudeModel, null, "sk-ant-test");
        var limits = new AdvisorLimits(MaxTurns: 10);
        return new ModelArms("scripted", AdvisorChats.For(options, limits, llm.Client()), limits, IncludeSkills: false);
    }

    private static IEnumerable<string?> ToolNames(JsonObject body) => body["tools"]!.AsArray().Select(t => (string?)t!["name"]);

    /// <summary>The model arm drives the real MCP tools (Validator, budget, audit) over the simulated DPI; trials are counted at the engine.</summary>
    [Fact]
    public async Task TheModelArmRunsTrialsThroughTheMcpTools()
    {
        var s = BenchScenarios.Select(["b-fake-md5"])[0];
        var llm = new FakeLlm()
            .Then(FakeLlm.Claude("tool_use", FakeLlm.ToolUse("t1", "diagnose", $$"""{"target":"{{s.Host}}"}""")))
            .Then(FakeLlm.Claude("tool_use", FakeLlm.ToolUse("t2", "trial_run", $$"""{"target":"{{s.Host}}","strategy":"--payload=tls_client_hello --lua-desync=multisplit:pos=1","attempts":3}""")))
            .Then(FakeLlm.Claude("tool_use", FakeLlm.ToolUse("t3", "trial_run", $$"""{"target":"{{s.Host}}","strategy":"--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5","attempts":3}""")))
            .Then(FakeLlm.Claude("end_turn", FakeLlm.Text("fake with tcp_md5 works")));
        var bench = new SearchBenchmark(new BenchOptions { Scenarios = [s], Budget = 20 }, Scripted(llm));

        var run = await bench.RunModelAsync(s, BenchArm.Model, 1, null, Scripted(llm), CancellationToken.None);

        Assert.True(run.Success, run.Note);
        Assert.Equal(2, run.Strategies);
        Assert.Equal(6, run.Attempts); // trial_run runs the whole series: 0/3 for the split, 3/3 for the fake
        Assert.Contains("fake:blob=fake_default_tls:tcp_md5", run.Winner, StringComparison.Ordinal);
        var first = llm.Requests[0].Body;
        Assert.Contains("trial_run", ToolNames(first));
        Assert.DoesNotContain("search_start", ToolNames(first));
        Assert.Contains(s.Host, (string?)first["messages"]![0]!["content"]!.ToJsonString(), StringComparison.Ordinal);
        // the diagnosis the model read is the scenario's, with its evidence and not its hidden rule
        var diagnosis = llm.Requests[1].Body["messages"]![2]!["content"]![0]!["content"]!.ToString();
        Assert.Contains("SniBlock", diagnosis, StringComparison.Ordinal);
        Assert.DoesNotContain("tcp_md5", diagnosis, StringComparison.Ordinal);
    }

    /// <summary>Bandit + model: the model's candidates go into the learned search through search_enqueue and search_start.</summary>
    [Fact]
    public async Task TheBanditModelArmFeedsTheLearnedSearch()
    {
        var options = SmallOptions with { Seeds = 1 };
        var s = options.Scenarios.Single(x => x.Id == "b-fake-md5");
        var llm = new FakeLlm()
            .Then(FakeLlm.Claude("tool_use", FakeLlm.ToolUse("t1", "search_enqueue", """{"strategies":["--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5"],"note":"reassembling DPI"}""")))
            .Then(FakeLlm.Claude("tool_use", FakeLlm.ToolUse("t2", "search_start", $$"""{"target":"{{s.Host}}","mode":"standard"}""")))
            .Then(FakeLlm.Claude("tool_use", FakeLlm.ToolUse("t3", "search_status")))
            .Then(FakeLlm.Claude("end_turn", FakeLlm.Text("done")));
        var bench = new SearchBenchmark(options, Scripted(llm));

        var events = new List<AdvisorEvent>();
        var run = await bench.RunModelAsync(s, BenchArm.BanditModel, 1, await bench.LearningAsync(s, 1), Scripted(llm), CancellationToken.None, e =>
        {
            lock (events)
                events.Add(e);
        });

        Assert.True(run.Success, run.Note);
        Assert.InRange(run.Strategies, 1, 10);
        var tools = ToolNames(llm.Requests[0].Body).ToList();
        Assert.Contains("search_enqueue", tools);
        Assert.DoesNotContain("trial_run", tools);
        // the search may succeed before the model's next turn: read the tool results from the advisor's events
        var results = events.Where(e => e.Kind == AdvisorEventKind.ToolResult).ToList();
        Assert.False(results.Single(e => e.Tool == "search_enqueue").IsError);
        var started = results.Single(e => e.Tool == "search_start");
        Assert.False(started.IsError, started.Text);
        Assert.Contains("\"queued_first\":1", started.Text, StringComparison.Ordinal);
    }
}
