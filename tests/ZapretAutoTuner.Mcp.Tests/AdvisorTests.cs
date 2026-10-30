using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Mcp.Advisor;

namespace ZapretAutoTuner.Mcp.Tests;

public sealed class AdvisorTests
{
    private static readonly AdvisorOptions ClaudeOptions = new(AdvisorProvider.Claude, AdvisorOptions.DefaultClaudeModel, null, "sk-ant-test");
    private static readonly AdvisorOptions LocalOptions = new(AdvisorProvider.OpenAiCompatible, "qwen-test", "http://127.0.0.1:8080/v1", "");

    private static async Task<(AdvisorSummary Summary, List<AdvisorEvent> Events)> Run(Rig rig, FakeLlm llm, AdvisorOptions o, AdvisorLimits? limits = null,
        string task = "", CancellationToken ct = default)
    {
        var l = limits ?? new AdvisorLimits();
        var runner = new AdvisorRunner(rig.Tools, l) { Client = "advisor", IncludeSkills = false };
        var events = new List<AdvisorEvent>();
        var s = await runner.RunAsync(AdvisorChats.For(o, l, llm.Client()), task, e =>
        {
            lock (events)
                events.Add(e);
        }, ct);
        return (s, events);
    }

    private static IEnumerable<string?> ClaudeToolNames(JsonObject body) => body["tools"]!.AsArray().Select(t => (string?)t!["name"]);

    [Fact]
    public async Task ClaudeToolLoopRunsOnlyPermittedToolsAndEchoesThinking()
    {
        using var rig = new Rig();
        var llm = new FakeLlm()
            .Then(FakeLlm.Claude("tool_use", FakeLlm.Thinking("sig-1"), FakeLlm.Text("Смотрю цели"), FakeLlm.ToolUse("tu_1", "targets_list"),
                FakeLlm.ToolUse("tu_2", "trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit:pos=1"}""")))
            .Then(FakeLlm.Claude("end_turn", FakeLlm.Text("Причина: блок по SNI.")));

        var (s, events) = await Run(rig, llm, ClaudeOptions);

        Assert.Equal(AdvisorOutcome.Finished, s.Outcome);
        Assert.Equal(2, s.Turns);
        Assert.Equal(2, s.ToolCalls);
        Assert.Equal(2, llm.Requests.Count);

        var (req, first) = llm.Requests[0];
        Assert.Equal("https://api.anthropic.com/v1/messages", req.RequestUri!.GetLeftPart(UriPartial.Path));
        Assert.Equal("sk-ant-test", req.Headers.GetValues("x-api-key").Single());
        Assert.Contains(ClaudeAdvisorChat.FallbackBeta, string.Join(",", req.Headers.GetValues("anthropic-beta")), StringComparison.Ordinal);
        Assert.Equal("claude-opus-5-5", (string?)first["model"]);
        Assert.Equal("default", (string?)first["fallbacks"]);
        Assert.Equal("high", (string?)first["output_config"]!["effort"]);
        Assert.Null(first["thinking"]);
        Assert.Null(first["tool_choice"]);
        // read-only by default: the model is not even shown trial_run
        Assert.Equal(["targets_list", "diagnose", "trials_history", "catalog_functions", "strategy_validate", "kb_query", "bug_report_draft", "geneva_status", "geneva_library", "geneva_check"], ClaudeToolNames(first));
        Assert.False((bool)first["tools"]![0]!["input_schema"]!["additionalProperties"]!);

        var msgs = llm.Requests[1].Body["messages"]!.AsArray();
        Assert.Equal(3, msgs.Count);
        var assistant = msgs[1]!["content"]!.AsArray();
        Assert.Equal("assistant", (string?)msgs[1]!["role"]);
        Assert.Equal(["thinking", "text", "tool_use", "tool_use"], assistant.Select(b => (string?)b!["type"]));
        Assert.Equal("sig-1", (string?)assistant[0]!["signature"]);
        var results = msgs[2]!["content"]!.AsArray();
        Assert.Equal(["tu_1", "tu_2"], results.Select(r => (string?)r!["tool_use_id"]));
        Assert.NotEqual(true, (bool?)results[0]!["is_error"]);
        Assert.True((bool)results[1]!["is_error"]!);
        Assert.Contains("not offered", (string?)results[1]!["content"], StringComparison.Ordinal);

        Assert.Empty(rig.Host.Engine.Started);
        var audit = rig.Session.Audit.Entries;
        Assert.Equal(["targets_list", "trial_run"], audit.Select(a => a.Tool));
        Assert.All(audit, a => Assert.Equal("advisor", a.Client));
        Assert.StartsWith("error:", audit[1].Outcome, StringComparison.Ordinal);
        Assert.Contains(events, e => e.Kind == AdvisorEventKind.Assistant && e.Text == "Причина: блок по SNI.");
        Assert.Contains(events, e => e.Kind == AdvisorEventKind.ToolCall && e.Tool == "targets_list");
    }

    [Fact]
    public async Task OpenAiCompatibleToolLoop()
    {
        using var rig = new Rig(new McpPermissions(Probes: true));
        var llm = new FakeLlm()
            .Then(FakeLlm.OpenAi("tool_calls", null, ("c1", "diagnose", """{"target":"blocked.example","refresh":true}""")))
            .Then(FakeLlm.OpenAi("stop", "SNI block; try multisplit."));

        var (s, _) = await Run(rig, llm, LocalOptions with { ApiKey = "local-key" });

        Assert.Equal(AdvisorOutcome.Finished, s.Outcome);
        Assert.Equal(660, s.Tokens);
        Assert.Equal(1, rig.Host.Classified);
        var (req, first) = llm.Requests[0];
        Assert.Equal("http://127.0.0.1:8080/v1/chat/completions", req.RequestUri!.ToString());
        Assert.Equal("Bearer local-key", req.Headers.Authorization!.ToString());
        Assert.Equal("qwen-test", (string?)first["model"]);
        Assert.Equal("system", (string?)first["messages"]![0]!["role"]);
        var names = first["tools"]!.AsArray().Select(t => (string?)t!["function"]!["name"]).ToList();
        Assert.Contains("trial_run", names);
        Assert.DoesNotContain("search_start", names);

        var msgs = llm.Requests[1].Body["messages"]!.AsArray();
        Assert.Equal(["system", "user", "assistant", "tool"], msgs.Select(m => (string?)m!["role"]));
        Assert.Equal("c1", (string?)msgs[2]!["tool_calls"]![0]!["id"]);
        Assert.Equal("c1", (string?)msgs[3]!["tool_call_id"]);
        var result = JsonNode.Parse((string)msgs[3]!["content"]!)!;
        Assert.Equal("SniBlock", (string?)result["primary"]);
        // the tool facade masked the user's address before it reached the model
        Assert.DoesNotContain("192.168.1.10", (string)msgs[3]!["content"]!, StringComparison.Ordinal);
        Assert.Equal("advisor", rig.Session.Audit.Entries.Single().Client);
    }

    [Fact]
    public async Task NoKeyMeansNoAuthorizationHeader()
    {
        using var rig = new Rig();
        var llm = new FakeLlm().Then(FakeLlm.OpenAi("stop", "ok"));
        await Run(rig, llm, LocalOptions);
        Assert.Null(llm.Requests[0].Request.Headers.Authorization);
    }

    [Fact]
    public async Task TurnLimitEndsTheSession()
    {
        using var rig = new Rig();
        var llm = new FakeLlm().Then(FakeLlm.Claude("tool_use", FakeLlm.ToolUse("tu", "targets_list")));
        var (s, events) = await Run(rig, llm, ClaudeOptions, new AdvisorLimits(MaxTurns: 3));
        Assert.Equal(AdvisorOutcome.TurnLimit, s.Outcome);
        Assert.Equal(3, llm.Requests.Count);
        Assert.Equal(3, s.ToolCalls);
        Assert.Contains(events, e => e.IsError && e.Text.StartsWith("TurnLimit", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ToolCallLimitAnswersEveryCallAndStops()
    {
        using var rig = new Rig();
        var llm = new FakeLlm().Then(FakeLlm.OpenAi("tool_calls", null, ("a", "targets_list", "{}"), ("b", "kb_query", "{}"), ("c", "trials_history", "{}")));
        var (s, _) = await Run(rig, llm, LocalOptions, new AdvisorLimits(MaxToolCalls: 2));
        Assert.Equal(AdvisorOutcome.ToolCallLimit, s.Outcome);
        Assert.Equal(2, s.ToolCalls);
        Assert.Single(llm.Requests);
        Assert.Equal(2, rig.Session.Audit.Entries.Count);
    }

    [Fact]
    public async Task TokenLimitEndsTheSession()
    {
        using var rig = new Rig();
        var llm = new FakeLlm().Then(FakeLlm.Claude("tool_use", 90_000, FakeLlm.ToolUse("tu", "targets_list")));
        var (s, _) = await Run(rig, llm, ClaudeOptions, new AdvisorLimits(MaxTokens: 150_000));
        Assert.Equal(AdvisorOutcome.TokenLimit, s.Outcome);
        Assert.Equal(2, llm.Requests.Count);
        Assert.True(s.Tokens >= 150_000);
    }

    [Fact]
    public async Task StopCancelsARequestInFlight()
    {
        using var rig = new Rig();
        using var cts = new CancellationTokenSource();
        var llm = new FakeLlm().Then(async (_, ct) =>
        {
            await cts.CancelAsync();
            await Task.Delay(Timeout.Infinite, ct);
            return "";
        });
        var (s, events) = await Run(rig, llm, ClaudeOptions, ct: cts.Token);
        Assert.Equal(AdvisorOutcome.Stopped, s.Outcome);
        Assert.Equal(0, s.Turns);
        Assert.DoesNotContain(events, e => e.IsError);
    }

    [Fact]
    public async Task StopBetweenTurnsSendsNothingMore()
    {
        using var rig = new Rig();
        using var cts = new CancellationTokenSource();
        var llm = new FakeLlm().Then(async (_, _) =>
        {
            await cts.CancelAsync();
            return FakeLlm.Claude("tool_use", FakeLlm.ToolUse("tu", "targets_list"));
        });
        var (s, _) = await Run(rig, llm, ClaudeOptions, ct: cts.Token);
        Assert.Equal(AdvisorOutcome.Stopped, s.Outcome);
        Assert.Single(llm.Requests);
        Assert.Empty(rig.Session.Audit.Entries);
    }

    [Fact]
    public async Task APermissionTurnedOffDuringTheSessionActsAtOnce()
    {
        using var rig = new Rig(new McpPermissions(Probes: true));
        var llm = new FakeLlm()
            .Then((_, _) =>
            {
                rig.Permissions = new McpPermissions();
                return Task.FromResult(FakeLlm.Claude("tool_use", FakeLlm.ToolUse("tu", "trial_run", """{"target":"blocked.example","strategy":"--lua-desync=multisplit:pos=1"}""")));
            })
            .Then(FakeLlm.Claude("end_turn", FakeLlm.Text("done")));
        var (s, _) = await Run(rig, llm, ClaudeOptions);
        Assert.Contains("trial_run", ClaudeToolNames(llm.Requests[0].Body));
        Assert.Equal(AdvisorOutcome.Finished, s.Outcome);
        Assert.Empty(rig.Host.Engine.Started);
        Assert.StartsWith("error:", rig.Session.Audit.Entries.Single().Outcome, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConfirmationsStillGoToTheUser()
    {
        using var rig = new Rig(new McpPermissions(Probes: true));
        var llm = new FakeLlm()
            .Then(FakeLlm.Claude("tool_use", FakeLlm.ToolUse("tu", "target_add", """{"target":"new.example","reason":"user asked"}""")))
            .Then(FakeLlm.Claude("end_turn", FakeLlm.Text("waiting for your yes")));
        var (s, _) = await Run(rig, llm, ClaudeOptions);
        Assert.Equal(AdvisorOutcome.Finished, s.Outcome);
        Assert.Single(rig.Confirm.Asked);
        Assert.DoesNotContain("new.example", rig.Host.Targets);
        var result = llm.Requests[1].Body["messages"]![2]!["content"]![0]!;
        Assert.Contains("pending_confirmation", (string?)result["content"], StringComparison.Ordinal);
        Assert.NotEqual(true, (bool?)result["is_error"]);
    }

    [Fact]
    public async Task ARefusalEndsTheSession()
    {
        using var rig = new Rig();
        var llm = new FakeLlm().Then(FakeLlm.Claude("refusal"));
        var (s, _) = await Run(rig, llm, ClaudeOptions);
        Assert.Equal(AdvisorOutcome.Refused, s.Outcome);
        Assert.Single(llm.Requests);
    }

    [Fact]
    public async Task AfterAMidAnswerFallbackTheDeclinedPartIsNotEchoed()
    {
        using var rig = new Rig();
        var fallback = new JsonObject { ["type"] = "fallback", ["from"] = new JsonObject { ["model"] = "claude-opus-5-5" }, ["to"] = new JsonObject { ["model"] = "claude-opus-5" } };
        var llm = new FakeLlm()
            .Then(FakeLlm.Claude("tool_use", FakeLlm.Thinking("declined"), FakeLlm.ToolUse("tu_x", "kb_query"), fallback, FakeLlm.Text("again"), FakeLlm.ToolUse("tu_y", "targets_list")))
            .Then(FakeLlm.Claude("end_turn", FakeLlm.Text("done")));
        var (s, _) = await Run(rig, llm, ClaudeOptions);
        Assert.Equal(1, s.ToolCalls);
        Assert.Equal("targets_list", rig.Session.Audit.Entries.Single().Tool);
        var assistant = llm.Requests[1].Body["messages"]![1]!["content"]!.AsArray();
        Assert.Equal(["text", "tool_use"], assistant.Select(b => (string?)b!["type"]));
        Assert.Equal("tu_y", (string?)assistant[1]!["id"]);
    }

    [Fact]
    public async Task AnotherClaudeModelGetsNoFallbackBeta()
    {
        using var rig = new Rig();
        var llm = new FakeLlm().Then(FakeLlm.Claude("end_turn", FakeLlm.Text("ok")));
        await Run(rig, llm, ClaudeOptions with { Model = "claude-haiku-5-5" });
        Assert.Null(llm.Requests[0].Body["fallbacks"]);
        Assert.False(llm.Requests[0].Request.Headers.TryGetValues("anthropic-beta", out var b) && b.Any(v => v.Contains("fallback", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task TheUsersTextIsMaskedAndInvalidArgumentsAreRefused()
    {
        using var rig = new Rig();
        var llm = new FakeLlm()
            .Then(FakeLlm.OpenAi("tool_calls", null, ("a", "diagnose", "{not json"), ("b", "shell", "{}")))
            .Then(FakeLlm.OpenAi("stop", "ok"));
        var (s, _) = await Run(rig, llm, LocalOptions, task: "My router 192.168.1.1 drops youtube");
        var user = (string)llm.Requests[0].Body["messages"]![1]!["content"]!;
        Assert.DoesNotContain("192.168.1.1", user, StringComparison.Ordinal);
        Assert.Contains("lan-", user, StringComparison.Ordinal);
        Assert.Equal(AdvisorOutcome.Finished, s.Outcome);
        Assert.Equal(2, rig.Session.Audit.Entries.Count);
        Assert.All(rig.Session.Audit.Entries, e => Assert.StartsWith("error:", e.Outcome, StringComparison.Ordinal));
        var tools = llm.Requests[1].Body["messages"]!.AsArray().Where(m => (string?)m!["role"] == "tool").Select(m => (string)m!["content"]!).ToList();
        Assert.Contains("invalid arguments", tools[0], StringComparison.Ordinal);
        Assert.Contains("not offered", tools[1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnHttpErrorFailsTheSessionWithItsMessage()
    {
        using var rig = new Rig();
        var handler = new StatusHandler(HttpStatusCode.Unauthorized, """{"error":"bad key"}""");
        var runner = new AdvisorRunner(rig.Tools, new AdvisorLimits()) { IncludeSkills = false };
        var s = await runner.RunAsync(AdvisorChats.For(LocalOptions, new AdvisorLimits(), new HttpClient(handler)), "", _ => { }, CancellationToken.None);
        Assert.Equal(AdvisorOutcome.Failed, s.Outcome);
        Assert.Contains("401", s.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void OptionsSayWhatIsMissing()
    {
        Assert.Equal("key", (ClaudeOptions with { ApiKey = " " }).Problem());
        Assert.Null(ClaudeOptions.Problem());
        Assert.Equal("model", (ClaudeOptions with { Model = "" }).Problem());
        Assert.Null(LocalOptions.Problem());
        Assert.Equal("endpoint", (LocalOptions with { Endpoint = "file:///etc/passwd" }).Problem());
        Assert.Equal("endpoint", (LocalOptions with { Endpoint = "http://user:pw@host/v1" }).Problem());
    }

    [Fact]
    public void TheSystemPromptCarriesTheRulesAndTheSkills()
    {
        var p = AdvisorPrompt.System(includeSkills: true);
        Assert.Contains("--lua-desync", p, StringComparison.Ordinal);
        Assert.Contains("<skill name=\"nfqws2-lua\">", p, StringComparison.Ordinal);
        Assert.Contains("<skill name=\"dpi-diagnostics\">", p, StringComparison.Ordinal);
        Assert.DoesNotContain("<skill", AdvisorPrompt.System(includeSkills: false), StringComparison.Ordinal);
    }

    private sealed class StatusHandler(HttpStatusCode code, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(code) { Content = new StringContent(body) });
    }
}
