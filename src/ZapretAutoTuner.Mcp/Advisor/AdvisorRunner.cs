using System.Text;
using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Mcp.Advisor;

/// <summary>
/// The built-in advisor (PLAN 4a.2, MCP M4): an MCP client of our own tools, in-process. It offers the model exactly the
/// tools the user's permissions allow (<see cref="AutoTunerTools.ListTools"/>) and runs every call through
/// <see cref="AutoTunerTools.CallAsync"/>, so the Validator, the masking, the budget, the audit log and the yes/no dialogs
/// work as for any external client. A tool that was not offered is refused here and audited. The loop is bounded by
/// <see cref="AdvisorLimits"/> and ends at once when the token is cancelled (the Stop button).
/// </summary>
public sealed class AdvisorRunner(AutoTunerTools tools, AdvisorLimits limits)
{
    /// <summary>Builds the provider's conversation for the offered tools and the system prompt.</summary>
    public delegate IAdvisorChat ChatFactory(IReadOnlyList<McpToolDefinition> offered, string system);

    /// <summary>Shown in the audit log and the confirmation dialogs as the caller.</summary>
    public string Client { get; init; } = "advisor";

    /// <summary>Put the skills into the system prompt (≈25k tokens; cached on Claude, often too large for a local model).</summary>
    public bool IncludeSkills { get; init; } = true;

    public string Language { get; init; } = "ru";

    public AdvisorLimits Limits => limits;

    public async Task<AdvisorSummary> RunAsync(ChatFactory factory, string task, Action<AdvisorEvent> onEvent, CancellationToken ct)
    {
        int turns = 0, calls = 0;
        long tokens = 0;
        try
        {
            var offered = tools.ListTools();
            var chat = factory(offered, AdvisorPrompt.System(IncludeSkills));
            chat.AddUser(AdvisorPrompt.First(task, Language, offered));
            onEvent(new AdvisorEvent(AdvisorEventKind.Info, $"tools: {string.Join(", ", offered.Select(t => t.Name))}"));
            while (true)
            {
                if (turns >= limits.MaxTurns)
                    return End(AdvisorOutcome.TurnLimit);
                ct.ThrowIfCancellationRequested();
                var reply = await chat.SendAsync(ct).ConfigureAwait(false);
                turns++;
                tokens += reply.Tokens;
                if (reply.Text.Length > 0)
                    onEvent(new AdvisorEvent(AdvisorEventKind.Assistant, reply.Text));
                if (reply.Stop == AdvisorStop.Refusal)
                    return End(AdvisorOutcome.Refused, reply.Detail);
                if (reply.Calls.Count == 0)
                {
                    if (reply.Stop == AdvisorStop.MaxTokens)
                        onEvent(new AdvisorEvent(AdvisorEventKind.Info, "the answer hit the output limit / ответ упёрся в лимит длины"));
                    return End(AdvisorOutcome.Finished);
                }
                var results = new List<AdvisorToolResult>(reply.Calls.Count);
                bool callLimit = false;
                foreach (var call in reply.Calls)
                {
                    ct.ThrowIfCancellationRequested();
                    if (calls >= limits.MaxToolCalls)
                    {
                        callLimit = true;
                        results.Add(new AdvisorToolResult(call.Id, Refusal($"tool-call limit of the session ({limits.MaxToolCalls}) reached"), true));
                        continue;
                    }
                    calls++;
                    results.Add(await CallAsync(call, onEvent, ct).ConfigureAwait(false));
                }
                // every tool call gets its result, also when the session ends now
                chat.AddToolResults(results);
                if (callLimit)
                    return End(AdvisorOutcome.ToolCallLimit);
                if (tokens >= limits.MaxTokens)
                    return End(AdvisorOutcome.TokenLimit);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return End(AdvisorOutcome.Stopped);
        }
        catch (Exception e) when (e is HttpRequestException or System.Text.Json.JsonException or Anthropic.Exceptions.AnthropicException
                                      or InvalidOperationException or IOException or TaskCanceledException)
        {
            onEvent(new AdvisorEvent(AdvisorEventKind.Error, e.Message, IsError: true));
            return End(AdvisorOutcome.Failed, e.Message);
        }

        AdvisorSummary End(AdvisorOutcome outcome, string? error = null)
        {
            var s = new AdvisorSummary(outcome, turns, calls, tokens, error);
            onEvent(new AdvisorEvent(outcome is AdvisorOutcome.Finished or AdvisorOutcome.Stopped ? AdvisorEventKind.Info : AdvisorEventKind.Error,
                $"{outcome}: turns {turns}/{limits.MaxTurns}, tool calls {calls}/{limits.MaxToolCalls}, tokens {tokens}/{limits.MaxTokens}" + (error is null ? "" : " · " + error),
                IsError: outcome is not (AdvisorOutcome.Finished or AdvisorOutcome.Stopped)));
            return s;
        }
    }

    private async Task<AdvisorToolResult> CallAsync(AdvisorToolCall call, Action<AdvisorEvent> onEvent, CancellationToken ct)
    {
        var argsText = call.Arguments is null ? "" : Observation.Short(AutoTunerTools.Mask(call.Arguments.DeepClone().AsObject()).ToJsonString(), 300) ?? "";
        onEvent(new AdvisorEvent(AdvisorEventKind.ToolCall, argsText, call.Name));
        string? refused = null;
        if (call.Problem is not null || call.Arguments is null)
            refused = "invalid arguments: " + (call.Problem ?? "not a JSON object");
        // the permissions are read again for every call: a switch turned off during the session takes effect at once
        else if (!tools.ListTools().Any(t => t.Name == call.Name))
            refused = $"{call.Name} is not offered to the advisor (no such tool or no permission for it)";
        if (refused is not null)
        {
            tools.Session.Audit.Add(new McpAuditEntry(DateTime.UtcNow, Client, Observation.Short(call.Name, 64) ?? "", argsText, "error: " + refused, TimeSpan.Zero));
            var text = Refusal(refused);
            onEvent(new AdvisorEvent(AdvisorEventKind.ToolResult, text, call.Name, IsError: true));
            return new AdvisorToolResult(call.Id, text, true);
        }
        var r = await tools.CallAsync(call.Name, call.Arguments, Client, ct).ConfigureAwait(false);
        onEvent(new AdvisorEvent(AdvisorEventKind.ToolResult, Observation.Short(r.Text, 600) ?? "", call.Name, r.IsError));
        return new AdvisorToolResult(call.Id, r.Text, r.IsError);
    }

    private static string Refusal(string error) => McpErrors.Error(error).ToJsonString();
}

/// <summary>The advisor's prompts. The model is told the rules the tools enforce anyway; the user's text is masked.</summary>
public static class AdvisorPrompt
{
    public static string System(bool includeSkills)
    {
        var sb = new StringBuilder();
        sb.AppendLine("""
            You are the advisor built into Zapret2 AutoTuner, a desktop program that tunes zapret2 (nfqws2/winws2) DPI-bypass
            strategies for the user's own blocked sites. You act only through the tools listed in this request; they are the
            program's own functions and nothing else exists (no shell, files, URLs, engine options or OS changes).

            How to work:
            - Start with targets_list, then diagnose. A strategy helps only when the diagnosis says so (strategy_can_help);
              otherwise explain the cause (DNS, IP block, dead server…) and stop.
            - Success means a full download (L2/L3), never just a handshake. Compare with the baseline the tools report.
            - Write strategies in nfqws2 syntax only: --payload=, --in-range=, --out-range= and --lua-desync= with catalog
              functions (catalog_functions lists them). Never --dpi-desync. Check a strategy with strategy_validate first.
            - Tools that change anything (adding a target, live experiments, commits, saving an export) wait for the user's
              yes in the AutoTuner window: the answer says pending_confirmation; call the same tool again later to see the
              decision, and do not insist after a no.
            - A tool missing from your list is switched off by the user: say which permission would help, do not work around it.
            - Be economical: the session has a fixed budget of turns, tool calls and tokens.
            - Finish with a short answer for the user: the cause, what you tried with its results, and the strategy you
              recommend (with its id) or the next step. Write it in the user's language.
            """);
        sb.AppendLine();
        sb.AppendLine(McpServerSetup.Instructions);
        if (includeSkills)
        {
            foreach (var name in new[] { "nfqws2-lua", "dpi-diagnostics" })
            {
                sb.AppendLine();
                sb.AppendLine($"<skill name=\"{name}\">");
                sb.AppendLine(McpResources.Skill(name));
                sb.AppendLine("</skill>");
            }
        }
        return sb.ToString();
    }

    /// <summary>The first user message: the user's task (masked like the report) and the session's frame.</summary>
    public static string First(string task, string language, IReadOnlyList<McpToolDefinition> offered)
    {
        var t = string.IsNullOrWhiteSpace(task)
            ? "Find out why my blocked targets do not open and find a strategy that opens them, checked with the tools you have."
            : (string?)AutoTunerTools.Mask(new JsonObject { ["task"] = Observation.Short(task.Trim(), 2000) })["task"] ?? "";
        var write = language == "en" ? "English" : "Russian";
        var scopes = offered.Select(o => McpPermissions.Name(o.Scope)).Distinct();
        return $"""
            {t}

            (Answer in {write}. Permissions the user granted: {string.Join(", ", scopes)}.)
            """;
    }
}

/// <summary>The provider's conversation for the options chosen in Settings.</summary>
public static class AdvisorChats
{
    public static AdvisorRunner.ChatFactory For(AdvisorOptions o, AdvisorLimits limits, HttpClient http) => o.Provider switch
    {
        AdvisorProvider.Claude => (offered, system) => new ClaudeAdvisorChat(o.ApiKey.Trim(), o.Model.Trim(), system, offered, limits.MaxOutputTokens, http),
        _ => (offered, system) => new OpenAiCompatibleChat(new Uri(o.Endpoint!.Trim()), o.ApiKey, o.Model.Trim(), system, offered, limits.MaxOutputTokens, http),
    };
}
