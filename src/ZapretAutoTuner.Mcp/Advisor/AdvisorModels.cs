using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Mcp.Advisor;

/// <summary>Where the advisor's requests go: Claude with the user's own key, or an OpenAI-compatible endpoint (a local model server).</summary>
public enum AdvisorProvider
{
    Claude,
    OpenAiCompatible,
}

/// <summary>
/// The bounds of one advisor session (PLAN 4a.2, MCP M4): turns of the model, tool calls and tokens (input and output of
/// every request, as the provider reports them). The first bound reached ends the session.
/// </summary>
public sealed record AdvisorLimits(int MaxTurns = 12, int MaxToolCalls = 30, long MaxTokens = 400_000, int MaxOutputTokens = 16_000);

/// <summary>What the user chose in Settings. The key lives in memory for this run only and is never written anywhere.</summary>
public sealed record AdvisorOptions(AdvisorProvider Provider, string Model, string? Endpoint, string ApiKey)
{
    public const string DefaultClaudeModel = "claude-opus-5-5";

    public const string DefaultLocalEndpoint = "http://127.0.0.1:11434/v1";

    public const string DefaultLocalModel = "qwen2.5:14b";

    /// <summary>What is missing before a start, or null when the options are usable.</summary>
    public string? Problem()
    {
        if (string.IsNullOrWhiteSpace(Model))
            return "model";
        if (Provider == AdvisorProvider.Claude)
            return string.IsNullOrWhiteSpace(ApiKey) ? "key" : null;
        return Uri.TryCreate(Endpoint?.Trim(), UriKind.Absolute, out var u) && u.Scheme is "http" or "https" && string.IsNullOrEmpty(u.UserInfo) ? null : "endpoint";
    }
}

public enum AdvisorEventKind
{
    /// <summary>The model's text.</summary>
    Assistant,

    /// <summary>A tool the model called, with its (masked) arguments.</summary>
    ToolCall,

    /// <summary>The tool's answer as the model got it (already masked by the tool facade).</summary>
    ToolResult,

    /// <summary>A note of the loop: limits, refusals, the end.</summary>
    Info,

    Error,
}

/// <summary>One line of the advisor panel.</summary>
public sealed record AdvisorEvent(AdvisorEventKind Kind, string Text, string? Tool = null, bool IsError = false);

/// <summary>A tool call as the model asked for it; <see cref="Problem"/> when its arguments were not a JSON object.</summary>
public sealed record AdvisorToolCall(string Id, string Name, JsonObject? Arguments, string? Problem = null);

public enum AdvisorStop
{
    EndTurn,
    ToolUse,
    MaxTokens,
    Refusal,
    Other,
}

/// <summary>One answer of the model: its text, its tool calls, why it stopped and the tokens the request cost.</summary>
public sealed record AdvisorReply(string Text, IReadOnlyList<AdvisorToolCall> Calls, AdvisorStop Stop, long Tokens, string? Detail = null);

public sealed record AdvisorToolResult(string Id, string Content, bool IsError);

/// <summary>
/// A conversation with one provider. It keeps the history in the provider's own format, append-only: every answer is
/// added as it came back (thinking blocks with their signatures included) before the tool results that follow it.
/// </summary>
public interface IAdvisorChat
{
    void AddUser(string text);

    void AddToolResults(IReadOnlyList<AdvisorToolResult> results);

    /// <summary>Sends the history and appends the answer to it.</summary>
    Task<AdvisorReply> SendAsync(CancellationToken ct);
}

public enum AdvisorOutcome
{
    Finished,
    Stopped,
    TurnLimit,
    ToolCallLimit,
    TokenLimit,
    Refused,
    Failed,
}

public sealed record AdvisorSummary(AdvisorOutcome Outcome, int Turns, int ToolCalls, long Tokens, string? Error = null);
