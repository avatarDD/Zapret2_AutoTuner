using System.Text.Json;
using System.Text.Json.Nodes;
using Anthropic;
using Anthropic.Models.Beta.Messages;

namespace ZapretAutoTuner.Mcp.Advisor;

/// <summary>
/// The advisor over the Claude API with the official SDK: a manual tool-use loop on the beta Messages endpoint (for the
/// server-side refusal fallback). Adaptive thinking is the model's default and is left on; effort is set explicitly.
/// Thinking blocks go back unchanged with their signatures, and the history is only ever appended to.
/// </summary>
public sealed class ClaudeAdvisorChat : IAdvisorChat
{
    /// <summary>Server-side fallback when the model declines for policy reasons ("default" picks the substitute per category).</summary>
    public const string FallbackBeta = "server-side-fallback-2026-07-01";

    /// <summary>The models that accept <c>fallbacks: "default"</c> on the Claude API.</summary>
    private static readonly HashSet<string> FallbackModels = new(StringComparer.Ordinal)
    {
        "claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-fable-5", "claude-sonnet-5-5",
    };

    private readonly AnthropicClient _client;
    private readonly string _model;
    private readonly int _maxOutputTokens;
    private readonly List<BetaTextBlockParam> _system;
    private readonly List<BetaToolUnion> _tools;
    private readonly List<BetaMessageParam> _messages = [];

    public ClaudeAdvisorChat(string apiKey, string model, string system, IReadOnlyList<McpToolDefinition> tools, int maxOutputTokens, HttpClient? http = null, Uri? baseUrl = null)
    {
        _client = new AnthropicClient { ApiKey = apiKey, MaxRetries = 2 };
        if (http is not null)
            _client = (AnthropicClient)_client.WithOptions(o => o with { HttpClient = http });
        if (baseUrl is not null)
            _client = (AnthropicClient)_client.WithOptions(o => o with { BaseUrl = baseUrl.ToString().TrimEnd('/') });
        _model = model;
        _maxOutputTokens = maxOutputTokens;
        // the system prompt and the tool list never change within a session: one cache breakpoint at the end of the system
        _system = [new BetaTextBlockParam { Text = system, CacheControl = new BetaCacheControlEphemeral() }];
        _tools = [.. tools.Select(t => (BetaToolUnion)new BetaTool
        {
            Name = t.Name,
            Description = t.Description,
            InputSchema = InputSchema.FromRawUnchecked(Elements(t.InputSchema)),
        })];
    }

    /// <summary>The messages sent so far (for tests and diagnostics).</summary>
    internal IReadOnlyList<BetaMessageParam> Messages => _messages;

    public void AddUser(string text) => _messages.Add(new BetaMessageParam { Role = Role.User, Content = text });

    public void AddToolResults(IReadOnlyList<AdvisorToolResult> results)
    {
        if (results.Count == 0)
            return;
        // every result of one answer in a single user message
        List<BetaContentBlockParam> blocks = [.. results.Select(r => (BetaContentBlockParam)new BetaToolResultBlockParam
        {
            ToolUseID = r.Id,
            Content = r.Content,
            IsError = r.IsError,
        })];
        _messages.Add(new BetaMessageParam { Role = Role.User, Content = blocks });
    }

    public async Task<AdvisorReply> SendAsync(CancellationToken ct)
    {
        var p = new MessageCreateParams
        {
            Model = _model,
            MaxTokens = _maxOutputTokens,
            System = _system,
            Tools = _tools,
            Messages = [.. _messages],
            OutputConfig = new BetaOutputConfig { Effort = Effort.High },
        };
        if (FallbackModels.Contains(_model))
            p = p with { Betas = [FallbackBeta], Fallbacks = new Default() };
        BetaMessage m = await _client.Beta.Messages.Create(p, ct).ConfigureAwait(false);

        long tokens = m.Usage.InputTokens + m.Usage.OutputTokens + (m.Usage.CacheCreationInputTokens ?? 0) + (m.Usage.CacheReadInputTokens ?? 0);
        string stopRaw = m.StopReason?.Raw() ?? "";
        var stop = stopRaw switch
        {
            "end_turn" or "stop_sequence" => AdvisorStop.EndTurn,
            "tool_use" => AdvisorStop.ToolUse,
            "max_tokens" => AdvisorStop.MaxTokens,
            "refusal" => AdvisorStop.Refusal,
            _ => AdvisorStop.Other,
        };
        if (stop == AdvisorStop.Refusal)
        {
            // a decline (after the fallback, if any, declined too): nothing of it goes back into the history
            var cat = m.StopDetails is { } d ? d.Category?.ToString() : null;
            return new AdvisorReply("", [], stop, tokens, cat);
        }

        // after a fallback in the middle of the answer, the declined part's thinking and tool calls are not echoed
        var content = m.Content;
        int lastFallback = -1;
        for (int i = 0; i < content.Count; i++)
        {
            if (content[i].TryPickFallback(out _))
                lastFallback = i;
        }
        var echo = new List<BetaContentBlockParam>();
        var calls = new List<AdvisorToolCall>();
        var text = new List<string>();
        for (int i = 0; i < content.Count; i++)
        {
            var b = content[i];
            bool beforeSwitch = i < lastFallback;
            if (b.TryPickText(out var t))
            {
                echo.Add(new BetaTextBlockParam { Text = t.Text });
                if (!beforeSwitch)
                    text.Add(t.Text);
            }
            else if (beforeSwitch)
            {
                continue;
            }
            else if (b.TryPickThinking(out var th))
            {
                echo.Add(new BetaThinkingBlockParam { Thinking = th.Thinking, Signature = th.Signature });
            }
            else if (b.TryPickRedactedThinking(out var rt))
            {
                echo.Add(new BetaRedactedThinkingBlockParam { Data = rt.Data });
            }
            else if (b.TryPickToolUse(out var tu))
            {
                echo.Add(new BetaToolUseBlockParam { ID = tu.ID, Name = tu.Name, Input = tu.Input });
                calls.Add(new AdvisorToolCall(tu.ID, tu.Name, ToObject(tu.Input)));
            }
        }
        if (echo.Count > 0)
            _messages.Add(new BetaMessageParam { Role = Role.Assistant, Content = echo });
        return new AdvisorReply(string.Join("\n", text).Trim(), calls, stop, tokens, stopRaw);
    }

    private static Dictionary<string, JsonElement> Elements(JsonObject o) =>
        o.ToDictionary(kv => kv.Key, kv => JsonSerializer.SerializeToElement(kv.Value));

    private static JsonObject ToObject(IReadOnlyDictionary<string, JsonElement> input)
    {
        var o = new JsonObject();
        foreach (var (k, v) in input)
            o[k] = JsonNode.Parse(v.GetRawText());
        return o;
    }
}
