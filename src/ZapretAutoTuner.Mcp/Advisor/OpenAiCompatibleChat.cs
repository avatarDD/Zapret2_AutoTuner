using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Mcp.Advisor;

/// <summary>
/// The advisor over an OpenAI-compatible <c>/chat/completions</c> endpoint (llama.cpp, Ollama, LM Studio, vLLM… with a
/// local Qwen or Llama). Plain HttpClient and JSON: function tools, <c>tool_calls</c> in the answer, <c>role: tool</c>
/// results. The key is optional (sent as a bearer token when given).
/// </summary>
public sealed class OpenAiCompatibleChat : IAdvisorChat
{
    private readonly HttpClient _http;
    private readonly Uri _url;
    private readonly string _model;
    private readonly string _apiKey;
    private readonly int _maxOutputTokens;
    private readonly JsonArray _tools;
    private readonly JsonArray _messages = [];

    public OpenAiCompatibleChat(Uri endpoint, string apiKey, string model, string system, IReadOnlyList<McpToolDefinition> tools, int maxOutputTokens, HttpClient http)
    {
        _http = http;
        var b = endpoint.ToString().TrimEnd('/');
        _url = new Uri(b.EndsWith("/chat/completions", StringComparison.Ordinal) ? b : b + "/chat/completions");
        _apiKey = apiKey;
        _model = model;
        _maxOutputTokens = maxOutputTokens;
        _tools = [.. tools.Select(t => (JsonNode)new JsonObject
        {
            ["type"] = "function",
            ["function"] = new JsonObject
            {
                ["name"] = t.Name,
                ["description"] = t.Description,
                ["parameters"] = t.InputSchema.DeepClone(),
            },
        })];
        _messages.Add(new JsonObject { ["role"] = "system", ["content"] = system });
    }

    internal JsonArray Messages => _messages;

    public void AddUser(string text) => _messages.Add(new JsonObject { ["role"] = "user", ["content"] = text });

    public void AddToolResults(IReadOnlyList<AdvisorToolResult> results)
    {
        foreach (var r in results)
            _messages.Add(new JsonObject { ["role"] = "tool", ["tool_call_id"] = r.Id, ["content"] = r.Content });
    }

    public async Task<AdvisorReply> SendAsync(CancellationToken ct)
    {
        var body = new JsonObject
        {
            ["model"] = _model,
            ["messages"] = _messages.DeepClone(),
            ["max_tokens"] = _maxOutputTokens,
        };
        if (_tools.Count > 0)
        {
            body["tools"] = _tools.DeepClone();
            body["tool_choice"] = "auto";
        }
        using var req = new HttpRequestMessage(HttpMethod.Post, _url)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        };
        if (!string.IsNullOrWhiteSpace(_apiKey))
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey.Trim());
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"{(int)resp.StatusCode} {resp.ReasonPhrase}: {Observation.Short(json, 300)}", null, resp.StatusCode);
        var root = JsonNode.Parse(json)?.AsObject() ?? throw new JsonException("empty answer");
        var choice = root["choices"]?.AsArray().FirstOrDefault()?.AsObject() ?? throw new JsonException("the answer has no choices");
        var msg = choice["message"]?.AsObject() ?? throw new JsonException("the answer has no message");
        var usage = root["usage"] as JsonObject;
        long tokens = (long?)usage?["total_tokens"] ?? ((long?)usage?["prompt_tokens"] ?? 0) + ((long?)usage?["completion_tokens"] ?? 0);
        string text = (string?)msg["content"] ?? "";
        var calls = new List<AdvisorToolCall>();
        var echoCalls = new JsonArray();
        if (msg["tool_calls"] is JsonArray tc)
        {
            int n = 0;
            foreach (var c in tc.OfType<JsonObject>())
            {
                var id = (string?)c["id"] is { Length: > 0 } s ? s : $"call_{_messages.Count}_{n}";
                n++;
                var fn = c["function"] as JsonObject;
                var name = (string?)fn?["name"] ?? "";
                var raw = fn?["arguments"];
                JsonObject? args = null;
                string? problem = null;
                try
                {
                    args = raw switch
                    {
                        null => [],
                        JsonObject o => o.DeepClone().AsObject(),
                        JsonValue v when v.TryGetValue<string>(out var str) => string.IsNullOrWhiteSpace(str) ? [] : JsonNode.Parse(str) as JsonObject,
                        _ => null,
                    };
                    if (args is null)
                        problem = "arguments are not a JSON object";
                }
                catch (JsonException e)
                {
                    problem = "arguments are not valid JSON: " + e.Message;
                }
                calls.Add(new AdvisorToolCall(id, name, args, problem));
                echoCalls.Add(new JsonObject
                {
                    ["id"] = id,
                    ["type"] = "function",
                    ["function"] = new JsonObject { ["name"] = name, ["arguments"] = raw is JsonValue rv && rv.TryGetValue<string>(out var rs) ? rs : raw?.ToJsonString() ?? "{}" },
                });
            }
        }
        var echo = new JsonObject { ["role"] = "assistant", ["content"] = text };
        if (echoCalls.Count > 0)
            echo["tool_calls"] = echoCalls;
        _messages.Add(echo);
        string finish = (string?)choice["finish_reason"] ?? "";
        var stop = calls.Count > 0 ? AdvisorStop.ToolUse : finish switch
        {
            "stop" or "" => AdvisorStop.EndTurn,
            "length" => AdvisorStop.MaxTokens,
            "content_filter" => AdvisorStop.Refusal,
            _ => AdvisorStop.Other,
        };
        return new AdvisorReply(text.Trim(), calls, stop, tokens, finish);
    }
}
