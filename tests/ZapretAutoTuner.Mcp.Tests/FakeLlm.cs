using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Mcp.Tests;

/// <summary>A provider on the other end of HttpClient: answers in order, records every request.</summary>
internal sealed class FakeLlm : HttpMessageHandler
{
    private readonly Queue<Func<JsonObject, CancellationToken, Task<string>>> _answers = new();

    public List<(HttpRequestMessage Request, JsonObject Body)> Requests { get; } = [];

    /// <summary>Repeats the last answer when the queue runs out.</summary>
    private Func<JsonObject, CancellationToken, Task<string>>? _last;

    public FakeLlm Then(string json) => Then((_, _) => Task.FromResult(json));

    public FakeLlm Then(Func<JsonObject, CancellationToken, Task<string>> answer)
    {
        _answers.Enqueue(answer);
        return this;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!.AsObject();
        lock (Requests)
            Requests.Add((request, body));
        var answer = _answers.Count > 0 ? (_last = _answers.Dequeue()) : _last ?? throw new InvalidOperationException("no answer queued");
        var json = await answer(body, ct);
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }

    public HttpClient Client() => new(this, disposeHandler: false);

    // ---- Claude Messages API answers

    public static string Claude(string stop, params JsonObject[] content) => Claude(stop, 100, content);

    public static string Claude(string stop, int inputTokens, params JsonObject[] content) => new JsonObject
    {
        ["id"] = "msg_" + Guid.NewGuid().ToString("N")[..8],
        ["type"] = "message",
        ["role"] = "assistant",
        ["model"] = "claude-opus-5-5",
        ["content"] = new JsonArray([.. content]),
        ["stop_reason"] = stop,
        ["stop_sequence"] = null,
        ["usage"] = new JsonObject { ["input_tokens"] = inputTokens, ["output_tokens"] = 20, ["cache_creation_input_tokens"] = 0, ["cache_read_input_tokens"] = 0 },
    }.ToJsonString();

    public static JsonObject Text(string t) => new() { ["type"] = "text", ["text"] = t };

    public static JsonObject Thinking(string signature) => new() { ["type"] = "thinking", ["thinking"] = "", ["signature"] = signature };

    public static JsonObject ToolUse(string id, string name, string input = "{}") => new() { ["type"] = "tool_use", ["id"] = id, ["name"] = name, ["input"] = JsonNode.Parse(input) };

    // ---- OpenAI-compatible answers

    public static string OpenAi(string finish, string? content, params (string Id, string Name, string Args)[] calls)
    {
        var msg = new JsonObject { ["role"] = "assistant", ["content"] = content };
        if (calls.Length > 0)
        {
            msg["tool_calls"] = new JsonArray([.. calls.Select(c => (JsonNode)new JsonObject
            {
                ["id"] = c.Id,
                ["type"] = "function",
                ["function"] = new JsonObject { ["name"] = c.Name, ["arguments"] = c.Args },
            })]);
        }
        return new JsonObject
        {
            ["id"] = "chatcmpl-1",
            ["object"] = "chat.completion",
            ["choices"] = new JsonArray(new JsonObject { ["index"] = 0, ["message"] = msg, ["finish_reason"] = finish }),
            ["usage"] = new JsonObject { ["prompt_tokens"] = 300, ["completion_tokens"] = 30, ["total_tokens"] = 330 },
        }.ToJsonString();
    }
}
