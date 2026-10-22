using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using ZapretAutoTuner.Core;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// Binds the tool facade to the official C# SDK: low-level handlers for tools, resources and prompts, so the list the
/// client sees is exactly <see cref="McpTools"/> filtered by the permissions, with the pinned schemas.
/// </summary>
public static class McpServerSetup
{
    public const string ServerName = "zapret2-autotuner";

    public static string Instructions { get; } = """
        Zapret2 AutoTuner: tune zapret2 (nfqws2/winws2) strategies on this PC. Only the program's own functions: no shell,
        files, URLs or OS changes. Strategies use --lua-desync with catalog functions only and pass the Validator. Probes go
        only to the user's targets; adding a target, live experiments, commits and saving exports wait for the user's yes
        in the AutoTuner window. Start with the prompt tune_strategy or targets_list, and read ztuner://skills/*.
        """;

    public static void Configure(McpServerOptions o, AutoTunerTools tools)
    {
        o.ServerInfo = new Implementation { Name = ServerName, Title = "Zapret2 AutoTuner", Version = AppInfo.Version };
        o.ServerInstructions = Instructions;
        o.Capabilities = new ServerCapabilities
        {
            Tools = new ToolsCapability(),
            Resources = new ResourcesCapability(),
            Prompts = new PromptsCapability(),
        };
        o.Handlers.ListToolsHandler = (_, _) => ValueTask.FromResult(new ListToolsResult { Tools = [.. tools.ListTools().Select(ToTool)] });
        o.Handlers.CallToolHandler = async (ctx, ct) =>
        {
            var p = ctx.Params ?? throw new ModelContextProtocol.McpProtocolException("missing params", ModelContextProtocol.McpErrorCode.InvalidParams);
            JsonObject? args = null;
            if (p.Arguments is { } a)
            {
                args = [];
                foreach (var (k, v) in a)
                    args[k] = JsonNode.Parse(v.GetRawText());
            }
            var r = await tools.CallAsync(p.Name, args, ClientName(ctx.Server.ClientInfo?.Name), ct).ConfigureAwait(false);
            return new CallToolResult
            {
                Content = [new TextContentBlock { Text = r.Text }],
                StructuredContent = JsonSerializer.SerializeToElement(r.Data, McpJson.Default.JsonObject),
                IsError = r.IsError,
            };
        };
        o.Handlers.ListResourcesHandler = (_, _) => ValueTask.FromResult(new ListResourcesResult
        {
            Resources = [.. McpResources.List(tools.Session).Select(r => new Resource { Uri = r.Uri, Name = r.Name, Title = r.Title, Description = r.Description, MimeType = r.MimeType })],
        });
        o.Handlers.ReadResourceHandler = (ctx, _) =>
        {
            var uri = ctx.Params?.Uri ?? "";
            var r = McpResources.Read(tools.Session, uri)
                ?? throw new ModelContextProtocol.McpProtocolException($"no resource {uri}", ModelContextProtocol.McpErrorCode.InvalidParams);
            return ValueTask.FromResult(new ReadResourceResult { Contents = [new TextResourceContents { Uri = uri, MimeType = r.MimeType, Text = r.Text }] });
        };
        o.Handlers.ListPromptsHandler = (_, _) => ValueTask.FromResult(new ListPromptsResult
        {
            Prompts =
            [
                new Prompt
                {
                    Name = McpPrompts.TuneName,
                    Title = "Подобрать стратегию для X / Tune a strategy for X",
                    Description = "The safe order of the tools to find a strategy for one of the user's targets.",
                    Arguments = [new PromptArgument { Name = "target", Description = "A target from targets_list", Required = true }],
                },
            ],
        });
        o.Handlers.GetPromptHandler = (ctx, _) =>
        {
            if (ctx.Params?.Name != McpPrompts.TuneName)
                throw new ModelContextProtocol.McpProtocolException($"no prompt {ctx.Params?.Name}", ModelContextProtocol.McpErrorCode.InvalidParams);
            var target = ctx.Params.Arguments is { } pa && pa.TryGetValue("target", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() ?? "" : "";
            if (target.Length == 0 || !System.Text.RegularExpressions.Regex.IsMatch(target, McpTools.HostPattern))
                target = "<target>";
            return ValueTask.FromResult(new GetPromptResult
            {
                Description = "Подобрать стратегию для " + target,
                Messages = [new PromptMessage { Role = Role.User, Content = new TextContentBlock { Text = McpPrompts.Tune(target) } }],
            });
        };
    }

    /// <summary>The client's self-chosen name is shown in the banner and dialogs: keep it short and printable.</summary>
    public static string ClientName(string? name)
    {
        var clean = new string([.. (name ?? "").Where(c => !char.IsControl(c)).Take(48)]).Trim();
        return clean.Length == 0 ? "mcp" : clean;
    }

    public static Tool ToTool(McpToolDefinition d) => new()
    {
        Name = d.Name,
        Description = d.Description + (d.Confirms ? " Needs the user's confirmation in the AutoTuner window." : ""),
        InputSchema = JsonSerializer.SerializeToElement(d.InputSchema, McpJson.Default.JsonObject),
    };

    /// <summary>Serves one MCP session over a pair of streams (stdio, or pipes in tests) until the client leaves.</summary>
    public static async Task RunStreamAsync(AutoTunerTools tools, Stream input, Stream output, CancellationToken ct)
    {
        var options = new McpServerOptions();
        Configure(options, tools);
        await using var transport = new StreamServerTransport(input, output, ServerName);
        await using var server = McpServer.Create(transport, options);
        await server.RunAsync(ct).ConfigureAwait(false);
    }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(JsonObject))]
internal sealed partial class McpJson : System.Text.Json.Serialization.JsonSerializerContext;
