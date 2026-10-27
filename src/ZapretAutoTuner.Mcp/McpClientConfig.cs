using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Mcp;

/// <summary>Snippets the settings page shows for connecting a client; nothing is written to the client's files.</summary>
public static class McpClientConfig
{
    /// <summary>The <c>mcpServers</c> entry of claude_desktop_config.json: this program in its stdio mode.</summary>
    public static string ClaudeDesktop(string executable)
    {
        var entry = new JsonObject
        {
            ["command"] = executable,
            ["args"] = new JsonArray("mcp"),
        };
        var root = new JsonObject { ["mcpServers"] = new JsonObject { [McpServerSetup.ServerName] = entry } };
        return root.ToJsonString(Indented);
    }

    /// <summary>
    /// An entry of the <c>mcpServers</c> config of a local MCP proxy for browser extensions (the format of
    /// <c>@srbhptl39/mcp-superassistant-proxy</c>: <c>type</c>, <c>command</c>/<c>args</c> or <c>url</c>/<c>headers</c>):
    /// this program in its stdio mode, which relays to the running window.
    /// </summary>
    public static string ProxyStdio(string executable) => Root(new JsonObject
    {
        ["type"] = "stdio",
        ["command"] = executable,
        ["args"] = new JsonArray("mcp"),
    });

    /// <summary>The same proxy config entry over our Streamable HTTP endpoint with the bearer token.</summary>
    public static string ProxyHttp(Uri endpoint, string token) => Root(new JsonObject
    {
        ["type"] = "streamable-http",
        ["url"] = endpoint.ToString(),
        ["headers"] = new JsonObject { ["Authorization"] = "Bearer " + token },
    });

    /// <summary>What an extension that connects by itself needs: the URLs of both transports and the header.</summary>
    public static string Direct(Uri endpoint, Uri sse, string token) =>
        $"Streamable HTTP: {endpoint}\nSSE (legacy): {sse}\nAuthorization: Bearer {token}";

    private static string Root(JsonObject entry) =>
        new JsonObject { ["mcpServers"] = new JsonObject { [McpServerSetup.ServerName] = entry } }.ToJsonString(Indented);

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };
}
