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

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };
}
