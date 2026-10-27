using System.IO.Pipelines;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace ZapretAutoTuner.Mcp.Tests;

/// <summary>The SDK binding end to end: stdio (as pipes), Streamable HTTP with its token, and the stdio bridge to HTTP.</summary>
public sealed class TransportTests
{
    private static readonly string Init = """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}""";

    [Fact]
    public async Task StdioRoundTrip()
    {
        using var rig = new Rig();
        var toServer = new Pipe();
        var toClient = new Pipe();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var server = McpServerSetup.RunStreamAsync(rig.Tools, toServer.Reader.AsStream(), toClient.Writer.AsStream(), cts.Token);

        await using (var client = await McpClient.CreateAsync(new StreamClientTransport(toServer.Writer.AsStream(), toClient.Reader.AsStream()), cancellationToken: cts.Token))
        {
            Assert.Equal(McpServerSetup.ServerName, client.ServerInfo.Name);
            var tools = await client.ListToolsAsync(cancellationToken: cts.Token);
            Assert.Equal(7, tools.Count);
            Assert.Contains(tools, t => t.Name == "strategy_validate");

            var r = await client.CallToolAsync("targets_list", new Dictionary<string, object?>(), cancellationToken: cts.Token);
            Assert.NotEqual(true, r.IsError);
            Assert.Contains("blocked.example", ((TextContentBlock)r.Content[0]).Text);
            Assert.Equal(System.Text.Json.JsonValueKind.Object, r.StructuredContent?.ValueKind);

            var denied = await client.CallToolAsync("trial_run", new Dictionary<string, object?> { ["target"] = "blocked.example", ["strategy"] = "--lua-desync=multisplit" }, cancellationToken: cts.Token);
            Assert.True(denied.IsError);

            var resources = await client.ListResourcesAsync(cancellationToken: cts.Token);
            Assert.Contains(resources, x => x.Uri == "ztuner://skills/nfqws2-lua");
            var skill = await client.ReadResourceAsync("ztuner://skills/dpi-diagnostics", cancellationToken: cts.Token);
            Assert.Contains("dpi-diagnostics", ((TextResourceContents)skill.Contents[0]).Text);

            var prompts = await client.ListPromptsAsync(cancellationToken: cts.Token);
            Assert.Equal(McpPrompts.TuneName, Assert.Single(prompts).Name);
            var prompt = await client.GetPromptAsync(McpPrompts.TuneName, new Dictionary<string, object?> { ["target"] = "blocked.example" }, cancellationToken: cts.Token);
            Assert.Contains("blocked.example", ((TextContentBlock)prompt.Messages[0].Content).Text);
        }
        toServer.Writer.Complete();
        await server.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Contains(rig.Session.Audit.Entries, e => e.Tool == "targets_list");
    }

    [Fact]
    public async Task HttpRefusesAWrongOrMissingToken()
    {
        using var rig = new Rig();
        var token = McpHttpServer.NewToken();
        await using var http = await McpHttpServer.StartAsync(rig.Tools, 0, token);
        Assert.NotEqual(0, http.Port);
        using var client = new HttpClient();

        async Task<HttpStatusCode> Post(string? bearer, string? host = null)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, http.Endpoint) { Content = new StringContent(Init, Encoding.UTF8, "application/json") };
            req.Headers.Accept.ParseAdd("application/json");
            req.Headers.Accept.ParseAdd("text/event-stream");
            if (bearer is not null)
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            if (host is not null)
                req.Headers.Host = host;
            using var r = await client.SendAsync(req);
            return r.StatusCode;
        }

        Assert.Equal(HttpStatusCode.Unauthorized, await Post(null));
        Assert.Equal(HttpStatusCode.Unauthorized, await Post("wrong-token"));
        Assert.Equal(HttpStatusCode.Unauthorized, await Post(token[..^1]));
        Assert.Equal(HttpStatusCode.Forbidden, await Post(token, "evil.example"));
        Assert.Equal(HttpStatusCode.OK, await Post(token));
        Assert.Empty(rig.Session.Audit.Entries);

        await using var mcp = await McpClient.CreateAsync(new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = http.Endpoint,
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer " + token },
        }));
        var tools = await mcp.ListToolsAsync();
        Assert.Equal(7, tools.Count);
    }

    [Fact]
    public async Task TheStdioBridgeRelaysToTheRunningInstance()
    {
        using var rig = new Rig(new McpPermissions(Probes: true));
        var token = McpHttpServer.NewToken();
        await using var http = await McpHttpServer.StartAsync(rig.Tools, 0, token);
        var toServer = new Pipe();
        var toClient = new Pipe();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var bridge = McpBridge.RunAsync(http.Endpoint, token, toServer.Reader.AsStream(), toClient.Writer.AsStream(), cts.Token);
        await using (var client = await McpClient.CreateAsync(new StreamClientTransport(toServer.Writer.AsStream(), toClient.Reader.AsStream()), cancellationToken: cts.Token))
        {
            var tools = await client.ListToolsAsync(cancellationToken: cts.Token);
            Assert.Contains(tools, t => t.Name == "trial_run");
            var r = await client.CallToolAsync("strategy_validate", new Dictionary<string, object?> { ["strategy"] = "--lua-desync=multisplit:pos=1" }, cancellationToken: cts.Token);
            Assert.NotEqual(true, r.IsError);
        }
        toServer.Writer.Complete();
        await bridge.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public void ClaudeDesktopSnippetRunsTheStdioMode()
    {
        var json = System.Text.Json.Nodes.JsonNode.Parse(McpClientConfig.ClaudeDesktop(@"C:\Program Files\AutoTuner\ZapretAutoTuner.exe"))!;
        var entry = json["mcpServers"]![McpServerSetup.ServerName]!;
        Assert.Equal(@"C:\Program Files\AutoTuner\ZapretAutoTuner.exe", (string?)entry["command"]);
        Assert.Equal("mcp", (string?)entry["args"]![0]);
    }

    [Theory]
    [InlineData(null, "mcp")]
    [InlineData("  ", "mcp")]
    [InlineData("claude-ai", "claude-ai")]
    [InlineData("evil\nYES\u0007", "evilYES")]
    public void ClientNamesAreCleanedForTheBanner(string? name, string expected) =>
        Assert.Equal(expected, McpServerSetup.ClientName(name));
}
