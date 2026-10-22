using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// Streamable HTTP on 127.0.0.1 only, with a bearer token generated on this machine. Requests from a browser page
/// (an Origin or Host that is not this loopback endpoint) are refused, so a web page cannot reach it by DNS rebinding.
/// Stopping it tears down every session.
/// </summary>
public sealed class McpHttpServer : IAsyncDisposable
{
    public const string Path = "/mcp";

    private readonly WebApplication _app;

    private McpHttpServer(WebApplication app, int port)
    {
        _app = app;
        Port = port;
    }

    public int Port { get; }

    public Uri Endpoint => new($"http://127.0.0.1:{Port}{Path}");

    /// <summary>A new random token (32 bytes, base64url).</summary>
    public static string NewToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <param name="port">0 picks a free port.</param>
    public static async Task<McpHttpServer> StartAsync(AutoTunerTools tools, int port, string token, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(token))
            throw new ArgumentException("a token is required", nameof(token));
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, port));
        builder.Services.AddMcpServer(o => McpServerSetup.Configure(o, tools)).WithHttpTransport();
        var app = builder.Build();
        var expected = Encoding.UTF8.GetBytes(token);
        app.Use(async (ctx, next) =>
        {
            int local = ctx.Connection.LocalPort;
            var host = ctx.Request.Host.Host;
            if (host is not ("127.0.0.1" or "localhost") || (ctx.Request.Headers.Origin is { Count: > 0 } origin
                && origin.ToString() is var o && o != $"http://127.0.0.1:{local}" && o != $"http://localhost:{local}"))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
            var auth = ctx.Request.Headers.Authorization.ToString();
            var given = auth.StartsWith("Bearer ", StringComparison.Ordinal) ? Encoding.UTF8.GetBytes(auth[7..].Trim()) : [];
            if (!CryptographicOperations.FixedTimeEquals(given, expected))
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                ctx.Response.Headers.WWWAuthenticate = "Bearer";
                return;
            }
            await next(ctx).ConfigureAwait(false);
        });
        app.MapMcp(Path);
        await app.StartAsync(ct).ConfigureAwait(false);
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses.FirstOrDefault();
        int actual = address is not null && Uri.TryCreate(address, UriKind.Absolute, out var u) ? u.Port : port;
        return new McpHttpServer(app, actual);
    }

    public async Task StopAsync()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await _app.StopAsync(cts.Token).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await StopAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        await _app.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>
/// <c>ZapretAutoTuner mcp</c> while the window already runs with HTTP on: stdio from the client is relayed to that
/// instance, so there is one AutoTuner, one Agent and one place to confirm.
/// </summary>
public static class McpBridge
{
    public static async Task RunAsync(Uri endpoint, string token, Stream input, Stream output, CancellationToken ct)
    {
        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = endpoint,
            TransportMode = HttpTransportMode.StreamableHttp,
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer " + token },
        });
        await using var client = await McpClient.CreateAsync(transport, cancellationToken: ct).ConfigureAwait(false);
        var options = new McpServerOptions
        {
            ServerInfo = new Implementation { Name = McpServerSetup.ServerName, Version = Core.AppInfo.Version },
            ServerInstructions = McpServerSetup.Instructions,
            Capabilities = new ServerCapabilities { Tools = new ToolsCapability(), Resources = new ResourcesCapability(), Prompts = new PromptsCapability() },
        };
        options.Handlers.ListToolsHandler = async (c, t) => await client.ListToolsAsync(c.Params ?? new ListToolsRequestParams(), t).ConfigureAwait(false);
        options.Handlers.CallToolHandler = async (c, t) => await client.CallToolAsync(c.Params!, t).ConfigureAwait(false);
        options.Handlers.ListResourcesHandler = async (c, t) => await client.ListResourcesAsync(c.Params ?? new ListResourcesRequestParams(), t).ConfigureAwait(false);
        options.Handlers.ReadResourceHandler = async (c, t) => await client.ReadResourceAsync(c.Params!, t).ConfigureAwait(false);
        options.Handlers.ListPromptsHandler = async (c, t) => await client.ListPromptsAsync(c.Params ?? new ListPromptsRequestParams(), t).ConfigureAwait(false);
        options.Handlers.GetPromptHandler = async (c, t) => await client.GetPromptAsync(c.Params!, t).ConfigureAwait(false);
        await using var server = McpServer.Create(new StreamServerTransport(input, output, McpServerSetup.ServerName), options);
        await server.RunAsync(ct).ConfigureAwait(false);
    }
}
