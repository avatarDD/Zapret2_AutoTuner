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
/// Streamable HTTP on 127.0.0.1 only, with a bearer token generated on this machine, plus the legacy SSE transport
/// (<c>/mcp/sse</c> and <c>/mcp/message</c>) for MCP bridges that do not speak Streamable HTTP. Requests from a browser
/// page (an Origin or Host that is not this loopback endpoint) are refused, so a web page cannot reach it by DNS
/// rebinding; the one exception is a browser extension whose Origin the user allowed in Settings (PLAN 4a.7): it gets
/// CORS answers, and still needs the token. Stopping it tears down every session.
/// </summary>
public sealed class McpHttpServer : IAsyncDisposable
{
    public const string Path = "/mcp";

    /// <summary>The legacy SSE stream (the SDK maps it under <see cref="Path"/>); messages go to <c>/mcp/message</c>.</summary>
    public const string SsePath = Path + "/sse";

    private readonly WebApplication _app;

    private McpHttpServer(WebApplication app, int port)
    {
        _app = app;
        Port = port;
    }

    public int Port { get; }

    public Uri Endpoint => new($"http://127.0.0.1:{Port}{Path}");

    public Uri SseEndpoint => new($"http://127.0.0.1:{Port}{SsePath}");

    /// <summary>A new random token (32 bytes, base64url).</summary>
    public static string NewToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <param name="port">0 picks a free port.</param>
    /// <param name="allowedOrigins">
    /// The browser extensions' Origins the user allowed (read on every request, so a change acts at once); null or
    /// empty: every foreign Origin is refused.
    /// </param>
    public static async Task<McpHttpServer> StartAsync(AutoTunerTools tools, int port, string token, Func<IReadOnlyCollection<string>>? allowedOrigins = null, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(token))
            throw new ArgumentException("a token is required", nameof(token));
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, port));
        // legacy SSE keeps a session between GET /sse and POST /message, so sessions are kept for initialize clients
        // (Mcp-Session-Id); it has no request backpressure, so the SDK marks it obsolete: here every client holds the
        // local token and sits on this machine (loopback only), the trusted-client case the SDK allows it for
        builder.Services.AddMcpServer(o => McpServerSetup.Configure(o, tools)).WithHttpTransport(o =>
        {
            o.SessionMode = ModelContextProtocol.AspNetCore.HttpServerSessionMode.StatefulForInitializeClients;
#pragma warning disable MCP9004
            o.EnableLegacySse = true;
#pragma warning restore MCP9004
        });
        var app = builder.Build();
        var expected = Encoding.UTF8.GetBytes(token);
        app.Use(async (ctx, next) =>
        {
            int local = ctx.Connection.LocalPort;
            var host = ctx.Request.Host.Host;
            var origin = ctx.Request.Headers.Origin.ToString();
            bool foreign = origin.Length > 0 && origin != $"http://127.0.0.1:{local}" && origin != $"http://localhost:{local}";
            bool extension = foreign && BridgeOrigins.Allowed(allowedOrigins?.Invoke(), origin);
            if (host is not ("127.0.0.1" or "localhost") || (foreign && !extension))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
            if (extension)
            {
                var h = ctx.Response.Headers;
                h.AccessControlAllowOrigin = origin;
                h.Vary = "Origin";
                h.AccessControlExposeHeaders = "Mcp-Session-Id, MCP-Protocol-Version, WWW-Authenticate";
                // the preflight carries no token: it only learns what the real request may send
                if (HttpMethods.IsOptions(ctx.Request.Method) && ctx.Request.Headers.ContainsKey("Access-Control-Request-Method"))
                {
                    h.AccessControlAllowMethods = "GET, POST, DELETE, OPTIONS";
                    h.AccessControlAllowHeaders = "Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID";
                    h.AccessControlMaxAge = "600";
                    if (ctx.Request.Headers.ContainsKey("Access-Control-Request-Private-Network"))
                        h["Access-Control-Allow-Private-Network"] = "true";
                    ctx.Response.StatusCode = StatusCodes.Status204NoContent;
                    return;
                }
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
/// The Origins of browser extensions the user may allow to call the HTTP transport (PLAN 4a.7): only extension schemes
/// with an id, never a web site, so a page (claude.ai included) cannot call it directly.
/// </summary>
public static partial class BridgeOrigins
{
    [System.Text.RegularExpressions.GeneratedRegex("^(chrome-extension|moz-extension|safari-web-extension|ms-browser-extension)://[a-z0-9][a-z0-9-]{0,63}$")]
    private static partial System.Text.RegularExpressions.Regex Format();

    /// <summary>The Origin as compared (lower case, no trailing slash), or null when it is not an extension's Origin.</summary>
    public static string? Normalize(string? text)
    {
        var o = (text ?? "").Trim().TrimEnd('/').ToLowerInvariant();
        return Format().IsMatch(o) ? o : null;
    }

    /// <summary>Splits the Settings text (one per line, or separated by spaces or commas) into valid Origins and rejected entries.</summary>
    public static (IReadOnlyList<string> Valid, IReadOnlyList<string> Invalid) Parse(string? text)
    {
        var valid = new List<string>();
        var invalid = new List<string>();
        foreach (var part in (text ?? "").Split(['\n', '\r', ',', ' ', '\t', ';'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (Normalize(part) is { } o)
            {
                if (!valid.Contains(o))
                    valid.Add(o);
            }
            else
                invalid.Add(part);
        }
        return (valid, invalid);
    }

    public static bool Allowed(IReadOnlyCollection<string>? allowed, string origin) =>
        allowed is { Count: > 0 } && Normalize(origin) is { } o && allowed.Any(a => Normalize(a) == o);
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
