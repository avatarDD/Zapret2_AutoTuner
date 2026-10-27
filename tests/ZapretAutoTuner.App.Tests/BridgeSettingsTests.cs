using Avalonia.Headless.XUnit;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.App.ViewModels;

namespace ZapretAutoTuner.App.Tests;

/// <summary>PLAN 4a.7: the Settings section of the browser extension bridge.</summary>
public sealed class BridgeSettingsTests
{
    private const string Ext = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";

    /// <summary>A new host per test, never disposed (see ReviewFixTests: the view models keep their language subscriptions).</summary>
    private readonly AppHost? _host = new(Path.Combine(Path.GetTempPath(), "zt-bridge-" + Guid.NewGuid().ToString("N")));

    [AvaloniaFact]
    public void TheBridgeIsClosedByDefault()
    {
        var main = new MainViewModel(_host!);
        var s = main.Settings;
        Assert.False(s.PermRouterProxy);
        Assert.False(_host!.Settings.McpPermissions.RouterProxy);
        Assert.Equal("", s.BridgeOriginsText);
        Assert.True(s.BridgeOriginsEmpty);
        Assert.Empty(_host.Settings.McpBridgeOrigins);
        Assert.Empty(main.Mcp.BridgeOrigins);
        main.Mcp.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    [AvaloniaFact]
    public void OriginsAreValidatedKeptAndHandedToTheServer()
    {
        var main = new MainViewModel(_host!);
        var s = main.Settings;
        s.BridgeOriginsText = Ext + "\nhttps://claude.ai\nmoz-extension://0a1b2c3d-0000-4000-8000-123456789abc";
        Assert.Equal([Ext, "moz-extension://0a1b2c3d-0000-4000-8000-123456789abc"], _host!.Settings.McpBridgeOrigins);
        Assert.Equal(_host.Settings.McpBridgeOrigins, main.Mcp.BridgeOrigins);
        Assert.Contains("https://claude.ai", s.BridgeOriginsError, StringComparison.Ordinal);
        Assert.False(s.BridgeOriginsEmpty);

        // a fresh page reads them back
        var again = new MainViewModel(_host).Settings;
        Assert.Contains(Ext, again.BridgeOriginsText, StringComparison.Ordinal);

        s.BridgeOriginsText = "";
        Assert.Empty(_host.Settings.McpBridgeOrigins);
        Assert.Equal("", s.BridgeOriginsError);
        main.Mcp.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    [AvaloniaFact]
    public void RouterProxyIsAPermissionAndSaysWhenZapretGuiIsMissing()
    {
        var main = new MainViewModel(_host!);
        var s = main.Settings;
        s.McpEnabled = true;
        s.PermRouterProxy = true;
        Assert.True(_host!.Settings.McpPermissions.RouterProxy);
        Assert.True(s.BridgeGuiMissing);
        s.GuiUrl = "http://192.168.2.1:8080";
        s.GuiToken = "gui-token";
        Assert.False(s.BridgeGuiMissing);
        main.Mcp.StopAsync().GetAwaiter().GetResult();
        Avalonia.Threading.Dispatcher.UIThread.RunJobs();
        main.Mcp.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    [AvaloniaFact]
    public void SnippetsShowTheTokenOnlyWhenAsked()
    {
        var main = new MainViewModel(_host!);
        var s = main.Settings;
        Assert.Contains("\"stdio\"", s.BridgeProxyStdioSnippet, StringComparison.Ordinal);
        Assert.Contains("\"mcp\"", s.BridgeProxyStdioSnippet, StringComparison.Ordinal);
        Assert.Equal(Loc.Loc.I["mcp.bridge_no_http"], s.BridgeDirectSnippet);

        _host!.Settings.McpPort = 4711;
        Assert.Contains("http://127.0.0.1:4711/mcp", s.BridgeProxyHttpSnippet, StringComparison.Ordinal);
        Assert.Contains("streamable-http", s.BridgeProxyHttpSnippet, StringComparison.Ordinal);
        Assert.Contains("http://127.0.0.1:4711/mcp/sse", s.BridgeDirectSnippet, StringComparison.Ordinal);
        Assert.DoesNotContain(s.McpToken, s.BridgeProxyHttpSnippet, StringComparison.Ordinal);
        Assert.DoesNotContain(s.McpToken, s.BridgeDirectSnippet, StringComparison.Ordinal);
        s.BridgeRevealToken = true;
        Assert.Contains("Bearer " + s.McpToken, s.BridgeProxyHttpSnippet, StringComparison.Ordinal);
        Assert.Contains("Bearer " + s.McpToken, s.BridgeDirectSnippet, StringComparison.Ordinal);
        main.Mcp.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
