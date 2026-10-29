using System.Net;
using System.Net.Sockets;
using Avalonia;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.Mcp;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.App;

internal static class Program
{
    /// <summary>Set in <c>mcp</c> mode when this process serves stdio itself (no window was running).</summary>
    public static (Stream In, Stream Out)? Stdio { get; private set; }

    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "mcp")
        {
            int code = McpCommand();
            if (code >= 0)
                return code;
            args = args[1..];
        }
        int exit = BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        // the window is closed and the exit steps ran (or ran out of time): nothing of ours stays behind, and a thread
        // still blocked somewhere (a hung request, a stuck child) does not keep the process alive
        ChildProcesses.KillLeftovers();
        Environment.Exit(exit);
        return exit;
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();

    /// <summary>
    /// <c>ZapretAutoTuner mcp</c> for clients that start a stdio server (Claude Desktop). A window that already serves
    /// HTTP gets the client relayed to it; otherwise this process opens the window and serves stdio itself, so the user
    /// always has the window to confirm in and the Stop button. Returns -1 to go on with the window.
    /// </summary>
    private static int McpCommand()
    {
        bool enabled, http;
        int port;
        string token;
        using (var kb = KnowledgeBase.Open(Path.Combine(AppHost.DefaultDataDir, "knowledge.db")))
        {
            var s = new AppSettings(kb);
            (enabled, http, port, token) = (s.McpEnabled, s.McpHttp, s.McpPort, s.McpEnabled ? s.McpToken : "");
        }
        if (!enabled)
        {
            Console.Error.WriteLine("MCP выключен: включите его в настройках AutoTuner. / MCP is off: turn it on in AutoTuner's settings.");
            return 2;
        }
        var stdin = Console.OpenStandardInput();
        var stdout = Console.OpenStandardOutput();
        // stdout carries the protocol only; anything else printed goes to stderr
        Console.SetOut(Console.Error);
        if (http && port > 0 && Listening(port))
        {
            try
            {
                McpBridge.RunAsync(new Uri($"http://127.0.0.1:{port}{McpHttpServer.Path}"), token, stdin, stdout, CancellationToken.None).GetAwaiter().GetResult();
                return 0;
            }
            catch (HttpRequestException e)
            {
                Console.Error.WriteLine(e.Message);
                return 1;
            }
        }
        Stdio = (stdin, stdout);
        return -1;
    }

    private static bool Listening(int port)
    {
        using var client = new TcpClient();
        try
        {
            return client.ConnectAsync(IPAddress.Loopback, port).Wait(TimeSpan.FromMilliseconds(500)) && client.Connected;
        }
        catch (AggregateException)
        {
            return false;
        }
    }
}
