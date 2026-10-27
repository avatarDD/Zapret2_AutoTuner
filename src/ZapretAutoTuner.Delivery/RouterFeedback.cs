using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Monitor;

namespace ZapretAutoTuner.Delivery;

/// <summary>What a router says about the strategy it runs (PLAN 7.4).</summary>
public sealed record RouterFeedbackSnapshot(IReadOnlyList<AutoHostlistEntry> Entries, IReadOnlyList<string> AutoList, IReadOnlyList<string> EngineLog, DateTime Read)
{
    /// <summary>Hosts that fail on the router now: they go to the repair, new ones are offered for the strategy.</summary>
    public List<(string Host, int Failures, int Working, bool Added)> Failing(DateTime since) =>
        AutoHostlistLog.Summary(Entries, since).Where(x => x.Failures > x.Working).ToList();
}

/// <summary>
/// Reads the router's feedback, never writes (AGENTS.md rule 7). Keenetic: the autohostlist debug log and
/// <c>auto.list</c> of nfqws2-keenetic over SSH (they exist in MODE_AUTO). zapret-gui: the nfqws lines of its log over MCP.
/// </summary>
public static class RouterFeedback
{
    public const string KeeneticLog = "/opt/var/log/nfqws2.log";
    public const string KeeneticAutoList = "/opt/etc/nfqws2/lists/auto.list";

    /// <summary>How much of the log tail is read: the file grows forever on the router.</summary>
    public const int TailBytes = 256 * 1024;

    public static async Task<RouterFeedbackSnapshot> FromKeeneticAsync(IRemoteShell shell, CancellationToken ct = default)
    {
        var (_, log) = await shell.RunAsync($"tail -c {TailBytes} {SshRemoteShell.Quote(KeeneticLog)} 2>/dev/null", ct).ConfigureAwait(false);
        var list = await shell.ReadAsync(KeeneticAutoList, ct).ConfigureAwait(false);
        var auto = list is null ? [] : Lines(Encoding.UTF8.GetString(list));
        return new RouterFeedbackSnapshot(AutoHostlistLog.Parse(log), auto, [], DateTime.Now);
    }

    /// <param name="since">Unix time of the last read: only newer lines.</param>
    public static async Task<RouterFeedbackSnapshot> FromZapretGuiAsync(ZapretGuiMcp mcp, double since = 0, CancellationToken ct = default)
    {
        var args = new JsonObject { ["source"] = "nfqws", ["limit"] = 200 };
        if (since > 0)
            args["since"] = since;
        var r = await mcp.CallAsync("logs_tail", args, ct).ConfigureAwait(false);
        var lines = (r["items"] as JsonArray ?? []).OfType<JsonObject>().Select(e => (string?)e["message"]).OfType<string>().ToList();
        // the GUI relays the engine's autohostlist lines into its log as they are
        return new RouterFeedbackSnapshot(AutoHostlistLog.Parse(string.Join('\n', lines)), [], lines, DateTime.Now);
    }

    private static List<string> Lines(string text) =>
        text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).Select(l => l.ToLower(CultureInfo.InvariantCulture)).Distinct().ToList();
}
