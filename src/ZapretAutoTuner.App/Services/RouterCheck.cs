using ZapretAutoTuner.Delivery;

namespace ZapretAutoTuner.App.Services;

/// <summary>
/// "Проверить подключение" in Settings: reaches zapret-gui and the router's SSH with what the user typed, before any
/// install or trial needs them (UX audit P1: an error was only seen after "Установить"). Read-only: it lists one
/// resource kind of zapret-gui, opens its MCP session and logs in over SSH, and changes nothing on the router. A new SSH
/// key is only shown here; it is remembered where the user says yes to a delivery (AGENTS.md rule 7).
/// </summary>
public static class RouterCheck
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    public static async Task<IReadOnlyList<string>> RunAsync(AppSettings settings, CancellationToken ct)
    {
        var L = Loc.Loc.I;
        var lines = new List<string>();
        var gui = settings.GuiUrl.Trim();
        var ssh = settings.RouterHost.Trim();
        if (gui.Length == 0 && ssh.Length == 0)
            return [L["router.check_nothing"]];
        if (gui.Length > 0)
        {
            if (ZapretGuiClient.BaseAddress(gui) is not { } baseAddress)
            {
                lines.Add("✖ " + L.F("export.bad_url", gui));
            }
            else
            {
                lines.Add(await GuiAsync(baseAddress, ct).ConfigureAwait(false));
                if (settings.GuiToken.Trim() is { Length: > 0 } token)
                    lines.Add(await McpAsync(baseAddress, token, ct).ConfigureAwait(false));
                else
                    lines.Add("· " + L["router.check_no_token"]);
            }
        }
        if (ssh.Length > 0)
            lines.Add(await SshAsync(settings, ssh, ct).ConfigureAwait(false));
        return lines;
    }

    private static async Task<string> GuiAsync(Uri baseAddress, CancellationToken ct)
    {
        var L = Loc.Loc.I;
        try
        {
            using var http = new HttpClient { BaseAddress = baseAddress, Timeout = Timeout };
            var password = RouterCredentials.GuiPassword;
            var client = new ZapretGuiClient(http, null, password.Length == 0 ? null : password);
            var lists = await client.ListAsync(Core.Resources.ResourceKind.Hostlist, ct).ConfigureAwait(false);
            return "✓ " + L.F("router.check_gui_ok", baseAddress, lists.Count);
        }
        catch (Exception e) when (e is HttpRequestException or ZapretGuiException or TaskCanceledException or System.Text.Json.JsonException or InvalidOperationException)
        {
            return "✖ " + L.F("router.check_gui_failed", baseAddress, e.Message);
        }
    }

    private static async Task<string> McpAsync(Uri baseAddress, string token, CancellationToken ct)
    {
        var L = Loc.Loc.I;
        try
        {
            using var http = new HttpClient { BaseAddress = baseAddress, Timeout = Timeout };
            var mcp = new ZapretGuiMcp(http, token);
            var tools = await mcp.ToolsAsync(ct).ConfigureAwait(false);
            return "✓ " + L.F("router.check_mcp_ok", tools.Count);
        }
        catch (Exception e) when (e is HttpRequestException or ZapretGuiException or TaskCanceledException or System.Text.Json.JsonException or InvalidOperationException)
        {
            return "✖ " + L.F("router.check_mcp_failed", e.Message);
        }
    }

    private static async Task<string> SshAsync(AppSettings settings, string host, CancellationToken ct)
    {
        var L = Loc.Loc.I;
        var target = new SshTarget { Host = host, Password = RouterCredentials.RouterPassword.Length == 0 ? null : RouterCredentials.RouterPassword, Timeout = Timeout };
        try
        {
            var seen = await SshRemoteShell.HostKeyAsync(target, ct).ConfigureAwait(false);
            var check = HostKeys.Check(settings.RouterHostKey(host, target.Port), seen);
            if (check == HostKeyCheck.Mismatch)
                return "✖ " + L.F("router.check_ssh_mismatch", host, seen);
            if (target.Password is null)
                return "· " + L.F("router.check_ssh_no_password", host, seen);
            using var sh = await SshRemoteShell.ConnectAsync(target with { TrustHostKey = fp => fp == seen }, ct).ConfigureAwait(false);
            return "✓ " + L.F(check == HostKeyCheck.FirstUse ? "router.check_ssh_ok_new" : "router.check_ssh_ok", host, seen);
        }
        catch (Exception e) when (e is Renci.SshNet.Common.SshException or IOException or System.Net.Sockets.SocketException or OperationCanceledException
            or ArgumentException or InvalidOperationException)
        {
            return "✖ " + L.F("router.check_ssh_failed", host, e.Message);
        }
    }
}
