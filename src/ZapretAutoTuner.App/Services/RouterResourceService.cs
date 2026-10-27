using ZapretAutoTuner.Core.Resources;
using ZapretAutoTuner.Delivery;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.App.Services;

/// <summary>The router resources go to: whichever the user configured, prepared for the confirmation dialog.</summary>
public interface IRouterResourceProvider
{
    /// <summary>"zapret-gui http://…" or "nfqws2-keenetic host", or null when no router is configured.</summary>
    string? Describe();

    /// <summary>The operation with its plan; nothing on the router changes until its RunConfirmedAsync.</summary>
    Task<RouterResourceOperation> PrepareAsync(RouterResourceAction action, ResourceKind kind, string name, CancellationToken ct);
}

/// <summary>Router passwords the user typed in this run; never written to the knowledge base.</summary>
public static class RouterCredentials
{
    public static string GuiPassword { get; set; } = "";

    public static string RouterPassword { get; set; } = "";
}

/// <summary>
/// Resources on the router the settings name (PLAN 4a.5): zapret-gui when its address is set, otherwise
/// nfqws2-keenetic over SSH when a router host is set. The content is what may leave the PC
/// (<see cref="ResourceStore.ForDelivery"/>: a Lua script only in its approved version). SSH keys follow the wizard's
/// trust on first use: a changed key refuses, a new one is shown in the plan and remembered when the user said yes.
/// </summary>
public sealed class RouterResourceService(AppHost host) : IRouterResourceProvider, IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    private readonly Lock _lock = new();
    private readonly Dictionary<Uri, HttpClient> _clients = [];

    /// <summary>One client per zapret-gui address, reused by every operation and disposed with the service.</summary>
    private HttpClient ClientFor(Uri baseAddress)
    {
        lock (_lock)
        {
            if (!_clients.TryGetValue(baseAddress, out var http))
                _clients[baseAddress] = http = new HttpClient { BaseAddress = baseAddress, Timeout = Timeout };
            return http;
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            foreach (var c in _clients.Values)
                c.Dispose();
            _clients.Clear();
        }
    }

    public string? Describe()
    {
        if (ZapretGuiClient.BaseAddress(host.Settings.GuiUrl) is { } gui)
            return $"{RouterResources.ZapretGui} {gui}";
        return string.IsNullOrWhiteSpace(host.Settings.RouterHost) ? null : $"{RouterResources.Keenetic} {host.Settings.RouterHost.Trim()}";
    }

    public async Task<RouterResourceOperation> PrepareAsync(RouterResourceAction action, ResourceKind kind, string name, CancellationToken ct)
    {
        var data = action == RouterResourceAction.Put ? host.Resources.ForDelivery(kind, name) : null;
        if (ZapretGuiClient.BaseAddress(host.Settings.GuiUrl) is { } baseAddress)
        {
            var http = ClientFor(baseAddress);
            var password = RouterCredentials.GuiPassword;
            var client = new ZapretGuiClient(http, null, string.IsNullOrEmpty(password) ? null : password);
            return data is not null
                ? await RouterResources.GuiPutAsync(client, data, ct).ConfigureAwait(false)
                : await RouterResources.GuiDeleteAsync(client, kind, name, ct).ConfigureAwait(false);
        }
        if (string.IsNullOrWhiteSpace(host.Settings.RouterHost))
            throw new InvalidOperationException(Loc.Loc.I["resources.no_router"]);
        var target = new SshTarget { Host = host.Settings.RouterHost.Trim(), Password = RouterCredentials.RouterPassword };
        var seen = await SshRemoteShell.HostKeyAsync(target, ct).ConfigureAwait(false);
        var remembered = host.Settings.RouterHostKey(target.Host, target.Port);
        var check = HostKeys.Check(remembered, seen);
        if (check == HostKeyCheck.Mismatch)
            throw new InvalidOperationException(Loc.Loc.I.F("export.hostkey_mismatch", target.Host, remembered, seen));
        async Task<IRemoteShell> Connect(CancellationToken c)
        {
            var sh = await SshRemoteShell.ConnectAsync(target with { TrustHostKey = fp => fp == seen }, c).ConfigureAwait(false);
            if (check == HostKeyCheck.FirstUse)
                host.Settings.RememberRouterHostKey(target.Host, target.Port, seen);
            return sh;
        }
        var op = data is not null ? RouterResources.KeeneticPut(Connect, data) : RouterResources.KeeneticDelete(Connect, kind, name);
        // the key the user trusts by saying yes goes first in the plan
        DeliveryStep key = check == HostKeyCheck.FirstUse
            ? new($"Новый ключ SSH роутера {target.Host}: {seen} (запомнится после «Да»)", $"New SSH key of the router {target.Host}: {seen} (remembered after Yes)")
            : new($"Ключ SSH роутера совпадает с запомненным: {seen}", $"The router's SSH key matches the remembered one: {seen}");
        return op with { Steps = [key, .. op.Steps] };
    }
}
