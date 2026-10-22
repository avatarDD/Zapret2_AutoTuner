using System.Text;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Resources;

namespace ZapretAutoTuner.Delivery;

/// <summary>What happens to one resource on the router.</summary>
public enum RouterResourceAction
{
    /// <summary>Create it or replace its content.</summary>
    Put,

    /// <summary>Remove it (refused while a router strategy uses it).</summary>
    Delete,
}

/// <summary>
/// One resource change on the router, prepared but not done (PLAN 4a.5, AGENTS.md rule 7): the steps and the content
/// the confirmation dialog shows, and the action that runs only after the user said yes. The content was fixed when
/// the operation was prepared, so what is written is exactly what was shown.
/// </summary>
/// <param name="Router">"zapret-gui" or "nfqws2-keenetic".</param>
/// <param name="RunConfirmedAsync">Runs the change; call it only after the user confirmed this operation in the AutoTuner window.</param>
public sealed record RouterResourceOperation(
    string Router,
    RouterResourceAction Action,
    ResourceRef Resource,
    IReadOnlyList<DeliveryStep> Steps,
    string PreviewRu,
    string PreviewEn,
    Func<CancellationToken, Task<DeliveryResult>> RunConfirmedAsync)
{
    /// <summary>The dialog text: the steps, then what will be written.</summary>
    public string Text(bool russian) =>
        string.Join("\n", Steps.Select(s => "• " + (russian ? s.Ru : s.En)))
        + ((russian ? PreviewRu : PreviewEn) is { Length: > 0 } p ? "\n\n" + p : "");
}

/// <summary>
/// Single resources on the router (PLAN 4a.5, strategy-export §6): zapret-gui through its REST API, nfqws2-keenetic as
/// files under <c>/opt/etc/nfqws2</c>. Builds the operation the user confirms; nothing touches the router before that.
/// Only content from <c>ResourceStore.ForDelivery</c> goes here (for a Lua script, the approved version).
/// </summary>
public static class RouterResources
{
    public const string ZapretGui = "zapret-gui";
    public const string Keenetic = "nfqws2-keenetic";

    /// <summary>Lines of a list or a script the dialog shows before it says "and N more".</summary>
    public const int PreviewLines = 40;

    /// <summary>What will be written, for the dialog: the list items, the blob's size and first bytes, the script.</summary>
    public static (string Ru, string En) Preview(ResourceData data)
    {
        switch (data.Kind)
        {
            case ResourceKind.Blob:
                var head = Convert.ToHexString(data.Bytes.AsSpan(0, Math.Min(32, data.Bytes.Length))).ToLowerInvariant();
                var more = data.Bytes.Length > 32 ? "…" : "";
                return ($"Блоб {data.Name}: {data.Bytes.Length} байт, {head}{more}", $"Blob {data.Name}: {data.Bytes.Length} bytes, {head}{more}");
            case ResourceKind.LuaScript:
                var lines = data.Source.Split('\n');
                var shown = string.Join("\n", lines.Take(PreviewLines));
                var rest = lines.Length - PreviewLines;
                var fn = string.Join(", ", data.Functions);
                return (
                    $"Подтверждённый Lua-скрипт ({Encoding.UTF8.GetByteCount(data.Source)} байт, функции: {fn}):\n{shown}{(rest > 0 ? $"\n… и ещё {rest} строк" : "")}",
                    $"The approved Lua script ({Encoding.UTF8.GetByteCount(data.Source)} bytes, functions: {fn}):\n{shown}{(rest > 0 ? $"\n… and {rest} more lines" : "")}");
            default:
                var items = string.Join("\n", data.Items.Take(PreviewLines));
                var left = data.Items.Count - PreviewLines;
                var what = data.Kind == ResourceKind.Hostlist ? ("доменов", "domains") : ("адресов", "entries");
                return (
                    $"{data.Items.Count} {what.Item1}:\n{items}{(left > 0 ? $"\n… и ещё {left}" : "")}",
                    $"{data.Items.Count} {what.Item2}:\n{items}{(left > 0 ? $"\n… and {left} more" : "")}");
        }
    }

    // ---- zapret-gui ----

    /// <summary>
    /// Creating or replacing a resource in zapret-gui. A Lua script first goes through the GUI's own syntax check
    /// (read-only); a script the GUI calls broken is refused before the user is asked.
    /// </summary>
    public static async Task<RouterResourceOperation> GuiPutAsync(ZapretGuiClient client, ResourceData data, CancellationToken ct = default)
    {
        var gui = ZapretGuiClient.GuiName(data.Kind, data.Name);
        var users = await client.UsersOfAsync(data.Kind, data.Name, ct).ConfigureAwait(false);
        if (data.Kind == ResourceKind.LuaScript)
        {
            var (valid, errors) = await client.CheckLuaAsync(data.Source, ct).ConfigureAwait(false);
            if (!valid)
                throw new ZapretGuiException($"zapret-gui не принял скрипт {gui}: {string.Join("; ", errors)} / zapret-gui rejected the script {gui}: {string.Join("; ", errors)}") { Code = "lua_invalid" };
        }
        var steps = new List<DeliveryStep>
        {
            new($"Создать или заменить {ResourceNames.KindNameRu(data.Kind)} {gui} в zapret-gui", $"Create or replace the {ResourceNames.KindNameEn(data.Kind)} {gui} in zapret-gui"),
        };
        if (users.Count > 0)
            steps.Add(new($"Его используют стратегии zapret-gui {string.Join(", ", users)}: они получат новое содержимое при следующем применении",
                $"The zapret-gui strategies {string.Join(", ", users)} use it: they get the new content the next time they are applied"));
        steps.Add(new("Стратегия zapret-gui не применяется и не перезапускается", "No zapret-gui strategy is applied or restarted"));
        var (ru, en) = Preview(data);
        return new RouterResourceOperation(ZapretGui, RouterResourceAction.Put, data.Ref, steps, ru, en, async c =>
        {
            switch (data.Kind)
            {
                case ResourceKind.Hostlist:
                    await client.PutHostlistAsync(data.Name, data.Items, confirmedByUser: true, c).ConfigureAwait(false);
                    break;
                case ResourceKind.Ipset:
                    await client.PutIpsetAsync(data.Name, data.Items, confirmedByUser: true, c).ConfigureAwait(false);
                    break;
                case ResourceKind.Blob:
                    await client.PutBlobAsync(data.Name, data.Bytes, confirmedByUser: true, c).ConfigureAwait(false);
                    break;
                default:
                    await client.PutLuaAsync(data.Name, data.Source, confirmedByUser: true, c).ConfigureAwait(false);
                    break;
            }
            return new DeliveryResult(true, false, [$"put {gui}"], null);
        });
    }

    /// <summary>Deleting a resource of ours from zapret-gui; refused at once (naming them) while GUI strategies use it.</summary>
    public static async Task<RouterResourceOperation> GuiDeleteAsync(ZapretGuiClient client, ResourceKind kind, string name, CancellationToken ct = default)
    {
        var gui = ZapretGuiClient.GuiName(kind, name);
        var users = await client.UsersOfAsync(kind, name, ct).ConfigureAwait(false);
        if (users.Count > 0)
            throw new ZapretGuiException($"{gui} нельзя удалить: его используют стратегии zapret-gui {string.Join(", ", users)} / {gui} cannot be deleted: the zapret-gui strategies {string.Join(", ", users)} use it") { Code = "in_use" };
        var steps = new List<DeliveryStep>
        {
            new($"Проверено: ни одна стратегия zapret-gui не использует {gui}", $"Checked: no zapret-gui strategy uses {gui}"),
            new($"Удалить {ResourceNames.KindNameRu(kind)} {gui} из zapret-gui (без резервной копии)", $"Delete the {ResourceNames.KindNameEn(kind)} {gui} from zapret-gui (no backup is kept)"),
        };
        return new RouterResourceOperation(ZapretGui, RouterResourceAction.Delete, new ResourceRef(kind, name), steps, "", "", async c =>
        {
            await client.DeleteAsync(kind, name, confirmedByUser: true, c).ConfigureAwait(false);
            return new DeliveryResult(true, false, [$"deleted {gui}"], null);
        });
    }

    // ---- nfqws2-keenetic ----

    /// <summary>
    /// Writing a resource file on a nfqws2-keenetic router (<see cref="KeeneticDeployer.ResourceFile"/>); an existing
    /// file is kept as <c>.bak</c>. nfqws2 is not restarted: the change takes effect with its next start.
    /// </summary>
    /// <param name="connect">Opens the SSH shell; called only when the confirmed operation runs.</param>
    public static RouterResourceOperation KeeneticPut(Func<CancellationToken, Task<IRemoteShell>> connect, ResourceData data)
    {
        var file = KeeneticDeployer.ResourceFile(data.Kind, data.Name);
        var path = $"{KeeneticExporter.Root}/{file}";
        var steps = new List<DeliveryStep>
        {
            new($"Записать {path} (прежний файл сохраняется как {file}.bak)", $"Write {path} (the old file is kept as {file}.bak)"),
            new("nfqws2 не перезапускается: изменение подействует при следующем запуске службы", "nfqws2 is not restarted: the change takes effect the next time the service starts"),
        };
        var (ru, en) = Preview(data);
        return new RouterResourceOperation(Keenetic, RouterResourceAction.Put, data.Ref, steps, ru, en, async ct =>
        {
            using var sh = await connect(ct).ConfigureAwait(false);
            var log = new List<string>();
            var dir = path[..path.LastIndexOf('/')];
            var (mk, mkOut) = await sh.RunAsync($"mkdir -p {SshRemoteShell.Quote(dir)}", ct).ConfigureAwait(false);
            if (mk != 0)
                return new DeliveryResult(false, false, log, $"{dir}: {mkOut.Trim()}");
            var q = SshRemoteShell.Quote(path);
            var (exists, _) = await sh.RunAsync($"test -f {q}", ct).ConfigureAwait(false);
            if (exists == 0)
            {
                var (cp, cpOut) = await sh.RunAsync($"cp -p {q} {SshRemoteShell.Quote(path + ".bak")}", ct).ConfigureAwait(false);
                if (cp != 0)
                    return new DeliveryResult(false, false, log, $"резервная копия / backup {file}: {cpOut.Trim()}");
                log.Add($"backup {file}.bak");
            }
            await sh.WriteAsync(path, FileBytes(data), ct).ConfigureAwait(false);
            log.Add($"write {file}");
            return new DeliveryResult(true, false, log, null);
        });
    }

    /// <summary>Removing a resource file from a nfqws2-keenetic router (<see cref="KeeneticDeployer.DeleteResourceAsync"/>: kept as .bak).</summary>
    public static RouterResourceOperation KeeneticDelete(Func<CancellationToken, Task<IRemoteShell>> connect, ResourceKind kind, string name) =>
        new(Keenetic, RouterResourceAction.Delete, new ResourceRef(kind, name), KeeneticDeployer.PlanDelete(kind, name), "", "", async ct =>
        {
            using var sh = await connect(ct).ConfigureAwait(false);
            return await KeeneticDeployer.DeleteResourceAsync(sh, kind, name, confirmedByUser: true, ct).ConfigureAwait(false);
        });

    /// <summary>The file content as the exporters write it: one item per line, raw bytes, UTF-8 source.</summary>
    public static byte[] FileBytes(ResourceData data) => data.Kind switch
    {
        ResourceKind.Blob => data.Bytes,
        ResourceKind.LuaScript => new UTF8Encoding(false).GetBytes(data.Source),
        _ => Encoding.UTF8.GetBytes(string.Concat(data.Items.Select(i => i + "\n"))),
    };
}
