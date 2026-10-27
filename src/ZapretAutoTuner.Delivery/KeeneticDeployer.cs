using System.Text;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core.Export;
using ZapretAutoTuner.Core.Resources;

namespace ZapretAutoTuner.Delivery;

/// <summary>One step of a delivery, as the confirmation dialog lists it and the log reports it.</summary>
public sealed record DeliveryStep(string Ru, string En);

public sealed record DeliveryResult(bool Ok, bool RolledBack, IReadOnlyList<string> Log, string? Error);

/// <summary>
/// "Send to the router" for nfqws2-keenetic (PLAN 5.3, strategy-export §2.3): back up the conf and the files it
/// replaces, put only our variables into the user's own conf (their ISP_INTERFACE, policy and the rest stay), upload
/// the lists and blobs, restart the service and check it runs; on any failure put the backups back and restart.
/// Runs only on the user's explicit confirmation (AGENTS.md rule 7).
/// </summary>
public static partial class KeeneticDeployer
{
    public const string Conf = KeeneticExporter.Root + "/nfqws2.conf";
    public const string Service = "/opt/etc/init.d/S51nfqws2";
    public const string UserList = "lists/user.list";

    [GeneratedRegex("^(lists/[A-Za-z0-9_.-]+\\.list|blobs/[A-Za-z0-9_]+\\.bin|lua/zt-[a-z0-9_-]+\\.lua)$")]
    private static partial Regex SafeFile();

    /// <summary>What <see cref="DeployAsync"/> will do, for the confirmation dialog.</summary>
    public static List<DeliveryStep> Plan(ExportPackage pkg)
    {
        Require(pkg);
        var files = Files(pkg);
        var vars = KeeneticExporter.ParseVars(pkg.Text).Keys;
        return
        [
            new($"Резервная копия {Conf} → nfqws2.conf.bak и заменяемых файлов", $"Back up {Conf} to nfqws2.conf.bak and the files being replaced"),
            new($"Заменить в nfqws2.conf только {string.Join(", ", vars)}", $"Replace only {string.Join(", ", vars)} in nfqws2.conf"),
            .. files.Contains(UserList)
                ? new DeliveryStep[] { new($"Дописать наши домены в {UserList} (ваши остаются)", $"Add our domains to {UserList} (yours stay)") }
                : [],
            new($"Записать {string.Join(", ", files.Where(f => f != UserList))}", $"Write {string.Join(", ", files.Where(f => f != UserList))}"),
            new($"Перезапустить {Service} и проверить, что nfqws2 работает", $"Restart {Service} and check nfqws2 runs"),
            new("Если не поднялся — вернуть резервные копии и перезапустить", "If it fails, restore the backups and restart"),
        ];
    }

    private static void Require(ExportPackage pkg)
    {
        if (pkg.Format != "keenetic")
            throw new ArgumentException("нужен экспорт nfqws2-keenetic / a keenetic export is required", nameof(pkg));
    }

    private static List<string> Files(ExportPackage pkg) =>
        [.. pkg.Files.Keys.Where(k => k.StartsWith("lists/", StringComparison.Ordinal) || k.StartsWith("blobs/", StringComparison.Ordinal) || k.StartsWith("lua/", StringComparison.Ordinal))];

    /// <param name="confirmedByUser">Set by the confirmation dialog only; without it nothing is touched.</param>
    public static async Task<DeliveryResult> DeployAsync(IRemoteShell sh, ExportPackage pkg, bool confirmedByUser, CancellationToken ct = default)
    {
        Require(pkg);
        if (!confirmedByUser)
            throw new InvalidOperationException("доставка без подтверждения пользователя запрещена / delivery needs the user's confirmation");
        var log = new List<string>();
        var files = Files(pkg);
        foreach (var f in files)
        {
            if (!SafeFile().IsMatch(f))
                return new DeliveryResult(false, false, log, $"недопустимое имя файла {f}");
        }

        var current = await sh.ReadAsync(Conf, ct).ConfigureAwait(false);
        if (current is null)
            return new DeliveryResult(false, false, log, $"{Conf} не найден: установлен ли nfqws2-keenetic? / not found: is nfqws2-keenetic installed?");

        // backups: the conf and every file we replace (new files are removed on rollback)
        var backups = new List<(string Path, bool Existed)> { (Conf, true) };
        foreach (var f in files)
        {
            var path = $"{KeeneticExporter.Root}/{f}";
            var (exists, _) = await sh.RunAsync($"test -f {SshRemoteShell.Quote(path)}", ct).ConfigureAwait(false);
            backups.Add((path, exists == 0));
        }
        foreach (var (path, existed) in backups.Where(b => b.Existed))
        {
            var (code, output) = await sh.RunAsync($"cp -p {SshRemoteShell.Quote(path)} {SshRemoteShell.Quote(path + ".bak")}", ct).ConfigureAwait(false);
            if (code != 0)
                return new DeliveryResult(false, false, log, $"резервная копия {path}: {output}");
            log.Add($"backup {path}.bak");
        }

        try
        {
            var merged = Merge(Encoding.UTF8.GetString(current), pkg.Text);
            await sh.RunAsync($"mkdir -p {KeeneticExporter.Root}/lists {KeeneticExporter.Root}/blobs {KeeneticExporter.Root}/lua", ct).ConfigureAwait(false);
            foreach (var f in files)
            {
                var data = pkg.Files[f];
                if (f == UserList && await sh.ReadAsync($"{KeeneticExporter.Root}/{f}", ct).ConfigureAwait(false) is { } theirs)
                    data = MergeList(theirs, data);
                await sh.WriteAsync($"{KeeneticExporter.Root}/{f}", data, ct).ConfigureAwait(false);
                log.Add($"write {f}");
            }
            await sh.WriteAsync(Conf, Encoding.UTF8.GetBytes(merged), ct).ConfigureAwait(false);
            log.Add("write nfqws2.conf");
            var (code, output) = await RestartAsync(sh, ct).ConfigureAwait(false);
            log.Add(output.Trim());
            if (code == 0)
                return new DeliveryResult(true, false, log, null);
            return await RollbackAsync(sh, backups, log, "nfqws2 не запустился с новым конфигом / nfqws2 did not start with the new config").ConfigureAwait(false);
        }
        catch (Exception e)
        {
            // whatever broke the delivery, the router must not stay with half of it
            return await RollbackAsync(sh, backups, log, e.Message).ConfigureAwait(false);
        }
    }

    /// <summary>The router file of one of our resources: <c>lists/zt-x.list</c>, <c>lists/zt-x-ipset.list</c>, <c>blobs/x.bin</c>, <c>lua/zt-x.lua</c>.</summary>
    public static string ResourceFile(ResourceKind kind, string name)
    {
        if (!ResourceNames.IsValid(name))
            throw new ArgumentException("resource name must be [a-z0-9_-]{1,48}", nameof(name));
        return kind switch
        {
            ResourceKind.Hostlist => KeeneticExporter.ListFile(name),
            ResourceKind.Ipset => KeeneticExporter.IpsetFile(name),
            ResourceKind.Blob => KeeneticExporter.BlobFile(name),
            _ => "lua/" + ResourceNames.LuaFile(name),
        };
    }

    /// <summary>What <see cref="DeleteResourceAsync"/> will do, for the confirmation dialog.</summary>
    public static List<DeliveryStep> PlanDelete(ResourceKind kind, string name)
    {
        var file = ResourceFile(kind, name);
        return
        [
            new($"Проверить, что {Conf} не ссылается на {file}", $"Check that {Conf} does not refer to {file}"),
            new($"Переименовать {KeeneticExporter.Root}/{file} в {file}.bak (вернуть можно обратным переименованием)", $"Rename {KeeneticExporter.Root}/{file} to {file}.bak (rename it back to undo)"),
        ];
    }

    /// <summary>
    /// Removes one of our resource files from the router: refused while nfqws2.conf refers to it (the file path, or
    /// <c>blob=name</c>/<c>--blob=name:</c> for a blob); the file is kept as <c>.bak</c>, so the step can be undone.
    /// </summary>
    /// <param name="confirmedByUser">Set by the confirmation dialog only; without it nothing is touched.</param>
    public static async Task<DeliveryResult> DeleteResourceAsync(IRemoteShell sh, ResourceKind kind, string name, bool confirmedByUser, CancellationToken ct = default)
    {
        if (!confirmedByUser)
            throw new InvalidOperationException("удаление на роутере без подтверждения пользователя запрещено / deleting on the router needs the user's confirmation");
        var file = ResourceFile(kind, name);
        var path = $"{KeeneticExporter.Root}/{file}";
        var log = new List<string>();
        var conf = await sh.ReadAsync(Conf, ct).ConfigureAwait(false);
        if (conf is null)
            return new DeliveryResult(false, false, log, $"{Conf} не найден: установлен ли nfqws2-keenetic? / not found: is nfqws2-keenetic installed?");
        var text = Encoding.UTF8.GetString(conf);
        bool used = text.Contains(path, StringComparison.Ordinal)
            || (kind == ResourceKind.Blob && Regex.IsMatch(text, $"(?:--blob=|blob=|[%#]){Regex.Escape(name)}(?![A-Za-z0-9_])"));
        if (used)
            return new DeliveryResult(false, false, log, $"{file} используется в nfqws2.conf: сначала уберите его из стратегии / {file} is used in nfqws2.conf: remove it from the strategy first");
        var q = SshRemoteShell.Quote(path);
        var (exists, _) = await sh.RunAsync($"test -f {q}", ct).ConfigureAwait(false);
        if (exists != 0)
            return new DeliveryResult(false, false, log, $"{file} на роутере нет / {file} is not on the router");
        var (code, output) = await sh.RunAsync($"mv {q} {SshRemoteShell.Quote(path + ".bak")}", ct).ConfigureAwait(false);
        if (code != 0)
            return new DeliveryResult(false, false, log, $"{file}: {output.Trim()}");
        log.Add($"moved {file} to {file}.bak");
        return new DeliveryResult(true, false, log, null);
    }

    /// <summary>The user's list with our domains appended (theirs first, no duplicates).</summary>
    public static byte[] MergeList(byte[] theirs, byte[] ours)
    {
        static IEnumerable<string> Lines(byte[] b) => Encoding.UTF8.GetString(b).ReplaceLineEndings("\n").Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var all = Lines(theirs).Concat(Lines(ours)).Where(l => l.StartsWith('#') || seen.Add(l));
        return Encoding.UTF8.GetBytes(string.Join("\n", all) + "\n");
    }

    /// <summary>
    /// The user's conf with only the fragment's variables replaced. Their <c>NFQWS_ARGS_UDP</c> stays, so its ports stay
    /// in <c>UDP_PORTS</c> together with the ones they listed, and the <c>--blob</c>/<c>--lua-init</c> lines of their
    /// <c>NFQWS_BASE_ARGS</c> that we do not declare stay too (their UDP profile may use them).
    /// </summary>
    public static string Merge(string conf, string fragment)
    {
        var theirs = KeeneticExporter.ParseVars(conf);
        foreach (var (name, value) in KeeneticExporter.ParseVars(fragment))
        {
            var v = name switch
            {
                "UDP_PORTS" => UnionPorts(value, theirs.GetValueOrDefault("UDP_PORTS"), UdpFilter(theirs.GetValueOrDefault("NFQWS_ARGS_UDP", ""))),
                "NFQWS_BASE_ARGS" => KeepTheirDeclarations(value, theirs.GetValueOrDefault("NFQWS_BASE_ARGS", "")),
                _ => value,
            };
            conf = KeeneticExporter.ReplaceVar(conf, name, NeedsQuotes(name) ? $"\"{v}\"" : v);
        }
        return conf;
    }

    private static string UnionPorts(params string?[] lists)
    {
        // iptables "a:b" back to nfqws2 "a-b" for the union, then back
        var nfq = lists.Where(l => !string.IsNullOrWhiteSpace(l)).Select(l => l!.Replace(':', '-'));
        return KeeneticExporter.ToIptables(ZapretAutoTuner.Core.Model.PortList.Union(nfq));
    }

    private static string? UdpFilter(string args) =>
        Regex.Match(args, "--filter-udp=(\\S+)") is { Success: true } m ? m.Groups[1].Value : null;

    private static string KeepTheirDeclarations(string ours, string theirs)
    {
        var tokens = ZapretAutoTuner.Core.Model.ArgTokenizer.Split(ours);
        string? Key(string t) => t.StartsWith("--blob=", StringComparison.Ordinal) ? "b:" + t[7..].Split(':')[0]
            : t.StartsWith("--lua-init=", StringComparison.Ordinal) ? "l:" + t[11..] : null;
        var have = tokens.Select(Key).Where(k => k is not null).ToHashSet(StringComparer.Ordinal);
        List<string> theirTokens;
        try
        {
            theirTokens = ZapretAutoTuner.Core.Model.ArgTokenizer.Split(theirs);
        }
        catch (FormatException)
        {
            return ours;
        }
        var keep = theirTokens.Where(t => Key(t) is { } k && have.Add(k)).ToList();
        return keep.Count == 0 ? ours : ours + "\n" + string.Join("\n", keep);
    }

    private static bool NeedsQuotes(string name) => name is not ("TCP_PORTS" or "UDP_PORTS");

    private static async Task<(int, string)> RestartAsync(IRemoteShell sh, CancellationToken ct)
    {
        // our nfqws2, not another one on the router (zapret-gui runs its own): its argv has our lua paths
        var (code, output) = await sh.RunAsync($"{Service} restart 2>&1; sleep 2; ps w | grep '[n]fqws2' | grep -q {SshRemoteShell.Quote(KeeneticExporter.Root + "/lua/")}", ct).ConfigureAwait(false);
        return (code, output);
    }

    private static async Task<DeliveryResult> RollbackAsync(IRemoteShell sh, List<(string Path, bool Existed)> backups, List<string> log, string error)
    {
        // the rollback runs even if the delivery was cancelled; every step is checked, and a rollback that could not
        // finish (the connection is gone) is reported as such: the .bak files are still on the router
        var failed = new List<string>();
        try
        {
            foreach (var (path, existed) in backups)
            {
                var q = SshRemoteShell.Quote(path);
                var (code, output) = await sh.RunAsync(existed ? $"cp -p {SshRemoteShell.Quote(path + ".bak")} {q}" : $"rm -f {q}", CancellationToken.None).ConfigureAwait(false);
                if (code != 0)
                    failed.Add($"{path}: {output.Trim()}");
            }
            var (rc, restart) = await RestartAsync(sh, CancellationToken.None).ConfigureAwait(false);
            log.Add("rollback: " + restart.Trim());
            if (rc != 0)
                failed.Add("nfqws2 не запустился и с прежним конфигом / did not start with the previous config either");
        }
        catch (Exception e)
        {
            failed.Add(e.Message);
        }
        if (failed.Count == 0)
            return new DeliveryResult(false, true, log, $"{error}; возвращён прежний конфиг / the previous config is back");
        log.AddRange(failed.Select(f => "rollback failed: " + f));
        return new DeliveryResult(false, false, log,
            $"{error}; откат не завершён, копии лежат рядом с файлами (*.bak) / the rollback did not finish, the backups are next to the files (*.bak): {string.Join("; ", failed)}");
    }
}
