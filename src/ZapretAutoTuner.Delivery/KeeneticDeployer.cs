using System.Text;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core.Export;

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

    [GeneratedRegex("^(lists/[A-Za-z0-9_.-]+\\.list|blobs/[A-Za-z0-9_]+\\.bin)$")]
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
            new($"Записать {string.Join(", ", files)}", $"Write {string.Join(", ", files)}"),
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
        [.. pkg.Files.Keys.Where(k => k.StartsWith("lists/", StringComparison.Ordinal) || k.StartsWith("blobs/", StringComparison.Ordinal))];

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
            await sh.RunAsync($"mkdir -p {KeeneticExporter.Root}/lists {KeeneticExporter.Root}/blobs", ct).ConfigureAwait(false);
            foreach (var f in files)
            {
                await sh.WriteAsync($"{KeeneticExporter.Root}/{f}", pkg.Files[f], ct).ConfigureAwait(false);
                log.Add($"write {f}");
            }
            await sh.WriteAsync(Conf, Encoding.UTF8.GetBytes(merged), ct).ConfigureAwait(false);
            log.Add("write nfqws2.conf");
            var (code, output) = await RestartAsync(sh, ct).ConfigureAwait(false);
            log.Add(output.Trim());
            if (code == 0)
                return new DeliveryResult(true, false, log, null);
            await RollbackAsync(sh, backups, log).ConfigureAwait(false);
            return new DeliveryResult(false, true, log, "nfqws2 не запустился с новым конфигом, возвращён прежний / nfqws2 did not start, the previous config is back");
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or Renci.SshNet.Common.SshException)
        {
            await RollbackAsync(sh, backups, log).ConfigureAwait(false);
            return new DeliveryResult(false, true, log, e.Message);
        }
    }

    /// <summary>The user's conf with only the fragment's variables replaced.</summary>
    public static string Merge(string conf, string fragment)
    {
        foreach (var (name, value) in KeeneticExporter.ParseVars(fragment))
            conf = KeeneticExporter.ReplaceVar(conf, name, NeedsQuotes(name) ? $"\"{value}\"" : value);
        return conf;
    }

    private static bool NeedsQuotes(string name) => name is not ("TCP_PORTS" or "UDP_PORTS");

    private static async Task<(int, string)> RestartAsync(IRemoteShell sh, CancellationToken ct)
    {
        var (code, output) = await sh.RunAsync($"{Service} restart 2>&1; sleep 2; pidof nfqws2 >/dev/null", ct).ConfigureAwait(false);
        return (code, output);
    }

    private static async Task RollbackAsync(IRemoteShell sh, List<(string Path, bool Existed)> backups, List<string> log)
    {
        // the rollback runs even if the delivery was cancelled
        foreach (var (path, existed) in backups)
        {
            var q = SshRemoteShell.Quote(path);
            await sh.RunAsync(existed ? $"mv {SshRemoteShell.Quote(path + ".bak")} {q}" : $"rm -f {q}", CancellationToken.None).ConfigureAwait(false);
        }
        var (_, output) = await RestartAsync(sh, CancellationToken.None).ConfigureAwait(false);
        log.Add("rollback: " + output.Trim());
    }
}
