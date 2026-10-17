using System.Globalization;
using System.Text;
using ZapretAutoTuner.Core.Hosts;

namespace ZapretAutoTuner.Agent.Os;

/// <summary>
/// Writes the AutoTuner block of the hosts file (dpi-diagnostics §2a): a backup into the data dir first, then an
/// atomic replace, then a DNS cache flush. Only the block between the markers is ever changed.
/// </summary>
internal sealed class HostsManager(string path, string dataDir)
{
    private readonly SemaphoreSlim _lock = new(1, 1);

    public string Path { get; } = path;

    public async Task<List<HostsPin>> ListAsync(CancellationToken ct) =>
        HostsFile.Read(File.Exists(Path) ? await File.ReadAllTextAsync(Path, ct) : "");

    public async Task<(string Backup, bool Flushed, List<HostsPin> Pins)> SetAsync(IReadOnlyList<HostsPin> pins, CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var old = File.Exists(Path) ? await File.ReadAllTextAsync(Path, ct) : "";
            var updated = HostsFile.Apply(old, pins); // validates every pin before anything is written
            var backupDir = System.IO.Path.Combine(dataDir, "hosts-backup");
            Directory.CreateDirectory(backupDir);
            var backup = System.IO.Path.Combine(backupDir, "hosts." + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture));
            await File.WriteAllTextAsync(backup, old, ct);
            if (updated != old)
                await ReplaceAsync(updated, ct);
            bool flushed = await FlushDnsAsync(ct);
            return (backup, flushed, HostsFile.Read(updated));
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task ReplaceAsync(string content, CancellationToken ct)
    {
        // write next to the file and move over it, so a crash never leaves half a hosts file
        var tmp = Path + ".ztuner-tmp";
        await File.WriteAllTextAsync(tmp, content, new UTF8Encoding(false), ct);
        if (OperatingSystem.IsLinux() && File.Exists(Path))
            File.SetUnixFileMode(tmp, File.GetUnixFileMode(Path));
        File.Move(tmp, Path, overwrite: true);
    }

    private static async Task<bool> FlushDnsAsync(CancellationToken ct)
    {
        if (OperatingSystem.IsWindows())
            return (await Cmd.RunAsync("ipconfig", ["/flushdns"], ct: ct)).Ok;
        // systemd-resolved, then nscd; a system without a cache has nothing to flush
        bool any = false;
        foreach (var (file, args) in new[] { ("resolvectl", new[] { "flush-caches" }), ("nscd", ["-i", "hosts"]) })
        {
            var r = await Cmd.RunAsync(file, args, ct: ct);
            any |= r.Ok;
        }
        return any;
    }
}
