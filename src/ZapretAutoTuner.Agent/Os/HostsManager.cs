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

    public async Task<List<HostsPin>> ListAsync(CancellationToken ct) => HostsFile.Read((await ReadAsync(ct)).Text);

    public async Task<(string Backup, bool Flushed, List<HostsPin> Pins)> SetAsync(IReadOnlyList<HostsPin> pins, CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var (old, encoding) = await ReadAsync(ct);
            var updated = HostsFile.Apply(old, pins); // validates every pin before anything is written
            string backup = "";
            if (updated != old)
            {
                // the backup is a byte copy: whatever the file's encoding, it restores exactly
                var backupDir = System.IO.Path.Combine(dataDir, "hosts-backup");
                Directory.CreateDirectory(backupDir);
                backup = System.IO.Path.Combine(backupDir, "hosts." + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture));
                if (File.Exists(Path))
                    File.Copy(Path, backup);
                else
                    await File.WriteAllBytesAsync(backup, [], ct);
                await ReplaceAsync(encoding.GetPreamble().Concat(encoding.GetBytes(updated)).ToArray(), ct);
            }
            bool flushed = await FlushDnsAsync(ct);
            return (backup, flushed, HostsFile.Read(updated));
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Reads the file in its own encoding: UTF-8 (BOM kept) when it decodes as UTF-8, otherwise Latin-1, which maps
    /// every byte to one char and back, so a cp1251 comment survives the rewrite untouched.
    /// </summary>
    internal async Task<(string Text, Encoding Encoding)> ReadAsync(CancellationToken ct)
    {
        if (!File.Exists(Path))
            return ("", new UTF8Encoding(false));
        var bytes = await File.ReadAllBytesAsync(Path, ct);
        return Decode(bytes);
    }

    internal static (string Text, Encoding Encoding) Decode(byte[] bytes)
    {
        bool bom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
        var utf8 = new UTF8Encoding(bom, throwOnInvalidBytes: true);
        try
        {
            return (utf8.GetString(bytes, bom ? 3 : 0, bytes.Length - (bom ? 3 : 0)), utf8);
        }
        catch (DecoderFallbackException)
        {
            return (Encoding.Latin1.GetString(bytes), Encoding.Latin1);
        }
    }

    private async Task ReplaceAsync(byte[] content, CancellationToken ct)
    {
        // a symlinked hosts stays a symlink: the file it points to is the one replaced
        var target = File.Exists(Path) && File.ResolveLinkTarget(Path, returnFinalTarget: true) is { } link ? link.FullName : Path;
        // write next to the file and move over it, so a crash never leaves half a hosts file
        var tmp = target + ".ztuner-tmp";
        try
        {
            await File.WriteAllBytesAsync(tmp, content, ct);
            if (!File.Exists(target))
            {
                File.Move(tmp, target);
            }
            else if (OperatingSystem.IsWindows())
            {
                // hosts blockers often set read-only; File.Replace keeps the file's own ACL and attributes
                var attrs = File.GetAttributes(target);
                if (attrs.HasFlag(FileAttributes.ReadOnly))
                    File.SetAttributes(target, attrs & ~FileAttributes.ReadOnly);
                try
                {
                    File.Replace(tmp, target, null);
                }
                finally
                {
                    File.SetAttributes(target, attrs);
                }
            }
            else
            {
                File.SetUnixFileMode(tmp, File.GetUnixFileMode(target));
                File.Move(tmp, target, overwrite: true);
            }
        }
        finally
        {
            if (File.Exists(tmp))
                File.Delete(tmp);
        }
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
