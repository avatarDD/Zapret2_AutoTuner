using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Agent.Os;
using ZapretAutoTuner.Core.Engine;

namespace ZapretAutoTuner.Agent.Engine;

/// <summary>
/// The Agent's own copies of the files an engine loads from outside its directory (PLAN 4a.5, user Lua; review 2,
/// blobs). The UI sends the content of every <c>--lua-init=@file</c> and <c>--blob=name:[+ofs]@file</c> with the request
/// (<c>lua_files</c>); such a file is never loaded from where the UI keeps it. On Linux nfqws2 reads Lua only after
/// dropping root (nfqws.c: droproot, then <c>lua_test_init_script_files</c>), so a script in a 0700 home is unreadable
/// to it, but it reads blobs as root while parsing the options (<c>load_blob_to_collection</c>), so a symlink in the
/// user-writable data directory could make it read a root-only file into a blob that goes on the wire; on Windows
/// winws2 runs as Administrator, so a file in the user's writable %LOCALAPPDATA% could be swapped or redirected (a
/// junction) between the check and the load.
/// The copy lives in a folder only the Agent can write: Linux <c>/run/zapret-autotuner</c> (root, 0755; files 0644),
/// Windows <c>%ProgramData%\ZapretAutoTuner-agent</c> (Administrators and SYSTEM only, like the winws2 service folder),
/// in a subfolder with an unpredictable name and an owner marker (this Agent's pid and start time). Copies are named by
/// their SHA-256, so two engines with the same file share one; all go when the Agent exits. The store is capped
/// (<see cref="MaxStoreBytes"/>, <see cref="MaxStoreFolders"/>): copies no running engine uses are pruned first.
/// </summary>
internal sealed partial class LuaStore
{
    public const long MaxTotalBytes = 8L * 1024 * 1024;

    /// <summary>The whole store (on Linux it lives in /run, a tmpfs in RAM).</summary>
    public const long MaxStoreBytes = 32L * 1024 * 1024;

    public const int MaxStoreFolders = 256;

    /// <summary>A copy younger than this is kept even when no engine runs with it: a check may be using it.</summary>
    public static readonly TimeSpan PruneGrace = TimeSpan.FromMinutes(2);

    private const string OwnerFile = "owner";

    [GeneratedRegex("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,123}\\.lua\\z")]
    private static partial Regex SafeName();

    [GeneratedRegex("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,123}\\z")]
    private static partial Regex SafeBlobName();

    private readonly Lock _lock = new();
    private readonly string _engineDir;
    private readonly Func<IReadOnlyCollection<string>> _inUse;
    private bool _rootReady;

    /// <param name="root">This Agent's folder for the copies; created on first use.</param>
    /// <param name="engineDir">The engine's own directory: its files are the bundled ones and are loaded where they are.</param>
    /// <param name="inUse">The copies running engines use (never pruned).</param>
    public LuaStore(string root, string engineDir, Func<IReadOnlyCollection<string>>? inUse = null)
    {
        Root = root;
        _engineDir = engineDir;
        _inUse = inUse ?? (() => []);
    }

    public string Root { get; }

    /// <summary>The caps and the grace of this store (tests make them small).</summary>
    internal long StoreBytesCap { get; init; } = MaxStoreBytes;

    internal int StoreFoldersCap { get; init; } = MaxStoreFolders;

    internal TimeSpan Grace { get; init; } = PruneGrace;

    /// <summary>Where Lua and blobs may be loaded from: the engine's directory and this store.</summary>
    public IReadOnlyList<string> AllowedRoots => [_engineDir, Root];

    /// <summary>
    /// The default folder: protected when the Agent runs privileged, inside the data directory otherwise (tests and a
    /// UI that runs the Agent without rights, where the engine has nothing to drop and nothing to escalate to). The
    /// name is random, so nobody can create it in advance.
    /// </summary>
    public static string DefaultRoot(string dataDir)
    {
        var name = "lua-" + Guid.NewGuid().ToString("N");
        if (!Environment.IsPrivilegedProcess)
            return Path.Combine(dataDir, "agent-lua", name);
        return OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ZapretAutoTuner-agent", name)
            : Path.Combine(LinuxBase, name);
    }

    /// <summary>Directly under /run (root-owned, 0755): no other user can create or swap it.</summary>
    public const string LinuxBase = "/run/zapret-autotuner";

    /// <summary>
    /// The argv with each <c>--lua-init=@file</c> and <c>--blob=name:[+ofs]@file</c> outside the engine's directory
    /// replaced by the store's copy of the content the UI sent. Throws <see cref="EngineStartException"/>: "engine" when
    /// such a file came without its content (the UI could not read it) or the store cannot take it, "policy" when the
    /// content is not acceptable (name, size).
    /// </summary>
    public List<string> Prepare(IReadOnlyList<string> argv, IReadOnlyDictionary<string, byte[]> files)
    {
        var policy = new List<string>();
        var environment = new List<string>();
        var plan = new List<(int Index, string Prefix, string Name, byte[] Bytes)>();
        var result = new List<string>(argv.Count);
        long total = 0;
        foreach (var tok in argv)
        {
            const string lua = "--lua-init=@";
            const string blob = "--blob=";
            string prefix, path, name;
            if (tok.StartsWith(lua, StringComparison.Ordinal))
            {
                prefix = lua;
                path = tok[lua.Length..];
                name = Path.GetFileName(path.Replace('\\', '/'));
                if (!EngineArgvPolicy.IsUnder(path, [_engineDir]) && !SafeName().IsMatch(name))
                {
                    policy.Add($"--lua-init=@{path}: недопустимое имя Lua-файла");
                    continue;
                }
            }
            else if (tok.StartsWith(blob, StringComparison.Ordinal) && Protocol.LuaFiles.BlobPath(tok[blob.Length..]) is { } blobPath)
            {
                path = blobPath;
                prefix = tok[..(tok.Length - path.Length)];
                name = Path.GetFileName(path.Replace('\\', '/'));
                if (!SafeBlobName().IsMatch(name))
                    name = "blob.bin";
            }
            else
            {
                result.Add(tok);
                continue;
            }
            if (EngineArgvPolicy.IsUnder(path, [_engineDir]))
            {
                result.Add(tok);
                continue;
            }
            if (!files.TryGetValue(path, out var bytes))
            {
                environment.Add($"{prefix}{path}: файл вне каталога движка, а его содержимого в запросе нет (программа не смогла его прочитать)");
                continue;
            }
            total += bytes.Length;
            if (bytes.Length > Protocol.LuaFiles.MaxFileBytes || total > MaxTotalBytes)
            {
                policy.Add($"{prefix}{path}: файл слишком большой");
                continue;
            }
            plan.Add((result.Count, prefix, name, bytes));
            result.Add(tok);
        }
        if (policy.Count > 0)
            throw new EngineStartException("policy", [.. policy, .. environment]);
        if (environment.Count > 0)
            throw new EngineStartException("engine", environment);
        lock (_lock)
        {
            foreach (var (index, prefix, name, bytes) in plan)
                result[index] = prefix + Write(name, bytes);
        }
        return result;
    }

    /// <summary>Writes the content once (by its hash) and returns the copy's path. Under <see cref="_lock"/>.</summary>
    private string Write(string name, byte[] bytes)
    {
        var hash = Convert.ToHexStringLower(SHA256.HashData(bytes))[..32];
        EnsureRoot();
        var dir = Path.Combine(Root, hash);
        var path = Path.Combine(dir, name);
        if (File.Exists(path) && File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes))
        {
            // fresh again: the pruning leaves it to the check or engine that is about to load it
            Directory.SetLastWriteTimeUtc(dir, DateTime.UtcNow);
            return path;
        }
        if (!Directory.Exists(dir))
            MakeRoom(bytes.Length);
        CreateDir(dir);
        var tmp = Path.Combine(dir, "." + Guid.NewGuid().ToString("N") + ".tmp");
        File.WriteAllBytes(tmp, bytes);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        File.Move(tmp, path, overwrite: true);
        Directory.SetLastWriteTimeUtc(dir, DateTime.UtcNow);
        return path;
    }

    /// <summary>
    /// Keeps the store within its caps before a new folder of <paramref name="adding"/> bytes: the oldest copies that
    /// no running engine uses and no check may be using go first; if that is not enough, the new file is refused.
    /// </summary>
    private void MakeRoom(long adding)
    {
        var folders = new DirectoryInfo(Root).GetDirectories()
            .Select(d => (Dir: d, Bytes: d.GetFiles().Sum(f => f.Length)))
            .ToList();
        long bytes = folders.Sum(f => f.Bytes);
        int count = folders.Count;
        if (bytes + adding <= StoreBytesCap && count + 1 <= StoreFoldersCap)
            return;
        var inUse = _inUse().Select(p => Path.GetDirectoryName(Path.GetFullPath(p))).ToHashSet(StringComparer.Ordinal);
        var cutoff = DateTime.UtcNow - Grace;
        foreach (var (d, b) in folders.Where(f => !inUse.Contains(f.Dir.FullName) && f.Dir.LastWriteTimeUtc < cutoff).OrderBy(f => f.Dir.LastWriteTimeUtc))
        {
            if (bytes + adding <= StoreBytesCap && count + 1 <= StoreFoldersCap)
                break;
            try
            {
                d.Delete(recursive: true);
                bytes -= b;
                count--;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
            }
        }
        if (bytes + adding > StoreBytesCap || count + 1 > StoreFoldersCap)
            throw new EngineStartException("engine", [$"каталог копий Agent'а заполнен ({count} папок, {bytes / 1024} KB): остановите лишние экземпляры движка"]);
    }

    /// <summary>
    /// Creates the parent and this Agent's folder once. Privileged on Windows both are created protected (and refused
    /// when someone else made them); on Linux the folder must not exist yet: its name is random, so one that does was
    /// not made by this Agent.
    /// </summary>
    private void EnsureRoot()
    {
        if (_rootReady && Directory.Exists(Root))
            return;
        var parent = Path.GetDirectoryName(Root)!;
        bool privileged = Environment.IsPrivilegedProcess;
        if (OperatingSystem.IsWindows() && privileged)
        {
            WinwsService.CreateProtected(parent);
            WinwsService.CreateProtected(Root);
        }
        else
        {
            CreateDir(parent);
            if (privileged && !_rootReady && (Directory.Exists(Root) || File.Exists(Root)))
                throw new EngineStartException("engine", [$"{Root}: каталог уже существует, его создал не этот Agent"]);
            CreateDir(Root);
        }
        if (!File.Exists(Path.Combine(Root, OwnerFile)))
            WriteOwner();
        _rootReady = true;
    }

    private void WriteOwner()
    {
        using var self = System.Diagnostics.Process.GetCurrentProcess();
        File.WriteAllText(Path.Combine(Root, OwnerFile), OwnerText(Environment.ProcessId, self.StartTime.ToUniversalTime()));
    }

    internal static string OwnerText(int pid, DateTime startUtc) =>
        pid.ToString(CultureInfo.InvariantCulture) + " " + startUtc.Ticks.ToString(CultureInfo.InvariantCulture);

    /// <summary>A directory the engine can enter after dropping root (0755 on Linux), never through a symlink.</summary>
    private static void CreateDir(string dir)
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(dir);
            return;
        }
        const UnixFileMode mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
        var info = new DirectoryInfo(dir);
        if (info.Exists && info.LinkTarget is not null)
            throw new EngineStartException("engine", [$"{dir}: символическая ссылка вместо каталога Agent'а"]);
        Directory.CreateDirectory(dir, mode);
        File.SetUnixFileMode(dir, mode);
    }

    /// <summary>Removes this Agent's copies (on exit).</summary>
    public void Clear()
    {
        lock (_lock)
        {
            try
            {
                if (Directory.Exists(Root))
                    Directory.Delete(Root, recursive: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
            }
            _rootReady = false;
        }
    }

    /// <summary>
    /// Removes the folders of Agents that are gone (a crash left them behind): every <c>lua-*</c> folder but this one
    /// whose owner marker does not name a live process with the same start time (a recycled pid is not the owner).
    /// A folder without a marker is left alone for a minute: its Agent may be writing it right now.
    /// </summary>
    public void RemoveStale()
    {
        var parent = Path.GetDirectoryName(Root);
        if (parent is null || !Directory.Exists(parent))
            return;
        var self = Path.GetFullPath(Root);
        foreach (var dir in Directory.GetDirectories(parent, "lua-*"))
        {
            if (string.Equals(Path.GetFullPath(dir), self, StringComparison.Ordinal) || OwnedByLiveAgent(dir))
                continue;
            try
            {
                Directory.Delete(dir, recursive: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    private static bool OwnedByLiveAgent(string dir)
    {
        string text;
        try
        {
            var marker = Path.Combine(dir, OwnerFile);
            if (!File.Exists(marker))
                return DateTime.UtcNow - Directory.GetLastWriteTimeUtc(dir) < TimeSpan.FromMinutes(1);
            text = File.ReadAllText(marker);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return true;
        }
        var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2
            || !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var pid)
            || !long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var ticks))
            return false;
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            return !p.HasExited && Math.Abs((p.StartTime.ToUniversalTime() - new DateTime(ticks, DateTimeKind.Utc)).TotalSeconds) < 5;
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }
}
