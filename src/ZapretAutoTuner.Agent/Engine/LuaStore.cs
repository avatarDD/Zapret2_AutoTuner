using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Agent.Os;
using ZapretAutoTuner.Core.Engine;

namespace ZapretAutoTuner.Agent.Engine;

/// <summary>
/// The Agent's own copies of the Lua files an engine loads (PLAN 4a.5, user Lua). The UI sends the content of every
/// <c>--lua-init=@file</c> with the request (<c>lua_files</c>); a file outside the engine's directory is never loaded
/// from where the UI keeps it. On Linux nfqws2 reads Lua only after dropping root (nfqws.c: droproot, then
/// <c>lua_test_init_script_files</c>), so a script in a 0700 home is unreadable to it; on Windows winws2 runs as
/// Administrator, so a script in the user's writable %LOCALAPPDATA% could be swapped between the check and the load.
/// The copy lives in a folder only the Agent can write: Linux <c>/run/zapret-autotuner</c> (root, 0755; files 0644),
/// Windows <c>%ProgramData%\ZapretAutoTuner-agent</c> (Administrators and SYSTEM only, like the winws2 service folder).
/// Copies are named by their SHA-256, so two engines with the same script share one file; all go when the Agent exits.
/// </summary>
internal sealed partial class LuaStore
{
    public const long MaxTotalBytes = 8L * 1024 * 1024;

    [GeneratedRegex("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,123}\\.lua\\z")]
    private static partial Regex SafeName();

    private readonly Lock _lock = new();
    private readonly string _engineDir;

    /// <param name="root">This Agent's folder for the copies; created on first use.</param>
    /// <param name="engineDir">The engine's own directory: its Lua is the bundled one and is loaded where it is.</param>
    public LuaStore(string root, string engineDir)
    {
        Root = root;
        _engineDir = engineDir;
    }

    public string Root { get; }

    /// <summary>Where Lua may be loaded from: the engine's directory and this store.</summary>
    public IReadOnlyList<string> AllowedRoots => [_engineDir, Root];

    /// <summary>
    /// The default folder: protected when the Agent runs privileged, inside the data directory otherwise (tests and a
    /// UI that runs the Agent without rights, where the engine has nothing to drop and nothing to escalate to).
    /// </summary>
    public static string DefaultRoot(string dataDir)
    {
        var name = "lua-" + Environment.ProcessId.ToString(CultureInfo.InvariantCulture);
        if (!Environment.IsPrivilegedProcess)
            return Path.Combine(dataDir, "agent-lua", name);
        return OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ZapretAutoTuner-agent", name)
            : Path.Combine(LinuxBase, name);
    }

    /// <summary>Directly under /run (root-owned, 0755): no other user can create or swap it.</summary>
    public const string LinuxBase = "/run/zapret-autotuner";

    /// <summary>
    /// The argv with each <c>--lua-init=@file</c> outside the engine's directory replaced by the store's copy of the
    /// content the UI sent. Throws <see cref="EngineStartException"/> ("policy") when such a file came without its
    /// content or the content is not acceptable.
    /// </summary>
    public List<string> Prepare(IReadOnlyList<string> argv, IReadOnlyDictionary<string, byte[]> files)
    {
        var problems = new List<string>();
        var result = new List<string>(argv.Count);
        long total = 0;
        foreach (var tok in argv)
        {
            const string prefix = "--lua-init=@";
            if (!tok.StartsWith(prefix, StringComparison.Ordinal))
            {
                result.Add(tok);
                continue;
            }
            var path = tok[prefix.Length..];
            if (EngineArgvPolicy.IsUnder(path, [_engineDir]))
            {
                result.Add(tok);
                continue;
            }
            if (!files.TryGetValue(path, out var bytes))
            {
                problems.Add($"--lua-init=@{path}: файл вне каталога движка, а его содержимого в запросе нет");
                continue;
            }
            var name = Path.GetFileName(path.Replace('\\', '/'));
            if (!SafeName().IsMatch(name))
            {
                problems.Add($"--lua-init=@{path}: недопустимое имя Lua-файла");
                continue;
            }
            total += bytes.Length;
            if (bytes.Length > Protocol.LuaFiles.MaxFileBytes || total > MaxTotalBytes)
            {
                problems.Add($"--lua-init=@{path}: Lua-файл слишком большой");
                continue;
            }
            result.Add(prefix + Write(name, bytes));
        }
        if (problems.Count > 0)
            throw new EngineStartException("policy", problems);
        return result;
    }

    /// <summary>Writes the content once (by its hash) and returns the copy's path.</summary>
    private string Write(string name, byte[] bytes)
    {
        var hash = Convert.ToHexStringLower(SHA256.HashData(bytes))[..32];
        lock (_lock)
        {
            EnsureRoot();
            var dir = Path.Combine(Root, hash);
            var path = Path.Combine(dir, name);
            if (File.Exists(path) && File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes))
                return path;
            CreateDir(dir);
            var tmp = Path.Combine(dir, "." + Guid.NewGuid().ToString("N") + ".tmp");
            File.WriteAllBytes(tmp, bytes);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            File.Move(tmp, path, overwrite: true);
            return path;
        }
    }

    private void EnsureRoot()
    {
        if (Directory.Exists(Root))
            return;
        var parent = Path.GetDirectoryName(Root)!;
        if (OperatingSystem.IsWindows() && Environment.IsPrivilegedProcess)
            WinwsService.CreateProtected(parent);
        else
            CreateDir(parent);
        CreateDir(Root);
    }

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
            throw new EngineStartException("policy", [$"{dir}: символическая ссылка вместо каталога Agent'а"]);
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
        }
    }

    /// <summary>Removes the folders of Agents that are gone (a crash left them behind).</summary>
    public void RemoveStale()
    {
        var parent = Path.GetDirectoryName(Root);
        if (parent is null || !Directory.Exists(parent))
            return;
        foreach (var dir in Directory.GetDirectories(parent, "lua-*"))
        {
            if (!int.TryParse(Path.GetFileName(dir)[4..], NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid == Environment.ProcessId || Alive(pid))
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

    private static bool Alive(int pid)
    {
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }
}
