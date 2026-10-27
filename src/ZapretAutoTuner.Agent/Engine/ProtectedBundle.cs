using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using ZapretAutoTuner.Tools;

namespace ZapretAutoTuner.Agent.Engine;

/// <summary>
/// The engine files a privileged Agent runs (final review 9). A portable zip or tar.gz unpacked into the user's folder
/// leaves winws2/nfqws2, its DLLs and Lua writable by the user: the Agent would run as Administrator/root whatever the
/// user (or malware in the user's session) put there. So when the bundle is writable by anyone but administrators,
/// it is copied into the Agent's protected store and checked against the hashes of <c>bundle.json</c>
/// (<see cref="Zapret2Bundle.Verify"/>) on the copy, which is what runs; a mismatch refuses with stage "engine".
/// <para>
/// The Agent binary itself cannot be protected this way (it already runs): docs/USER.md says to use the installer,
/// .deb or .rpm for privileged use, or to unpack a portable archive into an admin-only folder.
/// </para>
/// </summary>
internal static class ProtectedBundle
{
    /// <summary>Why the bundle at <paramref name="root"/> could be changed by a non-administrator, or empty.</summary>
    public static List<string> WritableByOthers(string root, string engineFileName)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var dirs = new List<string> { full };
        var files = new List<string> { Path.Combine(full, engineFileName), Path.Combine(full, "bundle.json") };
        try
        {
            if (new Zapret2Bundle(full).ReadManifest() is { } manifest)
            {
                foreach (var rel in manifest.Files.Keys)
                {
                    if (!SafeRelative(rel))
                        continue;
                    var path = Path.Combine(full, rel.Replace('/', Path.DirectorySeparatorChar));
                    files.Add(path);
                    for (var d = Path.GetDirectoryName(path); d is not null && d.Length > full.Length; d = Path.GetDirectoryName(d))
                        dirs.Add(d);
                }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            // an unreadable manifest is Verify's to report; the folders are still checked
        }
        var ancestors = new List<string>();
        for (var d = Path.GetDirectoryName(full); d is not null; d = Path.GetDirectoryName(d))
            ancestors.Add(d);
        files = [.. files.Distinct(StringComparer.Ordinal).Where(File.Exists)];
        dirs = [.. dirs.Distinct(StringComparer.Ordinal).Where(Directory.Exists)];
        return OperatingSystem.IsWindows() ? Acl.WindowsProblems(dirs, files, ancestors) : UnixProblems(dirs, files, ancestors);
    }

    internal static bool SafeRelative(string rel) =>
        rel.Length > 0 && !Path.IsPathRooted(rel) && !rel.Contains('\\', StringComparison.Ordinal)
        && rel.Split('/').All(p => p.Length > 0 && p != "." && p != "..");

    /// <summary>
    /// Copies the bundle (bundle.json and every file it lists) into <paramref name="target"/> and verifies the copy.
    /// Throws <see cref="EngineStartException"/> (stage "engine") when it does not match.
    /// </summary>
    public static void CopyAndVerify(string source, string target, string engineFileName)
    {
        var src = new Zapret2Bundle(source);
        BundleManifest? manifest;
        try
        {
            manifest = src.ReadManifest();
        }
        catch (System.Text.Json.JsonException e)
        {
            throw Refusal(source, [$"bundle.json: {e.Message}"]);
        }
        if (manifest is null)
            throw Refusal(source, ["нет bundle.json: проверить файлы движка не по чему / no bundle.json to verify the engine files against"]);
        var bad = manifest.Files.Keys.Where(r => !SafeRelative(r)).ToList();
        if (bad.Count > 0)
            throw Refusal(source, [.. bad.Select(r => $"bundle.json: недопустимый путь {r}")]);
        Copy(src.ManifestPath, Path.Combine(target, "bundle.json"), executable: false);
        foreach (var rel in manifest.Files.Keys)
        {
            var from = Path.Combine(source, rel.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(from))
                continue; // Verify names it
            var to = Path.Combine(target, rel.Replace('/', Path.DirectorySeparatorChar));
            CreateDirs(target, Path.GetDirectoryName(to)!);
            Copy(from, to, executable: rel == engineFileName);
        }
        // the hashes are checked on the copy: what was verified is what runs, nobody can swap it in between
        var check = new Zapret2Bundle(target).Verify();
        if (!manifest.Files.ContainsKey(engineFileName))
            throw Refusal(source, [$"bundle.json не содержит {engineFileName} / does not list the engine"]);
        if (!check.Ok)
            throw Refusal(source, check.Problems);
    }

    private static EngineStartException Refusal(string source, IReadOnlyList<string> problems) =>
        new("engine", [$"движок в {source} доступен на запись не только администраторам, а его проверка не прошла / the engine folder is writable by non-administrators and its files did not verify; "
            + "используйте установщик, .deb или .rpm либо распакуйте архив в папку, доступную на запись только администраторам", .. problems]);

    private static void Copy(string from, string to, bool executable)
    {
        File.Copy(from, to, overwrite: true);
        if (!OperatingSystem.IsWindows())
        {
            var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
            if (executable)
                mode |= UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;
            File.SetUnixFileMode(to, mode);
        }
    }

    private static void CreateDirs(string root, string dir)
    {
        if (OperatingSystem.IsWindows())
        {
            // inside the Agent's protected folder: the subfolders inherit its ACL
            Directory.CreateDirectory(dir);
            return;
        }
        const UnixFileMode mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
        var chain = new Stack<string>();
        for (var d = dir; d.Length > root.Length; d = Path.GetDirectoryName(d)!)
            chain.Push(d);
        foreach (var d in chain)
        {
            Directory.CreateDirectory(d, mode);
            File.SetUnixFileMode(d, mode);
        }
    }

    // ---- Linux: owner and mode of every file, folder and ancestor

    /// <param name="stat">Owner uid and mode of a path (following symlinks), or null; tests pass their own.</param>
    internal static List<string> UnixProblems(List<string> dirs, List<string> files, List<string> ancestors, Func<IReadOnlyList<string>, IReadOnlyDictionary<string, (int Uid, int Mode)>>? stat = null)
    {
        var all = files.Concat(dirs).Concat(ancestors).Distinct(StringComparer.Ordinal).ToList();
        var info = (stat ?? Stat)(all);
        var problems = new List<string>();
        foreach (var p in all)
        {
            if (!info.TryGetValue(p, out var s))
            {
                problems.Add($"{p}: не удалось проверить владельца / could not check the owner");
                continue;
            }
            if (s.Uid != 0)
                problems.Add($"{p}: владелец не root (uid {s.Uid}) / not owned by root");
            bool sticky = (s.Mode & 0x200) != 0;
            bool othersWrite = (s.Mode & 0x12) != 0; // group or other write
            // a sticky ancestor (/tmp) lets others add entries but not rename or replace root's: only our own folders must be closed
            if (othersWrite && !(sticky && ancestors.Contains(p)))
                problems.Add($"{p}: доступен на запись группе или всем / writable by group or others");
        }
        return problems;
    }

    private static IReadOnlyDictionary<string, (int Uid, int Mode)> Stat(IReadOnlyList<string> paths)
    {
        var result = new Dictionary<string, (int, int)>(StringComparer.Ordinal);
        // not through PATH: the Agent runs as root
        var tool = new[] { "/usr/bin/stat", "/bin/stat" }.FirstOrDefault(File.Exists);
        if (tool is null || paths.Count == 0)
            return result;
        var psi = new ProcessStartInfo(tool) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        psi.ArgumentList.Add("-L");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("%u %f");
        psi.ArgumentList.Add("--");
        foreach (var p in paths)
            psi.ArgumentList.Add(p);
        using var proc = Process.Start(psi);
        if (proc is null)
            return result;
        var lines = proc.StandardOutput.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        // one line per path in order; a path stat cannot read prints nothing, so the order only holds when all are there
        if (lines.Length != paths.Count)
            return result;
        for (int i = 0; i < lines.Length; i++)
        {
            var parts = lines[i].Trim().Split(' ');
            if (parts.Length == 2 && int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var uid)
                && int.TryParse(parts[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var mode))
                result[paths[i]] = (uid, mode & 0xFFF);
        }
        return result;
    }

    // ---- Windows: the owner and the DACL of every file, folder and ancestor
    [SupportedOSPlatform("windows")]
    private static class Acl
    {
        private const FileSystemRights GenericAll = (FileSystemRights)0x10000000;
        private const FileSystemRights GenericWrite = (FileSystemRights)0x40000000;

        /// <summary>What lets one add or change files in a folder of the bundle (a DLL next to winws2.exe is loaded too).</summary>
        private const FileSystemRights DirWrite = FileSystemRights.CreateFiles | FileSystemRights.AppendData | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | FileSystemRights.WriteAttributes
            | GenericAll | GenericWrite;

        private const FileSystemRights FileWrite = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete
            | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | GenericAll | GenericWrite;

        /// <summary>An ancestor only matters when it lets one rename or replace what is in it, or change its own rights.</summary>
        private const FileSystemRights AncestorWrite = FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.Delete
            | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | GenericAll;

        internal static List<string> WindowsProblems(List<string> dirs, List<string> files, List<string> ancestors)
        {
            var problems = new List<string>();
            foreach (var d in dirs)
                Check(d, new DirectoryInfo(d).GetAccessControl(), DirWrite, problems);
            foreach (var f in files)
                Check(f, new FileInfo(f).GetAccessControl(), FileWrite, problems);
            foreach (var a in ancestors.Where(Directory.Exists))
                Check(a, new DirectoryInfo(a).GetAccessControl(), AncestorWrite, problems);
            return problems;
        }

        private static bool Trusted(IdentityReference? who)
        {
            if (who is not SecurityIdentifier sid)
                return false;
            return sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) || sid.IsWellKnown(WellKnownSidType.LocalSystemSid)
                // NT SERVICE\TrustedInstaller
                || sid.Value.StartsWith("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", StringComparison.Ordinal)
                // CREATOR OWNER: stands for the owner, which is checked on its own
                || sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid);
        }

        private static void Check(string path, FileSystemSecurity sec, FileSystemRights mask, List<string> problems)
        {
            var owner = sec.GetOwner(typeof(SecurityIdentifier));
            if (!Trusted(owner))
                problems.Add($"{path}: владелец {owner} — не администратор / owner is not an administrator");
            foreach (FileSystemAccessRule rule in sec.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow || rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly))
                    continue;
                if ((rule.FileSystemRights & mask) != 0 && !Trusted(rule.IdentityReference))
                {
                    problems.Add($"{path}: {rule.IdentityReference} может изменять ({rule.FileSystemRights}) / can modify");
                    return;
                }
            }
        }
    }
}
