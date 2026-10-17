using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Agent.Os;

/// <summary>
/// winws2 as a Windows service (PLAN 5.3, strategy-export §1.2): the winws2 export goes into a directory only
/// administrators and SYSTEM can write (the service runs as LocalSystem, so a user-writable path would be a privilege
/// escalation), together with a copy of the bundled engine; relative paths in the @config become absolute (a service
/// starts in System32); the config passes the Agent's precheck before <c>sc create</c>. The service stays after the
/// Agent exits: installing it is the user's explicit choice.
/// </summary>
internal static partial class WinwsService
{
    public const string Name = "zt_winws2";
    public const string ConfigFile = "zt-config.txt";
    private const long MaxBytes = 16 * 1024 * 1024;

    private static readonly string[] EngineFiles = ["winws2.exe", "cygwin1.dll", "WinDivert.dll", "WinDivert64.sys"];
    private static readonly string[] PathOptions = ["--hostlist", "--hostlist-exclude", "--hostlist-auto", "--ipset", "--ipset-exclude"];

    [GeneratedRegex("^(zt-config\\.txt|lists/[A-Za-z0-9_.-]+|files/[A-Za-z0-9_.-]+)$")]
    private static partial Regex SafeFile();

    /// <summary>Directly under ProgramData, so no user-owned parent can swap it.</summary>
    public static string Directory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ZapretAutoTuner-service");

    /// <summary>The files of a winws2 export the service may get, or why not.</summary>
    public static string? CheckFiles(IReadOnlyDictionary<string, byte[]> files)
    {
        if (!files.ContainsKey(ConfigFile))
            return $"нет {ConfigFile}";
        foreach (var name in files.Keys)
        {
            if (!SafeFile().IsMatch(name) || name.Contains("..", StringComparison.Ordinal))
                return $"недопустимое имя файла: {name}";
        }
        return files.Values.Sum(v => (long)v.Length) > MaxBytes ? "файлы больше 16 MB" : null;
    }

    /// <summary>The @config with every relative path made absolute under <paramref name="dir"/>.</summary>
    public static string RewriteConfig(string config, string dir)
    {
        string Abs(string p) => Path.IsPathRooted(p) || p.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? p
            : Path.Combine(dir, p.Replace('/', Path.DirectorySeparatorChar));
        var lines = new List<string>();
        foreach (var line in config.ReplaceLineEndings("\n").Split('\n'))
        {
            var tokens = ArgTokenizer.Split(line).Select(t =>
            {
                var (name, value) = ArgTokenizer.SplitOption(t);
                if (value is null)
                    return t;
                if (name == "--lua-init" && value.StartsWith('@'))
                    return $"{name}=@{Abs(value[1..])}";
                if (name == "--blob" && value.IndexOf(":@", StringComparison.Ordinal) is int at and > 0)
                    return $"{name}={value[..(at + 2)]}{Abs(value[(at + 2)..])}";
                if (PathOptions.Contains(name))
                    return $"{name}={Abs(value)}";
                return t;
            });
            lines.Add(string.Join(' ', tokens.Select(t => t.Contains(' ', StringComparison.Ordinal) ? $"'{t}'" : t)));
        }
        return string.Join("\n", lines.Where(l => l.Length > 0)) + "\n";
    }

    /// <summary>The argv the service will run, for the precheck.</summary>
    public static List<string> Argv(string config) => ArgTokenizer.Split(config);

    [SupportedOSPlatform("windows")]
    public static async Task<string> InstallAsync(IReadOnlyDictionary<string, byte[]> files, string enginePath, Func<IReadOnlyList<string>, string?> precheck, CancellationToken ct)
    {
        if (CheckFiles(files) is { } bad)
            throw new ArgumentException(bad);
        var dir = Directory;
        var staging = dir + ".new";
        if (System.IO.Directory.Exists(staging))
            System.IO.Directory.Delete(staging, true);
        CreateProtected(staging);
        try
        {
            var engineDir = Path.GetDirectoryName(enginePath)!;
            foreach (var f in EngineFiles.Where(f => File.Exists(Path.Combine(engineDir, f))))
                File.Copy(Path.Combine(engineDir, f), Path.Combine(staging, f));
            System.IO.Directory.CreateDirectory(Path.Combine(staging, "lua"));
            foreach (var f in System.IO.Directory.GetFiles(Path.Combine(engineDir, "lua"), "*.lua"))
                File.Copy(f, Path.Combine(staging, "lua", Path.GetFileName(f)));
            foreach (var (name, bytes) in files.Where(f => f.Key != ConfigFile))
            {
                var path = Path.Combine(staging, name.Replace('/', Path.DirectorySeparatorChar));
                System.IO.Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                await File.WriteAllBytesAsync(path, bytes, ct);
            }
            // the precheck sees the files where they are; the installed service is untouched until it passes
            var text = Encoding.UTF8.GetString(files[ConfigFile]);
            if (precheck(Argv(RewriteConfig(text, staging))) is { } problems)
                throw new ArgumentException(problems);
            await RemoveAsync(ct);
            if (System.IO.Directory.Exists(dir))
                System.IO.Directory.Delete(dir, true);
            System.IO.Directory.Move(staging, dir);
            await File.WriteAllTextAsync(Path.Combine(dir, ConfigFile), RewriteConfig(text, dir), new UTF8Encoding(false), ct);
        }
        catch
        {
            if (System.IO.Directory.Exists(staging))
                System.IO.Directory.Delete(staging, true);
            throw;
        }

        var exe = Path.Combine(dir, "winws2.exe");
        var cfg = Path.Combine(dir, ConfigFile);
        var bin = $"\"{exe}\" @\"{cfg}\"";
        var create = await Cmd.RunAsync("sc.exe", ["create", Name, "binPath=", bin, "start=", "auto", "DisplayName=", "Zapret2 AutoTuner (winws2)"], ct: ct);
        if (!create.Ok)
            throw new InvalidOperationException("sc create: " + create.Output);
        await Cmd.RunAsync("sc.exe", ["description", Name, "winws2 with the strategy chosen by Zapret2 AutoTuner"], ct: ct);
        var start = await Cmd.RunAsync("sc.exe", ["start", Name], ct: ct);
        return create.Output + "\n" + start.Output;
    }

    [SupportedOSPlatform("windows")]
    public static async Task<string> RemoveAsync(CancellationToken ct)
    {
        var query = await Cmd.RunAsync("sc.exe", ["query", Name], ct: ct);
        if (!query.Ok)
            return "";
        var stop = await Cmd.RunAsync("sc.exe", ["stop", Name], ct: ct);
        for (int i = 0; i < 20 && (await Cmd.RunAsync("sc.exe", ["query", Name], ct: ct)).Stdout.Contains("STOP_PENDING", StringComparison.Ordinal); i++)
            await Task.Delay(250, ct);
        var delete = await Cmd.RunAsync("sc.exe", ["delete", Name], ct: ct);
        return stop.Output + "\n" + delete.Output;
    }

    [SupportedOSPlatform("windows")]
    public static async Task<(bool Installed, bool Running, string Output)> QueryAsync(CancellationToken ct)
    {
        var q = await Cmd.RunAsync("sc.exe", ["query", Name], ct: ct);
        return (q.Ok, q.Ok && q.Stdout.Contains("RUNNING", StringComparison.Ordinal), q.Output);
    }

    /// <summary>A directory with inheritance cut: Administrators and SYSTEM full control, Users read.</summary>
    [SupportedOSPlatform("windows")]
    private static void CreateProtected(string dir)
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        sec.SetOwner(admins);
        var info = new DirectoryInfo(dir);
        info.Create(sec);
        // Create() keeps an existing directory as it is: if someone recreated it in between, refuse
        var actual = info.GetAccessControl();
        var owner = actual.GetOwner(typeof(SecurityIdentifier));
        if (!actual.AreAccessRulesProtected || (owner != admins && owner != new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)))
            throw new UnauthorizedAccessException($"{dir}: каталог создан не Agent'ом, служба не установлена");
    }
}
