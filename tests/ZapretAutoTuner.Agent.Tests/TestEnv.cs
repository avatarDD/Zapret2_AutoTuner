using System.Diagnostics;

namespace ZapretAutoTuner.Agent.Tests;

internal static class TestEnv
{
    public static string Root { get; } = FindRoot();

    public static string LuaDir => Path.Combine(Root, "third_party", "zapret2", "lua");

    /// <summary>A valid argv with the standard lua files (the Validator requires them for --lua-desync).</summary>
    public static List<string> SampleArgv() =>
    [
        "--lua-init=@" + Path.Combine(LuaDir, "zapret-lib.lua"),
        "--lua-init=@" + Path.Combine(LuaDir, "zapret-antidpi.lua"),
        "--filter-tcp=443",
        "--lua-desync=multisplit:pos=1",
    ];

    public static string NewTempDir()
    {
        var d = Path.Combine(Path.GetTempPath(), "zt-agent-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(d);
        return d;
    }

    public static bool IsRootLinux => OperatingSystem.IsLinux() && Environment.IsPrivilegedProcess;

    public static string AgentPath =>
        Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "ztuner-agent.exe" : "ztuner-agent");

    /// <summary>
    /// A shell script standing in for nfqws2: answers --version/--dry-run/--intercept=0, otherwise writes its pid,
    /// prints its argv and a profile line, and runs until SIGTERM.
    /// </summary>
    public static string WriteFakeEngine(string dir)
    {
        var path = Path.Combine(dir, "nfqws2");
        File.WriteAllText(path, """
            #!/bin/sh
            dir=$(dirname "$0")
            for a in "$@"; do
              case "$a" in
                --version) echo "github version v1.0.5.2 (fake) lua_compat_ver 6"; exit 0;;
                --dry-run) echo "parameters ok"; exit 0;;
                --intercept=0) echo "no intercept quit"; exit 0;;
              esac
            done
            echo $$ > "$dir/engine.pid"
            for a in "$@"; do echo "arg $a"; done
            echo "desync profile 1 (noname) matches"
            trap 'echo terminated; exit 0' TERM
            while true; do sleep 0.1; done
            """.Replace("\r", "", StringComparison.Ordinal));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    public static bool ProcessAlive(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    public static async Task<bool> WaitUntil(Func<bool> cond, TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            if (cond())
                return true;
            await Task.Delay(50);
        }
        return cond();
    }

    public static string Run(string file, params string[] args)
    {
        var psi = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args)
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        return o;
    }

    private static string FindRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AGENTS.md")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("repository root not found");
    }

    /// <summary>A long-running stand-in for the UI process.</summary>
    public static Process StartDummyUi() => OperatingSystem.IsWindows()
        ? Process.Start(new ProcessStartInfo("ping", "-n 60 127.0.0.1") { CreateNoWindow = true, RedirectStandardOutput = true })!
        : Process.Start(new ProcessStartInfo("sleep", "60"))!;
}

/// <summary>
/// Tests that start Agent processes run one at a time: the firewall table and chains are global by name, so a
/// second Agent's cleanup would remove the first one's rules (in real use there is one Agent per machine).
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class AgentProcessCollection
{
    public const string Name = "agent processes";
}
