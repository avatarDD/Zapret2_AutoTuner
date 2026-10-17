using System.Diagnostics;

namespace ZapretAutoTuner.Agent.Os;

internal sealed record CmdResult(int ExitCode, string Stdout, string Stderr)
{
    public bool Ok => ExitCode == 0;

    public string Output => (Stdout + Stderr).Trim();
}

/// <summary>Runs short system commands (nft, iptables, sysctl helpers) and collects their output.</summary>
internal static class Cmd
{
    public static async Task<CmdResult> RunAsync(string file, IEnumerable<string> args, string? stdin = null, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = stdin is not null,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in args)
            psi.ArgumentList.Add(a);
        Process p;
        try
        {
            p = Process.Start(psi) ?? throw new InvalidOperationException($"could not start {file}");
        }
        catch (System.ComponentModel.Win32Exception e)
        {
            return new CmdResult(127, "", $"{file}: {e.Message}");
        }
        using (p)
        {
            var outTask = p.StandardOutput.ReadToEndAsync(ct);
            var errTask = p.StandardError.ReadToEndAsync(ct);
            if (stdin is not null)
            {
                await p.StandardInput.WriteAsync(stdin.AsMemory(), ct);
                p.StandardInput.Close();
            }
            await p.WaitForExitAsync(ct);
            return new CmdResult(p.ExitCode, await outTask, await errTask);
        }
    }

    public static CmdResult Run(string file, IEnumerable<string> args, string? stdin = null) =>
        RunAsync(file, args, stdin).GetAwaiter().GetResult();

    /// <summary>Finds an executable in PATH and the usual sbin directories (pkexec clears PATH).</summary>
    public static string? Which(string name)
    {
        var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Concat(["/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin"]);
        foreach (var d in dirs)
        {
            var f = Path.Combine(d, name);
            if (File.Exists(f))
                return f;
        }
        return null;
    }
}
