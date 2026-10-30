using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

namespace ZapretAutoTuner.App.Services;

/// <summary>
/// On exit, the program's own helpers that it started go with it: the browser's driver and the browser of the page
/// check, whatever else runs from the program's folder or Playwright's. Only those: a site opened in the user's own
/// browser or a program started for "Программы" belongs to the user and stays. The Agent is not touched either: it got
/// its shutdown and stops its engines and firewall rules by itself (killed, it could leave them behind).
/// </summary>
public static partial class ChildProcesses
{
    private const string AgentName = "ztuner-agent";

    /// <summary>Kills what is left of this process's helpers and their children (Windows and Linux).</summary>
    public static void KillLeftovers()
    {
        Dictionary<int, int> parents;
        try
        {
            if (OperatingSystem.IsLinux())
                parents = ParentsFromProc();
            else if (OperatingSystem.IsWindows())
                parents = ParentsFromSnapshot();
            else
                return;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            return;
        }
        foreach (var pid in Descendants(Environment.ProcessId, parents))
        {
            if (!Ours(ExePath(pid), AppContext.BaseDirectory))
                continue;
            try
            {
                using var p = Process.GetProcessById(pid);
                p.Kill();
            }
            catch (Exception e) when (e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // gone already, or not ours to kill
            }
        }
    }

    /// <summary>
    /// A helper of the program: started from its folder (the bundled browser, Playwright's driver) or from Playwright's
    /// browser cache, and not the Agent. An unknown path is not ours.
    /// </summary>
    internal static bool Ours(string? exe, string baseDir)
    {
        if (string.IsNullOrEmpty(exe))
            return false;
        var path = exe.Replace('\\', '/');
        if (Path.GetFileNameWithoutExtension(path).Equals(AgentName, StringComparison.OrdinalIgnoreCase))
            return false;
        var root = baseDir.Replace('\\', '/').TrimEnd('/') + "/";
        var cmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return path.StartsWith(root, cmp) || path.Contains("/ms-playwright/", cmp);
    }

    /// <summary>Every descendant of <paramref name="root"/> in a pid → parent map, children before their parents' siblings.</summary>
    internal static List<int> Descendants(int root, IReadOnlyDictionary<int, int> parentOf)
    {
        var children = parentOf.GroupBy(kv => kv.Value).ToDictionary(g => g.Key, g => g.Select(kv => kv.Key).Order().ToList());
        var result = new List<int>();
        var stack = new Stack<int>([root]);
        while (stack.Count > 0)
        {
            foreach (var c in children.GetValueOrDefault(stack.Pop()) ?? [])
            {
                if (c == root || result.Contains(c))
                    continue;
                result.Add(c);
                stack.Push(c);
            }
        }
        return result;
    }

    private static string? ExePath(int pid)
    {
        try
        {
            if (OperatingSystem.IsLinux())
                return new FileInfo($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/exe").LinkTarget;
            using var p = Process.GetProcessById(pid);
            return p.MainModule?.FileName;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or InvalidOperationException
                                      or System.ComponentModel.Win32Exception or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>The ppid of every process, from the 4th field of /proc/&lt;pid&gt;/stat (after the parenthesised name).</summary>
    private static Dictionary<int, int> ParentsFromProc()
    {
        var map = new Dictionary<int, int>();
        foreach (var dir in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(dir), NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
                continue;
            try
            {
                var stat = File.ReadAllText(Path.Combine(dir, "stat"));
                var rest = stat[(stat.LastIndexOf(')') + 2)..].Split(' ');
                if (rest.Length > 1 && int.TryParse(rest[1], NumberStyles.None, CultureInfo.InvariantCulture, out var ppid))
                    map[pid] = ppid;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentOutOfRangeException)
            {
            }
        }
        return map;
    }

    /// <summary>The parent of every process from a Toolhelp snapshot (Windows has no ppid in <see cref="Process"/>).</summary>
    private static Dictionary<int, int> ParentsFromSnapshot()
    {
        var map = new Dictionary<int, int>();
        var snap = CreateToolhelp32Snapshot(SnapProcess, 0);
        if (snap == InvalidHandle)
            return map;
        try
        {
            var e = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            for (bool ok = Process32FirstW(snap, ref e); ok; ok = Process32NextW(snap, ref e))
                map[(int)e.ProcessId] = (int)e.ParentProcessId;
        }
        finally
        {
            CloseHandle(snap);
        }
        return map;
    }

    private const uint SnapProcess = 0x2;
    private static readonly IntPtr InvalidHandle = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriClassBase;
        public uint Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32FirstW(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32NextW(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
