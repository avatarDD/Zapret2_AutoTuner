using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ZapretAutoTuner.Probes.Programs;

/// <summary>A program's processes: the one we started and every descendant (launchers, renderers, updaters).</summary>
public static partial class ProcessTree
{
    /// <summary><paramref name="root"/> and its descendants that are alive now.</summary>
    public static HashSet<int> Descendants(int root) => Closure(root, Parents());

    /// <summary>Processes whose executable lies under <paramref name="directory"/> (packaged apps the shell starts).</summary>
    public static HashSet<int> UnderDirectory(string directory)
    {
        var result = new HashSet<int>();
        var dir = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                try
                {
                    if (p.MainModule?.FileName is { } f && f.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                        result.Add(p.Id);
                }
                catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
                {
                    // another user's or a protected process
                }
            }
        }
        return result;
    }

    public static HashSet<int> Closure(int root, IReadOnlyDictionary<int, int> parentOf)
    {
        var children = parentOf.Where(kv => kv.Key != kv.Value).ToLookup(kv => kv.Value, kv => kv.Key);
        var result = new HashSet<int>();
        var queue = new Queue<int>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            int pid = queue.Dequeue();
            if (!result.Add(pid))
                continue;
            foreach (var c in children[pid])
                queue.Enqueue(c);
        }
        if (!parentOf.ContainsKey(root))
            result.Remove(root); // gone already
        return result;
    }

    /// <summary>pid → parent pid of every process.</summary>
    public static Dictionary<int, int> Parents()
    {
        if (OperatingSystem.IsWindows())
            return ParentsWindows();
        var d = new Dictionary<int, int>();
        foreach (var dir in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(dir), NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
                continue;
            try
            {
                if (ParseStatParent(File.ReadAllText(Path.Combine(dir, "stat"))) is { } ppid)
                    d[pid] = ppid;
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
        return d;
    }

    /// <summary>The 4th field of <c>/proc/pid/stat</c>; the command name in parentheses may hold spaces and ')'.</summary>
    internal static int? ParseStatParent(string stat)
    {
        int close = stat.LastIndexOf(')');
        if (close < 0)
            return null;
        var fields = stat[(close + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return fields.Length > 1 && int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : null;
    }

    [SupportedOSPlatform("windows")]
    private static Dictionary<int, int> ParentsWindows()
    {
        var d = new Dictionary<int, int>();
        var snap = CreateToolhelp32Snapshot(2 /* TH32CS_SNAPPROCESS */, 0);
        if (snap == -1)
            return d;
        try
        {
            var e = new ProcessEntry32 { Size = Marshal.SizeOf<ProcessEntry32>() };
            for (bool ok = Process32FirstW(snap, ref e); ok; ok = Process32NextW(snap, ref e))
                d[(int)e.ProcessId] = (int)e.ParentProcessId;
        }
        finally
        {
            CloseHandle(snap);
        }
        return d;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public int Size;
        public uint Usage;
        public uint ProcessId;
        public nint DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriClassBase;
        public uint Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateToolhelp32Snapshot(uint flags, uint pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32FirstW(nint snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32NextW(nint snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);
}
