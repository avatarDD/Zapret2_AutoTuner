using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ZapretAutoTuner.Probes.Programs;

/// <summary>
/// A process that cannot be confused with a later one reusing its pid: the pid and the start time (Linux: clock ticks
/// since boot from <c>/proc/pid/stat</c>; Windows: the creation FILETIME). <see cref="Start"/> is 0 when it could not
/// be read (another user's process); such a key matches any process with that pid.
/// </summary>
public readonly record struct ProcessKey(int Pid, long Start)
{
    public bool Matches(ProcessEntry e) => e.Pid == Pid && (Start == 0 || e.Start == 0 || e.Start == Start);
}

/// <summary>One process in a <see cref="ProcessTree.Snapshot"/>.</summary>
public sealed record ProcessEntry(int Pid, int Parent, long Start)
{
    public ProcessKey Key => new(Pid, Start);
}

/// <summary>
/// Executable paths of processes, read once per process (by <see cref="ProcessKey"/>, so a reused pid is read again)
/// instead of opening every process's modules on every poll.
/// </summary>
public sealed class ProcessImageCache(Func<int, string?>? read = null)
{
    private readonly Func<int, string?> _read = read ?? ProcessTree.ImagePath;
    private readonly Dictionary<ProcessKey, string?> _paths = [];

    /// <summary>How many paths were read so far (for tests).</summary>
    public int Reads { get; private set; }

    /// <summary>Processes of <paramref name="snapshot"/> whose executable lies under <paramref name="directory"/>.</summary>
    public HashSet<int> UnderDirectory(string directory, IReadOnlyDictionary<int, ProcessEntry> snapshot)
    {
        var dir = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var cmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var live = new HashSet<ProcessKey>();
        var result = new HashSet<int>();
        foreach (var e in snapshot.Values)
        {
            var key = e.Key;
            live.Add(key);
            if (!_paths.TryGetValue(key, out var path))
            {
                Reads++;
                _paths[key] = path = _read(e.Pid);
            }
            if (path is not null && path.StartsWith(dir, cmp))
                result.Add(e.Pid);
        }
        foreach (var gone in _paths.Keys.Where(k => !live.Contains(k)).ToList())
            _paths.Remove(gone);
        return result;
    }
}

/// <summary>A program's processes: the one we started and every descendant (launchers, renderers, updaters).</summary>
public static partial class ProcessTree
{
    /// <summary><paramref name="root"/> and its descendants that are alive now.</summary>
    public static HashSet<int> Descendants(int root) => Closure(root, Parents());

    /// <summary>pid → parent pid of every process.</summary>
    public static Dictionary<int, int> Parents() => Snapshot().ToDictionary(kv => kv.Key, kv => kv.Value.Parent);

    /// <summary>Every process with its parent and start time.</summary>
    public static Dictionary<int, ProcessEntry> Snapshot() => OperatingSystem.IsWindows() ? SnapshotWindows() : SnapshotLinux();

    /// <summary>The key of a live process, or null when it is gone.</summary>
    public static ProcessKey? KeyOf(int pid) => Snapshot().TryGetValue(pid, out var e) ? e.Key : null;

    /// <summary>The processes among <paramref name="keys"/> that still run (a reused pid does not count).</summary>
    public static List<ProcessKey> Alive(IEnumerable<ProcessKey> keys, IReadOnlyDictionary<int, ProcessEntry>? snapshot = null)
    {
        snapshot ??= Snapshot();
        return keys.Where(k => snapshot.TryGetValue(k.Pid, out var e) && k.Matches(e)).ToList();
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

    /// <summary>
    /// <paramref name="root"/> and its live descendants by key. A process is a child only if it started no earlier
    /// than its parent: an older process whose parent pid was later reused by the root is not the root's child.
    /// </summary>
    public static HashSet<ProcessKey> Closure(ProcessKey root, IReadOnlyDictionary<int, ProcessEntry> snapshot)
    {
        var children = snapshot.Values.Where(e => e.Pid != e.Parent).ToLookup(e => e.Parent);
        var result = new HashSet<ProcessKey>();
        var queue = new Queue<ProcessKey>();
        snapshot.TryGetValue(root.Pid, out var r);
        bool rootAlive = r is not null && root.Matches(r);
        // the root exited and its pid went to another process: only children older than that process are the root's
        long reusedAt = r is not null && !rootAlive ? r.Start : long.MaxValue;
        queue.Enqueue(rootAlive ? r!.Key : root);
        var visited = new HashSet<int>();
        while (queue.Count > 0)
        {
            var k = queue.Dequeue();
            if (!visited.Add(k.Pid))
                continue;
            result.Add(k);
            foreach (var c in children[k.Pid])
            {
                if (k.Pid == root.Pid && !rootAlive && c.Start >= reusedAt && c.Start != 0)
                    continue;
                if (k.Start == 0 || c.Start == 0 || c.Start >= k.Start)
                    queue.Enqueue(c.Key);
            }
        }
        if (!rootAlive)
            result.Remove(root); // gone already, its orphans stay
        return result;
    }

    /// <summary>The 4th field of <c>/proc/pid/stat</c>; the command name in parentheses may hold spaces and ')'.</summary>
    internal static int? ParseStatParent(string stat) => StatField(stat, 1) is { } v && int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : null;

    /// <summary>The 22nd field of <c>/proc/pid/stat</c>: the start time in clock ticks after boot.</summary>
    internal static long? ParseStatStart(string stat) => StatField(stat, 19) is { } v && long.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var t) ? t : null;

    /// <summary>A field after the command name: index 0 is the state (field 3).</summary>
    private static string? StatField(string stat, int index)
    {
        int close = stat.LastIndexOf(')');
        if (close < 0)
            return null;
        var fields = stat[(close + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return fields.Length > index ? fields[index] : null;
    }

    private static Dictionary<int, ProcessEntry> SnapshotLinux()
    {
        var d = new Dictionary<int, ProcessEntry>();
        foreach (var dir in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(dir), NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
                continue;
            try
            {
                var stat = File.ReadAllText(Path.Combine(dir, "stat"));
                if (ParseStatParent(stat) is { } ppid)
                    d[pid] = new ProcessEntry(pid, ppid, ParseStatStart(stat) ?? 0);
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

    [SupportedOSPlatform("windows")]
    private static Dictionary<int, ProcessEntry> SnapshotWindows()
    {
        var d = new Dictionary<int, ProcessEntry>();
        foreach (var (pid, parent) in ParentsWindows())
            d[pid] = new ProcessEntry(pid, parent, StartTimeWindows(pid));
        return d;
    }

    /// <summary>The executable of a process, or null when it cannot be read (Windows: QueryFullProcessImageName,
    /// which needs only limited query rights; Linux: the <c>/proc/pid/exe</c> link).</summary>
    public static string? ImagePath(int pid)
    {
        if (OperatingSystem.IsWindows())
            return ImagePathWindows(pid);
        try
        {
            return new FileInfo($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/exe").LinkTarget;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private static long StartTimeWindows(int pid)
    {
        var h = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (h == 0)
            return 0;
        try
        {
            return GetProcessTimes(h, out var created, out _, out _, out _) ? created : 0;
        }
        finally
        {
            CloseHandle(h);
        }
    }

    [SupportedOSPlatform("windows")]
    private static string? ImagePathWindows(int pid)
    {
        var h = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (h == 0)
            return null;
        try
        {
            var buf = new char[32768];
            int size = buf.Length;
            return QueryFullProcessImageNameW(h, 0, buf, ref size) ? new string(buf, 0, size) : null;
        }
        finally
        {
            CloseHandle(h);
        }
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(nint process, out long creation, out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(nint process, uint flags, [Out] char[] name, ref int size);

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
