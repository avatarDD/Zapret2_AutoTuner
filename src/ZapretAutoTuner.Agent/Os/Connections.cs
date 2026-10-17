using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Agent.Os;

/// <summary>Sockets owned by a process (PLAN 1.1 <c>ListConnections</c>, used by the program picker in phase 6).</summary>
internal static partial class Connections
{
    public static List<Connection> List(int pid)
    {
        if (OperatingSystem.IsLinux())
            return ListLinux(pid, "/proc");
        if (OperatingSystem.IsWindows())
            return ListWindows(pid);
        return [];
    }

    private static readonly string[] TcpStates =
    [
        "", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT",
        "LAST_ACK", "LISTEN", "CLOSING",
    ];

    /// <summary>Socket inodes from <c>/proc/pid/fd</c> matched against <c>/proc/net/{tcp,udp}{,6}</c>.</summary>
    internal static List<Connection> ListLinux(int pid, string proc)
    {
        var inodes = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (var fd in Directory.EnumerateFiles(Path.Combine(proc, pid.ToString(CultureInfo.InvariantCulture), "fd")))
            {
                var target = new FileInfo(fd).LinkTarget;
                if (target is not null && target.StartsWith("socket:[", StringComparison.Ordinal))
                    inodes.Add(target[8..^1]);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
        }
        var result = new List<Connection>();
        foreach (var proto in new[] { "tcp", "tcp6", "udp", "udp6" })
        {
            var file = Path.Combine(proc, "net", proto);
            if (!File.Exists(file))
                continue;
            foreach (var line in File.ReadLines(file).Skip(1))
            {
                var c = ParseProcNetLine(line, proto);
                if (c is not null && inodes.Contains(c.Value.Inode))
                    result.Add(c.Value.Conn);
            }
        }
        return result;
    }

    /// <summary>One line of <c>/proc/net/tcp</c>: <c>sl local rem st … uid timeout inode</c>.</summary>
    internal static (Connection Conn, string Inode)? ParseProcNetLine(string line, string proto)
    {
        var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (f.Length < 10)
            return null;
        var (la, lp) = ParseHexEndpoint(f[1]);
        var (ra, rp) = ParseHexEndpoint(f[2]);
        int st = int.Parse(f[3], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        bool tcp = proto.StartsWith("tcp", StringComparison.Ordinal);
        var c = new Connection
        {
            Protocol = tcp ? "tcp" : "udp",
            LocalAddress = la.ToString(),
            LocalPort = lp,
            RemoteAddress = ra.ToString(),
            RemotePort = rp,
            State = tcp && st < TcpStates.Length ? TcpStates[st] : "",
        };
        return (c, f[9]);
    }

    /// <summary>
    /// <c>0100007F:0050</c> → 127.0.0.1:80. The kernel prints each 32-bit word of the address in host byte order
    /// (little endian on every platform we support).
    /// </summary>
    internal static (IPAddress, int) ParseHexEndpoint(string s)
    {
        var colon = s.IndexOf(':', StringComparison.Ordinal);
        var hex = s[..colon];
        int port = int.Parse(s[(colon + 1)..], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        var bytes = new byte[hex.Length / 2];
        for (int w = 0; w < hex.Length / 8; w++)
        {
            uint word = uint.Parse(hex.AsSpan(w * 8, 8), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            BitConverter.TryWriteBytes(bytes.AsSpan(w * 4, 4), word);
            if (!BitConverter.IsLittleEndian)
                bytes.AsSpan(w * 4, 4).Reverse();
        }
        return (new IPAddress(bytes), port);
    }

    [SupportedOSPlatform("windows")]
    private static List<Connection> ListWindows(int pid)
    {
        var result = new List<Connection>();
        foreach (var af in new[] { 2, 23 })
        {
            ReadTable(af, tcp: true, pid, result);
            ReadTable(af, tcp: false, pid, result);
        }
        return result;
    }

    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    [SupportedOSPlatform("windows")]
    private static void ReadTable(int af, bool tcp, int pid, List<Connection> result)
    {
        int size = 0;
        _ = tcp ? GetExtendedTcpTable(0, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0)
                : GetExtendedUdpTable(0, ref size, false, af, UDP_TABLE_OWNER_PID, 0);
        if (size == 0)
            return;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            uint rc = tcp ? GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0)
                          : GetExtendedUdpTable(buf, ref size, false, af, UDP_TABLE_OWNER_PID, 0);
            if (rc != 0)
                return;
            int n = Marshal.ReadInt32(buf);
            bool v6 = af == 23;
            // row layouts: MIB_TCPROW_OWNER_PID (24 bytes), MIB_TCP6ROW_OWNER_PID (56), MIB_UDPROW_OWNER_PID (12),
            // MIB_UDP6ROW_OWNER_PID (28)
            int rowSize = (tcp, v6) switch { (true, false) => 24, (true, true) => 56, (false, false) => 12, _ => 28 };
            var row = new byte[rowSize];
            for (int i = 0; i < n; i++)
            {
                Marshal.Copy(buf + 4 + i * rowSize, row, 0, rowSize);
                var c = ParseWindowsRow(row, tcp, v6, out int owner);
                if (owner == pid)
                    result.Add(c);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private static readonly string[] WinTcpStates =
    [
        "", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
        "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB",
    ];

    internal static Connection ParseWindowsRow(ReadOnlySpan<byte> r, bool tcp, bool v6, out int owner)
    {
        static int Port(ReadOnlySpan<byte> b) => (b[0] << 8) | b[1];
        var c = new Connection { Protocol = tcp ? "tcp" : "udp" };
        if (!v6 && tcp)
        {
            int st = BitConverter.ToInt32(r[..4]);
            c.State = st < WinTcpStates.Length ? WinTcpStates[st] : "";
            c.LocalAddress = new IPAddress(r.Slice(4, 4)).ToString();
            c.LocalPort = Port(r.Slice(8, 2));
            c.RemoteAddress = new IPAddress(r.Slice(12, 4)).ToString();
            c.RemotePort = Port(r.Slice(16, 2));
            owner = BitConverter.ToInt32(r.Slice(20, 4));
        }
        else if (v6 && tcp)
        {
            c.LocalAddress = new IPAddress(r[..16]).ToString();
            c.LocalPort = Port(r.Slice(20, 2));
            c.RemoteAddress = new IPAddress(r.Slice(24, 16)).ToString();
            c.RemotePort = Port(r.Slice(44, 2));
            int st = BitConverter.ToInt32(r.Slice(48, 4));
            c.State = st < WinTcpStates.Length ? WinTcpStates[st] : "";
            owner = BitConverter.ToInt32(r.Slice(52, 4));
        }
        else if (!v6)
        {
            c.LocalAddress = new IPAddress(r[..4]).ToString();
            c.LocalPort = Port(r.Slice(4, 2));
            owner = BitConverter.ToInt32(r.Slice(8, 4));
        }
        else
        {
            c.LocalAddress = new IPAddress(r[..16]).ToString();
            c.LocalPort = Port(r.Slice(20, 2));
            owner = BitConverter.ToInt32(r.Slice(24, 4));
        }
        return c;
    }

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(nint table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int af, int tableClass, uint reserved);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedUdpTable(nint table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int af, int tableClass, uint reserved);
}
