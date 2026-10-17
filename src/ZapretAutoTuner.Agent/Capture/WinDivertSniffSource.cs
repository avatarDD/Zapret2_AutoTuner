using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Agent.Capture;

/// <summary>
/// Windows capture with WinDivert in SNIFF | RECV_ONLY mode: the same driver winws2 uses (from the bundled
/// zapret2), a separate handle that copies packets without diverting them, so no Npcap is needed. The lowest
/// priority makes the handle see outgoing packets after winws2 has modified them, i.e. what goes on the wire.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed partial class WinDivertSniffSource : ICaptureSource
{
    private const ulong WINDIVERT_FLAG_SNIFF = 0x0001;
    private const ulong WINDIVERT_FLAG_RECV_ONLY = 0x0004;
    private const int WINDIVERT_LAYER_NETWORK = 0;
    private const short PriorityLowest = -30000;
    private const int WINDIVERT_SHUTDOWN_BOTH = 3;
    private const int AddressSize = 80;

    private nint _handle;
    private Thread? _thread;

    static WinDivertSniffSource()
    {
        NativeLibrary.SetDllImportResolver(typeof(WinDivertSniffSource).Assembly, Resolve);
    }

    private static nint Resolve(string name, Assembly asm, DllImportSearchPath? path)
    {
        if (!name.StartsWith("WinDivert", StringComparison.OrdinalIgnoreCase))
            return 0;
        var bundled = Path.Combine(Tools.Zapret2Bundle.Locate().Root, "WinDivert.dll");
        return File.Exists(bundled) && NativeLibrary.TryLoad(bundled, out var h) ? h : 0;
    }

    public void Start(CaptureFilter filter, PacketRing ring, int snaplen)
    {
        _handle = WinDivertOpen(filter.ToWinDivert(), WINDIVERT_LAYER_NETWORK, PriorityLowest, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
        if (_handle == -1 || _handle == 0)
            throw new InvalidOperationException($"WinDivertOpen: ошибка {Marshal.GetLastPInvokeError()} (нужны права администратора, драйвер WinDivert)");
        _thread = new Thread(() => Loop(ring, snaplen)) { IsBackground = true, Name = "capture" };
        _thread.Start();
    }

    private void Loop(PacketRing ring, int snaplen)
    {
        var buf = new byte[65535];
        var addr = new byte[AddressSize];
        while (true)
        {
            if (!WinDivertRecv(_handle, buf, (uint)buf.Length, out uint len, addr))
                return; // shut down or closed
            // WINDIVERT_ADDRESS: Timestamp (8), then a 32-bit bitfield: Layer:8 Event:8 Sniffed:1 Outbound:1 …
            uint bits = BitConverter.ToUInt32(addr, 8);
            bool outbound = (bits & (1u << 17)) != 0;
            int cap = (int)Math.Min(len, (uint)snaplen);
            ring.Add(new CapturedPacket(DateTime.UtcNow, buf.AsSpan(0, cap).ToArray(), (int)len, outbound ? PacketDirection.Outbound : PacketDirection.Inbound));
        }
    }

    public void Dispose()
    {
        if (_handle is 0 or -1)
            return;
        WinDivertShutdown(_handle, WINDIVERT_SHUTDOWN_BOTH);
        _thread?.Join(TimeSpan.FromSeconds(2));
        WinDivertClose(_handle);
        _handle = 0;
    }

    [LibraryImport("WinDivert.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [LibraryImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WinDivertRecv(nint handle, [Out] byte[] packet, uint packetLen, out uint recvLen, [Out] byte[] addr);

    [LibraryImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WinDivertShutdown(nint handle, int how);

    [LibraryImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WinDivertClose(nint handle);
}
