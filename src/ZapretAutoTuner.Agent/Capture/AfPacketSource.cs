using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Agent.Capture;

/// <summary>
/// Linux capture through an AF_PACKET SOCK_DGRAM socket: the kernel strips the link header, so every interface
/// (Ethernet, Wi-Fi, tun/wireguard, loopback) yields plain IP packets with a direction. No libpcap needed.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed partial class AfPacketSource : ICaptureSource
{
    private const int AF_PACKET = 17;
    private const int SOCK_DGRAM = 2;
    private const ushort ETH_P_ALL_BE = 0x0300; // htons(0x0003)
    private const int SOL_SOCKET = 1;
    private const int SO_RCVTIMEO = 20;
    private const int SO_RCVBUFFORCE = 33;
    private const int MSG_TRUNC = 0x20;
    private const byte PACKET_OUTGOING = 4;

    private readonly string? _iface;
    private int _fd = -1;
    private Thread? _thread;
    private volatile bool _stop;

    public AfPacketSource(string? iface)
    {
        _iface = iface;
    }

    public void Start(CaptureFilter filter, PacketRing ring, int snaplen)
    {
        _fd = socket(AF_PACKET, SOCK_DGRAM, ETH_P_ALL_BE);
        if (_fd < 0)
            throw new InvalidOperationException($"AF_PACKET socket: errno {Marshal.GetLastPInvokeError()} (нужны права root)");
        int bufSize = 8 << 20;
        setsockopt(_fd, SOL_SOCKET, SO_RCVBUFFORCE, ref bufSize, sizeof(int));
        var tv = new Timeval { Sec = 0, Usec = 200_000 };
        setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, ref tv, Marshal.SizeOf<Timeval>());
        if (_iface is not null)
        {
            uint idx = if_nametoindex(_iface);
            if (idx == 0)
            {
                close(_fd);
                throw new InvalidOperationException($"интерфейс {_iface} не найден");
            }
            var sa = new SockaddrLl { Family = AF_PACKET, Protocol = ETH_P_ALL_BE, Ifindex = (int)idx };
            if (bind(_fd, ref sa, Marshal.SizeOf<SockaddrLl>()) != 0)
            {
                close(_fd);
                throw new InvalidOperationException($"bind {_iface}: errno {Marshal.GetLastPInvokeError()}");
            }
        }
        int lo = (int)if_nametoindex("lo");
        _thread = new Thread(() => Loop(filter, ring, snaplen, lo)) { IsBackground = true, Name = "capture" };
        _thread.Start();
    }

    private void Loop(CaptureFilter filter, PacketRing ring, int snaplen, int loIndex)
    {
        var buf = new byte[65536];
        int salen = Marshal.SizeOf<SockaddrLl>();
        while (!_stop)
        {
            var sa = new SockaddrLl();
            int len = salen;
            nint n = recvfrom(_fd, buf, buf.Length, MSG_TRUNC, ref sa, ref len);
            if (n < 0)
                continue; // timeout (EAGAIN) or EINTR: check _stop
            if (sa.Protocol is not (0x0008 or 0xDD86)) // 0x0800 / 0x86DD in network order
                continue;
            // loopback packets are delivered twice (out and in): keep one copy
            if (sa.Ifindex == loIndex && sa.Pkttype == PACKET_OUTGOING)
                continue;
            int orig = (int)n;
            int cap = Math.Min(Math.Min(orig, buf.Length), snaplen);
            var span = buf.AsSpan(0, cap);
            if (!filter.Matches(span))
                continue;
            var dir = sa.Pkttype == PACKET_OUTGOING ? PacketDirection.Outbound : PacketDirection.Inbound;
            ring.Add(new CapturedPacket(DateTime.UtcNow, span.ToArray(), orig, dir));
        }
    }

    public void Dispose()
    {
        _stop = true;
        _thread?.Join(TimeSpan.FromSeconds(2));
        if (_fd >= 0)
        {
            close(_fd);
            _fd = -1;
        }
    }

    // Pack = 4 keeps the 8-byte address at offset 12 (struct sockaddr_ll is 20 bytes)
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct SockaddrLl
    {
        public ushort Family;
        public ushort Protocol;
        public int Ifindex;
        public ushort Hatype;
        public byte Pkttype;
        public byte Halen;
        public ulong Addr;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Timeval
    {
        public nint Sec;
        public nint Usec;
    }

    [LibraryImport("libc", SetLastError = true)]
    private static partial int socket(int domain, int type, int protocol);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int setsockopt(int fd, int level, int name, ref int value, int len);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int setsockopt(int fd, int level, int name, ref Timeval value, int len);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int bind(int fd, ref SockaddrLl addr, int len);

    [LibraryImport("libc", SetLastError = true)]
    private static partial nint recvfrom(int fd, [Out] byte[] buf, nint len, int flags, ref SockaddrLl addr, ref int addrlen);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int close(int fd);

    [LibraryImport("libc", StringMarshalling = StringMarshalling.Utf8)]
    private static partial uint if_nametoindex(string name);
}
