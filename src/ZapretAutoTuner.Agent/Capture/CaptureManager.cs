using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Agent.Capture;

/// <summary>Which packets a capture keeps: any of the addresses (either direction) and any of the ports.</summary>
internal sealed class CaptureFilter
{
    public HashSet<IPAddress> Addresses { get; } = [];

    public HashSet<int> Ports { get; } = [];

    public static CaptureFilter From(Protocol.StartCaptureRequest r)
    {
        var f = new CaptureFilter();
        foreach (var a in r.Addresses)
            f.Addresses.Add(IPAddress.Parse(a));
        foreach (var p in r.Ports)
        {
            if (p is < 1 or > 65535)
                throw new FormatException($"bad port {p}");
            f.Ports.Add(p);
        }
        return f;
    }

    /// <summary>
    /// Runs for every packet on every interface, so it reads the headers in place without allocating. IPv6
    /// extension headers are not walked: such packets match by address only.
    /// </summary>
    public bool Matches(ReadOnlySpan<byte> l3)
    {
        if (Addresses.Count == 0 && Ports.Count == 0)
            return true;
        if (l3.Length < 20)
            return false;
        int ver = l3[0] >> 4;
        int proto, l4;
        bool fragment = false;
        IPAddress src, dst;
        if (ver == 4)
        {
            int ihl = (l3[0] & 0x0F) * 4;
            proto = l3[9];
            fragment = (BinaryPrimitives.ReadUInt16BigEndian(l3[6..]) & 0x1FFF) != 0;
            l4 = ihl;
            if (Addresses.Count > 0)
            {
                src = new IPAddress(l3.Slice(12, 4));
                dst = new IPAddress(l3.Slice(16, 4));
                if (!Addresses.Contains(src) && !Addresses.Contains(dst))
                    return false;
            }
        }
        else if (ver == 6 && l3.Length >= 40)
        {
            proto = l3[6];
            l4 = 40;
            if (Addresses.Count > 0)
            {
                src = new IPAddress(l3.Slice(8, 16));
                dst = new IPAddress(l3.Slice(24, 16));
                if (!Addresses.Contains(src) && !Addresses.Contains(dst))
                    return false;
            }
        }
        else
        {
            return false;
        }
        if (Ports.Count == 0)
            return true;
        if (proto is not (6 or 17) || fragment || l3.Length < l4 + 4)
            return Addresses.Count > 0;
        int sport = BinaryPrimitives.ReadUInt16BigEndian(l3[l4..]);
        int dport = BinaryPrimitives.ReadUInt16BigEndian(l3[(l4 + 2)..]);
        return Ports.Contains(sport) || Ports.Contains(dport);
    }

    /// <summary>The same filter as a WinDivert expression (evaluated in the driver, so fewer copies).</summary>
    public string ToWinDivert()
    {
        var parts = new List<string>();
        if (Addresses.Count > 0)
        {
            parts.Add("(" + string.Join(" or ", Addresses.Select(a =>
            {
                var p = a.AddressFamily == global::System.Net.Sockets.AddressFamily.InterNetworkV6 ? "ipv6" : "ip";
                return $"{p}.SrcAddr=={a} or {p}.DstAddr=={a}";
            })) + ")");
        }
        if (Ports.Count > 0)
        {
            parts.Add("(" + string.Join(" or ", Ports.Select(p => string.Create(CultureInfo.InvariantCulture,
                $"tcp.SrcPort=={p} or tcp.DstPort=={p} or udp.SrcPort=={p} or udp.DstPort=={p}"))) + ")");
        }
        return parts.Count == 0 ? "true" : string.Join(" and ", parts);
    }
}

/// <summary>Captured packets bounded by total size: the oldest are evicted first.</summary>
internal sealed class PacketRing
{
    private readonly Queue<CapturedPacket> _q = new();
    private readonly long _max;
    private readonly Lock _lock = new();
    private long _bytes;

    public PacketRing(long maxBytes)
    {
        _max = maxBytes;
    }

    public long Packets { get; private set; }

    public long Dropped { get; private set; }

    public void Add(CapturedPacket p)
    {
        lock (_lock)
        {
            _q.Enqueue(p);
            _bytes += p.Data.Length + 32;
            Packets++;
            while (_bytes > _max && _q.Count > 1)
            {
                var old = _q.Dequeue();
                _bytes -= old.Data.Length + 32;
                Dropped++;
            }
        }
    }

    public List<CapturedPacket> Snapshot()
    {
        lock (_lock)
            return [.. _q];
    }
}

/// <summary>A running packet source feeding a ring.</summary>
internal interface ICaptureSource : IDisposable
{
    void Start(CaptureFilter filter, PacketRing ring, int snaplen);
}

internal sealed record CaptureResult(byte[] Pcapng, long Packets, long Dropped);

/// <summary>Packet captures (PLAN 1.4): AF_PACKET on Linux, WinDivert SNIFF on Windows; results as pcapng.</summary>
internal sealed class CaptureManager
{
    public const long DefaultMaxBytes = 32L << 20;
    public const long LimitMaxBytes = 256L << 20;

    private readonly ConcurrentDictionary<string, (ICaptureSource Source, PacketRing Ring, int Snaplen)> _captures = new();
    private int _seq;

    /// <summary>Creates the platform source; tests replace it.</summary>
    public Func<string?, ICaptureSource> SourceFactory { get; set; } = DefaultSource;

    public IReadOnlyList<string> Running => [.. _captures.Keys];

    private static ICaptureSource DefaultSource(string? iface)
    {
        if (OperatingSystem.IsLinux())
            return new AfPacketSource(iface);
        if (OperatingSystem.IsWindows())
            return new WinDivertSniffSource();
        throw new PlatformNotSupportedException("capture is supported on Linux and Windows");
    }

    public string Start(CaptureFilter filter, long maxBytes, int snaplen, string? iface)
    {
        if (maxBytes <= 0)
            maxBytes = DefaultMaxBytes;
        maxBytes = Math.Min(maxBytes, LimitMaxBytes);
        if (snaplen <= 0 || snaplen > 65535)
            snaplen = 65535;
        var ring = new PacketRing(maxBytes);
        var src = SourceFactory(string.IsNullOrEmpty(iface) ? null : iface);
        src.Start(filter, ring, snaplen);
        var id = "c" + Interlocked.Increment(ref _seq).ToString(CultureInfo.InvariantCulture);
        _captures[id] = (src, ring, snaplen);
        return id;
    }

    public CaptureResult? Stop(string id)
    {
        if (!_captures.TryRemove(id, out var c))
            return null;
        c.Source.Dispose();
        var packets = c.Ring.Snapshot();
        return new CaptureResult(PcapNgWriter.ToBytes(packets, c.Snaplen), c.Ring.Packets, c.Ring.Dropped);
    }

    public void StopAll()
    {
        foreach (var id in _captures.Keys.ToList())
        {
            if (_captures.TryRemove(id, out var c))
                c.Source.Dispose();
        }
    }
}
