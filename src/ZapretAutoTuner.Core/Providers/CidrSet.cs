using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace ZapretAutoTuner.Core.Providers;

/// <summary>One network: a family, the first address as a number and the prefix length.</summary>
public readonly record struct Cidr(AddressFamily Family, UInt128 Start, int Prefix)
{
    public int Bits => Family == AddressFamily.InterNetwork ? 32 : 128;

    public UInt128 Size => Prefix == 0 && Bits == 128 ? UInt128.MaxValue : UInt128.One << (Bits - Prefix);

    public UInt128 Last => Start + (Size - 1);

    public static bool TryParse(string text, out Cidr cidr)
    {
        cidr = default;
        var parts = text.Trim().Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var a))
            return false;
        if (a.IsIPv4MappedToIPv6)
            a = a.MapToIPv4();
        int bits = a.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        int prefix = bits;
        if (parts.Length == 2 && (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out prefix) || prefix > bits))
            return false;
        var n = ToNumber(a);
        var mask = prefix == 0 ? UInt128.Zero : UInt128.MaxValue << (128 - prefix) >> (128 - bits);
        cidr = new Cidr(a.AddressFamily, n & mask, prefix);
        return true;
    }

    public bool Contains(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6)
            a = a.MapToIPv4();
        if (a.AddressFamily != Family)
            return false;
        var n = ToNumber(a);
        return n >= Start && n <= Last;
    }

    public IPAddress At(UInt128 offset) => FromNumber(Family, Start + offset);

    public override string ToString() => $"{FromNumber(Family, Start)}/{Prefix.ToString(CultureInfo.InvariantCulture)}";

    internal static UInt128 ToNumber(IPAddress a)
    {
        UInt128 n = 0;
        foreach (var b in a.GetAddressBytes())
            n = (n << 8) | b;
        return n;
    }

    internal static IPAddress FromNumber(AddressFamily f, UInt128 n)
    {
        var bytes = new byte[f == AddressFamily.InterNetwork ? 4 : 16];
        for (int i = bytes.Length - 1; i >= 0; i--)
        {
            bytes[i] = (byte)(n & 0xFF);
            n >>= 8;
        }
        return new IPAddress(bytes);
    }
}

/// <summary>
/// A set of networks merged like <c>ip2net</c>: overlapping and adjacent ranges joined, then cut back into the fewest
/// CIDRs, so AWS's or Azure's lists do not blow up an ipset (dpi-diagnostics §4a).
/// </summary>
public static class CidrSet
{
    /// <summary>The merged networks; lines that are not a CIDR or an address are skipped.</summary>
    public static List<Cidr> Aggregate(IEnumerable<string> cidrs)
    {
        var parsed = new List<Cidr>();
        foreach (var c in cidrs)
        {
            if (Cidr.TryParse(c, out var x))
                parsed.Add(x);
        }
        return Aggregate(parsed);
    }

    public static List<Cidr> Aggregate(IEnumerable<Cidr> cidrs)
    {
        var result = new List<Cidr>();
        foreach (var family in cidrs.GroupBy(c => c.Family).OrderBy(g => g.Key == AddressFamily.InterNetwork ? 0 : 1))
        {
            int bits = family.Key == AddressFamily.InterNetwork ? 32 : 128;
            // merged [start, last] ranges
            var ranges = new List<(UInt128 Start, UInt128 Last)>();
            foreach (var c in family.OrderBy(c => c.Start))
            {
                if (ranges.Count > 0 && (ranges[^1].Last == UInt128.MaxValue || c.Start <= ranges[^1].Last + 1))
                {
                    if (c.Last > ranges[^1].Last)
                        ranges[^1] = (ranges[^1].Start, c.Last);
                }
                else
                {
                    ranges.Add((c.Start, c.Last));
                }
            }
            foreach (var (start, last) in ranges)
                result.AddRange(Split(family.Key, bits, start, last));
        }
        return result;
    }

    /// <summary>The fewest aligned CIDRs covering [start, last].</summary>
    private static IEnumerable<Cidr> Split(AddressFamily f, int bits, UInt128 start, UInt128 last)
    {
        while (true)
        {
            // the largest block aligned at start that does not pass last
            int size = start == 0 ? bits : Math.Min(bits, (int)UInt128.TrailingZeroCount(start));
            while (size > 0 && (size >= 128 ? UInt128.MaxValue : start + ((UInt128.One << size) - 1)) > last)
                size--;
            yield return new Cidr(f, start, bits - size);
            var end = size >= 128 ? UInt128.MaxValue : start + ((UInt128.One << size) - 1);
            if (end >= last)
                yield break;
            start = end + 1;
        }
    }

    /// <summary>
    /// Addresses to test (§4a step 2): one from each of the largest distinct networks, at most
    /// <paramref name="count"/>, half of them IPv4 when both families exist. The address is the network's first
    /// host plus a stable offset, never the network or broadcast address.
    /// </summary>
    public static List<IPAddress> Sample(IReadOnlyList<Cidr> networks, int count, int seed = 0)
    {
        var picks = new List<IPAddress>();
        var v4 = networks.Where(c => c.Family == AddressFamily.InterNetwork).OrderBy(c => c.Prefix).ThenBy(c => c.Start).ToList();
        var v6 = networks.Where(c => c.Family == AddressFamily.InterNetworkV6).OrderBy(c => c.Prefix).ThenBy(c => c.Start).ToList();
        int want4 = v6.Count == 0 ? count : v4.Count == 0 ? 0 : (count + 1) / 2;
        foreach (var (list, want) in new[] { (v4, want4), (v6, count - want4) })
        {
            // spread over the list, so neighbouring blocks of one announcement are not all picked
            for (int i = 0; i < want && i < list.Count; i++)
            {
                var c = list[(int)((long)i * list.Count / Math.Max(1, Math.Min(want, list.Count)))];
                var hosts = c.Size <= 2 ? UInt128.One : c.Size - 2;
                var offset = 1 + (UInt128)(uint)HashCode.Combine(seed, i, (ulong)c.Start) % (hosts > uint.MaxValue ? uint.MaxValue : hosts);
                picks.Add(c.Size == 1 ? c.At(0) : c.At(offset >= c.Size ? 1 : offset));
            }
        }
        return picks;
    }
}
