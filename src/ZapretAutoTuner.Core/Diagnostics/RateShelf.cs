namespace ZapretAutoTuner.Core.Diagnostics;

/// <summary>
/// The steady speed of one download: the median of its last windows with data (the first window, slow start, is not
/// counted), how much the windows differ (coefficient of variation) and the fastest one. Bytes per second.
/// </summary>
public sealed record RateReading(double Rate, double Cv, double Peak, int Windows, long Bytes)
{
    public override string ToString() => $"{RateShelf.Human(Rate)} (cv {Cv:0.00}, {Windows} windows, {Bytes} B)";
}

/// <summary>
/// The shaper ("шейпер", policer) check of dpi-diagnostics §2.16, the same rule as THROTTLE of geneva_c's detector
/// (<c>docs/EXT.md</c>, X9b): in the last <see cref="Windows"/> windows with data the median speed is below a quarter of
/// the link capacity, the windows are even (coefficient of variation below <see cref="MaxCv"/>), none is faster than
/// two medians, and at least <see cref="MinBytes"/> came: a flat shelf. A slow server or a busy link does not look
/// like that; a constant-rate stream (internet radio) does, so a shelf is a suspicion that a probe must confirm.
/// </summary>
public static class RateShelf
{
    /// <summary>Windows with data the reading takes (the last ones).</summary>
    public const int Windows = 5;

    /// <summary>The fewest windows a reading needs.</summary>
    public const int MinWindows = 4;

    public const double MaxCv = 0.3;

    public const long MinBytes = 64 * 1024;

    /// <summary>
    /// A shelf when the link capacity is not known yet: 64 KB/s (512 kbit/s). Shapers of the TSPU sit at 16–100 KB/s,
    /// and a download of the program's probe is rarely that slow on its own.
    /// </summary>
    public const double FloorRate = 64 * 1024;

    /// <summary>
    /// The reading of per-window byte counts in time order (zero = no data in that window); null when there are
    /// fewer than <see cref="MinWindows"/> windows with data after the first one.
    /// </summary>
    public static RateReading? Read(IReadOnlyList<long> perWindow, TimeSpan window)
    {
        if (window <= TimeSpan.Zero)
            return null;
        var data = perWindow.Where(b => b > 0).ToList();
        if (data.Count < MinWindows + 1)
            return null;
        // the first window with data is slow start: skip it
        var last = data.Skip(1).TakeLast(Windows).Select(b => b / window.TotalSeconds).ToList();
        double median = Median(last);
        double mean = last.Average();
        double sd = Math.Sqrt(last.Sum(x => (x - mean) * (x - mean)) / last.Count);
        return new RateReading(median, mean > 0 ? sd / mean : 0, last.Max(), last.Count, data.Sum());
    }

    /// <summary>A flat shelf below a quarter of <paramref name="capacity"/> (B/s; 0 or less: unknown, <see cref="FloorRate"/> instead).</summary>
    public static bool IsShelf(RateReading? r, double capacity)
    {
        if (r is null || r.Bytes < MinBytes || r.Cv >= MaxCv || r.Peak > 2 * r.Rate)
            return false;
        return capacity > 0 ? r.Rate < capacity / 4 : r.Rate < FloorRate;
    }

    /// <summary>
    /// The speed a bypass must reach on a throttled resource: three shelves (geneva_c counts a success on a key
    /// throttled so only above that), but never more than half the link.
    /// </summary>
    public static double Threshold(double shelf, double capacity)
    {
        double t = 3 * shelf;
        return capacity > 0 ? Math.Max(1.5 * shelf, Math.Min(t, capacity / 2)) : t;
    }

    public static string Human(double bytesPerSecond) => bytesPerSecond >= 1024 * 1024
        ? $"{bytesPerSecond / (1024 * 1024):0.0} MB/s"
        : $"{bytesPerSecond / 1024:0} KB/s";

    private static double Median(List<double> v)
    {
        var s = v.Order().ToList();
        int n = s.Count;
        return n % 2 == 1 ? s[n / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
    }
}

/// <summary>
/// The capacity of the user's link: the fastest steady download the program has seen lately (probes, classifier, the
/// "Авто" mode's flows). Like C of geneva_c: a record older than <see cref="Lifetime"/> is dropped and taken anew.
/// </summary>
public sealed class LinkCapacity
{
    public static LinkCapacity Shared { get; } = new();

    public static TimeSpan Lifetime { get; } = TimeSpan.FromMinutes(10);

    private readonly Lock _lock = new();
    private double _rate;
    private DateTime _at;

    /// <summary>A steady speed seen now (B/s) that is not a shelf (a shelf would become the capacity and hide itself).</summary>
    public void Observe(double rate, DateTime? now = null)
    {
        var t = now ?? DateTime.UtcNow;
        lock (_lock)
        {
            if (t - _at > Lifetime || rate > _rate)
                (_rate, _at) = (rate, t);
        }
    }

    /// <summary>
    /// Judges a reading against the capacity now (<see cref="RateShelf.IsShelf"/>) and, when it is not a shelf, keeps
    /// it as a candidate for the capacity. Returns whether it is a shelf.
    /// </summary>
    public bool Judge(RateReading? r, DateTime? now = null)
    {
        if (r is null)
            return false;
        bool shelf = RateShelf.IsShelf(r, Current(now));
        if (!shelf)
            Observe(r.Rate, now);
        return shelf;
    }

    /// <summary>The capacity in B/s; 0 when nothing fast was seen within <see cref="Lifetime"/>.</summary>
    public double Current(DateTime? now = null)
    {
        var t = now ?? DateTime.UtcNow;
        lock (_lock)
            return t - _at > Lifetime ? 0 : _rate;
    }
}
