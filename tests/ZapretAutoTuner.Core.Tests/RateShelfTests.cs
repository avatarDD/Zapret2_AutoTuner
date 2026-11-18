using ZapretAutoTuner.Core.Diagnostics;

namespace ZapretAutoTuner.Core.Tests;

public class RateShelfTests
{
    private static readonly TimeSpan Second = TimeSpan.FromSeconds(1);

    [Fact]
    public void A_flat_slow_download_is_a_shelf()
    {
        // slow start, then 20 KB every second
        var r = RateShelf.Read([3_000, 20_000, 20_500, 19_800, 20_100, 20_000, 0], Second);
        Assert.NotNull(r);
        Assert.InRange(r!.Rate, 19_900, 20_200);
        Assert.True(r.Cv < 0.05);
        Assert.True(RateShelf.IsShelf(r, 0));                // below the 128 KB/s floor
        Assert.True(RateShelf.IsShelf(r, 1_000_000));        // below a quarter of the link
        Assert.False(RateShelf.IsShelf(r, 60_000));          // a slow link: no shelf
    }

    [Fact]
    public void Uneven_or_short_downloads_are_not_shelves()
    {
        Assert.Null(RateShelf.Read([10_000, 20_000, 20_000], Second));
        var bursty = RateShelf.Read([1_000, 50_000, 2_000, 60_000, 1_000, 55_000, 3_000], Second);
        Assert.False(RateShelf.IsShelf(bursty, 0));
        var little = RateShelf.Read([1_000, 5_000, 5_000, 5_000, 5_000, 5_000], Second);
        Assert.False(RateShelf.IsShelf(little, 0)); // under 64 KB in all
    }

    [Fact]
    public void The_threshold_is_three_shelves_but_at_most_half_the_link()
    {
        Assert.Equal(60_000, RateShelf.Threshold(20_000, 0));
        Assert.Equal(60_000, RateShelf.Threshold(20_000, 1_000_000));
        Assert.Equal(50_000, RateShelf.Threshold(30_000, 100_000));
        Assert.Equal(45_000, RateShelf.Threshold(30_000, 70_000)); // never below 1.5 shelves
    }

    [Fact]
    public void The_capacity_keeps_the_record_and_forgets_it()
    {
        var c = new LinkCapacity();
        var t = new DateTime(2026, 11, 18, 12, 0, 0, DateTimeKind.Utc);
        Assert.Equal(0, c.Current(t));
        c.Observe(1_000_000, t);
        c.Observe(500_000, t.AddMinutes(1));
        Assert.Equal(1_000_000, c.Current(t.AddMinutes(2)));
        Assert.Equal(0, c.Current(t.AddMinutes(11)));
        // a shelf is judged against the record and does not become it
        var shelf = new RateReading(20_000, 0.02, 21_000, 5, 200_000);
        Assert.True(c.Judge(shelf, t.AddMinutes(3)));
        Assert.Equal(1_000_000, c.Current(t.AddMinutes(3)));
    }

    [Fact]
    public void While_no_capacity_is_known_only_a_fast_download_becomes_it()
    {
        var c = new LinkCapacity();
        var t = new DateTime(2026, 11, 18, 12, 0, 0, DateTimeKind.Utc);
        // a shaper at 150 KB/s: above the floor, so not called a shelf, but it must not become "the link" and hide itself
        var shaped = new RateReading(150_000, 0.03, 155_000, 5, 900_000);
        Assert.False(c.Judge(shaped, t));
        Assert.Equal(0, c.Current(t));
        var fast = new RateReading(3_000_000, 0.2, 3_500_000, 5, 15_000_000);
        Assert.False(c.Judge(fast, t));
        Assert.Equal(3_000_000, c.Current(t));
        Assert.True(c.Judge(shaped, t.AddSeconds(1)));
    }

    [Fact]
    public void A_download_too_short_for_windows_gives_its_average_and_is_never_a_shelf()
    {
        Assert.Null(RateShelf.Burst(500_000, TimeSpan.FromSeconds(0.2)));
        var r = RateShelf.Burst(4_000_000, TimeSpan.FromSeconds(0.5));
        Assert.Equal(8_000_000, r!.Rate);
        Assert.False(RateShelf.IsShelf(r, 100_000_000));
    }
}
