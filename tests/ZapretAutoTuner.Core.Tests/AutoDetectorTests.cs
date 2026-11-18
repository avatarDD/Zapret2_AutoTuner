using System.Net;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>geneva's detector (--ext-auto observe) in the "Авто" mode: a shaper or a freeze makes a fine-looking site suspected.</summary>
public class AutoDetectorTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static AutoSample Site(string site, DateTime time, string ip = "203.0.113.5") => new()
    {
        Key = "web:" + site,
        Kind = AutoKind.Web,
        Transport = L4Kind.Tcp,
        Name = site,
        Host = "www." + site,
        App = "tls",
        Server = new IPEndPoint(IPAddress.Parse(ip), 443),
        Time = time,
        Health = AutoHealth.Ok,
        Why = "",
    };

    [Fact]
    public void A_throttled_name_is_suspected_although_its_flows_look_fine()
    {
        var book = new AutoBook();
        book.Feed([Site("example.com", T0), Site("other.org", T0, "198.51.100.7")], T0);
        Assert.Equal(["example.com"], book.Detect("host", "rr1.cdn.example.com", "THROTTLE", T0.AddSeconds(5)));
        // the same key again within the minute: no new report
        Assert.Empty(book.Detect("host", "rr1.cdn.example.com", "THROTTLE", T0.AddSeconds(20)));
        book.Evaluate(T0.AddSeconds(30));
        var s = book.Find("web:example.com")!;
        Assert.Equal(AutoStatus.Suspected, s.Status);
        Assert.Contains("шейпер", s.Why, StringComparison.Ordinal);
        Assert.Equal(AutoStatus.Watching, book.Find("web:other.org")!.Status);
    }

    [Fact]
    public void An_address_freeze_matches_by_address_and_other_classes_are_left_to_the_slices()
    {
        var book = new AutoBook();
        book.Feed([Site("example.com", T0)], T0);
        Assert.Empty(book.Detect("ip", "203.0.113.5", "RST_INJECT", T0));
        Assert.Empty(book.Detect("port", "tcp/443", "FREEZE_N", T0));
        Assert.Equal(["example.com"], book.Detect("ip", "203.0.113.5", "FREEZE_N", T0));
    }

    [Fact]
    public void An_applied_service_is_not_touched()
    {
        var book = new AutoBook();
        book.Feed([Site("example.com", T0)], T0);
        book.Find("web:example.com")!.Status = AutoStatus.Applied;
        Assert.Empty(book.Detect("host", "example.com", "THROTTLE", T0));
    }
}
