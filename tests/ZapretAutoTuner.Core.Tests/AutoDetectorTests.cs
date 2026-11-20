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

    [Fact]
    public void A_shaper_on_an_applied_strategy_makes_it_checked_once_it_settled()
    {
        var book = new AutoBook();
        book.Feed([Site("example.com", T0)], T0);
        book.Applied("web:example.com", "\\/", 400, T0);
        var s = book.Find("web:example.com")!;
        // just applied: the probe that found it passed a moment ago
        Assert.Empty(book.Detect("host", "example.com", "THROTTLE", T0.AddMinutes(1)));
        var t = T0 + AutoRules.DetectorHold;
        Assert.Equal(["example.com"], book.Detect("host", "example.com", "THROTTLE", t));
        book.Evaluate(t.AddSeconds(15));
        Assert.Equal(AutoStatus.Degraded, s.Status);
        Assert.Contains("шейпер", s.Why, StringComparison.Ordinal);
        // the probe with the bypass passed: kept, and the same shaper is not judged again at once
        book.Confirmed("web:example.com", AutoConfirm.NotBlocked, t.AddSeconds(30));
        Assert.Equal(AutoStatus.Applied, s.Status);
        Assert.Empty(book.Detect("host", "example.com", "THROTTLE", t.AddMinutes(2)));
    }

    [Fact]
    public void A_pinned_strategy_is_kept_whatever_the_detector_says()
    {
        var book = new AutoBook();
        book.Feed([Site("example.com", T0)], T0);
        book.Applied("web:example.com", "\\/", 400, T0);
        book.Pin("web:example.com", true);
        var t = T0 + AutoRules.DetectorHold;
        book.Detect("ip", "203.0.113.5", "FREEZE_N", t);
        book.Evaluate(t.AddSeconds(15));
        Assert.Equal(AutoStatus.Applied, book.Find("web:example.com")!.Status);
    }

    [Fact]
    public void A_sites_quic_is_not_judged_by_the_detectors_tcp_classes()
    {
        var book = new AutoBook();
        var quic = Site("example.com", T0) with { Key = "quic:example.com", Kind = AutoKind.Quic, Transport = L4Kind.Udp, App = "quic" };
        book.Feed([quic], T0);
        Assert.Empty(book.Detect("host", "example.com", "THROTTLE", T0));
        Assert.Empty(book.Detect("ip", "203.0.113.5", "FREEZE_N", T0));
    }

    [Fact]
    public void A_reset_forgets_the_detectors_marks()
    {
        var book = new AutoBook();
        book.Feed([Site("example.com", T0)], T0);
        book.Detect("host", "example.com", "THROTTLE", T0);
        book.Reset("web:example.com", T0.AddSeconds(10));
        book.Evaluate(T0.AddSeconds(20));
        Assert.Equal(AutoStatus.Watching, book.Find("web:example.com")!.Status);
    }

    [Fact]
    public void A_failure_on_a_new_address_counts_against_a_strategy_applied_by_name()
    {
        var book = new AutoBook();
        book.Feed([Site("example.com", T0)], T0);
        var s = book.Find("web:example.com")!;
        s.Status = AutoStatus.Applied;
        s.Strategy = "\\/";
        var failed = Site("example.com", T0.AddSeconds(5), "198.51.100.9") with { Health = AutoHealth.Failed, Why = "rst" };
        // an address group only: the new CDN address went without the bypass, its failure says nothing
        book.Feed([failed], T0.AddSeconds(5));
        Assert.Empty(s.Fails);
        // by name the strategy reaches every address: the failure is the strategy's
        book.ByName = new HashSet<string> { "web:example.com" };
        book.Feed([failed with { Server = new IPEndPoint(IPAddress.Parse("198.51.100.10"), 443) }], T0.AddSeconds(6));
        Assert.Single(s.Fails);
    }
}
