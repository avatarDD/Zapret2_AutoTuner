using System.Net;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Tuning.Geneva;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>geneva's <c>ext_status</c> answer (src/ext/auto.c, detect.c of geneva_c 2.0) read into the "Авто" book.</summary>
public sealed class GenevaDetectorTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void An_impaired_host_becomes_a_suspicion_and_the_capacity_is_learned()
    {
        var book = new AutoBook();
        book.Feed([new AutoSample
        {
            Key = "web:example.com", Kind = AutoKind.Web, Transport = L4Kind.Tcp, Name = "example.com",
            Host = "www.example.com", App = "tls", Server = new IPEndPoint(IPAddress.Parse("203.0.113.5"), 443),
            Time = T0, Health = AutoHealth.Ok, Why = "",
        }], T0);
        var status = JsonNode.Parse("""
            {"ok":true,"auto":"observe","source":"nflog","observing":true,"capacity":5000000,"link_degraded":false,
             "impaired":[{"key":"www.example.com","level":"host","impaired":true,"class":"THROTTLE","flows":4,"fails":4,
                          "classes":{"THROTTLE":4}},
                         {"key":"tcp/443","level":"port","impaired":true,"class":"RETRANS","flows":9,"fails":3}],
             "surgical":true}
            """)!.AsObject();
        var log = GenevaAuto.Detected(status, book, new Lock(), T0.AddSeconds(5));
        Assert.Single(log);
        Assert.Contains("example.com", log[0], StringComparison.Ordinal);
        Assert.True(LinkCapacity.Shared.Current() >= 5_000_000);
    }

    [Fact]
    public void A_status_without_a_detector_changes_nothing()
    {
        var book = new AutoBook();
        var status = JsonNode.Parse("""{"ok":true,"auto":"off"}""")!.AsObject();
        Assert.Empty(GenevaAuto.Detected(status, book, new Lock(), T0));
    }
}
