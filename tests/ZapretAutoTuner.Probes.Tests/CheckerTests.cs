using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Probes.Diagnostics;

namespace ZapretAutoTuner.Probes.Tests;

public class CheckerTests
{
    [Fact]
    public void Resource_set_is_valid()
    {
        var d = CheckerData.Default;
        Assert.True(d.Resources.Count >= 30);
        Assert.Equal(d.Resources.Count, d.Resources.Select(r => r.Id).Distinct().Count());
        Assert.Contains(d.Resources, r => r.IsControl);
        Assert.Contains(d.Resources, r => r.Kind == "provider");
        Assert.All(d.Resources, r =>
        {
            Assert.Contains(r.Kind, new[] { "service", "provider", "control" });
            Assert.False(string.IsNullOrWhiteSpace(r.NameRu));
            Assert.False(string.IsNullOrWhiteSpace(r.NameEn));
            Assert.NotEmpty(r.Targets);
            Assert.All(r.Targets, t =>
            {
                Assert.True(Target.IsValidHostName(t.Host), t.Host);
                Assert.StartsWith("/", t.Path, StringComparison.Ordinal);
            });
        });
    }

    private static int ClosedPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    [Fact]
    public async Task Rows_get_traffic_lights_and_controls_detect_a_dead_network()
    {
        await using var open = new TestServer(ServerMode.Ok, TestCerts.Leaf("open.test"), bodyBytes: 200_000);
        await using var cut = new TestServer(ServerMode.StallAfter, TestCerts.Leaf("cut.test"), bodyBytes: 200_000);
        int closed = ClosedPort();
        var ports = new Dictionary<string, int> { ["open.test"] = open.Port, ["cut.test"] = cut.Port, ["dead.test"] = closed, ["ctl.test"] = closed };
        static CheckerResource R(string id, string kind, string host) => new() { Id = id, Kind = kind, NameRu = id, NameEn = id, Targets = [new CheckerTarget { Host = host }] };

        var report = await Checker.RunAsync(
            [R("open", "service", "open.test"), R("cut", "service", "cut.test"), R("dead", "service", "dead.test"), R("ctl", "control", "ctl.test")],
            new CheckerOptions
            {
                Tweak = (t, o) => o with
                {
                    Addresses = [IPAddress.Loopback],
                    Port = ports[t.Host],
                    Pause = TimeSpan.Zero,
                    TweakHttp = h => h with { TrustedRoots = TestCerts.Roots, StallTimeout = TimeSpan.FromSeconds(1) },
                },
            });

        var rows = report.Rows.ToDictionary(r => r.Resource.Id);
        Assert.Equal(TrafficLight.Green, rows["open"].Light);
        Assert.Equal("Открывается", rows["open"].SummaryRu);
        Assert.Equal(TrafficLight.Yellow, rows["cut"].Light);
        Assert.Equal(BlockLabel.Cutoff16K, rows["cut"].Primary);
        Assert.Equal(TrafficLight.Red, rows["dead"].Light);
        Assert.True(rows["dead"].Targets[0].Retried);
        Assert.False(rows["open"].Targets[0].Retried);
        Assert.True(report.NetworkProblem); // the only control is dead
    }
}
