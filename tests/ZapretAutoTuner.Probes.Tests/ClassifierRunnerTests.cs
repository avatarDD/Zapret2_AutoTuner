using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Probes.Diagnostics;

namespace ZapretAutoTuner.Probes.Tests;

public class ClassifierRunnerTests
{
    private static ClassifierOptions Options(int port) => new()
    {
        Addresses = [IPAddress.Loopback],
        Port = port,
        BaselineAttempts = 2,
        Pause = TimeSpan.Zero,
        CheckHttp = false,
        CheckQuic = false,
        Profiles = [ClientProfile.BuiltIn.Single(p => p.Id == "chrome")],
        HelloTimeout = TimeSpan.FromSeconds(1),
        TweakHttp = o => o with { TrustedRoots = TestCerts.Roots, HandshakeTimeout = TimeSpan.FromSeconds(1), StallTimeout = TimeSpan.FromSeconds(1) },
    };

    [Fact]
    public async Task Open_server_is_open_and_steps_are_reported()
    {
        await using var s = new TestServer(ServerMode.Ok, TestCerts.Leaf("blocked.test"), bodyBytes: 300_000);
        var steps = new List<ClassifierStep>();
        var run = await ClassifierRunner.RunAsync("blocked.test", Options(s.Port), new Sync(steps));
        Assert.Equal(BlockLabel.Open, run.Verdict.Primary);
        Assert.Equal(["port", "baseline", "baseline", "tls", "fingerprint", "fingerprint", "fingerprint", "verdict"], steps.Select(x => x.Stage));
        Assert.All(steps, x => Assert.False(string.IsNullOrEmpty(x.MessageRu)));
        Assert.Equal(3, run.Observation.Addresses[0].Hellos.Count); // as sent, without kyber, without ECH
    }

    [Fact]
    public async Task Reset_everywhere_with_a_live_control_is_partial_ip()
    {
        await using var s = new TestServer(ServerMode.ResetOnHello);
        await using var control = new TestServer(ServerMode.Ok, TestCerts.Leaf("iana.org"));
        var o = Options(s.Port) with { NeutralAddress = IPAddress.Loopback, Profiles = [] };
        // the control runs on the same port number as the target: give it its own server
        o = o with { TweakHttp = x => (x.Host == "iana.org" ? x with { Port = control.Port } : x) with { TrustedRoots = TestCerts.Roots, HandshakeTimeout = TimeSpan.FromSeconds(1) } };
        var run = await ClassifierRunner.RunAsync("blocked.test", o);
        Assert.Equal(BlockLabel.PartialIp, run.Verdict.Primary);
    }

    [Fact]
    public void Hello_variants_cover_kyber_and_ech()
    {
        var v = ClassifierRunner.HelloVariants(ClientProfile.BuiltIn.Where(p => p.Id is "chrome" or "firefox"));
        Assert.Contains(v, x => x.Spec.Id == "chrome141" && x.Kyber && x.Ech);
        Assert.Contains(v, x => x.Spec.Id == "chrome141" && !x.Kyber && x.Ech);
        Assert.Contains(v, x => x.Spec.Id == "chrome141" && x.Kyber && !x.Ech);
        Assert.Equal(6, v.Count);
        Assert.Equal(v.Count, v.Distinct().Count());
    }

    private sealed class Sync(List<ClassifierStep> list) : IProgress<ClassifierStep>
    {
        public void Report(ClassifierStep value)
        {
            lock (list)
                list.Add(value);
        }
    }
}
