using System.Diagnostics;
using Xunit.Abstractions;
using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Probes.Diagnostics;

namespace ZapretAutoTuner.Probes.Tests;

/// <summary>
/// PLAN 2.5 "Готово, когда": on the stand with the DPI emulator (tools/stand/stand.sh) every block type is classified
/// right. Needs root, iproute2, iptables and python3; runs in the CI integration job and returns early elsewhere.
/// </summary>
[Trait("Category", "Integration")]
public sealed class StandIntegrationTests(ITestOutputHelper output) : IAsyncLifetime
{
    private const string Net = "10.124.0";
    private string? _dir;
    private bool _up;

    private static string Stand => Path.Combine(RepoRoot(), "tools", "stand", "stand.sh");

    private static string RepoRoot()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "ZapretAutoTuner.slnx")))
            d = d.Parent;
        return d?.FullName ?? throw new InvalidOperationException("repo root not found");
    }

    private static (int Code, string Output) Sh(string cmd)
    {
        var p = Process.Start(new ProcessStartInfo("/bin/sh", ["-c", cmd]) { RedirectStandardOutput = true, RedirectStandardError = true })!;
        var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, output);
    }

    private static bool Available() =>
        OperatingSystem.IsLinux() && Environment.UserName == "root"
        && Sh("command -v ip && command -v iptables && command -v python3 && command -v ss").Code == 0;

    public async Task InitializeAsync()
    {
        if (!Available())
            return;
        _dir = Directory.CreateTempSubdirectory("ztstand").FullName;
        var cert = TestCerts.Leaf("open.test", "sni.test", "drop.test", "ip.test", "port.test", "cut.test", "kyber.test", "fp.test", "redirect.test", "iana.org");
        await File.WriteAllTextAsync(Path.Combine(_dir, "c.pem"), cert.ExportCertificatePem());
        using var key = System.Security.Cryptography.X509Certificates.RSACertificateExtensions.GetRSAPrivateKey(cert)!;
        await File.WriteAllTextAsync(Path.Combine(_dir, "k.pem"), key.ExportPkcs8PrivateKeyPem());
        var (code, output) = Sh($"{Stand} up {_dir}/c.pem {_dir}/k.pem");
        Assert.True(code == 0, output);
        _up = true;
    }

    public Task DisposeAsync()
    {
        if (_up)
            Sh($"{Stand} down");
        if (_dir is not null)
            Directory.Delete(_dir, true);
        return Task.CompletedTask;
    }

    private static ClassifierOptions Options(string ip) => new()
    {
        Addresses = [IPAddress.Parse(ip)],
        Path = "/big",
        BaselineAttempts = 2,
        Pause = TimeSpan.FromMilliseconds(50),
        NeutralAddress = IPAddress.Parse($"{Net}.11"),
        CheckQuic = false,
        HelloTimeout = TimeSpan.FromSeconds(2),
        TweakHttp = o => o with
        {
            TrustedRoots = TestCerts.Roots,
            ConnectTimeout = TimeSpan.FromSeconds(2),
            HandshakeTimeout = TimeSpan.FromSeconds(2),
            StallTimeout = TimeSpan.FromSeconds(1.5),
        },
    };

    [Fact]
    public async Task Every_block_type_is_classified()
    {
        if (!_up)
            return;
        var cases = new (string Host, string Ip, BlockLabel Expected, NextStep Next)[]
        {
            ("open.test", $"{Net}.11", BlockLabel.Open, NextStep.Nothing),
            ("sni.test", $"{Net}.12", BlockLabel.SniBlock, NextStep.SearchStrategy),
            ("drop.test", $"{Net}.13", BlockLabel.SniBlock, NextStep.SearchStrategy),
            ("ip.test", $"{Net}.14", BlockLabel.IpBlock, NextStep.FindOtherIp),
            ("port.test", $"{Net}.15", BlockLabel.PortBlock, NextStep.FindOtherIp),
            ("cut.test", $"{Net}.16", BlockLabel.Cutoff16K, NextStep.SearchStrategy),
            ("kyber.test", $"{Net}.17", BlockLabel.KyberMultiPkt, NextStep.SearchStrategy),
            ("fp.test", $"{Net}.18", BlockLabel.Fingerprint, NextStep.SearchStrategy),
            ("redirect.test", $"{Net}.19", BlockLabel.HttpBlock, NextStep.SearchStrategy),
        };
        // different addresses do not share DPI rules, so the cases can run side by side
        var runs = await Task.WhenAll(cases.Select(async c =>
        {
            var steps = new List<ClassifierStep>();
            var run = await ClassifierRunner.RunAsync(c.Host, Options(c.Ip), new SyncProgress<ClassifierStep>(steps.Add));
            return (c, run, steps);
        }));

        var report = string.Join("\n", runs.Select(r => $"{r.c.Host}: {r.run.Verdict}\n  " + string.Join("\n  ", r.run.Verdict.Findings)));
        output.WriteLine(report);
        foreach (var (c, run, steps) in runs)
        {
            Assert.True(c.Expected == run.Verdict.Primary, $"{c.Host}: expected {c.Expected}\n{report}");
            Assert.True(c.Next == run.Verdict.Next, $"{c.Host}: expected {c.Next}\n{report}");
            Assert.NotEmpty(steps);
            Assert.Equal("verdict", steps[^1].Stage);
        }

        // evidence the user sees: the cross-SNI test and the stall point
        var sni = runs.Single(r => r.c.Host == "sni.test").run.Verdict.Findings.Single(f => f.Label == BlockLabel.SniBlock);
        Assert.Contains(sni.Evidence, e => e.Contains("iana.org", StringComparison.Ordinal));
        var cut = runs.Single(r => r.c.Host == "cut.test").run.Observation.Addresses[0].Baseline[0];
        Assert.InRange(cut.StalledAt ?? cut.BytesIn, Classifier.CutoffMin, Classifier.CutoffMax);
    }

    /// <summary>Progress&lt;T&gt; posts to the thread pool; tests need the calls in order.</summary>
    private sealed class SyncProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value)
        {
            lock (this)
                report(value);
        }
    }
}
