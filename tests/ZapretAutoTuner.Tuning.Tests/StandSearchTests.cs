using System.Diagnostics;
using System.Net;
using Xunit.Abstractions;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Unify;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Probes.Http;
using ZapretAutoTuner.Protocol;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>
/// PLAN 3.3 and 3.4 "Готово, когда" on the DPI stand (tools/stand/stand.sh) with the real nfqws2 through the Agent:
/// a strategy is found for the SNI blocks (reset and silence), the balancing DPI's 50% strategy is refined to N/N
/// inside its family, the found strategies pass the final N/N check, and a second search finds the same one. Needs
/// root, iproute2, iptables, python3 and the engine (<c>ZT_ZAPRET2_DIR</c>); runs in the CI integration job and
/// returns early elsewhere.
/// </summary>
[Trait("Category", "Integration")]
public sealed class StandSearchTests(ITestOutputHelper output) : IAsyncLifetime
{
    private const string Net = "10.124.0";
    private string? _dir;
    private bool _up;

    private static string RepoRoot()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "ZapretAutoTuner.slnx")))
            d = d.Parent;
        return d?.FullName ?? throw new InvalidOperationException("repo root not found");
    }

    private static string Stand => Path.Combine(RepoRoot(), "tools", "stand", "stand.sh");

    private static string? EngineDir() =>
        Environment.GetEnvironmentVariable("ZT_ZAPRET2_DIR") is { Length: > 0 } d && File.Exists(Path.Combine(d, "nfqws2")) ? d : null;

    private static (int Code, string Output) Sh(string cmd)
    {
        var p = Process.Start(new ProcessStartInfo("/bin/sh", ["-c", cmd]) { RedirectStandardOutput = true, RedirectStandardError = true })!;
        var o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, o);
    }

    private static bool Available() =>
        OperatingSystem.IsLinux() && Environment.IsPrivilegedProcess && EngineDir() is not null
        && Sh("command -v ip && command -v iptables && command -v python3 && command -v ss").Code == 0;

    public async Task InitializeAsync()
    {
        if (!OperatingSystem.IsLinux() || !Available())
            return;
        _dir = Directory.CreateTempSubdirectory("ztsearch").FullName;
        // the engine drops root: the lua files in the data dir must be readable by everyone
        File.SetUnixFileMode(_dir, (UnixFileMode)0b111_101_101);
        var cert = TestCerts.Leaf("sni.test", "drop.test", "flaky.test");
        await File.WriteAllTextAsync(Path.Combine(_dir, "c.pem"), cert.ExportCertificatePem());
        using var key = System.Security.Cryptography.X509Certificates.RSACertificateExtensions.GetRSAPrivateKey(cert)!;
        await File.WriteAllTextAsync(Path.Combine(_dir, "k.pem"), key.ExportPkcs8PrivateKeyPem());
        var (code, o) = Sh($"{Stand} up {_dir}/c.pem {_dir}/k.pem");
        Assert.True(code == 0, o);
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

    private static HttpProbeOptions Tweak(HttpProbeOptions o) => o with
    {
        TrustedRoots = TestCerts.Roots,
        ConnectTimeout = TimeSpan.FromSeconds(2),
        HandshakeTimeout = TimeSpan.FromSeconds(2),
        StallTimeout = TimeSpan.FromSeconds(1.5),
    };

    [Fact]
    public async Task Strategies_are_found_refined_and_confirmed_on_the_stand()
    {
        if (!_up)
            return;
        var lua = Path.Combine(_dir!, "lua");
        Directory.CreateDirectory(lua);
        foreach (var f in Directory.GetFiles(Path.Combine(EngineDir()!, "lua"), "*.lua"))
            File.Copy(f, Path.Combine(lua, Path.GetFileName(f)));
        await using var conn = await AgentConnection.LaunchAsync(new AgentLaunchOptions
        {
            AgentPath = Path.Combine(AppContext.BaseDirectory, "ztuner-agent"),
            DataDir = _dir!,
            Elevation = AgentElevation.None,
            EnginePath = Path.Combine(EngineDir()!, "nfqws2"),
        });
        var engine = new AgentEngineControl(conn.Client);
        var generator = new GeneratorOptions { Mode = SearchMode.Standard, Labels = [BlockLabel.SniBlock] };
        var blobs = StrategyGenerator.Generate(generator).Blobs;
        using var kb = KnowledgeBase.OpenInMemory();

        AgentTrialExecutor Executor(string host, string ip) => new(engine,
            new TrialTarget { Host = host, Addresses = [IPAddress.Parse(ip)], Path = "/big" },
            new AgentTrialOptions { LuaDir = lua, Blobs = blobs, TweakHttp = Tweak });

        async Task<(SearchResult Result, long Session)> Search(string host, string ip)
        {
            var target = new TrialTarget { Host = host, Addresses = [IPAddress.Parse(ip)], Path = "/big" };
            // baseline first (AGENTS.md rule 5): the search runs only on a blocked resource
            var baseline = await HttpProbe.RunAsync(Tweak(new HttpProbeOptions { Host = host, Address = IPAddress.Parse(ip), Path = "/big" }));
            Assert.False(baseline.Passes(ProbeLevel.L2Body), $"{host} is not blocked: {baseline}");
            long session = kb.StartSession(host, "standard", blockLabel: "SNI_BLOCK");
            var log = new KnowledgeBaseSearchLog(kb, session, target, blockLabel: "SNI_BLOCK");
            var options = new SearchOptions { Generator = generator, StopAfterFound = 1, RefineTime = TimeSpan.FromMinutes(3) };
            var sw = Stopwatch.StartNew();
            var r = await new StrategySearch(Executor(host, ip), options, log).RunAsync();
            TuningSession.Finish(kb, session, host, r);
            output.WriteLine($"{host}: {r.Reason} in {sw.Elapsed.TotalSeconds:0}s after {r.Tried}: {r.Best?.Candidate} {r.Best?.Efficiency} {r.Best?.MutationPath}");
            foreach (var s in kb.TuningSteps(session))
                output.WriteLine($"  {s.Mutation}: {s.Efficiency} {(s.Accepted ? "accepted" : "")}");
            return (r, session);
        }

        var history = new List<DomainResult>();
        foreach (var (host, ip) in new[] { ("sni.test", $"{Net}.12"), ("drop.test", $"{Net}.13") })
        {
            var (r, _) = await Search(host, ip);
            history.AddRange(r.Working.Select(f => new DomainResult(host, L4Kind.Tcp, f.Candidate.Strategy, f.Efficiency, f.Score.Total)));
            Assert.True(r.Best is not null, $"{host}: nothing found");
            var check = await FinalCheck.RunAsync(Executor(host, ip), [r.Best], host, openPage: null);
            Assert.True(check[0].Passed, $"{host}: final check {check[0].L2}");
            // the second run gives the same answer (PLAN 3.4)
            var (again, _) = await Search(host, ip);
            Assert.Equal(r.Best.Candidate.Key, again.Best?.Candidate.Key);
        }

        // PLAN 3.3: the balancing DPI; the partial strategy is refined in its family, not replaced by another one
        var (flaky, flakySession) = await Search("flaky.test", $"{Net}.21");
        Assert.True(flaky.Best is not null, "flaky.test: nothing found");
        Assert.True(flaky.Best.Refined, $"not refined: {flaky.Best.Candidate}");
        Assert.Equal("multisplit", flaky.Best.Candidate.Family);
        Assert.Equal(flaky.Best.Efficiency.Attempts, flaky.Best.Efficiency.Successes);
        Assert.Contains(kb.TuningSteps(flakySession), s => s.Accepted || s.Efficiency.Successes == s.Efficiency.Attempts);
        var flakyCheck = await FinalCheck.RunAsync(Executor("flaky.test", $"{Net}.21"), [flaky.Best], "flaky.test", openPage: null);
        Assert.True(flakyCheck[0].Passed, $"flaky.test: final check {flakyCheck[0].L2}");
        history.AddRange(flaky.Working.Select(f => new DomainResult("flaky.test", L4Kind.Tcp, f.Candidate.Strategy, f.Efficiency, f.Score.Total)));

        // PLAN 4.1-4.2: the cross-check shows midsld+1 works on all three, so one profile; one engine run confirms it
        var ips = new Dictionary<string, string> { ["sni.test"] = $"{Net}.12", ["drop.test"] = $"{Net}.13", ["flaky.test"] = $"{Net}.21" };
        var plan = await UnifyRunner.RunAsync(history, [.. ips.Keys], new ExecutorCrossChecker(d => Executor(d, ips[d])));
        output.WriteLine("unified: " + string.Join(" | ", plan.Profiles));
        var profile = Assert.Single(plan.Profiles);
        Assert.Equal(3, profile.Domains.Count);
        var targets = ips.Select(kv => new TrialTarget { Host = kv.Key, Addresses = [IPAddress.Parse(kv.Value)], Path = "/big" }).ToList();
        var config = await ConfigCheck.RunAsync(engine, Unifier.ToSolution(plan), targets, new AgentTrialOptions { LuaDir = lua, Blobs = blobs, TweakHttp = Tweak });
        output.WriteLine(string.Join(" ", config.Argv));
        Assert.True(config.Passed, string.Join("; ", config.Domains.Select(d => $"{d.Domain} {d.L2}")));

        // the adaptive variant must start in the real engine (dry-run and lua init through the Agent)
        var circular = Unifier.Circular([Core.Model.Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5"), flaky.Best.Candidate.Strategy]);
        var adaptive = Unifier.ToSolution(new UnifyPlan([], [], [new UnifiedProfile(circular, [.. ips.Keys], L4Kind.Tcp, 0, Adaptive: true)]), adaptive: true);
        var (circularArgv, _) = ConfigCheck.BuildLaunch(adaptive, targets, new AgentTrialOptions { LuaDir = lua, Blobs = blobs });
        var dryRun = new CheckEngineArgsRequest();
        dryRun.Argv.AddRange(circularArgv);
        var cr = await conn.Client.CheckEngineArgsAsync(dryRun);
        Assert.True(cr.Ok, cr.Stage + ": " + string.Join("\n", cr.Output));
    }
}
