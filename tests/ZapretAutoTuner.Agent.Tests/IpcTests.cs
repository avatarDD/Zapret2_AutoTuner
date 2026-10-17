using System.Diagnostics;
using Grpc.Core;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Agent.Tests;

/// <summary>
/// The Agent as a separate process, reached over its unix socket / named pipe (PLAN 1.1 "Готово, когда": the UI
/// dies → the Agent removes everything within 5 s).
/// </summary>
[Collection(AgentProcessCollection.Name)]
public class IpcTests
{
    private static AgentLaunchOptions Options(string dir, int? uiPid = null, string? engine = null) => new()
    {
        AgentPath = TestEnv.AgentPath,
        DataDir = dir,
        Elevation = AgentElevation.None,
        UiPid = uiPid,
        EnginePath = engine,
        StartTimeout = TimeSpan.FromSeconds(30),
    };

    [Fact]
    public async Task Heartbeat_reports_agent_and_wrong_token_is_rejected()
    {
        var dir = TestEnv.NewTempDir();
        await using var conn = await AgentConnection.LaunchAsync(Options(dir));
        var hb = conn.LastHeartbeat!;
        Assert.Equal(OperatingSystem.IsWindows() ? "windows" : "linux", hb.Platform);
        Assert.True(hb.AgentPid > 0);
        Assert.Empty(Directory.GetFiles(dir, "*.token"));

        await using var bad = OperatingSystem.IsWindows()
            ? AgentConnection.Connect(null, conn.Endpoint, "wrong", TimeSpan.FromHours(1))
            : AgentConnection.Connect(conn.Endpoint, null, "wrong", TimeSpan.FromHours(1));
        var e = await Assert.ThrowsAsync<RpcException>(async () => await bad.Client.HeartbeatAsync(new HeartbeatRequest()));
        Assert.Equal(StatusCode.Unauthenticated, e.StatusCode);

        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(conn.Endpoint);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
        }
    }

    [Fact]
    public async Task Agent_exits_within_5_seconds_after_ui_dies()
    {
        var dir = TestEnv.NewTempDir();
        using var ui = TestEnv.StartDummyUi();
        var conn = await AgentConnection.LaunchAsync(Options(dir, ui.Id));
        using var agent = Process.GetProcessById(conn.LastHeartbeat!.AgentPid);
        ui.Kill();
        var sw = Stopwatch.StartNew();
        using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
            await agent.WaitForExitAsync(cts.Token);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5));
        Assert.False(File.Exists(Path.Combine(dir, "agent-state.json")));
        await conn.DisposeAsync();
    }

    [Fact]
    public async Task Shutdown_on_dispose()
    {
        var dir = TestEnv.NewTempDir();
        var conn = await AgentConnection.LaunchAsync(Options(dir));
        using var agent = Process.GetProcessById(conn.LastHeartbeat!.AgentPid);
        await conn.DisposeAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await agent.WaitForExitAsync(cts.Token);
    }

    [Fact]
    public async Task Invalid_argv_is_refused_before_anything_runs()
    {
        var dir = TestEnv.NewTempDir();
        await using var conn = await AgentConnection.LaunchAsync(Options(dir));
        var req = new CheckEngineArgsRequest();
        req.Argv.AddRange(["--filter-tcp=443", "--dpi-desync=fake"]);
        var r = await conn.Client.CheckEngineArgsAsync(req);
        Assert.False(r.Ok);
        Assert.Equal("validator", r.Stage);

        var req2 = new CheckEngineArgsRequest();
        req2.Argv.AddRange(TestEnv.SampleArgv().Prepend("--user=root"));
        var r2 = await conn.Client.CheckEngineArgsAsync(req2);
        Assert.Equal("policy", r2.Stage);

        var start = new StartEngineRequest();
        start.Argv.AddRange(["--filter-tcp=443", "--lua-desync=nosuchfunc"]);
        var e = await Assert.ThrowsAsync<RpcException>(async () => await conn.Client.StartEngineAsync(start));
        Assert.Equal(StatusCode.FailedPrecondition, e.StatusCode);
    }

    /// <summary>
    /// Root only (the container / CI integration job): engine start with a firewall rule, output streaming, rule
    /// removal on stop, and the engine dying with a SIGKILLed Agent; then --cleanup removes the leftovers.
    /// </summary>
    [Fact]
    public async Task Engine_lifecycle_with_firewall_and_crash_cleanup()
    {
        if (!TestEnv.IsRootLinux)
            return;
        var dir = TestEnv.NewTempDir();
        var engine = TestEnv.WriteFakeEngine(dir);
        var conn = await AgentConnection.LaunchAsync(Options(dir, engine: engine));
        try
        {
            var check = new CheckEngineArgsRequest();
            check.Argv.AddRange(TestEnv.SampleArgv());
            var cr = await conn.Client.CheckEngineArgsAsync(check);
            Assert.True(cr.Ok, cr.Stage + ": " + string.Join("\n", cr.Output));

            var start = new StartEngineRequest
            {
                Tag = "test",
                Queue = new QueueRule { QueueNum = 377, TcpPorts = "443", Targets = { "198.51.100.77" } },
            };
            start.Argv.AddRange(TestEnv.SampleArgv());
            var sr = await conn.Client.StartEngineAsync(start);
            var hb = await conn.Client.HeartbeatAsync(new HeartbeatRequest());
            Assert.Contains(sr.EngineId, hb.Engines);
            Assert.Contains("377", FirewallDump(hb.FirewallBackend), StringComparison.Ordinal);

            using var watch = conn.Client.WatchEngine(new WatchEngineRequest { EngineId = sr.EngineId });
            var seen = new List<string>();
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
            {
                await foreach (var m in watch.ResponseStream.ReadAllAsync(cts.Token))
                {
                    seen.Add(m.Line);
                    if (m.Line.Contains("matches", StringComparison.Ordinal))
                        break;
                }
            }
            Assert.Contains("arg --qnum=377", seen);
            Assert.Contains("arg --fwmark=0x40000000", seen);

            var stop = await conn.Client.StopEngineAsync(new StopEngineRequest { EngineId = sr.EngineId });
            Assert.True(stop.WasRunning);
            Assert.DoesNotContain("377", FirewallDump(hb.FirewallBackend), StringComparison.Ordinal);

            // again, then kill the Agent hard: the engine must die with it
            File.Delete(Path.Combine(dir, "engine.pid"));
            await conn.Client.StartEngineAsync(start);
            Assert.True(await TestEnv.WaitUntil(() => File.Exists(Path.Combine(dir, "engine.pid")), TimeSpan.FromSeconds(5)));
            int enginePid = int.Parse(File.ReadAllText(Path.Combine(dir, "engine.pid")).Trim(), System.Globalization.CultureInfo.InvariantCulture);
            using var agent = Process.GetProcessById(hb.AgentPid);
            agent.Kill();
            await agent.WaitForExitAsync();
            Assert.True(await TestEnv.WaitUntil(() => !TestEnv.ProcessAlive(enginePid), TimeSpan.FromSeconds(4)), "engine survived the agent");
            Assert.Contains("377", FirewallDump(hb.FirewallBackend), StringComparison.Ordinal); // SIGKILL: no cleanup ran

            var cleanup = TestEnv.Run(TestEnv.AgentPath, "--cleanup", "--data-dir=" + dir);
            Assert.Contains("cleanup done", cleanup, StringComparison.Ordinal);
            Assert.DoesNotContain("377", FirewallDump(hb.FirewallBackend), StringComparison.Ordinal);
        }
        finally
        {
            await conn.DisposeAsync();
            TestEnv.Run(TestEnv.AgentPath, "--cleanup", "--data-dir=" + dir);
        }
    }

    private static string FirewallDump(string backend) => backend == "nft"
        ? TestEnv.Run("nft", "list", "ruleset")
        : TestEnv.Run("iptables", "-t", "mangle", "-S");
}
