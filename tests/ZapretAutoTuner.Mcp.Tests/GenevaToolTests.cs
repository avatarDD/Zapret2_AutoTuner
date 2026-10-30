using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Tuning.Geneva;
using ZapretAutoTuner.Tuning.Tests;

namespace ZapretAutoTuner.Mcp.Tests;

/// <summary>geneva over MCP: the engine choice, the search on a target and the bypass behind the user's yes.</summary>
public sealed class GenevaToolTests
{
    private static ProbeResult Result(string host, bool loaded) => loaded
        ? new() { Host = host, Address = "192.0.2.1", ConnectOk = true, TlsOk = true, CertValid = true, HttpStatus = 200, Complete = true, BodyBytes = 200_000 }
        : new() { Host = host, Address = "192.0.2.1", ConnectOk = true, Error = ProbeError.TlsReset };

    private static (Rig Rig, FakeGenevaAgent Agent) Make(McpPermissions? permissions = null)
    {
        var rig = new Rig(permissions ?? Rig.All);
        var agent = new FakeGenevaAgent();
        int calls = 0;
        rig.Host.Geneva = new GenevaController(_ => Task.FromResult<IGenevaAgent>(agent), new MemoryGenevaStore(),
            (host, port, tls, local, ct) => Task.FromResult(Result(host, Interlocked.Increment(ref calls) == 3)));
        return (rig, agent);
    }

    [Fact]
    public async Task Status_reports_the_engine_and_select_switches_it()
    {
        var (rig, _) = Make();
        using var _r = rig;
        var s = await rig.Call("geneva_status");
        Assert.False(s.IsError);
        Assert.Equal("nfqws2", (string?)s.Data["engine"]);
        var sel = await rig.Call("engine_select", """{"engine":"geneva"}""");
        Assert.False(sel.IsError);
        Assert.Equal(BypassEngine.Geneva, rig.Host.Geneva!.Engine);
        Assert.Equal("geneva", (string?)(await rig.Call("geneva_status")).Data["engine"]);
    }

    [Fact]
    public async Task A_search_runs_only_on_a_target_and_its_result_shows_in_status()
    {
        var (rig, agent) = Make();
        using var _r = rig;
        var bad = await rig.Call("geneva_search_start", """{"target":"elsewhere.example"}""");
        Assert.True(bad.IsError);
        Assert.Empty(agent.Started);

        var r = await rig.Call("geneva_search_start", """{"target":"blocked.example","population":10,"generations":3}""");
        Assert.False(r.IsError);
        await Rig.Until(() => Task.FromResult(!rig.Host.Geneva!.SearchRunning));
        var s = (await rig.Call("geneva_status")).Data;
        Assert.Equal("blocked.example", (string?)s["search"]!["target"]);
        Assert.True((bool?)s["search"]!["blocked_without_bypass"]);
        Assert.Equal("[TCP:flags:PA]-fragment{tcp:8:True}-| \\/", (string?)s["found"]![0]!["strategy"]);
    }

    [Fact]
    public async Task The_bypass_waits_for_the_user_and_stops_on_request()
    {
        var (rig, agent) = Make();
        using var _r = rig;
        const string args = """{"strategy":"[TCP:flags:PA]-fragment{tcp:8:True}-| \\/","ports":"443"}""";
        var r = await rig.Call("geneva_run_start", args);
        Assert.Equal("pending_confirmation", (string?)r.Data["status"]);
        Assert.Empty(agent.Started);
        Assert.Contains("443", rig.Confirm.Asked[0].TextEn, StringComparison.Ordinal);

        rig.Confirm.Answer(true);
        await Rig.Until(async () => (string?)(await rig.Call("geneva_run_start", args)).Data["status"] == "running");
        Assert.Equal("run", Assert.Single(agent.Started).Mode);

        var refused = await rig.Call("engine_select", """{"engine":"nfqws2"}""");
        Assert.True(refused.IsError);

        var stop = await rig.Call("geneva_run_stop");
        Assert.False(stop.IsError);
        Assert.NotEmpty(agent.Stopped);
    }

    [Fact]
    public async Task The_models_local_work_waits_while_geneva_runs()
    {
        var (rig, _) = Make();
        using var _r = rig;
        Assert.Null(rig.Session.LocalWorkRefusal());
        const string args = """{"strategy":"[TCP:flags:PA]-fragment{tcp:8:True}-| \\/","ports":"443"}""";
        await rig.Call("geneva_run_start", args);
        rig.Confirm.Answer(true);
        await Rig.Until(() => Task.FromResult(rig.Host.Geneva!.RunRunning));
        Assert.Contains("geneva", (string?)rig.Session.LocalWorkRefusal()?["error"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task Control_tools_need_the_control_switch()
    {
        var (rig, agent) = Make(new McpPermissions());
        using var _r = rig;
        Assert.False((await rig.Call("geneva_status")).IsError);
        Assert.True((await rig.Call("engine_select", """{"engine":"geneva"}""")).IsError);
        Assert.True((await rig.Call("geneva_search_start", """{"target":"blocked.example"}""")).IsError);
        Assert.Empty(agent.Started);
        Assert.Equal(BypassEngine.Nfqws2, rig.Host.Geneva!.Engine);
    }
}
