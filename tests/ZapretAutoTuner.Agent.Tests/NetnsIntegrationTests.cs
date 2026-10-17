using System.Diagnostics;
using Google.Protobuf;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Agent.Tests;

/// <summary>
/// PLAN 1.2 "Готово, когда": the real nfqws2, started through the Agent, runs fake+multisplit against a TLS
/// server in a network namespace, and the Agent's own capture shows the modified packets. Needs root, iproute2,
/// openssl, curl and the engine: <c>ZT_NFQWS2</c> or the bundle (<c>ZT_ZAPRET2_DIR</c>). Runs in the CI
/// integration job; elsewhere it returns early.
/// </summary>
[Trait("Category", "Integration")]
[Collection(AgentProcessCollection.Name)]
public sealed class NetnsIntegrationTests : IDisposable
{
    private const string Ns = "ztit";
    private const string ServerIp = "10.123.0.2";
    private readonly List<Process> _procs = [];

    private static string? EnginePath()
    {
        if (Environment.GetEnvironmentVariable("ZT_NFQWS2") is { Length: > 0 } e && File.Exists(e))
            return e;
        if (Environment.GetEnvironmentVariable("ZT_ZAPRET2_DIR") is { Length: > 0 } d && File.Exists(Path.Combine(d, "nfqws2")))
            return Path.Combine(d, "nfqws2");
        return null;
    }

    private static string LuaDir() =>
        Environment.GetEnvironmentVariable("ZT_ZAPRET2_DIR") is { Length: > 0 } d && Directory.Exists(Path.Combine(d, "lua"))
            ? Path.Combine(d, "lua")
            : TestEnv.LuaDir;

    private static void Sh(string cmd)
    {
        var o = TestEnv.Run("/bin/sh", "-c", cmd + " ; echo rc=$?");
        if (!o.TrimEnd().EndsWith("rc=0", StringComparison.Ordinal))
            throw new InvalidOperationException(cmd + ": " + o);
    }

    [Fact]
    public async Task Fake_and_multisplit_reach_the_wire()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var engine = EnginePath();
        if (!TestEnv.IsRootLinux || engine is null || TestEnv.Run("/bin/sh", "-c", "command -v ip && command -v openssl && command -v curl").Split('\n', StringSplitOptions.RemoveEmptyEntries).Length < 3)
            return;

        var dir = TestEnv.NewTempDir();
        // the engine drops root: lua files and the data dir must be readable by everyone
        File.SetUnixFileMode(dir, (UnixFileMode)0b111_101_101);
        var lua = Path.Combine(dir, "lua");
        Directory.CreateDirectory(lua);
        foreach (var f in Directory.GetFiles(LuaDir(), "*.lua"))
            File.Copy(f, Path.Combine(lua, Path.GetFileName(f)));

        Sh($"ip netns add {Ns}");
        Sh($"ip link add zt0 type veth peer name zt1 && ip link set zt1 netns {Ns}");
        Sh("ip addr add 10.123.0.1/24 dev zt0 && ip link set zt0 up");
        Sh($"ip netns exec {Ns} sh -c 'ip addr add {ServerIp}/24 dev zt1 && ip link set zt1 up && ip link set lo up'");
        Sh($"openssl req -x509 -newkey rsa:2048 -nodes -keyout {dir}/k.pem -out {dir}/c.pem -days 1 -subj /CN=test.local 2>/dev/null");
        _procs.Add(Process.Start(new ProcessStartInfo("ip", ["netns", "exec", Ns, "openssl", "s_server", "-quiet", "-accept", "443", "-key", $"{dir}/k.pem", "-cert", $"{dir}/c.pem", "-www"])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!);
        await Task.Delay(1000);

        await using var conn = await AgentConnection.LaunchAsync(new AgentLaunchOptions
        {
            AgentPath = TestEnv.AgentPath,
            DataDir = dir,
            Elevation = AgentElevation.None,
            EnginePath = engine,
        });

        var cap = new StartCaptureRequest { Interface = "zt0", Addresses = { ServerIp }, Ports = { 443 } };
        var capId = (await conn.Client.StartCaptureAsync(cap)).CaptureId;

        var start = new StartEngineRequest
        {
            Tag = "it",
            Queue = new QueueRule { QueueNum = 391, TcpPorts = "443", Targets = { ServerIp } },
        };
        start.Argv.AddRange(
        [
            $"--lua-init=@{lua}/zapret-lib.lua",
            $"--lua-init=@{lua}/zapret-antidpi.lua",
            "--filter-tcp=443",
            "--lua-desync=fake:blob=fake_default_tls:tcp_md5",
            "--lua-desync=multisplit:pos=2",
        ]);
        var check = new CheckEngineArgsRequest();
        check.Argv.AddRange(start.Argv);
        var cr = await conn.Client.CheckEngineArgsAsync(check);
        Assert.True(cr.Ok, cr.Stage + ": " + string.Join("\n", cr.Output));

        var eng = await conn.Client.StartEngineAsync(start);
        await Task.Delay(500);
        var curl = TestEnv.Run("curl", "-sk", "--noproxy", "*", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}", "--resolve", $"test.local:443:{ServerIp}", "https://test.local/");
        await conn.Client.StopEngineAsync(new StopEngineRequest { EngineId = eng.EngineId });

        var bytes = new MemoryStream();
        using (var stream = conn.Client.StopCapture(new StopCaptureRequest { CaptureId = capId }))
        {
            while (await stream.ResponseStream.MoveNext(CancellationToken.None))
                stream.ResponseStream.Current.Data.WriteTo(bytes);
        }
        var packets = PcapReader.Read(bytes.ToArray());
        File.WriteAllBytes(Path.Combine(dir, "it.pcapng"), bytes.ToArray());

        Assert.Equal("200", curl.Trim());
        var outData = packets.Select(p => p.Parse()!).Where(p => p.IsTcp && p.DestinationPort == 443 && p.Payload.Length > 0).ToList();
        // fake: a segment carrying the TCP MD5 signature option (kind 19)
        Assert.Contains(outData, p => HasOption(p.TcpOptions.Span, 19));
        // multisplit: the real ClientHello leaves in more than one segment, the first one ending at offset 2 (pos=2)
        var real = outData.Where(p => !HasOption(p.TcpOptions.Span, 19)).ToList();
        Assert.True(real.Count >= 2, $"real segments: {real.Count}");
        Assert.Equal(2, real[0].Payload.Length);
        var flow = Assert.Single(FlowAnalyzer.Analyze(packets), f => f.ClientHello is not null);
        // the fake hello (another SNI) comes first, the real one last
        Assert.True(flow.ClientHellos.Count >= 2);
        Assert.Equal("test.local", flow.ClientHello!.Sni);
    }

    private static bool HasOption(ReadOnlySpan<byte> o, byte kind)
    {
        for (int i = 0; i < o.Length;)
        {
            if (o[i] == 0)
                return false;
            if (o[i] == 1)
            {
                i++;
                continue;
            }
            if (o[i] == kind)
                return true;
            if (i + 1 >= o.Length || o[i + 1] < 2)
                return false;
            i += o[i + 1];
        }
        return false;
    }

    public void Dispose()
    {
        foreach (var p in _procs)
        {
            try
            {
                p.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }
            p.Dispose();
        }
        if (TestEnv.IsRootLinux)
            TestEnv.Run("/bin/sh", "-c", $"ip netns del {Ns} 2>/dev/null; ip link del zt0 2>/dev/null; true");
    }
}
