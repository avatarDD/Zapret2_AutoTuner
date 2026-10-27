using System.Net;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Agent.Tests;

/// <summary>
/// PLAN 1.2 on Windows: the bundled winws2 passes --dry-run and --intercept=0 through the Agent, then runs
/// multisplit on real HTTPS traffic while the Agent's WinDivert sniff capture records it. Needs Administrator
/// (GitHub runners have it) and the bundle in <c>ZT_ZAPRET2_DIR</c>.
/// </summary>
[Trait("Category", "Integration")]
[Collection(AgentProcessCollection.Name)]
public sealed class WindowsIntegrationTests
{
    [Fact]
    public async Task Winws2_multisplit_is_visible_in_windivert_capture()
    {
        if (!OperatingSystem.IsWindows() || !Environment.IsPrivilegedProcess)
            return;
        if (Environment.GetEnvironmentVariable("ZT_ZAPRET2_DIR") is not { Length: > 0 } bundle || !File.Exists(Path.Combine(bundle, "winws2.exe")))
            return;

        var dir = TestEnv.NewTempDir();
        var lua = Path.Combine(bundle, "lua").Replace('\\', '/');
        var target = "github.com";
        var addrs = (await Dns.GetHostAddressesAsync(target)).Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToList();
        Assert.NotEmpty(addrs);
        var ip = addrs[0];

        await using var conn = await AgentConnection.LaunchAsync(new AgentLaunchOptions
        {
            AgentPath = TestEnv.AgentPath,
            DataDir = dir,
            Elevation = AgentElevation.None,
            EnginePath = Path.Combine(bundle, "winws2.exe"),
        });

        var argv = new List<string>
        {
            "--wf-tcp-out=443",
            $"--wf-raw-filter=(ip.DstAddr=={ip} or ip.SrcAddr=={ip})",
            $"--lua-init=@{lua}/zapret-lib.lua",
            $"--lua-init=@{lua}/zapret-antidpi.lua",
            "--filter-tcp=443",
            "--lua-desync=multisplit:pos=2",
        };
        var check = new CheckEngineArgsRequest();
        check.Argv.AddRange(argv);
        var cr = await conn.Client.CheckEngineArgsAsync(check.WithLuaFiles());
        Assert.True(cr.Ok, cr.Stage + ": " + string.Join("\n", cr.Output));

        var capId = (await conn.Client.StartCaptureAsync(new StartCaptureRequest { Addresses = { ip.ToString() }, Ports = { 443 } })).CaptureId;
        var start = new StartEngineRequest { Tag = "win-it" };
        start.Argv.AddRange(argv);
        var eng = await conn.Client.StartEngineAsync(start.WithLuaFiles());
        await Task.Delay(1500);

        using (var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectCallback = async (ctx, ct) =>
            {
                var s = new System.Net.Sockets.Socket(System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
                await s.ConnectAsync(new IPEndPoint(ip, 443), ct);
                return new System.Net.Sockets.NetworkStream(s, ownsSocket: true);
            },
        })
        using (var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) })
        {
            var resp = await http.GetAsync(new Uri($"https://{target}/"));
            Assert.True((int)resp.StatusCode < 500);
        }

        await conn.Client.StopEngineAsync(new StopEngineRequest { EngineId = eng.EngineId });
        var bytes = new MemoryStream();
        using (var stream = conn.Client.StopCapture(new StopCaptureRequest { CaptureId = capId }))
        {
            while (await stream.ResponseStream.MoveNext(CancellationToken.None))
                stream.ResponseStream.Current.Data.WriteTo(bytes);
        }
        var packets = PcapReader.Read(bytes.ToArray());
        Assert.NotEmpty(packets);
        var flow = Assert.Single(FlowAnalyzer.Analyze(packets), f => f.ClientHello is not null);
        Assert.Equal(target, flow.ClientHello!.Sni);
        var firstData = packets.Select(p => p.Parse()!).First(p => p.IsTcp && p.DestinationPort == 443 && p.Payload.Length > 0);
        Assert.Equal(2, firstData.Payload.Length);
        Assert.Equal(PacketDirection.Outbound, packets.First(p => p.Parse()!.DestinationPort == 443).Direction);
    }
}
