using System.Net;
using ZapretAutoTuner.Agent.Capture;
using ZapretAutoTuner.Agent.Os;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Agent.Tests;

public class UnitTests
{
    [Fact]
    public void Options_parse_and_require_endpoint_token_and_ui()
    {
        var o = AgentOptions.Parse(["--socket=/run/x.sock", "--token-file=/t", "--ui-pid=42", "--data-dir=/d", "--heartbeat-timeout=1500"]);
        Assert.Equal("/run/x.sock", o.Socket);
        Assert.Equal(42, o.UiPid);
        Assert.Equal(TimeSpan.FromMilliseconds(1500), o.HeartbeatTimeout);
        Assert.Throws<ArgumentException>(() => AgentOptions.Parse(["--token-file=/t", "--ui-pid=42", "--data-dir=/d"]));
        Assert.Throws<ArgumentException>(() => AgentOptions.Parse(["--socket=/s", "--pipe=p", "--token-file=/t", "--ui-pid=42", "--data-dir=/d"]));
        Assert.Throws<ArgumentException>(() => AgentOptions.Parse(["--socket=/s", "--token-file=/t", "--data-dir=/d"]));
        Assert.Throws<ArgumentException>(() => AgentOptions.Parse(["--bogus"]));
        Assert.True(AgentOptions.Parse(["--cleanup", "--data-dir=/d"]).CleanupOnly);
    }

    [Fact]
    public void Token_file_is_read_and_deleted()
    {
        var dir = TestEnv.NewTempDir();
        var f = Path.Combine(dir, "t");
        File.WriteAllText(f, new string('a', 64));
        var o = AgentOptions.Parse(["--socket=/s", "--token-file=" + f, "--ui-pid=1", "--data-dir=" + dir]);
        Assert.Equal(new string('a', 64), o.ReadToken());
        Assert.False(File.Exists(f));
        File.WriteAllText(f, "short");
        Assert.Throws<InvalidOperationException>(() => o.ReadToken());
    }

    [Theory]
    [InlineData("0100007F:0050", "127.0.0.1", 80)]
    [InlineData("0A71000A:01BB", "10.0.113.10", 443)]
    [InlineData("B80D0120000000000000000001000000:1F90", "2001:db8::1", 8080)]
    public void Proc_net_endpoints(string hex, string ip, int port)
    {
        var (a, p) = Connections.ParseHexEndpoint(hex);
        Assert.Equal(IPAddress.Parse(ip), a);
        Assert.Equal(port, p);
    }

    [Fact]
    public void Proc_net_tcp_line()
    {
        var c = Connections.ParseProcNetLine("   0: 0100007F:1F90 0A71000A:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0", "tcp")!.Value;
        Assert.Equal("123456", c.Inode);
        Assert.Equal("ESTABLISHED", c.Conn.State);
        Assert.Equal(8080, c.Conn.LocalPort);
        Assert.Equal("10.0.113.10", c.Conn.RemoteAddress);
    }

    [Fact]
    public void Own_listening_socket_is_listed()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsWindows())
            return;
        using var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        var list = Connections.List(Environment.ProcessId);
        Assert.Contains(list, c => c.Protocol == "tcp" && c.LocalPort == port && c.State == "LISTEN");
    }

    [Fact]
    public void Windows_row_parsing()
    {
        // MIB_TCPROW_OWNER_PID: state 5 (ESTABLISHED), 10.0.0.2:51515 → 203.0.113.10:443, pid 4242
        var row = new byte[24];
        BitConverter.GetBytes(5).CopyTo(row, 0);
        new byte[] { 10, 0, 0, 2 }.CopyTo(row, 4);
        row[8] = 0xC9;
        row[9] = 0x3B;
        new byte[] { 203, 0, 113, 10 }.CopyTo(row, 12);
        row[16] = 0x01;
        row[17] = 0xBB;
        BitConverter.GetBytes(4242).CopyTo(row, 20);
        var c = Connections.ParseWindowsRow(row, tcp: true, v6: false, out int pid);
        Assert.Equal(4242, pid);
        Assert.Equal("ESTABLISHED", c.State);
        Assert.Equal(51515, c.LocalPort);
        Assert.Equal("203.0.113.10", c.RemoteAddress);
        Assert.Equal(443, c.RemotePort);
    }

    [Fact]
    public void Capture_filter_matches_address_and_port()
    {
        var f = new CaptureFilter();
        f.Addresses.Add(IPAddress.Parse("203.0.113.10"));
        f.Ports.Add(443);
        var pk = PcapReader.Read(File.ReadAllBytes(Path.Combine(TestEnv.Root, "tests", "pcaps", "tls13_single.pcap")));
        Assert.All(pk, p => Assert.True(f.Matches(p.Data.Span)));
        var other = new CaptureFilter();
        other.Ports.Add(80);
        Assert.All(pk, p => Assert.False(other.Matches(p.Data.Span)));
        Assert.Equal("(ip.SrcAddr==203.0.113.10 or ip.DstAddr==203.0.113.10) and (tcp.SrcPort==443 or tcp.DstPort==443 or udp.SrcPort==443 or udp.DstPort==443)", f.ToWinDivert());
    }

    [Fact]
    public void Ring_evicts_oldest_beyond_limit()
    {
        var ring = new PacketRing(1000);
        for (int i = 0; i < 20; i++)
            ring.Add(new CapturedPacket(DateTime.UtcNow, new byte[100], 100));
        var snap = ring.Snapshot();
        Assert.True(snap.Count * 132 <= 1000);
        Assert.Equal(20, ring.Packets);
        Assert.Equal(20 - snap.Count, ring.Dropped);
    }

    [Fact]
    public void Sysctl_apply_remembers_and_restores_originals()
    {
        var dir = TestEnv.NewTempDir();
        var proc = Path.Combine(dir, "sys");
        Directory.CreateDirectory(Path.Combine(proc, "net", "netfilter"));
        File.WriteAllText(Path.Combine(proc, "net/netfilter/nf_conntrack_tcp_be_liberal"), "0\n");
        var state = new AgentStateStore(dir);
        var s = new Sysctl(state, proc);
        var problems = s.Apply(new Dictionary<string, string> { ["net/netfilter/nf_conntrack_tcp_be_liberal"] = "1", ["net/netfilter/missing"] = "1" });
        Assert.Single(problems);
        Assert.Equal("1", s.Read("net/netfilter/nf_conntrack_tcp_be_liberal"));
        // a second apply must not overwrite the remembered original with our own value
        s.Apply(new Dictionary<string, string> { ["net/netfilter/nf_conntrack_tcp_be_liberal"] = "1" });
        Assert.Equal("0", state.Load().SysctlOriginals["net/netfilter/nf_conntrack_tcp_be_liberal"]);
        // a new Agent (after a crash) restores from the state file
        new Sysctl(new AgentStateStore(dir), proc).RestoreAll();
        Assert.Equal("0", s.Read("net/netfilter/nf_conntrack_tcp_be_liberal"));
        Assert.Empty(state.Load().SysctlOriginals);
    }

    [Fact]
    public async Task Watchdog_stops_when_heartbeats_stop()
    {
        var dir = TestEnv.NewTempDir();
        var o = AgentOptions.Parse(["--socket=/unused", "--token=" + new string('x', 64), "--ui-pid=" + Environment.ProcessId, "--data-dir=" + dir, "--heartbeat-timeout=400"]);
        await using var host = new AgentHost(o);
        using var wd = new Watchdog(host);
        await wd.StartAsync(CancellationToken.None);
        host.Heartbeat();
        Assert.False(await TestEnv.WaitUntil(() => host.Stopping.IsCancellationRequested, TimeSpan.FromMilliseconds(200)));
        Assert.True(await TestEnv.WaitUntil(() => host.Stopping.IsCancellationRequested, TimeSpan.FromSeconds(2)));
        Assert.Equal("no heartbeat", host.StopReason);
        await wd.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Watchdog_waits_for_the_first_heartbeat_within_the_startup_grace()
    {
        var dir = TestEnv.NewTempDir();
        var o = AgentOptions.Parse(["--socket=/unused", "--token=" + new string('x', 64), "--ui-pid=" + Environment.ProcessId, "--data-dir=" + dir, "--heartbeat-timeout=200"]);
        o.StartupGrace = TimeSpan.FromMilliseconds(1500);
        await using var host = new AgentHost(o);
        using var wd = new Watchdog(host);
        await wd.StartAsync(CancellationToken.None);
        Assert.False(await TestEnv.WaitUntil(() => host.Stopping.IsCancellationRequested, TimeSpan.FromMilliseconds(800)));
        Assert.True(await TestEnv.WaitUntil(() => host.Stopping.IsCancellationRequested, TimeSpan.FromSeconds(3)));
        Assert.Equal("no heartbeat", host.StopReason);
        await wd.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Supervisor_stops_engine_when_stdin_closes()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var dir = TestEnv.NewTempDir();
        var engine = TestEnv.WriteFakeEngine(dir);
        using var inst = Engine.EngineInstance.Start("e1", "t", engine, ["--filter-tcp=443"], null);
        Assert.True(await TestEnv.WaitUntil(() => File.Exists(Path.Combine(dir, "engine.pid")), TimeSpan.FromSeconds(5)));
        int pid = int.Parse(File.ReadAllText(Path.Combine(dir, "engine.pid")).Trim(), System.Globalization.CultureInfo.InvariantCulture);
        Assert.True(TestEnv.ProcessAlive(pid));
        int code = await inst.StopAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(0, code);
        Assert.False(TestEnv.ProcessAlive(pid));
        var lines = inst.Snapshot();
        Assert.Contains("arg --filter-tcp=443", lines);
        Assert.Contains("terminated", lines);
    }
}
