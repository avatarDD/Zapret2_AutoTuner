using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Core.Providers;
using ZapretAutoTuner.Core.Validation;
using static ZapretAutoTuner.Tuning.Tests.ProgramFixtures;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>The program check (PLAN 6.3) and address results for the unifier (PLAN 6.3–6.4).</summary>
public sealed class ProgramCheckTests
{
    private const string UdpFake = "--payload=stun --lua-desync=fake:blob=0x00000000000000000000000000000000:repeats=6";
    private const string TlsFake = "--payload=tls_client_hello --lua-desync=fake:blob=tls_white:tcp_md5";
    private const string MtSplit = "--payload=mtproto_initial --lua-desync=multisplit:pos=1";

    private static readonly EndpointStrategy Stun = new(Endpoint("198.51.100.7", 3478, L4Kind.Udp, AppProtocol.Stun, "stun.example.com"), Candidate(UdpFake, L4Kind.Udp));
    private static readonly EndpointStrategy Discord = new(Endpoint("162.159.135.232", 443, L4Kind.Tcp, AppProtocol.Tls, "discord.com", FlowHealth.Reset), Candidate(TlsFake, L4Kind.Tcp));
    private static readonly EndpointStrategy Voice = new(Endpoint("66.22.196.10", 50005, L4Kind.Udp, AppProtocol.Discord), Candidate(UdpFake, L4Kind.Udp));
    private static readonly EndpointStrategy Telegram = new(Endpoint("149.154.167.51", 443, L4Kind.Tcp, AppProtocol.Mtproto), Candidate(MtSplit, L4Kind.Tcp));

    private static ProgramRecording Rerun(params ProgramEndpoint[] endpoints) => new(endpoints, [1], endpoints.Length, 10, 0);

    private static ProgramEndpoint Seen(string address, int port, L4Kind l4, FlowHealth health, string? host = null, AppProtocol app = AppProtocol.Unknown) =>
        Endpoint(address, port, l4, app, host, health);

    [Fact]
    public void Rerun_endpoints_match_by_address_else_by_name()
    {
        var r = ProgramCheck.Compare([Stun, Discord, Voice], Rerun(
            Seen("198.51.100.7", 3478, L4Kind.Udp, FlowHealth.Ok),
            // the CDN answered from another address: matched by name, same port and protocol
            Seen("162.159.136.1", 443, L4Kind.Tcp, FlowHealth.Ok, "Discord.com", AppProtocol.Tls)));

        Assert.Equal(3, r.Endpoints.Count);
        Assert.True(r.Endpoints[0].Fixed);
        Assert.Equal(IPAddress.Parse("162.159.136.1"), r.Endpoints[1].After!.Remote.Address);
        Assert.True(r.Endpoints[1].Fixed);
        Assert.Null(r.Endpoints[2].After); // the program did not reach it this time
        Assert.False(r.Endpoints[2].Fixed);
        Assert.Empty(r.StillBroken);
        Assert.True(r.Passed);
    }

    [Fact]
    public void Name_match_needs_the_same_port_and_protocol_and_endpoints_without_a_name_match_only_by_address()
    {
        var r = ProgramCheck.Compare([Discord, Voice], Rerun(
            Seen("162.159.136.1", 8443, L4Kind.Tcp, FlowHealth.Ok, "discord.com"),
            Seen("162.159.136.2", 443, L4Kind.Udp, FlowHealth.Ok, "discord.com"),
            Seen("66.22.196.11", 50005, L4Kind.Udp, FlowHealth.Ok)));
        Assert.All(r.Endpoints, e => Assert.Null(e.After));
        Assert.False(r.Passed); // nothing reached
    }

    [Fact]
    public void Passed_needs_every_reached_endpoint_working_and_nothing_else_broken()
    {
        var broken = Seen("203.0.113.77", 9000, L4Kind.Udp, FlowHealth.NoReply);
        var stillOther = ProgramCheck.Compare([Stun], Rerun(Seen("198.51.100.7", 3478, L4Kind.Udp, FlowHealth.Ok), broken, Seen("203.0.113.78", 9000, L4Kind.Udp, FlowHealth.Unknown)));
        Assert.Equal([broken], stillOther.StillBroken);
        Assert.False(stillOther.Passed);

        var notFixed = ProgramCheck.Compare([Stun, Telegram], Rerun(Seen("198.51.100.7", 3478, L4Kind.Udp, FlowHealth.Ok), Seen("149.154.167.51", 443, L4Kind.Tcp, FlowHealth.Reset)));
        Assert.Empty(notFixed.StillBroken); // the matched endpoint is reported as not fixed, not twice
        Assert.False(notFixed.Endpoints[1].Fixed);
        Assert.False(notFixed.Passed);

        var withError = Compare(Stun) with { Error = "engine refused" };
        Assert.False(withError.Passed);
    }

    private static ProgramCheckResult Compare(EndpointStrategy f) => ProgramCheck.Compare([f], Rerun(f.Endpoint with { Health = FlowHealth.Ok }));

    private static AgentTrialOptions Options(EnginePlatform platform) => new()
    {
        LuaDir = "/opt/zapret2/lua",
        Platform = platform,
        QueueNum = 320,
        Warmup = TimeSpan.Zero,
        Blobs = new Dictionary<string, string> { ["tls_white"] = "0x1603", ["unused"] = "0x00" },
    };

    [Fact]
    public void Linux_launch_by_name_profiles_leave_the_queue_open()
    {
        var (argv, queue) = ProgramCheck.BuildLaunch([Discord, Stun], Options(EnginePlatform.Linux));

        Assert.DoesNotContain(argv, a => a.StartsWith("--qnum=", StringComparison.Ordinal) || a.StartsWith("--fwmark=", StringComparison.Ordinal));
        Assert.Contains("--name=ep0", argv);
        Assert.Contains("--name=ep1", argv);
        Assert.Contains("--hostlist-domains=discord.com", argv);
        // a STUN server with a DNS name is still filtered by address: there is no SNI to match
        Assert.Contains("--ipset-ip=198.51.100.7", argv);
        Assert.Contains("--filter-tcp=443", argv);
        Assert.Contains("--filter-udp=3478", argv);
        Assert.Contains("--blob=tls_white:0x1603", argv);
        Assert.DoesNotContain(argv, a => a.StartsWith("--blob=unused", StringComparison.Ordinal));
        Assert.NotNull(queue);
        Assert.Equal(320, queue.QueueNum);
        Assert.Equal("443", queue.TcpPorts);
        Assert.Equal("3478", queue.UdpPorts);
        Assert.Empty(queue.Targets); // a CDN may answer from anywhere
    }

    [Fact]
    public void Linux_launch_by_address_limits_the_queue_to_the_endpoints()
    {
        var (argv, queue) = ProgramCheck.BuildLaunch([Voice, Telegram, Stun], Options(EnginePlatform.Linux));
        Assert.DoesNotContain(argv, a => a.StartsWith("--hostlist-domains", StringComparison.Ordinal));
        Assert.Contains("--ipset-ip=66.22.196.10", argv);
        Assert.Contains("--ipset-ip=149.154.167.51", argv);
        Assert.NotNull(queue);
        Assert.Equal(["66.22.196.10", "149.154.167.51", "198.51.100.7"], queue.Targets);
        Assert.Equal("3478,50005", queue.UdpPorts);
        Assert.Equal("443", queue.TcpPorts);
    }

    [Fact]
    public void Windows_launch_filters_by_address_unless_a_name_is_used()
    {
        var (argv, queue) = ProgramCheck.BuildLaunch([Voice, Telegram], Options(EnginePlatform.Windows));
        Assert.Null(queue);
        var filter = Assert.Single(argv, a => a.StartsWith("--wf-raw-filter=", StringComparison.Ordinal));
        Assert.Contains("66.22.196.10", filter, StringComparison.Ordinal);
        Assert.Contains("149.154.167.51", filter, StringComparison.Ordinal);

        var (named, _) = ProgramCheck.BuildLaunch([Discord, Voice], Options(EnginePlatform.Windows));
        Assert.DoesNotContain(named, a => a.StartsWith("--wf-raw-filter=", StringComparison.Ordinal));
        Assert.Throws<ArgumentException>(() => ProgramCheck.BuildLaunch([], Options(EnginePlatform.Linux)));
    }

    [Fact]
    public async Task Check_runs_the_program_under_one_engine_and_stops_it()
    {
        var engine = new RecordingEngine();
        var packets = Capture(
            Udp("192.168.1.2", 50000, "198.51.100.7", 3478, ProgramFixtures.Stun()),
            Udp("198.51.100.7", 3478, "192.168.1.2", 50000, new byte[32]),
            Udp("198.51.100.7", 3478, "192.168.1.2", 50000, new byte[32]));
        var monitor = new FakeMonitor(packets, new Dictionary<int, ObservedSocket[]> { [42] = [new ObservedSocket(L4Kind.Udp, new IPEndPoint(IPAddress.Any, 50000), null)] });
        int launched = 0;

        var r = await ProgramCheck.RunAsync(engine, monitor, [Stun], () =>
        {
            launched++;
            return new RecordOptions { Duration = TimeSpan.FromMilliseconds(100), PollInterval = TimeSpan.FromMilliseconds(30), Pids = () => new HashSet<int> { 42 } };
        }, Options(EnginePlatform.Linux), "discord");

        Assert.True(r.Passed, string.Join("; ", r.Recording.Endpoints));
        Assert.Equal(1, launched);
        var (_, _, tag) = Assert.Single(engine.Started);
        Assert.Equal("program:discord", tag);
        Assert.Equal(["e1"], engine.Stopped);

        var refused = await ProgramCheck.RunAsync(new RecordingEngine { Refuse = "validator: no" }, monitor, [Stun], () => throw new InvalidOperationException(), Options(EnginePlatform.Linux), "x");
        Assert.False(refused.Passed);
        Assert.Contains("no", refused.Error, StringComparison.Ordinal);
    }

    // ---- AddressResults ----

    [Fact]
    public void Program_results_group_address_endpoints_by_strategy()
    {
        var wg = new EndpointStrategy(Endpoint("203.0.113.9", 51820, L4Kind.Udp, AppProtocol.WireGuard), Candidate(UdpFake, L4Kind.Udp));
        var other = new EndpointStrategy(Endpoint("203.0.113.10", 7000, L4Kind.Udp, AppProtocol.Unknown), Candidate(UdpFake.Replace("repeats=6", "repeats=2", StringComparison.Ordinal), L4Kind.Udp));
        var tlsNoName = new EndpointStrategy(Endpoint("203.0.113.11", 443, L4Kind.Tcp, AppProtocol.Tls), Candidate(TlsFake, L4Kind.Tcp));

        var results = AddressResults.Program("/usr/bin/Discord Canary", [Stun, Voice, wg, Discord, other, tlsNoName]);

        Assert.Equal(["discord-canary", "discord-canary-2", "discord-canary-3"], results.Select(r => r.Name));
        var first = results[0];
        Assert.Equal(["198.51.100.7", "66.22.196.10", "203.0.113.9"], first.Cidrs);
        Assert.Equal(L4Kind.Udp, first.L4);
        Assert.Equal("3478,50005,51820", first.Ports);
        Assert.Equal(["stun", "discord", "wireguard"], first.L7);
        Assert.Equal(UdpFake, first.Strategy.ToString());
        // unknown traffic has no L7 name: no filter for the group
        Assert.Empty(results[1].L7);
        Assert.Equal(["tls"], results[2].L7);
        Assert.Equal(L4Kind.Tcp, results[2].L4);
        // the named TLS endpoint goes to the hostlist pipeline
        Assert.DoesNotContain(results, r => r.Cidrs.Contains("162.159.135.232"));
    }

    [Theory]
    [InlineData("/usr/bin/telegram-desktop", "telegram-desktop")]
    [InlineData("/opt/Some App/Bin/App.v2.AppImage", "app-v2")]
    [InlineData("/opt/apps/", "apps")]
    [InlineData("Телеграм", "program")]
    [InlineData("", "program")]
    [InlineData("/x/AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEE", "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd")]
    public void Slug_is_a_safe_file_name(string id, string expected) => Assert.Equal(expected, AddressResults.Slug(id));

    [Fact]
    public void Provider_result_covers_its_ranges_over_tls()
    {
        var p = ProviderCatalog.Default.Find("cloudflare")!;
        var ranges = CidrSet.Aggregate(["104.16.0.0/13", "2606:4700::/32"]);
        var r = AddressResults.Provider(p, ranges, Core.Model.Strategy.Parse(TlsFake));
        Assert.Equal("cloudflare", r.Name);
        Assert.Equal(["104.16.0.0/13", "2606:4700::/32"], r.Cidrs);
        Assert.Equal(L4Kind.Tcp, r.L4);
        Assert.Equal("443", r.Ports);
        Assert.Equal(["tls"], r.L7);
        Assert.Equal("443,8443", AddressResults.Provider(p, ranges, Core.Model.Strategy.Parse(TlsFake), "443,8443").Ports);
    }
}
