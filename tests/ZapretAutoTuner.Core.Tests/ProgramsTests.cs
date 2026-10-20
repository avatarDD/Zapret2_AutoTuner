using System.Buffers.Binary;
using System.Net;
using System.Text;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Programs;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>Program targets (PLAN 6.1–6.2): desktop entries, shortcuts, the merged list and recorded endpoints.</summary>
public sealed class ProgramsTests
{
    // ---- DesktopEntry ----

    [Theory]
    [InlineData("discord %U", new[] { "discord" })]
    [InlineData("/usr/bin/app --new-window %F", new[] { "/usr/bin/app", "--new-window" })]
    [InlineData("\"/opt/My App/app\" --flag %u", new[] { "/opt/My App/app", "--flag" })]
    [InlineData("env FOO=1 app %f %i %c %k", new[] { "env", "FOO=1", "app" })]
    [InlineData("app 100%%", new[] { "app", "100%" })]
    [InlineData("app --file=%f", new[] { "app", "--file=" })]
    [InlineData("sh -c \"echo \\\"hi\\\" $HOME\"", new[] { "sh", "-c", "echo \"hi\" $HOME" })]
    [InlineData("  app\t  x  ", new[] { "app", "x" })]
    [InlineData("", new string[0])]
    [InlineData("%U", new string[0])]
    public void Exec_is_split_with_field_codes_removed(string exec, string[] expected) =>
        Assert.Equal(expected, DesktopEntry.SplitExec(exec));

    private const string Telegram = """
        # comment
        [Desktop Entry]
        Type=Application
        Name=Telegram Desktop
        Name[ru]=Телеграм
        Exec="/opt/Telegram/Telegram" -- %u
        Icon=telegram

        [Desktop Action quit]
        Exec=/opt/Telegram/Telegram -quit
        Name=Quit
        """;

    [Fact]
    public void Desktop_entry_gives_name_executable_arguments_and_icon()
    {
        var p = DesktopEntry.Parse(Telegram, "/usr/share/applications/telegram.desktop", "en");
        Assert.NotNull(p);
        Assert.Equal("Telegram Desktop", p.Name);
        Assert.Equal("/opt/Telegram/Telegram", p.Executable);
        Assert.Equal(["--"], p.Arguments);
        Assert.Equal("telegram", p.Icon);
        Assert.Equal(ProgramSource.Desktop, p.Source);
        Assert.Equal("/usr/share/applications/telegram.desktop", p.Id);
        Assert.True(p.CanLaunch);

        Assert.Equal("Телеграм", DesktopEntry.Parse(Telegram, "t.desktop", "ru")!.Name);
    }

    [Theory]
    [InlineData("Type=Link\nName=x\nExec=x")]
    [InlineData("Name=x\nExec=x\nNoDisplay=true")]
    [InlineData("Name=x\nExec=x\nHidden=true")]
    [InlineData("Name=x\nIcon=y")]
    [InlineData("Name=x\nExec=%U")]
    public void Hidden_links_and_entries_without_exec_are_skipped(string body) =>
        Assert.Null(DesktopEntry.Parse("[Desktop Entry]\n" + body, "x.desktop", "en"));

    [Fact]
    public void Keys_outside_the_desktop_entry_group_are_ignored_and_name_falls_back_to_the_file()
    {
        var p = DesktopEntry.Parse("[Other]\nExec=wrong\n[Desktop Entry]\nExec=right\r\n", "/x/my-tool.desktop", "en");
        Assert.NotNull(p);
        Assert.Equal("right", p.Executable);
        Assert.Equal("my-tool", p.Name);
        Assert.Null(DesktopEntry.Parse("[Other]\nExec=wrong\n", "x.desktop", "en"));
    }

    // ---- ShellLink (MS-SHLLINK) ----

    private const uint HasIdList = 0x1, HasLinkInfo = 0x2, HasRelativePath = 0x8, HasWorkingDir = 0x10, HasArguments = 0x20, HasIcon = 0x40, IsUnicode = 0x80;

    private static void U16(Stream s, int v)
    {
        Span<byte> b = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(b, (ushort)v);
        s.Write(b);
    }

    private static void U32(Stream s, int v)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)v);
        s.Write(b);
    }

    private static void StringData(Stream s, string v, bool unicode)
    {
        U16(s, v.Length);
        s.Write(unicode ? Encoding.Unicode.GetBytes(v) : Encoding.Latin1.GetBytes(v));
    }

    /// <summary>LinkInfo with VolumeIDAndLocalBasePath: ANSI paths, or Unicode ones when the header is 0x24 bytes.</summary>
    private static byte[] LinkInfo(string basePath, string suffix, bool unicodeHeader)
    {
        int headerSize = unicodeHeader ? 0x24 : 0x1C;
        var volume = new byte[0x14];
        BinaryPrimitives.WriteUInt32LittleEndian(volume, 0x14);
        var enc = unicodeHeader ? Encoding.Unicode : Encoding.Latin1;
        int z = unicodeHeader ? 2 : 1;
        var baseA = Encoding.Latin1.GetBytes("WRONG\0");
        var sufA = Encoding.Latin1.GetBytes("\0");
        var baseB = enc.GetBytes(basePath).Concat(new byte[z]).ToArray();
        var sufB = enc.GetBytes(suffix).Concat(new byte[z]).ToArray();
        int volOfs = headerSize, baseOfs = volOfs + volume.Length, sufOfs = baseOfs + baseA.Length;
        int baseUOfs = sufOfs + sufA.Length, sufUOfs = baseUOfs + baseB.Length;
        var ms = new MemoryStream();
        int total = unicodeHeader ? sufUOfs + sufB.Length : baseOfs + baseB.Length + sufB.Length;
        U32(ms, total);
        U32(ms, headerSize);
        U32(ms, 1);
        U32(ms, volOfs);
        U32(ms, baseOfs);
        U32(ms, 0);
        if (unicodeHeader)
        {
            U32(ms, sufOfs);
            U32(ms, baseUOfs);
            U32(ms, sufUOfs);
            ms.Write(volume);
            ms.Write(baseA);
            ms.Write(sufA);
            ms.Write(baseB);
            ms.Write(sufB);
        }
        else
        {
            U32(ms, baseOfs + baseB.Length);
            ms.Write(volume);
            ms.Write(baseB);
            ms.Write(sufB);
        }
        return ms.ToArray();
    }

    private static byte[] Lnk(uint flags, byte[]? linkInfo, params string[] strings)
    {
        var ms = new MemoryStream();
        U32(ms, 0x4C);
        ms.Write(new Guid("00021401-0000-0000-c000-000000000046").ToByteArray());
        U32(ms, (int)flags);
        ms.Write(new byte[0x4C - 0x18]);
        if ((flags & HasIdList) != 0)
        {
            U16(ms, 6);
            ms.Write(new byte[] { 4, 0, 0xAA, 0xBB, 0, 0 });
        }
        if (linkInfo is not null)
            ms.Write(linkInfo);
        foreach (var s in strings)
            StringData(ms, s, (flags & IsUnicode) != 0);
        return ms.ToArray();
    }

    [Fact]
    public void Shortcut_with_ansi_link_info_and_unicode_strings()
    {
        var b = Lnk(HasIdList | HasLinkInfo | HasWorkingDir | HasArguments | HasIcon | IsUnicode,
            LinkInfo(@"C:\Program Files\App\", "app.exe", unicodeHeader: false),
            @"C:\Program Files\App", "--профиль main", @"C:\Program Files\App\app.ico");
        var info = ShellLink.Parse(b);
        Assert.NotNull(info);
        Assert.Equal(@"C:\Program Files\App\app.exe", info.Target);
        Assert.Equal(@"C:\Program Files\App", info.WorkingDirectory);
        Assert.Equal("--профиль main", info.Arguments);
        Assert.Equal(@"C:\Program Files\App\app.ico", info.IconLocation);
    }

    [Fact]
    public void Shortcut_prefers_the_unicode_base_path()
    {
        var b = Lnk(HasLinkInfo | HasArguments, LinkInfo(@"D:\Игры\", "game.exe", unicodeHeader: true), "-windowed");
        var info = ShellLink.Parse(b);
        Assert.NotNull(info);
        Assert.Equal(@"D:\Игры\game.exe", info.Target);
        Assert.Equal("-windowed", info.Arguments); // ANSI string data
        Assert.Null(info.WorkingDirectory);
    }

    [Fact]
    public void Shortcut_without_link_info_uses_the_relative_path_or_has_no_target()
    {
        var wd = Path.Combine(Path.GetTempPath(), "app", "bin");
        var rel = Path.Combine("..", "lib", "tool");
        var info = ShellLink.Parse(Lnk(HasRelativePath | HasWorkingDir | IsUnicode, null, rel, wd));
        Assert.NotNull(info);
        Assert.Equal(Path.GetFullPath(Path.Combine(wd, rel)), info.Target);

        var shellOnly = ShellLink.Parse(Lnk(HasIdList, null));
        Assert.NotNull(shellOnly);
        Assert.Null(shellOnly.Target);
    }

    [Fact]
    public void Broken_shortcuts_give_null()
    {
        Assert.Null(ShellLink.Parse(new byte[10]));
        var b = Lnk(HasArguments | IsUnicode, null, "abc");
        b[0] = 0x4D;
        Assert.Null(ShellLink.Parse(b));
        var full = Lnk(HasLinkInfo | HasArguments | IsUnicode, LinkInfo(@"C:\a\", "b.exe", false), "--long-argument");
        Assert.Null(ShellLink.Parse(full.AsSpan(0, full.Length - 6)));
    }

    // ---- ProgramInfo.Merge ----

    [Fact]
    public void Merge_keeps_one_entry_per_executable_the_most_descriptive_first()
    {
        var merged = ProgramInfo.Merge(
        [
            new ProgramInfo { Id = "u1", Name = "Zoom (uninstall)", Executable = "/opt/zoom/zoom", Source = ProgramSource.Uninstall },
            new ProgramInfo { Id = "d1", Name = "Zoom", Executable = "/opt/zoom/zoom", Arguments = ["%U"], Source = ProgramSource.Desktop },
            new ProgramInfo { Id = "p1", Name = "zoom", Executable = "/opt/zoom/zoom", Source = ProgramSource.Path },
            new ProgramInfo { Id = "x", Name = "Avast", Source = ProgramSource.Uninstall },
            new ProgramInfo { Id = "y", Name = "Avast", Source = ProgramSource.Uninstall },
            new ProgramInfo { Id = "b", Name = "Brave", Executable = "/usr/bin/brave", Source = ProgramSource.Path },
        ]);
        Assert.Equal(["Avast", "Brave", "Zoom"], merged.Select(p => p.Name));
        Assert.Equal("d1", merged[2].Id);
        Assert.False(merged[0].CanLaunch);
    }

    // ---- ProgramEndpoints ----

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("149.154.167.51", true)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.31.255.1", false)]
    [InlineData("172.32.0.1", true)]
    [InlineData("192.168.0.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("100.127.255.1", false)]
    [InlineData("100.128.0.1", true)]
    [InlineData("127.0.0.1", false)]
    [InlineData("0.0.0.0", false)]
    [InlineData("224.0.0.251", false)]
    [InlineData("255.255.255.255", false)]
    [InlineData("::ffff:10.0.0.1", false)]
    [InlineData("::ffff:1.1.1.1", true)]
    [InlineData("2a00:1450:4001::1", true)]
    [InlineData("::1", false)]
    [InlineData("::", false)]
    [InlineData("fe80::1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("ff02::fb", false)]
    public void Internet_addresses(string address, bool expected) =>
        Assert.Equal(expected, ProgramEndpoints.IsInternet(IPAddress.Parse(address)));

    [Fact]
    public void Dns_answers_map_addresses_to_the_asked_name()
    {
        var names = ProgramEndpoints.DnsNames(TestPackets.Capture(
            TestPackets.Udp("192.168.1.2", 40000, "192.168.1.1", 53, new byte[20]),
            TestPackets.Udp("192.168.1.1", 53, "192.168.1.2", 40000, TestPackets.DnsAResponse("Stun.Example.COM", "198.51.100.7")),
            TestPackets.Udp("192.168.1.1", 5353, "192.168.1.2", 40000, TestPackets.DnsAResponse("other.example", "198.51.100.8"))));
        var pair = Assert.Single(names);
        Assert.Equal(IPAddress.Parse("198.51.100.7"), pair.Key);
        Assert.Equal("stun.example.com", pair.Value);
    }

    [Fact]
    public void Recording_gives_the_program_endpoints_only()
    {
        const string me = "192.168.1.2", stunSrv = "198.51.100.7", tg = "149.154.167.51";
        var obf = new byte[64];
        new Random(3).NextBytes(obf);
        obf[0] = 0x11;
        var packets = TestPackets.Capture(
            TestPackets.Udp("192.168.1.1", 53, me, 40000, TestPackets.DnsAResponse("stun.example.com", stunSrv)),
            // the program's STUN, no answer (two sockets, one endpoint)
            TestPackets.Udp(me, 50000, stunSrv, 3478, TestPackets.Stun()),
            TestPackets.Udp(me, 50000, stunSrv, 3478, TestPackets.Stun()),
            TestPackets.Udp(me, 50002, stunSrv, 3478, TestPackets.Stun()),
            TestPackets.Udp(me, 50002, stunSrv, 3478, TestPackets.Stun()),
            TestPackets.Udp(me, 50002, stunSrv, 3478, TestPackets.Stun()),
            TestPackets.Udp(me, 50002, stunSrv, 3478, TestPackets.Stun()),
            // the program's Telegram connection, working
            TestPackets.Tcp(me, 40001, tg, 443, TcpFlags.Syn, 1, 0),
            TestPackets.Tcp(tg, 443, me, 40001, TcpFlags.Syn | TcpFlags.Ack, 9, 2),
            TestPackets.Tcp(me, 40001, tg, 443, TcpFlags.Ack | TcpFlags.Psh, 2, 10, obf),
            TestPackets.Tcp(tg, 443, me, 40001, TcpFlags.Ack | TcpFlags.Psh, 10, 66, new byte[5000]),
            // another program's flow, a LAN flow and DNS
            TestPackets.Udp(me, 60000, "203.0.113.5", 3478, TestPackets.Stun()),
            TestPackets.Udp(me, 50001, "192.168.1.50", 8009, new byte[30]),
            TestPackets.Udp(me, 50003, "1.1.1.1", 53, new byte[30]));
        var sockets = new[]
        {
            new ObservedSocket(L4Kind.Udp, new IPEndPoint(IPAddress.Any, 50000), null),
            new ObservedSocket(L4Kind.Udp, new IPEndPoint(IPAddress.Any, 50001), null),
            new ObservedSocket(L4Kind.Udp, new IPEndPoint(IPAddress.Any, 50002), null),
            new ObservedSocket(L4Kind.Udp, new IPEndPoint(IPAddress.Any, 50003), null),
            new ObservedSocket(L4Kind.Tcp, new IPEndPoint(IPAddress.Parse(me), 40001), new IPEndPoint(IPAddress.Parse(tg), 443)),
            // a TCP socket on the STUN client port: the protocol must match too
            new ObservedSocket(L4Kind.Tcp, new IPEndPoint(IPAddress.Any, 60000), null),
        };

        var flows = FlowAnalyzer.Analyze(packets);
        var eps = ProgramEndpoints.FromRecording(sockets, flows, packets);

        Assert.Equal(2, eps.Count);
        var telegram = eps[0]; // most bytes first
        Assert.Equal(L4Kind.Tcp, telegram.Protocol);
        Assert.Equal(new IPEndPoint(IPAddress.Parse(tg), 443), telegram.Remote);
        Assert.Equal(AppProtocol.Mtproto, telegram.App);
        Assert.Equal(FlowHealth.Ok, telegram.Health);
        Assert.Null(telegram.Host);
        Assert.Equal(TargetKind.Ip, telegram.ToTarget().Kind);

        var stun = eps[1];
        Assert.Equal(L4Kind.Udp, stun.Protocol);
        Assert.Equal(2, stun.Flows);
        Assert.Equal(6, stun.PacketsOut);
        Assert.Equal(0, stun.PacketsIn);
        Assert.Equal("stun.example.com", stun.Host);
        Assert.Equal(AppProtocol.Stun, stun.App);
        Assert.Equal(FlowHealth.NoReply, stun.Health);
        Assert.NotEmpty(stun.InitialPayloads);
        // a name without TLS/QUIC/HTTP is still searched by address
        var t = stun.ToTarget();
        Assert.Equal(TargetKind.Ip, t.Kind);
        Assert.Equal(stunSrv, t.Value);
        Assert.Equal(3478, t.Port);
        Assert.Equal(L4Kind.Udp, t.Protocol);
    }

    [Fact]
    public void Tls_endpoint_with_a_name_becomes_a_domain_target()
    {
        var e = new ProgramEndpoint { Protocol = L4Kind.Tcp, Remote = new IPEndPoint(IPAddress.Parse("162.159.135.232"), 443), Host = "discord.com", App = AppProtocol.Tls };
        var t = e.ToTarget();
        Assert.Equal(TargetKind.Domain, t.Kind);
        Assert.Equal("discord.com", t.Value);
        Assert.Equal(TargetKind.Ip, (e with { Host = null }).ToTarget().Kind);
    }

    [Fact]
    public void One_working_flow_makes_the_endpoint_work()
    {
        var server = new IPEndPoint(IPAddress.Parse("198.51.100.9"), 50005);
        Flow Udp(int port, int o, int i) => new() { Protocol = "udp", Client = new IPEndPoint(IPAddress.Parse("192.168.1.2"), port), Server = server, PacketsOut = o, PacketsIn = i };
        var flows = new List<Flow> { Udp(1000, 10, 0), Udp(1001, 4, 4) };
        var sockets = new[] { new ObservedSocket(L4Kind.Udp, new IPEndPoint(IPAddress.Any, 1000), null), new ObservedSocket(L4Kind.Udp, new IPEndPoint(IPAddress.Any, 1001), null) };
        var e = Assert.Single(ProgramEndpoints.FromRecording(sockets, flows));
        Assert.Equal(FlowHealth.Ok, e.Health);
        Assert.Equal(2, e.Flows);
        Assert.Equal(FlowHealth.NoReply, Assert.Single(ProgramEndpoints.FromRecording(sockets.Take(1), flows)).Health);
    }
}
