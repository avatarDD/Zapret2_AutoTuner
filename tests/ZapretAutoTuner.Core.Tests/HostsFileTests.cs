using System.Net;
using ZapretAutoTuner.Core.Hosts;

namespace ZapretAutoTuner.Core.Tests;

public sealed class HostsFileTests
{
    private static readonly HostsPin Yt = new("www.youtube.com", IPAddress.Parse("142.250.1.10"));
    private static readonly HostsPin Yt6 = new("www.youtube.com", IPAddress.Parse("2a00:1450::10"));
    private static readonly HostsPin Gv = new("rr1.googlevideo.com", IPAddress.Parse("173.194.1.1"));

    private const string Original = "127.0.0.1 localhost\n::1 localhost\n# my comment\n10.0.0.5 nas.lan\n";

    [Fact]
    public void Apply_appends_a_block_and_keeps_the_rest()
    {
        var r = HostsFile.Apply(Original, [Yt, Gv]);
        Assert.StartsWith(Original, r, StringComparison.Ordinal);
        Assert.Equal(
            Original + HostsFile.Begin + "\n# Added by Zapret2 AutoTuner: addresses that are not blocked. Remove in the app or delete this block.\n" +
            "173.194.1.1 rr1.googlevideo.com\n142.250.1.10 www.youtube.com\n" + HostsFile.End + "\n", r);
        Assert.Equal([Gv, Yt], HostsFile.Read(r));
    }

    [Fact]
    public void Reapply_replaces_in_place_and_remove_restores_the_original()
    {
        var withBlock = HostsFile.Apply(Original, [Yt]);
        var extra = withBlock + "192.168.1.1 router.lan\n";
        var again = HostsFile.Apply(extra, [Yt, Yt6]);
        Assert.EndsWith("192.168.1.1 router.lan\n", again, StringComparison.Ordinal); // the block stayed where it was
        Assert.Equal(2, HostsFile.Read(again).Count);
        Assert.Equal(Original + "192.168.1.1 router.lan\n", HostsFile.Remove(again));
        Assert.Equal(Original, HostsFile.Remove(HostsFile.Apply(Original, [Yt])));
    }

    [Fact]
    public void Windows_line_endings_are_kept()
    {
        var win = Original.Replace("\n", "\r\n", StringComparison.Ordinal);
        var r = HostsFile.Apply(win, [Yt]);
        Assert.DoesNotContain("\n", r.Replace("\r\n", "", StringComparison.Ordinal), StringComparison.Ordinal);
        Assert.Equal(win, HostsFile.Remove(r));
    }

    [Fact]
    public void File_without_final_newline_and_empty_file()
    {
        Assert.Equal("1.1.1.1 a.b", HostsFile.Remove(HostsFile.Apply("1.1.1.1 a.b", [Yt])).TrimEnd('\n'));
        var fromEmpty = HostsFile.Apply("", [Yt]);
        Assert.Single(HostsFile.Read(fromEmpty));
        Assert.Equal("", HostsFile.Remove(fromEmpty));
    }

    [Fact]
    public void Cut_block_and_duplicate_blocks_are_cleaned()
    {
        var broken = Original + HostsFile.Begin + "\n1.2.3.4 old.example\n";
        Assert.Equal(Original, HostsFile.Remove(broken));
        // the user's own lines below a block that lost its END stay
        var userBelow = Original + HostsFile.Begin + "\n1.2.3.4 old.example\n\n192.168.1.1 router.lan\n";
        Assert.Equal(Original + "\n192.168.1.1 router.lan\n", HostsFile.Remove(userBelow));
        Assert.Equal(["old.example"], HostsFile.Read(userBelow).Select(p => p.Host));
        var commentBelow = Original + HostsFile.Begin + "\n1.2.3.4 old.example\n# my router\n192.168.1.1 router.lan\n";
        Assert.Equal(Original + "# my router\n192.168.1.1 router.lan\n", HostsFile.Remove(commentBelow));
        var two = HostsFile.Apply(Original, [Yt]) + HostsFile.Apply("", [Gv]);
        var fixedUp = HostsFile.Apply(two, [Gv]);
        Assert.Equal([Gv], HostsFile.Read(fixedUp));
        Assert.Single(fixedUp.Split('\n'), l => l.TrimEnd('\r') == HostsFile.Begin); // CRLF on Windows
    }

    [Theory]
    [InlineData("evil.com\n1.2.3.4 bank.com", "1.2.3.4")]
    [InlineData("not a host", "1.2.3.4")]
    [InlineData("localhost", "1.2.3.4")]
    [InlineData("good.example", "127.0.0.1")]
    [InlineData("good.example", "0.0.0.0")]
    public void Bad_pins_are_rejected(string host, string ip)
    {
        Assert.Throws<ArgumentException>(() => HostsFile.Apply(Original, [new HostsPin(host, IPAddress.Parse(ip))]));
    }
}
