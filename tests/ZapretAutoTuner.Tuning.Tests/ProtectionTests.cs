using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Tuning.Tests;

public sealed class ProtectionTests
{
    private static Solution Sample()
    {
        var s = new Solution();
        s.Hostlists["video"] = ["youtube.com", "googlevideo.com"];
        s.Profiles.Add(new Profile { Name = "video", TcpPorts = "80,443", L7 = ["tls"], Hostlists = [new ListRef("video")], Strategy = Strategy.Parse("--lua-desync=multisplit:pos=1") });
        s.Profiles.Add(new Profile { Name = "solo", TcpPorts = "443", HostlistDomains = ["discord.com"], Strategy = Strategy.Parse("--lua-desync=fake:blob=fake_default_tls") });
        s.Profiles.Add(new Profile { Name = "ext", TcpPorts = "443", Hostlists = [new ListRef("other", "/opt/lists/other.txt")], Strategy = Strategy.Parse("--lua-desync=multidisorder:pos=2") });
        return s;
    }

    [Fact]
    public void FindsTheServingProfileIncludingSubdomains()
    {
        var s = Sample();
        Assert.Equal("--lua-desync=multisplit:pos=1", Protection.CurrentOf(s, "rr1.googlevideo.com")!.Strategy.ToString());
        Assert.Equal("--lua-desync=fake:blob=fake_default_tls", Protection.CurrentOf(s, "discord.com")!.Strategy.ToString());
        Assert.Null(Protection.CurrentOf(s, "example.org"));
        Assert.Equal(["youtube.com", "googlevideo.com", "discord.com"], Protection.Domains(s));
    }

    [Fact]
    public void ReplacingPutsTheDomainFirstWithItsOwnProfile()
    {
        var s = Sample();
        var fix = new StrategyCandidate(Strategy.Parse("--lua-desync=fakedsplit:pos=1"), "f", 0, [], L4Kind.Tcp);
        var next = Protection.ReplaceDomain(s, "youtube.com", fix);
        Assert.Equal("fix-youtube-com", next.Profiles[0].Name);
        Assert.Equal(["youtube.com"], next.Profiles[0].HostlistDomains);
        Assert.Equal("80,443", next.Profiles[0].TcpPorts);
        Assert.Equal(["tls"], next.Profiles[0].L7);
        Assert.Equal(["googlevideo.com"], next.Hostlists["video"]);
        Assert.Equal(fix.Strategy.ToString(), Protection.CurrentOf(next, "youtube.com")!.Strategy.ToString());
        // the original is untouched: a failed swap keeps it running
        Assert.Equal(["youtube.com", "googlevideo.com"], s.Hostlists["video"]);
        Assert.Equal(3, s.Profiles.Count);
    }

    [Fact]
    public void RemovingTheLastDomainDropsTheProfileButNotExternalLists()
    {
        var next = Protection.ReplaceDomain(Sample(), "discord.com", null);
        Assert.DoesNotContain(next.Profiles, p => p.Name == "solo");
        Assert.Contains(next.Profiles, p => p.Name == "ext");
        Assert.Null(Protection.CurrentOf(next, "discord.com"));
    }

    [Fact]
    public void LaunchUsesItsOwnQueueAndInlineHostlists()
    {
        var (argv, queue) = Protection.Launch(Sample(), "/opt/zapret2/lua");
        Assert.Contains(argv, a => a.StartsWith("--hostlist-domains=", StringComparison.Ordinal) && a.Contains("youtube.com", StringComparison.Ordinal));
        if (OperatingSystem.IsWindows())
            Assert.Null(queue);
        else
        {
            Assert.Equal(Protection.QueueNum, queue!.QueueNum);
            Assert.Empty(queue.Targets);
        }
    }
}
