using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.Tests;

/// <summary>What the search found survives closing the app: the export and the protection work on it after a restart.</summary>
public sealed class SolutionStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "zt-sol-" + Guid.NewGuid().ToString("N"));

    public SolutionStoreTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, true);

    private static Solution Sample()
    {
        var s = new Solution();
        s.Meta.Targets = ["discord.com", "youtube.com"];
        s.Hostlists["tcp1"] = ["discord.com", "youtube.com"];
        s.Blobs["tls_white"] = [0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5];
        s.Profiles.Add(new Profile
        {
            Name = "tcp1", TcpPorts = "443", L7 = ["tls"], Hostlists = [new ListRef("tcp1")],
            Strategy = Strategy.Parse("--payload=tls_client_hello --lua-desync=fake:blob=tls_white:tcp_md5 --lua-desync=multisplit:pos=1:seqovl=681:seqovl_pattern=tls_white"),
        });
        return s;
    }

    [Fact]
    public void A_solution_set_in_the_session_comes_back_in_a_new_one()
    {
        var first = new SessionState();
        using (var store = new SolutionStore(_dir, first))
        {
            Assert.False(store.Restore());
            first.Last = new PipelineResult([], null, Sample());
            Assert.True(File.Exists(store.Path));
        }

        var second = new SessionState();
        using var again = new SolutionStore(_dir, second);
        Assert.True(again.Restore());
        var s = second.Last!.Solution!;
        var p = Assert.Single(s.Profiles);
        Assert.Equal(Sample().Profiles[0].Strategy.ToString(), p.Strategy.ToString());
        Assert.Equal(["discord.com", "youtube.com"], s.Hostlists.Values.Single());
        Assert.Equal(Sample().Blobs["tls_white"], s.Blobs["tls_white"]);
        // a session that already has a solution keeps it
        Assert.False(again.Restore());
    }

    [Fact]
    public void A_broken_file_is_ignored()
    {
        File.WriteAllText(Path.Combine(_dir, SolutionStore.FileName), "{ not json");
        var state = new SessionState();
        using var store = new SolutionStore(_dir, state);
        Assert.False(store.Restore());
        Assert.Null(state.Last);
    }
}
