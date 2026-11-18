using ZapretAutoTuner.Agent.Firewall;
using ZapretAutoTuner.Agent.Os;
using ZapretAutoTuner.Core.Engine;

namespace ZapretAutoTuner.Agent.Tests;

/// <summary>nft takes the first queue rule that matches: the order of the owners' rules decides which engine gets a packet.</summary>
public class FirewallOrderTests
{
    private sealed class Recorder : IFirewallBackend
    {
        public List<int> Last { get; private set; } = [];

        public string Name => "test";

        public string? Apply(IReadOnlyList<NftQueueRule> rules, uint fwmark)
        {
            Last = [.. rules.Select(r => r.QueueNum)];
            return null;
        }

        public void Remove() => Last = [];
    }

    [Fact]
    public void Engines_keep_the_order_they_came_in_and_a_catch_all_by_name_goes_last()
    {
        var dir = Directory.CreateTempSubdirectory("fw-order").FullName;
        try
        {
            var state = new AgentStateStore(dir);
            var rec = new Recorder();
            var fw = new FirewallManager(state, new Sysctl(state, Path.Combine(dir, "sys")), 0x40000000, [rec]);
            fw.Set("e9", new NftQueueRule { QueueNum = 310 });
            fw.Set("e10", new NftQueueRule { QueueNum = 377 });
            Assert.Equal([310, 377], rec.Last); // "e10" sorts before "e9" as text: the order is the engines' own
            fw.Replace("geneva-auto/", new Dictionary<string, NftQueueRule>
            {
                ["geneva-auto/~host"] = new() { QueueNum = 348 },
                ["geneva-auto/g1"] = new() { QueueNum = 340 },
            });
            Assert.Equal(348, rec.Last[^1]);
            fw.Set("e9", new NftQueueRule { QueueNum = 311 }); // replaced in place: keeps its turn
            Assert.Equal(311, rec.Last[0]);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
