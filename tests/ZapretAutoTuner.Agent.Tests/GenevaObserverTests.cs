using ZapretAutoTuner.Agent.Geneva;
using ZapretAutoTuner.Core.Geneva.Auto;

namespace ZapretAutoTuner.Agent.Tests;

/// <summary>geneva's detector (<c>run --ext --ext-auto observe</c>) beside the "Авто" groups.</summary>
public class GenevaObserverTests
{
    [Fact]
    public void Linux_the_detector_has_its_own_queue_and_geneva_keeps_its_rules()
    {
        var argv = GenevaManager.ObserverArgv(40123, windows: false);
        Assert.Equal(["run", "--ext", "--ext-auto", "observe"], argv.Take(4));
        Assert.Contains("tcp:40123", argv);
        int q = argv.IndexOf("-q");
        Assert.Equal(AutoRules.ObserveQueue.ToString(), argv[q + 1]);
        // NFLOG copies come from geneva's own rules: the firewall stays geneva's (removed on exit)
        Assert.DoesNotContain("--firewall", argv);
        Assert.DoesNotContain("--priority", argv);
    }

    [Fact]
    public void Windows_the_sniffing_handle_sits_above_every_group_and_the_host_process()
    {
        var argv = GenevaManager.ObserverArgv(40123, windows: true);
        int p = argv.IndexOf("--priority");
        Assert.True(int.Parse(argv[p + 1]) > 0);
        Assert.DoesNotContain("-q", argv);
    }
}
