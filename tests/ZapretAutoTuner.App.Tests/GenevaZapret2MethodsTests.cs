using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.Core.Geneva;
using ZapretAutoTuner.Core.Geneva.Auto;

namespace ZapretAutoTuner.App.Tests;

/// <summary>zapret2's methods (geneva_c 2.0 x-actions) on the geneva search page: the seeds and the library rows.</summary>
public sealed class GenevaZapret2MethodsTests
{
    [Fact]
    public void A_site_search_starts_from_the_quick_round_and_http_first_on_port_80()
    {
        Assert.Equal(AutoCandidates.XTcp, EngineViewModel.Zapret2Methods(443));
        var http = EngineViewModel.Zapret2Methods(80);
        Assert.StartsWith("[TCP:flags:PA]-xhttp", http[0], StringComparison.Ordinal);
        Assert.Superset(AutoCandidates.XTcp.ToHashSet(), http.ToHashSet());
        // all of them need --ext, and they fit geneva's seed limit next to the found ones
        Assert.All(http, s => Assert.True(GenevaStrategyText.NeedsExt(s)));
        Assert.True(http.Count + 20 < GenevaArgv.MaxSeeds);
    }

    [Fact]
    public void The_library_lists_every_method_the_auto_mode_tries_once_with_its_actions()
    {
        var rows = EngineViewModel.Zapret2Library().ToList();
        Assert.Equal(rows.Count, rows.Select(r => r.Strategy).Distinct(StringComparer.Ordinal).Count());
        foreach (var x in AutoCandidates.XTcp.Concat(AutoCandidates.XTcpWide).Concat(AutoCandidates.XQuic).Concat(AutoCandidates.XUdp))
            Assert.Contains(rows, r => r.Strategy == x);
        Assert.All(rows, r => Assert.Null(GenevaStrategyText.Problem(r.Strategy)));
        Assert.Equal("xfake, xdisorder", EngineViewModel.XActions(@"[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=4}(xdisorder{pos=1,midsld},)-| \/"));
        Assert.Equal("xwssize", EngineViewModel.XActions(@"[FLOW:n:a]-xwssize{wsize=1;scale=6}-| \/"));
    }
}
