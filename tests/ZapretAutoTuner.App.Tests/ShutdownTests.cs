using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.App.ViewModels;

namespace ZapretAutoTuner.App.Tests;

/// <summary>The program's own helpers go with it on exit, the user's programs stay; every page says in the menu what it is for.</summary>
public sealed class ShutdownTests
{
    [Fact]
    public void Every_descendant_is_found_and_unrelated_processes_are_not()
    {
        // 100 is the program: 200 (a browser driver) → 201, 202 (its browsers) → 300; 500 is someone else's
        var parents = new Dictionary<int, int> { [200] = 100, [201] = 200, [202] = 200, [300] = 201, [500] = 1, [100] = 1 };
        var found = ChildProcesses.Descendants(100, parents);
        Assert.Equal([200, 201, 202, 300], found.Order());
        Assert.DoesNotContain(500, found);
        Assert.DoesNotContain(100, found);
        Assert.Empty(ChildProcesses.Descendants(500, parents));
    }

    [Theory]
    [InlineData("/opt/zt/browsers/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell", true)]
    [InlineData("/opt/zt/.playwright/node/linux-x64/node", true)]
    [InlineData("/home/u/.cache/ms-playwright/chromium-1194/chrome-linux64/chrome", true)]
    [InlineData("/opt/zt/ztuner-agent", false)]
    [InlineData("/usr/bin/firefox", false)]
    [InlineData("/usr/lib/discord/Discord", false)]
    [InlineData(null, false)]
    public void Only_the_programs_own_helpers_are_killed(string? exe, bool ours) =>
        Assert.Equal(ours, ChildProcesses.Ours(exe, "/opt/zt/"));

    [Fact]
    public void Every_menu_page_has_a_hint_in_both_languages()
    {
        foreach (var key in new[] { "nav.home", "nav.wizard", "nav.monitor", "nav.reports", "nav.expert", "nav.resources", "nav.advisor", "nav.settings" })
            Assert.Contains(key + "_hint", Loc.Loc.I.Keys);
    }
}
