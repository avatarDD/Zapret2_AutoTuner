using Avalonia.Headless.XUnit;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.App.ViewModels;

namespace ZapretAutoTuner.App.Tests;

/// <summary>Every page builds and lays out in both languages (a broken binding or template throws here).</summary>
public sealed class ViewsTests : IAsyncLifetime
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "zt-app-" + Guid.NewGuid().ToString("N"));
    private AppHost? _host;

    public Task InitializeAsync()
    {
        _host = new AppHost(_dir);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        if (_host is not null)
            await _host.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    [AvaloniaFact]
    public void EveryPageRenders()
    {
        var main = new MainViewModel(_host!);
        var window = new MainWindow { DataContext = main };
        window.Show();
        foreach (var english in new[] { false, true })
        {
            Loc.Loc.I.English = english;
            foreach (var page in main.Pages)
            {
                main.Current = page;
                window.UpdateLayout();
                Assert.Equal(page, main.Current);
            }
        }
        foreach (var step in Enumerable.Range(1, 5))
        {
            main.Current = main.Wizard;
            main.Wizard.Step = step;
            window.UpdateLayout();
        }
        window.Close();
    }

    [AvaloniaFact]
    public void SettingsPersistInTheKnowledgeBase()
    {
        var s = new SettingsViewModel(_host!) { ModeIndex = 0, AutoApply = true, RouterHost = " 192.168.1.1 " };
        Assert.Equal("Quick", _host!.Settings.SearchMode);
        Assert.Equal("auto", _host.Settings.ApplyPolicy);
        Assert.Equal("192.168.1.1", _host.Settings.RouterHost);
        s.GuiToken = "secret";
        Assert.Equal("", _host.Settings.GuiToken); // not remembered unless asked
        s.RememberToken = true;
        Assert.Equal("secret", _host.Settings.GuiToken);
        s.RememberToken = false;
        Assert.Equal("", _host.Settings.GuiToken);
    }

    [AvaloniaFact]
    public void ExpertImportsAndValidates()
    {
        var e = new ExpertViewModel { ImportText = "--filter-tcp=443 --hostlist-domains=example.com --lua-desync=multisplit:pos=1" };
        e.ImportCommand.Execute(null);
        Assert.Single(e.Profiles);
        Assert.True(e.CanUse);
        e.UseCommand.Execute(null);
        Assert.NotNull(SessionState.I.Last?.Solution);

        e.ImportText = "--filter-tcp=443 --lua-desync=nosuchfunction";
        e.ImportCommand.Execute(null);
        Assert.False(e.CanUse);
        Assert.Contains(e.Issues, i => i.StartsWith('✖'));

        e.StrategyText = "--lua-desync=multisplit:pos=1";
        e.CheckStrategyCommand.Execute(null);
        Assert.NotEmpty(e.StrategyResult);
        Assert.DoesNotContain("✖", e.StrategyResult, StringComparison.Ordinal);
    }
}
