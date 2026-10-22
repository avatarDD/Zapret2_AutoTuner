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
    public void McpIsOffByDefaultAndStopTurnsItOff()
    {
        var main = new MainViewModel(_host!);
        var s = main.Settings;
        Assert.False(s.McpEnabled);
        Assert.False(s.McpHttp);
        Assert.Equal(new Mcp.McpPermissions(), _host!.Settings.McpPermissions);
        Assert.DoesNotContain(main.Mcp.Tools.ListTools(), t => t.Scope != Mcp.McpScope.Read);

        s.McpEnabled = true;
        s.PermProbes = true;
        Assert.True(_host.Settings.McpEnabled);
        Assert.True(_host.Settings.McpPermissions.Probes);
        Assert.Contains(main.Mcp.Tools.ListTools(), t => t.Scope == Mcp.McpScope.Probes);
        Assert.NotEmpty(s.McpToken);
        Assert.Contains("\"mcp\"", s.StdioSnippet, StringComparison.Ordinal);

        main.Mcp.StopAsync().GetAwaiter().GetResult();
        Avalonia.Threading.Dispatcher.UIThread.RunJobs();
        Assert.False(_host.Settings.McpEnabled);
        Assert.False(s.McpEnabled);
        // off means no permissions at all, whatever the switches say
        Assert.DoesNotContain(main.Mcp.Tools.ListTools(), t => t.Scope != Mcp.McpScope.Read);
        main.Mcp.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    [AvaloniaFact]
    public void WizardTargetsAreKept()
    {
        _host!.Settings.AddTargets(["Example.COM.", "bad host", "example.com", "rutracker.org"]);
        Assert.Equal(["example.com", "rutracker.org"], _host.Settings.Targets);
    }

    [AvaloniaFact]
    public void SettingsPersistInTheKnowledgeBase()
    {
        var s = new MainViewModel(_host!).Settings;
        s.ModeIndex = 0;
        s.AutoApply = true;
        s.RouterHost = " 192.168.1.1 ";
        Assert.Equal("Quick", _host!.Settings.SearchMode);
        Assert.Equal("auto", _host.Settings.ApplyPolicy);
        Assert.Equal("192.168.1.1", _host.Settings.RouterHost);
        s.GuiToken = "secret";
        Assert.Equal("secret", _host.Settings.GuiToken);   // for this run
        Assert.Null(_host.Kb.GetSetting("gui.token"));    // never in the file
        // the monitor and the settings page share one auto-apply switch
        var m = new MonitorViewModel(_host);
        Assert.True(m.AutoApply);
        m.AutoApply = false;
        Assert.Equal("ask", _host.Settings.ApplyPolicy);
        Avalonia.Threading.Dispatcher.UIThread.RunJobs();
        Assert.False(s.AutoApply);
        s.AutoApply = true;
        Avalonia.Threading.Dispatcher.UIThread.RunJobs();
        Assert.True(m.AutoApply);
        // the wizard starts from the remembered addresses
        Assert.Equal("192.168.1.1", new WizardViewModel(_host).RouterHost);
    }

    [AvaloniaFact]
    public async Task RouterModeIsOptInAndNeedsZapretGui()
    {
        // the MCP router permission is off by default, and acts only with control and probes
        Assert.False(_host!.Settings.McpPermissions.Router);
        _host.Settings.McpPermissions = new Mcp.McpPermissions(Router: true);
        Assert.True(_host.Settings.McpPermissions.Router);
        Assert.False(_host.Settings.McpPermissions.Granted(Mcp.McpScope.Router));

        var w = new WizardViewModel(_host);
        Assert.True(w.OnPc);
        Assert.False(w.OnRouter);
        var window = new Avalonia.Controls.Window { Content = new Views.WizardView { DataContext = w } };
        window.Show();
        w.OnRouter = true;
        Assert.False(w.OnPc);
        foreach (var step in new[] { 1, 4 })
        {
            w.Step = step;
            window.UpdateLayout();
        }
        // without an address and a token nothing is started and nothing is asked
        bool asked = false;
        w.Confirm = (_, _) =>
        {
            asked = true;
            return Task.FromResult(false);
        };
        w.Step = 1;
        w.InputText = "rutracker.org";
        w.GuiUrl = "";
        await w.StartCommand.ExecuteAsync(null);
        Assert.False(asked);
        Assert.Equal(1, w.Step);
        Assert.NotEmpty(w.Error);
        Assert.False(_host.Router.Configured);
        w.GuiUrl = "http://192.168.1.1:8080";
        w.GuiToken = "tok";
        Assert.True(_host.Router.Configured);
        Assert.Null(_host.Kb.GetSetting("gui.token"));   // the token stays in memory
        window.Close();
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
