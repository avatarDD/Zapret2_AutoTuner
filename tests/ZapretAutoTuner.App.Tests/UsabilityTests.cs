using Avalonia.Headless.XUnit;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.Core.Resources;

namespace ZapretAutoTuner.App.Tests;

/// <summary>
/// The GUI usability pass: the status bar and "Остановить всё", the engine badges, "Состояние", the wizard's last step,
/// the shared router passwords, the expert's single strategy, the resources' tools and the settings tabs.
/// </summary>
public sealed class UsabilityTests : IAsyncLifetime
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "zt-ux-" + Guid.NewGuid().ToString("N"));
    private AppHost? _host;

    private AppHost Host => _host!;

    public Task InitializeAsync()
    {
        SessionState.I.Last = null;
        RouterCredentials.GuiPassword = RouterCredentials.RouterPassword = "";
        _host = new AppHost(_dir);
        return Task.CompletedTask;
    }

    /// <summary>The host stays open, as in <see cref="ViewsTests"/>: the view models keep language subscriptions.</summary>
    public Task DisposeAsync()
    {
        SessionState.I.Last = null;
        RouterCredentials.GuiPassword = RouterCredentials.RouterPassword = "";
        return Task.CompletedTask;
    }

    [Fact]
    public void NoTextKeyIsDefinedTwice() => Assert.Empty(Loc.Loc.I.Duplicates);

    [AvaloniaFact]
    public void TheMenuNamesTheEngineOfEveryPage()
    {
        var main = new MainViewModel(Host);
        Assert.Equal("geneva", main.Auto.Engine);
        Assert.Equal("geneva", main.Engine.Engine);
        Assert.All(new PageViewModel[] { main.Home, main.Wizard, main.Monitor, main.Expert, main.Resources }, p => Assert.Equal("zapret2", p.Engine));
        Assert.All(new PageViewModel[] { main.Reports, main.Advisor, main.EnvironmentPage, main.Settings }, p => Assert.Null(p.Engine));
        Assert.Contains(main.EnvironmentPage, main.Pages);
        // the geneva search page says it is geneva's
        var was = Loc.Loc.I.English;
        Loc.Loc.I.English = false;
        Assert.Contains("geneva", main.Engine.Title, StringComparison.Ordinal);
        Loc.Loc.I.English = was;
    }

    [AvaloniaFact]
    public async Task NothingRunsAtStartAndStopAllIsHarmless()
    {
        var main = new MainViewModel(Host);
        main.RefreshStatus();
        Assert.False(main.AnythingRunning);
        Assert.Empty(main.Running);
        Assert.False(main.Wizard.Busy);
        // nothing to stop: nothing is asked and no Agent is started
        var asked = false;
        main.Confirm = (_, _) =>
        {
            asked = true;
            return Task.FromResult(true);
        };
        await main.StopAllCommand.ExecuteAsync(null);
        Assert.False(asked);
        await main.StopEverythingAsync();
        Assert.False(Host.AgentRunning);
        Assert.Equal(Loc.Loc.I["status.stopped_all"], main.StopResult);
    }

    [AvaloniaFact]
    public void ShortcutsGoToThePagesInMenuOrderAndTheTitleFollows()
    {
        var main = new MainViewModel(Host);
        main.GoToCommand.Execute("3");
        Assert.Same(main.Pages[2], main.Current);
        Assert.StartsWith(main.Pages[2].Title, main.WindowTitle, StringComparison.Ordinal);
        main.GoToCommand.Execute("42");
        Assert.Same(main.Pages[2], main.Current);
        main.Navigate("settings_router");
        Assert.Same(main.Settings, main.Current);
        Assert.Equal(SettingsViewModel.RouterTab, main.Settings.TabIndex);
    }

    [AvaloniaFact]
    public async Task TheEnvironmentPageSaysWhatIsMissing()
    {
        var env = new MainViewModel(Host).EnvironmentPage;
        await env.CheckAsync();
        var ids = env.Rows.Select(r => r.Id).ToList();
        Assert.Contains("zapret2", ids);
        Assert.Contains("geneva", ids);
        Assert.Contains("browser", ids);
        Assert.Contains("agent", ids);
        Assert.Contains("router", ids);
        Assert.Contains("data", ids);
        Assert.Equal(OperatingSystem.IsLinux(), ids.Contains("linux"));
        // a test build has no zapret2 bundle next to it: an error, named in the status bar
        var zapret2 = env.Rows.Single(r => r.Id == "zapret2");
        if (!File.Exists(Host.Bundle.EnginePath))
        {
            Assert.Equal(EnvLevel.Error, zapret2.Level);
            Assert.Equal("zapret2", env.Problem);
            Assert.True(zapret2.HasAction);
        }
        Assert.Contains(Host.DataDir, env.Rows.Single(r => r.Id == "data").Text, StringComparison.Ordinal);
        Assert.All(env.Rows, r => Assert.False(string.IsNullOrWhiteSpace(r.LevelText)));
    }

    [AvaloniaFact]
    public void TheWizardEndsWithDoneAndRecommendsOneDestination()
    {
        var main = new MainViewModel(Host);
        var w = main.Wizard;
        Assert.True(w.RecommendPc);
        Host.Settings.RouterHost = "192.168.1.1";
        w.Step = 5;
        Assert.True(w.RecommendKeenetic);
        Host.Settings.GuiUrl = "http://192.168.1.1:8080";
        w.OnShown();
        Assert.True(w.RecommendGui);
        Assert.False(w.RecommendPc || w.RecommendKeenetic);

        main.Current = w;
        w.DoneCommand.Execute(null);
        Assert.Equal(1, w.Step);
        Assert.Same(main.Home, main.Current);
    }

    [AvaloniaFact]
    public void RouterPasswordsAreTypedOnceForTheWholeProgram()
    {
        var main = new MainViewModel(Host);
        main.Settings.RouterPassword = "ssh-secret";
        main.Settings.GuiPassword = "web-secret";
        main.Wizard.OnShown();
        Assert.Equal("ssh-secret", main.Wizard.RouterPassword);
        Assert.Equal("web-secret", main.Wizard.GuiPassword);
        main.Wizard.RouterPassword = "changed";
        Assert.Equal("changed", main.Settings.RouterPassword);
        // never on disk
        Assert.DoesNotContain(Host.Kb.AllSettings().Values, v => v.Contains("secret", StringComparison.Ordinal) || v == "changed");
    }

    [Fact]
    public async Task TheRouterCheckNeedsAnAddressAndChangesNothing()
    {
        var lines = await RouterCheck.RunAsync(Host.Settings, CancellationToken.None);
        Assert.Equal([Loc.Loc.I["router.check_nothing"]], lines);
        Host.Settings.GuiUrl = "not a url";
        lines = await RouterCheck.RunAsync(Host.Settings, CancellationToken.None);
        Assert.StartsWith("✖", lines[0], StringComparison.Ordinal);
    }

    [AvaloniaFact]
    public async Task ASingleStrategyBecomesTheCurrentOneForTheGivenSitesOnly()
    {
        var main = new MainViewModel(Host);
        var e = main.Expert;
        Func<Task>? protect = null;
        var protectedHere = 0;
        e.ProtectHere = protect = () =>
        {
            protectedHere++;
            return Task.CompletedTask;
        };
        e.StrategyText = "--lua-desync=fake:blob=fake_default_tls:tcp_md5 --lua-desync=multisplit:pos=1,midsld";
        e.UseStrategyCommand.Execute(null);
        // no sites: refused, the strategy must not touch all traffic
        Assert.Null(SessionState.I.Last);
        Assert.Equal(Loc.Loc.I["expert.strategy_need_sites"], e.StrategyStatus);
        Assert.False(e.Used);

        e.StrategySites = "https://www.YouTube.com/watch?v=1, googlevideo.com\nbad";
        e.UseStrategyCommand.Execute(null);
        var s = SessionState.I.Last?.Solution;
        Assert.NotNull(s);
        var p = Assert.Single(s.Profiles);
        Assert.Equal(["www.youtube.com", "googlevideo.com"], p.HostlistDomains);
        Assert.Equal("80,443", p.TcpPorts);
        Assert.True(e.Used);
        await e.ProtectCommand.ExecuteAsync(null);
        Assert.Equal(1, protectedHere);

        // a broken strategy is not used
        SessionState.I.Last = null;
        e.StrategyText = "--lua-desync=no_such_function";
        e.UseStrategyCommand.Execute(null);
        Assert.Null(SessionState.I.Last);
    }

    [AvaloniaFact]
    public void TheProtectionSaysWhereAStrategyComesFromBeforeTheClick()
    {
        var main = new MainViewModel(Host);
        main.Monitor.OnShown();
        Assert.True(main.Monitor.NeedsSolution);
        main.Monitor.GoToCommand.Execute("expert");
        Assert.Same(main.Expert, main.Current);
        SessionState.I.Last = new Tuning.PipelineResult([], null, new Core.Model.Solution());
        main.Monitor.OnShown();
        Assert.False(main.Monitor.NeedsSolution);
    }

    [Fact]
    public void ListsAreCountedAndRepeatsRemoved()
    {
        var text = "# video\nyoutube.com\n\nYouTube.com\ngooglevideo.com\n youtube.com \n";
        Assert.Equal((4, 2, 1), ResourcesViewModel.Count(text));
        Assert.Equal("# video\nyoutube.com\ngooglevideo.com", ResourcesViewModel.Dedupe(text));
    }

    [AvaloniaFact]
    public void ResourcesAreImportedSearchedExportedAndCopied()
    {
        var vm = new ResourcesViewModel(Host.Resources);
        IReadOnlyList<(string, byte[])> files =
        [
            ("YouTube.txt", "﻿youtube.com\r\ngooglevideo.com\r\n"u8.ToArray()),
            ("discord.list", "discord.com\n"u8.ToArray()),
            ("broken.txt", "not a domain at all\n"u8.ToArray()),
        ];
        vm.OpenFiles = () => Task.FromResult(files);
        vm.ImportCommand.Execute(null);
        Assert.NotNull(Host.Resources.Get(ResourceKind.Hostlist, "youtube"));
        Assert.Equal(["youtube.com", "googlevideo.com"], Host.Resources.Get(ResourceKind.Hostlist, "youtube")!.Data.Items);
        Assert.NotNull(Host.Resources.Get(ResourceKind.Hostlist, "discord"));
        Assert.Contains(vm.Problems, p => p.Contains("broken.txt", StringComparison.Ordinal));

        vm.Filter = "you";
        Assert.Equal(["youtube"], vm.Items.Select(i => i.Name));
        Assert.NotEmpty(vm.Shown);
        vm.Filter = "zzz";
        Assert.True(vm.NothingFound);
        vm.Filter = "";
        Assert.Equal(2, vm.Items.Count);

        // export: the same file zapret2 uses; import of it gives the same list back
        var stored = Host.Resources.Get(ResourceKind.Hostlist, "youtube")!;
        var (file, bytes) = ResourcesViewModel.ExportFile(stored);
        Assert.Equal("youtube.txt", file);
        var again = ResourcesViewModel.ImportInput(ResourceKind.Hostlist, "youtube", bytes);
        Assert.Equal(stored.Data.Items, again.Items.Where(i => i.Length > 0));

        // a blob round-trips its bytes
        var blob = ResourcesViewModel.ImportInput(ResourceKind.Blob, "hello", [1, 2, 3, 255]);
        Assert.Equal([1, 2, 3, 255], blob.Bytes);

        // searching keeps unsaved edits of the selected resource
        vm.Selected = vm.Items.First(i => i.Name == "youtube");
        vm.Content += "\nytimg.com";
        vm.Filter = "y";
        vm.Filter = "yo";
        Assert.Contains("ytimg.com", vm.Content, StringComparison.Ordinal);
        Assert.Equal("youtube", vm.Selected?.Name);
        vm.Filter = "";

        // a copy is a new unsaved resource under a free name
        vm.Selected = vm.Items.First(i => i.Name == "youtube");
        vm.DuplicateCommand.Execute(null);
        Assert.True(vm.IsNew);
        Assert.Equal("youtube-2", vm.Name);
        Assert.Contains("googlevideo.com", vm.Content, StringComparison.Ordinal);
    }

    [AvaloniaFact]
    public void SettingsHaveALanguageListAndAScaleThatIsKept()
    {
        var s = new MainViewModel(Host).Settings;
        var was = Loc.Loc.I.English;
        try
        {
            s.LanguageIndex = 1;
            Assert.True(Loc.Loc.I.English);
            Assert.Equal("en", Host.Settings.Language);
            s.LanguageIndex = 0;
            Assert.False(Loc.Loc.I.English);
        }
        finally
        {
            Loc.Loc.I.English = was;
        }
        Assert.Equal(100, Host.Settings.UiScale);
        s.ScaleIndex = 2;
        Assert.Equal(130, Host.Settings.UiScale);
        Assert.Equal(130, App.Scale);
        App.ApplyScale(100);
        Assert.NotEmpty(s.ModeHint);
    }

    [Fact]
    public void TheOldLargeFontBecomesALargerScale()
    {
        Host.Settings.LargeFont = true;
        Assert.Equal(115, Host.Settings.UiScale);
        Host.Settings.UiScale = 150;
        Assert.Equal(150, Host.Settings.UiScale);
        // a scale the settings do not offer is not trusted
        Host.Kb.SetSetting("ui.scale", "120");
        Assert.Equal(115, Host.Settings.UiScale);
    }

    [Fact]
    public void SitesAreHostnamesOnly() =>
        Assert.Equal(["example.org", "xn--e1afmkfd.xn--p1ai"], ExpertViewModel.ParseSites("1.2.3.4 https://Example.org/x [2001:db8::1] пример.рф https://10.0.0.1/"));

    [AvaloniaFact]
    public void TheStatusBarKeepsItsItemsWhileOnlyTheTextChanges()
    {
        var main = new MainViewModel(Host);
        var item = new StatusItem("wizard", "1 %", main.Wizard);
        main.Running.Add(item);
        main.RefreshStatus();
        // nothing really runs: the fake item goes, and the old answer of "Остановить всё" stays while idle
        Assert.Empty(main.Running);
    }

    [AvaloniaFact]
    public void EverySettingsTabAndTheStatusPageRender()
    {
        var main = new MainViewModel(Host);
        var window = new MainWindow { DataContext = main };
        window.Show();
        foreach (var english in new[] { false, true })
        {
            Loc.Loc.I.English = english;
            main.Current = main.Settings;
            for (int t = SettingsViewModel.InterfaceTab; t <= SettingsViewModel.DataTab; t++)
            {
                main.Settings.TabIndex = t;
                window.UpdateLayout();
            }
            main.Current = main.EnvironmentPage;
            window.UpdateLayout();
            main.Current = main.Expert;
            window.UpdateLayout();
        }
        Loc.Loc.I.English = false;
        // the window scales as a whole
        App.ApplyScale(150);
        window.UpdateLayout();
        App.ApplyScale(100);
        window.Close();
    }
}
