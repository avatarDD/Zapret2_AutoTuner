using System.Diagnostics;
using System.Text.Json.Nodes;
using Avalonia.Headless.XUnit;
using Avalonia.Threading;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.Mcp;

namespace ZapretAutoTuner.App.Tests;

/// <summary>Regression tests of the code review (M5, M6, L2, L4, L5) on the app's view models.</summary>
public sealed class ReviewFixTests
{
    /// <summary>
    /// One host for the whole run, never disposed: a MainViewModel keeps its language subscriptions (the monitor reads
    /// the journal on a language switch), so a disposed host would break the other tests that switch the language.
    /// </summary>
    private static readonly Lazy<AppHost> Shared = new(() => new AppHost(Path.Combine(Path.GetTempPath(), "zt-review-" + Guid.NewGuid().ToString("N"))));

    private static AppHost Host => Shared.Value;

    private static void RunUntil(Func<bool> done)
    {
        var sw = Stopwatch.StartNew();
        while (!done() && sw.Elapsed < TimeSpan.FromSeconds(10))
        {
            Dispatcher.UIThread.RunJobs();
            Thread.Sleep(10);
        }
        Assert.True(done());
    }

    /// <summary>Final review 7: the data folder keeps the MCP token: on Linux it is the user's alone.</summary>
    [AvaloniaFact]
    public void TheDataFolderAndKnowledgeBaseAreTheUsersAlone()
    {
        if (OperatingSystem.IsWindows())
            return;
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(Host.DataDir));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(Host.DataDir, "knowledge.db")));
    }

    /// <summary>M5 + L5: turning MCP off in Settings is the full stop: a waiting dialog is withdrawn and closed.</summary>
    [AvaloniaFact]
    public void TurningMcpOffStopsEverythingAndClosesTheDialog()
    {
        var main = new MainViewModel(Host);
        var s = main.Settings;
        s.McpEnabled = true;
        CancellationToken dialogToken = default;
        main.Mcp.Ask = async (_, _, ct) =>
        {
            dialogToken = ct;
            await Task.Delay(Timeout.Infinite, ct).ContinueWith(_ => { }, TaskScheduler.Default);
            return false;
        };
        var answer = main.Mcp.Session.Confirmations.Request("k", new ConfirmRequest("t", "т", "t", "т", "t"), _ => Task.FromResult(new JsonObject { ["ok"] = true }));
        Assert.Equal("pending_confirmation", (string?)answer["status"]);
        RunUntil(() => dialogToken.CanBeCanceled);
        Assert.Equal(1, main.Mcp.Session.Confirmations.PendingCount);

        s.McpEnabled = false;
        RunUntil(() => main.Mcp.Session.Confirmations.PendingCount == 0 && dialogToken.IsCancellationRequested);
        main.Mcp.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    /// <summary>Review 2: a permission toggled while MCP is off does not run the full stop (nor cancel the advisor).</summary>
    [AvaloniaFact]
    public void APermissionChangeWhileMcpIsOffDoesNotStop()
    {
        var main = new MainViewModel(Host);
        var s = main.Settings;
        int stops = 0;
        main.Mcp.Stopped += () => stops++;
        s.McpEnabled = true;
        s.McpEnabled = false;
        // switching it off is the full stop
        RunUntil(() => stops == 1);
        s.PermProbes = !s.PermProbes;
        s.PermControl = !s.PermControl;
        for (int i = 0; i < 30; i++)
        {
            Dispatcher.UIThread.RunJobs();
            Thread.Sleep(10);
        }
        Assert.Equal(1, stops);
        main.Mcp.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    /// <summary>M5: the Stop banner shows while work runs or a dialog waits, even with MCP off.</summary>
    [Fact]
    public void TheBannerShowsWhileWorkRunsWhateverTheSettings()
    {
        Assert.True(McpService.ShowBanner(enabled: false, busy: true, pending: 0, recentCall: false));
        Assert.True(McpService.ShowBanner(enabled: false, busy: false, pending: 1, recentCall: false));
        Assert.False(McpService.ShowBanner(enabled: false, busy: false, pending: 0, recentCall: true));
        Assert.True(McpService.ShowBanner(enabled: true, busy: false, pending: 0, recentCall: true));
    }

    /// <summary>L2: a zapret-gui token entered in Settings is what the wizard shows, not the copy it took at start.</summary>
    [AvaloniaFact]
    public void TheWizardReadsTheTokenEnteredInSettings()
    {
        var main = new MainViewModel(Host);
        main.Settings.GuiUrl = "http://192.168.1.1:8080";
        main.Settings.GuiToken = "tok-from-settings";
        main.Current = main.Wizard;
        Assert.Equal("tok-from-settings", main.Wizard.GuiToken);
        Assert.Equal("http://192.168.1.1:8080", main.Wizard.GuiUrl);
        Assert.Equal("tok-from-settings", Host.Settings.GuiToken);
        main.Wizard.GuiToken = "tok-from-wizard";
        main.Current = main.Settings;
        Assert.Equal("tok-from-wizard", main.Settings.GuiToken);
        main.Mcp.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    /// <summary>M6: the wizard refuses to tune while the MCP session works on the model's behalf.</summary>
    [AvaloniaFact]
    public async Task TheWizardRefusesWhileTheMcpSessionIsBusy()
    {
        var main = new MainViewModel(Host);
        main.Wizard.McpBusy = () => true;
        main.Wizard.InputText = "example.com";
        await main.Wizard.StartCommand.ExecuteAsync(null);
        Assert.Equal(Loc.Loc.I["wizard.mcp_busy"], main.Wizard.Error);
        Assert.Equal(1, main.Wizard.Step);
        main.Wizard.OnRouter = true;
        await main.Wizard.StartCommand.ExecuteAsync(null);
        Assert.Equal(Loc.Loc.I["wizard.mcp_busy"], main.Wizard.Error);
        await main.Mcp.DisposeAsync();
    }

    /// <summary>L4: an exit step that hangs (an unreachable router) is given up after its timeout.</summary>
    [Fact]
    public async Task ShutdownStepsAreBounded()
    {
        var sw = Stopwatch.StartNew();
        await App.BoundedAsync(() => Task.Delay(Timeout.Infinite), TimeSpan.FromMilliseconds(50));
        await App.BoundedAsync(() => throw new HttpRequestException("down"));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5));
    }
}
