using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Styling;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.App.ViewModels;

namespace ZapretAutoTuner.App;

public sealed partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var host = new AppHost();
            AppHost.Current = host;
            if (host.Settings.Language is "en" or "ru")
                Loc.Loc.I.English = host.Settings.Language == "en";
            ApplyTheme(host.Settings.Theme);
            ApplyFont(host.Settings.LargeFont);
            var main = new MainViewModel(host);
            desktop.MainWindow = new MainWindow { DataContext = main };
            _ = main.Mcp.ApplyAsync();
            if (Program.Stdio is { } io)
            {
                _ = Task.Run(async () =>
                {
                    // the client closed stdin: this window was opened for it, so it goes too
                    if (await main.Mcp.RunStdioAsync(io.In, io.Out, CancellationToken.None).ConfigureAwait(false))
                        Avalonia.Threading.Dispatcher.UIThread.Post(() => desktop.Shutdown());
                });
            }
            desktop.ShutdownRequested += (_, _) =>
            {
                // the built-in advisor stops talking to its provider at once
                main.Advisor.Cancel();
                var mcp = main.Mcp.DisposeAsync().AsTask();
                // the protection engine and the Agent's firewall rules go away with the app (AGENTS.md rule 6)
                var steps = Task.Run(async () =>
                {
                    // the router steps are bounded: an unreachable router must not hold the exit for a minute (its
                    // dead-man switch reverts an uncommitted experiment anyway)
                    await BoundedAsync(() => mcp).ConfigureAwait(false);
                    // an uncommitted router experiment of the wizard is rolled back (AGENTS.md rule 7)
                    await BoundedAsync(main.Wizard.ShutdownAsync).ConfigureAwait(false);
                    // an Agent that stopped answering must not hold the exit: it stops by itself once this process is gone
                    await BoundedAsync(main.Monitor.ShutdownAsync, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                    await BoundedAsync(() => host.DisposeAsync().AsTask(), TimeSpan.FromSeconds(20)).ConfigureAwait(false);
                });
                try
                {
                    // the window waits for the steps, but not forever: Program.Main kills what is left after it
                    steps.Wait(TimeSpan.FromSeconds(45));
                }
                catch (AggregateException e)
                {
                    Console.Error.WriteLine("shutdown: " + e.InnerException?.Message);
                }
            };
        }
        base.OnFrameworkInitializationCompleted();
    }

    /// <summary>How long an exit step that talks to the router may take.</summary>
    public static readonly TimeSpan ShutdownStepTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Runs an exit step for at most <see cref="ShutdownStepTimeout"/>; its failure does not stop the next steps.</summary>
    public static async Task BoundedAsync(Func<Task> step, TimeSpan? timeout = null)
    {
        try
        {
            await step().WaitAsync(timeout ?? ShutdownStepTimeout).ConfigureAwait(false);
        }
        catch (Exception e) when (e is TimeoutException or OperationCanceledException or HttpRequestException or IOException or InvalidOperationException
            or Delivery.ZapretGuiException or Grpc.Core.RpcException or ObjectDisposedException)
        {
            Console.Error.WriteLine("shutdown: " + e.Message);
        }
    }

    public static void ApplyTheme(string theme)
    {
        if (Current is not null)
            Current.RequestedThemeVariant = theme switch { "light" => ThemeVariant.Light, "dark" => ThemeVariant.Dark, _ => ThemeVariant.Default };
    }

    /// <summary>"Крупный шрифт": a bigger base size for every control (accessibility).</summary>
    public static void ApplyFont(bool large)
    {
        if (Current is not null)
            Current.Resources["ControlContentThemeFontSize"] = large ? 17.0 : 14.0;
    }
}
