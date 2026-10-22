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
                var mcp = main.Mcp.DisposeAsync().AsTask();
                // the protection engine and the Agent's firewall rules go away with the app (AGENTS.md rule 6)
                Task.Run(async () =>
                {
                    await mcp.ConfigureAwait(false);
                    // an uncommitted router experiment of the wizard is rolled back (AGENTS.md rule 7)
                    await main.Wizard.ShutdownAsync().ConfigureAwait(false);
                    await main.Monitor.ShutdownAsync().ConfigureAwait(false);
                    await host.DisposeAsync().ConfigureAwait(false);
                }).GetAwaiter().GetResult();
            };
        }
        base.OnFrameworkInitializationCompleted();
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
