using Avalonia;
using Avalonia.Headless;

[assembly: AvaloniaTestApplication(typeof(ZapretAutoTuner.App.Tests.TestApp))]
// the language is one process-wide setting that several tests switch: running them side by side races
[assembly: Xunit.CollectionBehavior(DisableTestParallelization = true)]

namespace ZapretAutoTuner.App.Tests;

public static class TestApp
{
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>().UseHeadless(new AvaloniaHeadlessPlatformOptions());
}
