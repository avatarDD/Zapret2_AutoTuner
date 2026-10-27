using Avalonia;
using Avalonia.Headless;

[assembly: AvaloniaTestApplication(typeof(ZapretAutoTuner.App.Tests.TestApp))]

namespace ZapretAutoTuner.App.Tests;

public static class TestApp
{
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>().UseHeadless(new AvaloniaHeadlessPlatformOptions());
}
