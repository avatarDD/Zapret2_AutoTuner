using System.Net;
using System.Reflection;
using System.Text;
using Avalonia.Headless.XUnit;
using Avalonia.Threading;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.Mcp;
using ZapretAutoTuner.Mcp.Advisor;

namespace ZapretAutoTuner.App.Tests;

/// <summary>The advisor page: off by default, nothing goes out before the user enables it and presses Start.</summary>
public sealed class AdvisorPageTests : IAsyncLifetime
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "zt-adv-" + Guid.NewGuid().ToString("N"));
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

    private sealed class CountingHandler : HttpMessageHandler
    {
        public int Calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            const string json = """{"choices":[{"index":0,"message":{"role":"assistant","content":"Причина: блок по SNI."},"finish_reason":"stop"}],"usage":{"total_tokens":42}}""";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") });
        }
    }

    [AvaloniaFact]
    public async Task OffByDefaultAndSendsNothingUntilEnabled()
    {
        var s = _host!.Settings;
        Assert.False(s.AdvisorEnabled);
        Assert.Equal(AdvisorProvider.Claude, s.AdvisorProvider);
        Assert.Equal(AdvisorOptions.DefaultClaudeModel, s.AdvisorModel);
        Assert.Equal("", s.AdvisorKey);

        var handler = new CountingHandler();
        // a session over a host that is never reached: only the read tools are listed, none is called
        var tools = new AutoTunerTools(new McpSession(DispatchProxy.Create<IAutoTunerHost, Unreached>(), DispatchProxy.Create<IUserConfirm, Unreached>(), () => new McpPermissions()));
        var page = new AdvisorViewModel(_host, tools) { Client = new HttpClient(handler) };
        await page.StartCommand.ExecuteAsync(null);
        Assert.Equal(Loc.Loc.I["advisor.off"], page.Status);

        s.AdvisorEnabled = true;
        await page.StartCommand.ExecuteAsync(null);
        Assert.Equal(Loc.Loc.I["advisor.missing_key"], page.Status);
        Assert.Equal(0, handler.Calls);

        s.AdvisorProvider = AdvisorProvider.OpenAiCompatible;
        s.AdvisorEndpoint = "http://127.0.0.1:9/v1";
        Assert.Equal(AdvisorOptions.DefaultLocalModel, s.AdvisorModel);
        await page.StartCommand.ExecuteAsync(null);
        Dispatcher.UIThread.RunJobs();
        Assert.Equal(1, handler.Calls);
        Assert.Contains(page.Lines, l => l.Text == "Причина: блок по SNI.");
        Assert.False(page.Running);
        Assert.Equal(Loc.Loc.I.F("advisor.done_finished", 1, 0, 42), page.Status);

        // the key is never written to the knowledge base
        s.AdvisorKey = "sk-secret";
        Assert.DoesNotContain(_host.Kb.AllSettings().Values, v => v.Contains("sk-secret", StringComparison.Ordinal));
    }

    public class Unreached : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) => throw new InvalidOperationException("not expected: " + targetMethod?.Name);
    }

    [Fact]
    public void EveryOutcomeAndProblemHasItsText()
    {
        var keys = Enum.GetValues<AdvisorOutcome>().Select(AdvisorViewModel.OutcomeKey)
            .Concat(new[] { "model", "key", "endpoint" }.Select(AdvisorViewModel.MissingKey));
        Assert.Equal([], keys.Where(k => !Loc.Loc.I.Keys.Contains(k)).ToList());
    }

    /// <summary>The settings page states the limits in words: they must match the code.</summary>
    [Fact]
    public void TheStatedLimitsAreTheDefaults()
    {
        var l = new AdvisorLimits();
        Assert.Equal((12, 30, 400_000L), (l.MaxTurns, l.MaxToolCalls, l.MaxTokens));
        Assert.Contains("12", Loc.Loc.I["advisor.data"], StringComparison.Ordinal);
    }
}
