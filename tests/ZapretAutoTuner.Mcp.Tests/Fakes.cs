using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Probes.Http;
using ZapretAutoTuner.Protocol;
using ZapretAutoTuner.Storage;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.Mcp.Tests;

/// <summary>The engine as the Agent would run it: remembers what is running; a strategy "works" when its argv has the magic function.</summary>
internal sealed class FakeEngine : IEngineControl
{
    private readonly Dictionary<string, IReadOnlyList<string>> _running = [];
    private int _next;

    public List<IReadOnlyList<string>> Started { get; } = [];

    public int Stops { get; private set; }

    public string WorkingFunction { get; set; } = "multisplit";

    public IReadOnlyCollection<IReadOnlyList<string>> Running
    {
        get
        {
            lock (_running)
                return [.. _running.Values];
        }
    }

    public bool Works => Running.Any(a => a.Any(x => x.Contains("--lua-desync=" + WorkingFunction, StringComparison.Ordinal)));

    public Task<string> StartAsync(IReadOnlyList<string> argv, QueueRule? queue, string tag, CancellationToken ct)
    {
        lock (_running)
        {
            var id = "e" + (++_next);
            _running[id] = argv;
            Started.Add(argv);
            return Task.FromResult(id);
        }
    }

    public Task StopAsync(string engineId, CancellationToken ct)
    {
        lock (_running)
        {
            _running.Remove(engineId);
            Stops++;
        }
        return Task.CompletedTask;
    }
}

internal sealed class FakeConfirm : IUserConfirm
{
    private readonly List<(ConfirmRequest Request, TaskCompletionSource<bool> Answer)> _asked = [];

    public IReadOnlyList<ConfirmRequest> Asked
    {
        get
        {
            lock (_asked)
                return [.. _asked.Select(a => a.Request)];
        }
    }

    public Task<bool> ConfirmAsync(ConfirmRequest request, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        ct.Register(() => tcs.TrySetCanceled());
        lock (_asked)
            _asked.Add((request, tcs));
        return tcs.Task;
    }

    /// <summary>The user's answer to the oldest open dialog.</summary>
    public void Answer(bool yes)
    {
        TaskCompletionSource<bool> tcs;
        lock (_asked)
            tcs = _asked.First(a => !a.Answer.Task.IsCompleted).Answer;
        tcs.SetResult(yes);
    }
}

internal sealed class FakeHost : IAutoTunerHost, IDisposable
{
    public FakeHost()
    {
        Kb = KnowledgeBase.OpenInMemory();
    }

    public KnowledgeBase Kb { get; }

    public List<string> TargetList { get; } = ["blocked.example", "open.example"];

    public IReadOnlyList<string> Targets => TargetList;

    public FakeEngine Engine { get; } = new();

    public Func<HttpProbeOptions, bool, ProbeResult>? Probe { get; set; }

    public List<Solution> Committed { get; } = [];

    public List<string> Saved { get; } = [];

    public int Classified { get; private set; }

    public bool ProtectionActive { get; set; }

    public Tuning.Geneva.GenevaController? Geneva { get; set; }

    public Tools.GenevaBundle? GenevaBundle { get; set; }

    public bool LocalTuningRunning { get; set; }

    public bool RouterTuningRunning { get; set; }

    public WizardSnapshot? Wizard { get; set; }

    public Dictionary<string, ClassifierVerdict> WizardVerdicts { get; } = new(StringComparer.OrdinalIgnoreCase);

    public ClassifierVerdict? WizardVerdict(string host) => WizardVerdicts.GetValueOrDefault(host);

    public AgentTrialOptions TrialOptions { get; } = new() { LuaDir = "/opt/zapret2/lua", Platform = Core.Validation.EnginePlatform.Linux, Warmup = TimeSpan.Zero, Pause = TimeSpan.Zero };

    public Func<string, CancellationToken, Task<PageLoad>>? OpenPage => null;

    public ITrialCapture? Capture { get; set; }

    public void AddTarget(string host) => TargetList.Add(host);

    /// <summary>Replaces the classifier (a slow one, a failing one); null: the instant verdict below.</summary>
    public Func<string, CancellationToken, Task<ClassifierVerdict>>? Classifier { get; set; }

    /// <summary>What "Сообщить о проблеме" would start from (the wizard's last run).</summary>
    public BugReportInput BugContext { get; set; } = new();

    public BugReportInput BugReportContext() => BugContext;

    public Task<ClassifierVerdict> ClassifyAsync(string host, CancellationToken ct)
    {
        Classified++;
        if (Classifier is { } classifier)
            return classifier(host, ct);
        var blocked = host.StartsWith("blocked", StringComparison.Ordinal);
        return Task.FromResult(new ClassifierVerdict
        {
            Host = host,
            Primary = blocked ? BlockLabel.SniBlock : BlockLabel.Open,
            Next = blocked ? NextStep.SearchStrategy : NextStep.Nothing,
            LiveAddresses = ["203.0.113.7"],
            Findings = [new LabelFinding(blocked ? BlockLabel.SniBlock : BlockLabel.Open, "203.0.113.7", ["RST after ClientHello, our address 192.168.1.10"])],
        });
    }

    public Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken ct) => Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Parse("203.0.113.7")]);

    /// <summary>Runs while the Agent "starts" (a UAC prompt, say); null starts it at once.</summary>
    public Func<Task>? AgentStarting { get; set; }

    public async Task<IEngineControl> EngineAsync(CancellationToken ct)
    {
        if (AgentStarting is { } starting)
            await starting();
        return Engine;
    }

    public Task<ProbeResult> ProbeAsync(HttpProbeOptions options, CancellationToken ct)
    {
        bool works = Engine.Works || options.Host.StartsWith("open", StringComparison.Ordinal);
        if (Probe is not null)
            return Task.FromResult(Probe(options, works));
        return Task.FromResult(works
            ? new ProbeResult { Host = options.Host, Address = options.Address.ToString(), ConnectOk = true, TlsOk = true, CertValid = true, HttpStatus = 200, BodyBytes = 200_000, BytesIn = 201_000, Complete = true, BodySha256 = new string('a', 64), Duration = TimeSpan.FromMilliseconds(120) }
            : new ProbeResult { Host = options.Host, Address = options.Address.ToString(), ConnectOk = true, Error = ProbeError.TlsReset, RstSeen = true, RstOrigin = RstOrigin.Injected, ErrorDetail = "reset from 192.168.1.10 side", Duration = TimeSpan.FromMilliseconds(40) });
    }

    public Task CommitAsync(Solution solution, CancellationToken ct)
    {
        Committed.Add(solution);
        return Task.CompletedTask;
    }

    public Task<string> SaveExportAsync(string name, byte[] zip, CancellationToken ct)
    {
        Saved.Add(name);
        return Task.FromResult(name);
    }

    /// <summary>zapret-gui on the router; null is "not set up in AutoTuner".</summary>
    public Delivery.ZapretGuiExperiments? Router { get; set; }

    public List<(IReadOnlyList<string> Targets, string Strategy)> RouterCommits { get; } = [];

    public Delivery.ZapretGuiExperiments? RouterExperiments() => Router;

    /// <summary>zapret-gui's MCP link for relaying its tools (router_proxy); null is "not set up".</summary>
    public Delivery.ZapretGuiMcp? RouterLink { get; set; }

    public Delivery.ZapretGuiMcp? RouterMcp() => RouterLink;

    public void RouterCommitted(IReadOnlyList<string> targets, string strategy) => RouterCommits.Add((targets, strategy));

    public ResourceStore? Resources { get; set; }

    /// <summary>The configured router of resource pushes; null: none is configured.</summary>
    public Func<Delivery.RouterResourceAction, Core.Resources.ResourceKind, string, Delivery.RouterResourceOperation>? ResourceRouter { get; set; }

    public Task<Delivery.RouterResourceOperation> PrepareRouterResourceAsync(Delivery.RouterResourceAction action, Core.Resources.ResourceKind kind, string name, CancellationToken ct) =>
        ResourceRouter is null ? throw new InvalidOperationException("no router is configured") : Task.FromResult(ResourceRouter(action, kind, name));

    public void Dispose() => Kb.Dispose();
}

/// <summary>A clock the test moves by hand.</summary>
internal sealed class ManualTime : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => Now;
}

/// <summary>A session over the fakes with the given switches.</summary>
internal sealed class Rig : IDisposable
{
    public Rig(McpPermissions? permissions = null, BudgetOptions? budget = null, TimeProvider? time = null)
    {
        Permissions = permissions ?? new McpPermissions();
        Session = new McpSession(Host, Confirm, () => Permissions, budget, time);
        Tools = new AutoTunerTools(Session);
    }

    public FakeHost Host { get; } = new();

    public FakeConfirm Confirm { get; } = new();

    public McpPermissions Permissions { get; set; }

    public McpSession Session { get; }

    public AutoTunerTools Tools { get; }

    public static McpPermissions All => new(Probes: true, Control: true, Experiments: true, Export: true, Router: true);

    public Task<McpToolResult> Call(string tool, string json = "{}") =>
        Tools.CallAsync(tool, System.Text.Json.Nodes.JsonNode.Parse(json)!.AsObject(), "test");

    /// <summary>Waits until the condition holds (background work of the search and the experiment).</summary>
    public static async Task Until(Func<Task<bool>> condition, int seconds = 20)
    {
        var end = DateTime.UtcNow.AddSeconds(seconds);
        while (!await condition())
        {
            if (DateTime.UtcNow > end)
                throw new TimeoutException("condition not reached");
            await Task.Delay(20);
        }
    }

    public void Dispose() => Host.Dispose();
}
