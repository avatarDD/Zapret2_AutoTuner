using ZapretAutoTuner.Protocol;
using ZapretAutoTuner.Storage;
using ZapretAutoTuner.Tools;

namespace ZapretAutoTuner.App.Services;

/// <summary>
/// The app's shared state: data folder, knowledge base, settings, the engine bundle and the Agent connection. The
/// UI itself never has rights (AGENTS.md rule 6): everything privileged goes through the Agent, started on demand.
/// </summary>
public sealed class AppHost : IAsyncDisposable
{
    private readonly SemaphoreSlim _agentGate = new(1, 1);
    private AgentConnection? _agent;

    public AppHost(string? dataDir = null)
    {
        DataDir = dataDir ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ZapretAutoTuner");
        Directory.CreateDirectory(DataDir);
        Kb = KnowledgeBase.Open(Path.Combine(DataDir, "knowledge.db"));
        Bundle = new Zapret2Bundle(Path.Combine(AppContext.BaseDirectory, "zapret2"));
        Settings = new AppSettings(Kb);
    }

    public static AppHost? Current { get; set; }

    public string DataDir { get; }

    public KnowledgeBase Kb { get; }

    public Zapret2Bundle Bundle { get; }

    public AppSettings Settings { get; }

    public bool AgentRunning => _agent is not null;

    /// <summary>The Agent dropped (crash, the user closed the elevation prompt): the UI says so and offers to restart.</summary>
    public event Action<string>? AgentLost;

    /// <summary>The Agent connection, started on first use (one UAC / pkexec prompt).</summary>
    public async Task<AgentConnection> AgentAsync(CancellationToken ct = default)
    {
        await _agentGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_agent is not null)
                return _agent;
            var agent = await AgentConnection.LaunchAsync(new AgentLaunchOptions
            {
                DataDir = Path.Combine(DataDir, "agent"),
                EnginePath = File.Exists(Bundle.EnginePath) ? Bundle.EnginePath : null,
            }, ct).ConfigureAwait(false);
            agent.Lost += (_, e) =>
            {
                _agent = null;
                AgentLost?.Invoke(e.Message);
            };
            _agent = agent;
            return agent;
        }
        finally
        {
            _agentGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        // the Agent removes its firewall rules and stops engines on shutdown (AGENTS.md rule 6)
        if (_agent is not null)
            await _agent.DisposeAsync().ConfigureAwait(false);
        Kb.Dispose();
        _agentGate.Dispose();
    }
}

/// <summary>Settings in the knowledge base's <c>settings</c> table (PLAN: SQLite for settings).</summary>
public sealed class AppSettings
{
    private readonly KnowledgeBase kb;

    public AppSettings(KnowledgeBase kb)
    {
        this.kb = kb;
        // earlier versions could keep the MCP token in plain text: it goes (see GuiToken)
        kb.RemoveSetting("gui.token");
    }

    /// <summary>The auto-apply choice changed (the settings page and the monitor show the same switch).</summary>
    public event Action? ApplyPolicyChanged;

    public string Language
    {
        get => kb.GetSetting("ui.language") ?? "";
        set => kb.SetSetting("ui.language", value);
    }

    public string Theme
    {
        get => kb.GetSetting("ui.theme") ?? "system";
        set => kb.SetSetting("ui.theme", value);
    }

    public string SearchMode
    {
        get => kb.GetSetting("search.mode") ?? "Standard";
        set => kb.SetSetting("search.mode", value);
    }

    /// <summary>"ask" (default) or "auto": whether the monitor applies a repaired strategy by itself (PLAN 7.3).</summary>
    public string ApplyPolicy
    {
        get => kb.GetSetting("monitor.apply") ?? "ask";
        set
        {
            if (value == ApplyPolicy)
                return;
            kb.SetSetting("monitor.apply", value);
            ApplyPolicyChanged?.Invoke();
        }
    }

    public string GuiUrl
    {
        get => kb.GetSetting("gui.url") ?? "";
        set => kb.SetSetting("gui.url", value);
    }

    /// <summary>
    /// The MCP token is a secret and the knowledge base is a plain file: it lives in memory for this run only (no
    /// protected store is available on both platforms without another dependency).
    /// </summary>
    public string GuiToken { get; set; } = "";

    public string RouterHost
    {
        get => kb.GetSetting("router.host") ?? "";
        set => kb.SetSetting("router.host", value);
    }

    /// <summary>The SSH host key remembered for a router (trust on first use), or null.</summary>
    public string? RouterHostKey(string host, int port) => kb.GetSetting(Delivery.HostKeys.SettingKey(host, port));

    public void RememberRouterHostKey(string host, int port, string fingerprint) => kb.SetSetting(Delivery.HostKeys.SettingKey(host, port), fingerprint);

    public bool LargeFont
    {
        get => kb.GetSetting("ui.large_font") == "1";
        set => kb.SetSetting("ui.large_font", value ? "1" : "0");
    }
}
