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
        DataDir = dataDir ?? DefaultDataDir;
        Directory.CreateDirectory(DataDir);
        Kb = KnowledgeBase.Open(Path.Combine(DataDir, "knowledge.db"));
        Bundle = new Zapret2Bundle(Path.Combine(AppContext.BaseDirectory, "zapret2"));
        Settings = new AppSettings(Kb);
    }

    public static AppHost? Current { get; set; }

    public static string DefaultDataDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ZapretAutoTuner");

    public string DataDir { get; }

    public KnowledgeBase Kb { get; }

    public Zapret2Bundle Bundle { get; }

    public AppSettings Settings { get; }

    public bool AgentRunning => _agent is not null;

    /// <summary>zapret-gui on the router: the experiments link and the feedback after a commit (PLAN 7.6).</summary>
    public RouterService Router => _router ??= new RouterService(this);

    private RouterService? _router;

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
        if (_router is not null)
            await _router.DisposeAsync().ConfigureAwait(false);
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
    /// The zapret-gui MCP token is a secret and the knowledge base is a plain file: it lives in memory for this run only (no
    /// protected store is available on both platforms without another dependency).
    /// </summary>
    public string GuiToken { get; set; } = "";

    public string RouterHost
    {
        get => kb.GetSetting("router.host") ?? "";
        set => kb.SetSetting("router.host", value);
    }

    /// <summary>Learned search order (PLAN 4a.1): on by default; off is the generator's static order.</summary>
    public bool Learning
    {
        get => kb.GetSetting("search.learning") != "0";
        set => kb.SetSetting("search.learning", value ? "1" : "0");
    }

    /// <summary>The provider's ASN as the user entered it ("AS12389" or "12389"); empty when unknown. Nothing is looked up online.</summary>
    public string ProviderAsn
    {
        get => kb.GetSetting("search.asn") ?? "";
        set
        {
            if (string.IsNullOrWhiteSpace(value))
                kb.RemoveSetting("search.asn");
            else
                kb.SetSetting("search.asn", value.Trim());
        }
    }
    /// <summary>The SSH host key remembered for a router (trust on first use), or null.</summary>
    public string? RouterHostKey(string host, int port) => kb.GetSetting(Delivery.HostKeys.SettingKey(host, port));

    public void RememberRouterHostKey(string host, int port, string fingerprint) => kb.SetSetting(Delivery.HostKeys.SettingKey(host, port), fingerprint);

    public bool LargeFont
    {
        get => kb.GetSetting("ui.large_font") == "1";
        set => kb.SetSetting("ui.large_font", value ? "1" : "0");
    }

    /// <summary>The MCP server; off by default, and the Stop button turns it off again.</summary>
    public bool McpEnabled
    {
        get => Flag("mcp.enabled");
        set => SetFlag("mcp.enabled", value);
    }

    /// <summary>Streamable HTTP on 127.0.0.1 next to stdio; off by default.</summary>
    public bool McpHttp
    {
        get => Flag("mcp.http");
        set => SetFlag("mcp.http", value);
    }

    /// <summary>The HTTP port; 0 until the first start picks a free one, then kept so clients keep working.</summary>
    public int McpPort
    {
        get => int.TryParse(kb.GetSetting("mcp.port"), out var p) && p is > 0 and < 65536 ? p : 0;
        set => kb.SetSetting("mcp.port", value.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// The local bearer token of our own HTTP transport, generated on first use. It is kept (unlike <see cref="GuiToken"/>):
    /// it only opens a loopback port, and <c>ZapretAutoTuner mcp</c> needs it to relay stdio to a running window.
    /// </summary>
    public string McpToken
    {
        get
        {
            var t = kb.GetSetting("mcp.token");
            if (!string.IsNullOrEmpty(t))
                return t;
            t = Mcp.McpHttpServer.NewToken();
            kb.SetSetting("mcp.token", t);
            return t;
        }
        set => kb.SetSetting("mcp.token", value);
    }

    /// <summary>The permission groups beyond "read" (all off by default, as in zapret-gui).</summary>
    public Mcp.McpPermissions McpPermissions
    {
        get => new(Flag("mcp.perm.probes"), Flag("mcp.perm.control"), Flag("mcp.perm.experiments"), Flag("mcp.perm.export"), Flag("mcp.perm.router"));
        set
        {
            SetFlag("mcp.perm.probes", value.Probes);
            SetFlag("mcp.perm.control", value.Control);
            SetFlag("mcp.perm.experiments", value.Experiments);
            SetFlag("mcp.perm.export", value.Export);
            SetFlag("mcp.perm.router", value.Router);
        }
    }

    /// <summary>The user's targets (the wizard's domains and the ones added over MCP after a yes).</summary>
    public IReadOnlyList<string> Targets
    {
        get
        {
            try
            {
                return System.Text.Json.JsonSerializer.Deserialize<List<string>>(kb.GetSetting("targets.list") ?? "[]") ?? [];
            }
            catch (System.Text.Json.JsonException)
            {
                return [];
            }
        }
        set => kb.SetSetting("targets.list", System.Text.Json.JsonSerializer.Serialize(value.Distinct(StringComparer.OrdinalIgnoreCase).Take(500).ToList()));
    }

    public void AddTargets(IEnumerable<string> hosts)
    {
        var list = Targets.ToList();
        foreach (var h in hosts)
        {
            var host = h.Trim().TrimEnd('.').ToLowerInvariant();
            if (Core.Model.Target.IsValidHostName(host) && !list.Contains(host, StringComparer.OrdinalIgnoreCase))
                list.Add(host);
        }
        Targets = list;
    }

    private bool Flag(string key) => kb.GetSetting(key) == "1";

    private void SetFlag(string key, bool value) => kb.SetSetting(key, value ? "1" : "0");
}
