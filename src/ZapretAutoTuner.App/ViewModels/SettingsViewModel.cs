using Avalonia;
using Avalonia.Styling;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>Settings, kept in the knowledge base. The zapret-gui token is kept in memory for this run only.</summary>
public sealed partial class SettingsViewModel : PageViewModel
{
    private readonly AppHost _host;
    private readonly McpService _mcp;
    private bool _loading;

    public SettingsViewModel(AppHost host, McpService mcp)
    {
        _host = host;
        _mcp = mcp;
        mcp.Stopped += LoadMcp;
        mcp.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(McpService.HttpStatus))
                RefreshBridge();
        };
        L.PropertyChanged += (_, _) => RefreshBridge();
        LoadMcp();
        _bridgeOriginsText = string.Join("\n", host.Settings.McpBridgeOrigins);
        _english = L.English;
        _themeIndex = host.Settings.Theme switch { "light" => 1, "dark" => 2, _ => 0 };
        _modeIndex = Array.IndexOf(Modes, host.Settings.SearchMode) is var i and >= 0 ? i : 1;
        _autoApply = host.Settings.ApplyPolicy == "auto";
        _learning = host.Settings.Learning;
        _providerAsn = host.Settings.ProviderAsn;
        host.Settings.ApplyPolicyChanged += () => AutoApply = host.Settings.ApplyPolicy == "auto";
        _guiUrl = host.Settings.GuiUrl;
        _guiToken = host.Settings.GuiToken;
        _routerHost = host.Settings.RouterHost;
        _largeFont = host.Settings.LargeFont;
        _advisorEnabled = host.Settings.AdvisorEnabled;
        _advisorProviderIndex = host.Settings.AdvisorProvider == ZapretAutoTuner.Mcp.Advisor.AdvisorProvider.Claude ? 0 : 1;
        _advisorModel = host.Settings.AdvisorModel;
        _advisorEndpoint = host.Settings.AdvisorEndpoint;
        _advisorKey = host.Settings.AdvisorKey;
    }

    public override string TitleKey => "nav.settings";

    public static string[] Modes { get; } = ["Quick", "Standard", "Full"];

    public string DataDir => _host.DataDir;

    [ObservableProperty]
    private bool _english;

    [ObservableProperty]
    private int _themeIndex;

    [ObservableProperty]
    private int _modeIndex;

    [ObservableProperty]
    private bool _autoApply;

    [ObservableProperty]
    private bool _learning;

    [ObservableProperty]
    private string _providerAsn;

    [ObservableProperty]
    private string _guiUrl;

    [ObservableProperty]
    private string _guiToken;

    [ObservableProperty]
    private string _routerHost;

    [ObservableProperty]
    private bool _largeFont;

    [ObservableProperty]
    private bool _mcpEnabled;

    [ObservableProperty]
    private bool _mcpHttp;

    [ObservableProperty]
    private bool _permProbes;

    [ObservableProperty]
    private bool _permControl;

    [ObservableProperty]
    private bool _permExperiments;

    [ObservableProperty]
    private bool _permExport;

    [ObservableProperty]
    private bool _permRouter;

    [ObservableProperty]
    private bool _permResources;

    [ObservableProperty]
    private bool _permRouterProxy;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BridgeProxyHttpSnippet), nameof(BridgeDirectSnippet))]
    private string _mcpToken = "";

    [ObservableProperty]
    private string _mcpError = "";

    public McpService Mcp => _mcp;

    /// <summary>For Claude Desktop's claude_desktop_config.json: the stdio command of this program.</summary>
    public string StdioSnippet => ZapretAutoTuner.Mcp.McpClientConfig.ClaudeDesktop(Environment.ProcessPath ?? "ZapretAutoTuner");

    private void LoadMcp()
    {
        _loading = true;
        McpEnabled = _host.Settings.McpEnabled;
        McpHttp = _host.Settings.McpHttp;
        var p = _host.Settings.McpPermissions;
        (PermProbes, PermControl, PermExperiments, PermExport, PermRouter, PermResources, PermRouterProxy) = (p.Probes, p.Control, p.Experiments, p.Export, p.Router, p.Resources, p.RouterProxy);
        McpToken = _host.Settings.McpToken;
        _loading = false;
    }

    partial void OnMcpEnabledChanged(bool value) => SaveMcp();

    partial void OnMcpHttpChanged(bool value) => SaveMcp();

    partial void OnPermProbesChanged(bool value) => SaveMcp();

    partial void OnPermControlChanged(bool value) => SaveMcp();

    partial void OnPermExperimentsChanged(bool value) => SaveMcp();

    partial void OnPermExportChanged(bool value) => SaveMcp();

    partial void OnPermRouterChanged(bool value) => SaveMcp();

    partial void OnPermResourcesChanged(bool value) => SaveMcp();

    partial void OnPermRouterProxyChanged(bool value)
    {
        SaveMcp();
        OnPropertyChanged(nameof(BridgeGuiMissing));
    }

    private void SaveMcp()
    {
        if (_loading)
            return;
        bool turnedOff = _host.Settings.McpEnabled && !McpEnabled;
        _host.Settings.McpEnabled = McpEnabled;
        _host.Settings.McpHttp = McpHttp;
        _host.Settings.McpPermissions = new ZapretAutoTuner.Mcp.McpPermissions(PermProbes, PermControl, PermExperiments, PermExport, PermRouter, PermResources, PermRouterProxy);
        // a permission toggled while MCP is off changes only the settings: nothing runs that could be stopped
        if (McpEnabled || turnedOff)
            _ = ApplyMcpAsync();
    }

    private async Task ApplyMcpAsync()
    {
        try
        {
            // off means off: the same full stop as the banner's button (stdio closes, the search and the experiments
            // stop and roll back, dialogs go), not only the HTTP transport; only when MCP is switched off
            if (!McpEnabled)
                await _mcp.StopAsync();
            else
                await _mcp.ApplyAsync();
            McpError = "";
        }
        catch (Exception e) when (e is IOException or InvalidOperationException or System.Net.Sockets.SocketException)
        {
            McpError = e.Message;
        }
    }

    /// <summary>A new token: clients holding the old one are refused from now on.</summary>
    [RelayCommand]
    private async Task NewTokenAsync()
    {
        _host.Settings.McpToken = ZapretAutoTuner.Mcp.McpHttpServer.NewToken();
        McpToken = _host.Settings.McpToken;
        await _mcp.RestartHttpAsync();
    }

    partial void OnEnglishChanged(bool value)
    {
        L.English = value;
        _host.Settings.Language = value ? "en" : "ru";
    }

    partial void OnThemeIndexChanged(int value)
    {
        _host.Settings.Theme = value switch { 1 => "light", 2 => "dark", _ => "system" };
        App.ApplyTheme(_host.Settings.Theme);
    }

    partial void OnModeIndexChanged(int value) => _host.Settings.SearchMode = Modes[Math.Clamp(value, 0, Modes.Length - 1)];

    partial void OnAutoApplyChanged(bool value) => _host.Settings.ApplyPolicy = value ? "auto" : "ask";

    partial void OnLearningChanged(bool value) => _host.Settings.Learning = value;

    partial void OnProviderAsnChanged(string value) => _host.Settings.ProviderAsn = value;

    partial void OnGuiUrlChanged(string value)
    {
        _host.Settings.GuiUrl = value.Trim();
        OnPropertyChanged(nameof(BridgeGuiMissing));
    }

    partial void OnGuiTokenChanged(string value)
    {
        _host.Settings.GuiToken = value;
        OnPropertyChanged(nameof(BridgeGuiMissing));
    }

    // ---- the browser extension bridge (PLAN 4a.7): the same HTTP endpoint, extensions' Origins, snippets

    /// <summary>The allowed Origins as the user types them; valid ones are kept and act at once.</summary>
    [ObservableProperty]
    private string _bridgeOriginsText;

    [ObservableProperty]
    private string _bridgeOriginsError = "";

    /// <summary>The snippets show the real token only when asked.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BridgeProxyHttpSnippet), nameof(BridgeDirectSnippet))]
    private bool _bridgeRevealToken;

    public bool BridgeOriginsEmpty => _host.Settings.McpBridgeOrigins.Count == 0;

    /// <summary>router_proxy is on but there is no zapret-gui to relay.</summary>
    public bool BridgeGuiMissing => PermRouterProxy && !_host.Router.Configured;

    partial void OnBridgeOriginsTextChanged(string value)
    {
        var (valid, invalid) = ZapretAutoTuner.Mcp.BridgeOrigins.Parse(value);
        _host.Settings.McpBridgeOrigins = valid;
        _mcp.BridgeOrigins = valid;
        BridgeOriginsError = invalid.Count == 0 ? "" : L.F("mcp.bridge_origins_invalid", string.Join(", ", invalid));
        OnPropertyChanged(nameof(BridgeOriginsEmpty));
    }

    private Uri? BridgeEndpoint => _mcp.HttpEndpoint ?? (_host.Settings.McpPort > 0 ? new Uri($"http://127.0.0.1:{_host.Settings.McpPort}{ZapretAutoTuner.Mcp.McpHttpServer.Path}") : null);

    private string SnippetToken => BridgeRevealToken ? McpToken : L["mcp.bridge_token_hidden"];

    /// <summary>For a local proxy's mcpConfig: <c>ZapretAutoTuner mcp</c>, which relays to this window.</summary>
    public string BridgeProxyStdioSnippet => ZapretAutoTuner.Mcp.McpClientConfig.ProxyStdio(Environment.ProcessPath ?? "ZapretAutoTuner");

    public string BridgeProxyHttpSnippet => BridgeEndpoint is { } e ? ZapretAutoTuner.Mcp.McpClientConfig.ProxyHttp(e, SnippetToken) : L["mcp.bridge_no_http"];

    public string BridgeDirectSnippet => BridgeEndpoint is { } e
        ? ZapretAutoTuner.Mcp.McpClientConfig.Direct(e, new Uri($"http://127.0.0.1:{e.Port}{ZapretAutoTuner.Mcp.McpHttpServer.SsePath}"), SnippetToken)
        : L["mcp.bridge_no_http"];

    private void RefreshBridge()
    {
        OnPropertyChanged(nameof(BridgeProxyHttpSnippet));
        OnPropertyChanged(nameof(BridgeDirectSnippet));
    }

    /// <summary>The wizard edits the same zapret-gui address and token: the settings are the source.</summary>
    public override void OnShown()
    {
        if (GuiUrl.Trim() != _host.Settings.GuiUrl)
            GuiUrl = _host.Settings.GuiUrl;
        if (GuiToken != _host.Settings.GuiToken)
            GuiToken = _host.Settings.GuiToken;
        if (RouterHost != _host.Settings.RouterHost)
            RouterHost = _host.Settings.RouterHost;
    }

    /// <summary>Forgets the remembered SSH host keys, after the user changed the router or its key on purpose.</summary>
    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private void ForgetSshKeys()
    {
        foreach (var k in _host.Kb.AllSettings().Keys.Where(k => k.StartsWith("ssh.hostkey.", StringComparison.Ordinal)).ToList())
            _host.Kb.RemoveSetting(k);
        SshKeysStatus = L["settings.ssh_forgotten"];
    }

    [ObservableProperty]
    private string _sshKeysStatus = "";

    partial void OnRouterHostChanged(string value) => _host.Settings.RouterHost = value.Trim();

    // ---- the built-in advisor (PLAN 4a.2, MCP M4); the key stays in memory for this run only

    [ObservableProperty]
    private bool _advisorEnabled;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AdvisorLocal))]
    private int _advisorProviderIndex;

    [ObservableProperty]
    private string _advisorModel;

    [ObservableProperty]
    private string _advisorEndpoint;

    [ObservableProperty]
    private string _advisorKey;

    public bool AdvisorLocal => AdvisorProviderIndex == 1;

    partial void OnAdvisorEnabledChanged(bool value) => _host.Settings.AdvisorEnabled = value;

    partial void OnAdvisorProviderIndexChanged(int value)
    {
        var p = value == 1 ? ZapretAutoTuner.Mcp.Advisor.AdvisorProvider.OpenAiCompatible : ZapretAutoTuner.Mcp.Advisor.AdvisorProvider.Claude;
        if (p == _host.Settings.AdvisorProvider)
            return;
        _host.Settings.AdvisorProvider = p;
        // the other provider's default model does not fit this one
        AdvisorModel = p == ZapretAutoTuner.Mcp.Advisor.AdvisorProvider.Claude ? ZapretAutoTuner.Mcp.Advisor.AdvisorOptions.DefaultClaudeModel : ZapretAutoTuner.Mcp.Advisor.AdvisorOptions.DefaultLocalModel;
    }

    partial void OnAdvisorModelChanged(string value) => _host.Settings.AdvisorModel = value;

    partial void OnAdvisorEndpointChanged(string value) => _host.Settings.AdvisorEndpoint = value;

    partial void OnAdvisorKeyChanged(string value) => _host.Settings.AdvisorKey = value;

    partial void OnLargeFontChanged(bool value)
    {
        _host.Settings.LargeFont = value;
        App.ApplyFont(value);
    }
}
