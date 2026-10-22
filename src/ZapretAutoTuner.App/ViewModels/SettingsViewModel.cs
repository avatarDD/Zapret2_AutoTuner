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
        LoadMcp();
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
    private bool _permResources;

    [ObservableProperty]
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
        (PermProbes, PermControl, PermExperiments, PermExport, PermResources) = (p.Probes, p.Control, p.Experiments, p.Export, p.Resources);
        McpToken = _host.Settings.McpToken;
        _loading = false;
    }

    partial void OnMcpEnabledChanged(bool value) => SaveMcp();

    partial void OnMcpHttpChanged(bool value) => SaveMcp();

    partial void OnPermProbesChanged(bool value) => SaveMcp();

    partial void OnPermControlChanged(bool value) => SaveMcp();

    partial void OnPermExperimentsChanged(bool value) => SaveMcp();

    partial void OnPermExportChanged(bool value) => SaveMcp();

    partial void OnPermResourcesChanged(bool value) => SaveMcp();

    private void SaveMcp()
    {
        if (_loading)
            return;
        _host.Settings.McpEnabled = McpEnabled;
        _host.Settings.McpHttp = McpHttp;
        _host.Settings.McpPermissions = new ZapretAutoTuner.Mcp.McpPermissions(PermProbes, PermControl, PermExperiments, PermExport, PermResources);
        _ = ApplyMcpAsync();
    }

    private async Task ApplyMcpAsync()
    {
        try
        {
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

    partial void OnGuiUrlChanged(string value) => _host.Settings.GuiUrl = value.Trim();

    partial void OnGuiTokenChanged(string value) => _host.Settings.GuiToken = value;

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

    partial void OnLargeFontChanged(bool value)
    {
        _host.Settings.LargeFont = value;
        App.ApplyFont(value);
    }
}
