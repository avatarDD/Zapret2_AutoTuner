using Avalonia;
using Avalonia.Styling;
using CommunityToolkit.Mvvm.ComponentModel;
using ZapretAutoTuner.App.Services;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>Settings, kept in the knowledge base. Secrets (the MCP token) are kept in memory for this run only.</summary>
public sealed partial class SettingsViewModel : PageViewModel
{
    private readonly AppHost _host;

    public SettingsViewModel(AppHost host)
    {
        _host = host;
        _english = L.English;
        _themeIndex = host.Settings.Theme switch { "light" => 1, "dark" => 2, _ => 0 };
        _modeIndex = Array.IndexOf(Modes, host.Settings.SearchMode) is var i and >= 0 ? i : 1;
        _autoApply = host.Settings.ApplyPolicy == "auto";
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
    private string _guiUrl;

    [ObservableProperty]
    private string _guiToken;

    [ObservableProperty]
    private string _routerHost;

    [ObservableProperty]
    private bool _largeFont;

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
