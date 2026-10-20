using Avalonia;
using Avalonia.Styling;
using CommunityToolkit.Mvvm.ComponentModel;
using ZapretAutoTuner.App.Services;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>Settings, kept in the knowledge base. Secrets (the MCP token) are kept only when the user asks.</summary>
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
        _learning = host.Settings.Learning;
        _providerAsn = host.Settings.ProviderAsn;
        _guiUrl = host.Settings.GuiUrl;
        _rememberToken = host.Settings.GuiToken.Length > 0;
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
    private bool _rememberToken;

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

    partial void OnLearningChanged(bool value) => _host.Settings.Learning = value;

    partial void OnProviderAsnChanged(string value) => _host.Settings.ProviderAsn = value;

    partial void OnGuiUrlChanged(string value) => _host.Settings.GuiUrl = value.Trim();

    partial void OnGuiTokenChanged(string value) => _host.Settings.GuiToken = RememberToken ? value : "";

    partial void OnRememberTokenChanged(bool value) => _host.Settings.GuiToken = value ? GuiToken : "";

    partial void OnRouterHostChanged(string value) => _host.Settings.RouterHost = value.Trim();

    partial void OnLargeFontChanged(bool value)
    {
        _host.Settings.LargeFont = value;
        App.ApplyFont(value);
    }
}
