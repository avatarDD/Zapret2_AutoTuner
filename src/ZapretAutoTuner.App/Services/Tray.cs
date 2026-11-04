using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform;
using Avalonia.Threading;
using ZapretAutoTuner.App.ViewModels;

namespace ZapretAutoTuner.App.Services;

/// <summary>
/// The tray icon: a click opens the window, the menu turns the Auto bypass on or off and exits. The window hides to the
/// tray on minimize (and, if the user chose so, on close): the bypass keeps working while the program runs.
/// </summary>
public sealed class Tray : IDisposable
{
    private readonly IClassicDesktopStyleApplicationLifetime _desktop;
    private readonly MainWindow _window;
    private readonly AppHost _host;
    private readonly MainViewModel _main;
    private readonly TrayIcon _icon;
    private readonly NativeMenuItem _toggle;
    private bool _exiting;

    public Tray(Application app, IClassicDesktopStyleApplicationLifetime desktop, MainWindow window, AppHost host, MainViewModel main)
    {
        _desktop = desktop;
        _window = window;
        _host = host;
        _main = main;
        var open = new NativeMenuItem(Loc.Loc.I["tray.open"]);
        open.Click += (_, _) => Show();
        _toggle = new NativeMenuItem(Loc.Loc.I["tray.auto_on"]);
        _toggle.Click += (_, _) =>
        {
            if (_main.Auto.ToggleAutoCommand.CanExecute(null))
                _main.Auto.ToggleAutoCommand.Execute(null);
        };
        var exit = new NativeMenuItem(Loc.Loc.I["tray.exit"]);
        exit.Click += (_, _) => Exit();
        var menu = new NativeMenu { open, _toggle, new NativeMenuItemSeparator(), exit };
        menu.NeedsUpdate += (_, _) => UpdateTexts();
        _icon = new TrayIcon
        {
            Icon = new WindowIcon(AssetLoader.Open(new Uri("avares://ZapretAutoTuner/Assets/icon.ico"))),
            ToolTipText = "Zapret2 AutoTuner",
            Menu = menu,
            IsVisible = true,
        };
        _icon.Clicked += (_, _) => Show();
        TrayIcon.SetIcons(app, [_icon]);
        host.GenevaAuto.Changed += () => Dispatcher.UIThread.Post(UpdateTexts);
        Loc.Loc.I.PropertyChanged += (_, _) => Dispatcher.UIThread.Post(UpdateTexts);
        window.PropertyChanged += (_, e) =>
        {
            if (e.Property == Window.WindowStateProperty && window.WindowState == WindowState.Minimized && _host.Settings.MinimizeToTray)
                window.Hide();
        };
        window.Closing += (_, e) =>
        {
            // "закрывать в трей": the window goes, the program and its bypass stay; Exit in the menu really closes
            if (!_exiting && _host.Settings.CloseToTray && !e.IsProgrammatic && e.CloseReason == WindowCloseReason.WindowClosing)
            {
                e.Cancel = true;
                window.Hide();
            }
        };
        UpdateTexts();
    }

    private void UpdateTexts()
    {
        // not the whole View: it copies every service, and this runs on each change
        var auto = _host.GenevaAuto;
        bool running = auto.Running;
        var p = auto.CurrentPhase;
        _toggle.Header = Loc.Loc.I[running ? "tray.auto_off" : "tray.auto_on"];
        var phase = running ? (Loc.Loc.I.English ? p.En : p.Ru) : Loc.Loc.I["engine.auto_off"];
        // the tooltip has a short limit on Windows (127 characters)
        var tip = "Zapret2 AutoTuner — " + phase;
        _icon.ToolTipText = tip.Length > 120 ? tip[..120] : tip;
    }

    private void Show()
    {
        _window.Show();
        if (_window.WindowState == WindowState.Minimized)
            _window.WindowState = WindowState.Normal;
        _window.Activate();
    }

    private void Exit()
    {
        _exiting = true;
        _desktop.Shutdown();
    }

    public void Dispose()
    {
        _icon.IsVisible = false;
        _icon.Dispose();
    }
}
