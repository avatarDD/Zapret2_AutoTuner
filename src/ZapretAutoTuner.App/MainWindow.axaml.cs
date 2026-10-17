using Avalonia.Controls;
using ZapretAutoTuner.Core;

namespace ZapretAutoTuner.App;

public sealed partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        VersionText.Text = $"{AppInfo.Version} · zapret2 {AppInfo.Zapret2Version}";
    }
}
