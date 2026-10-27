using Avalonia.Controls;
using ZapretAutoTuner.App.ViewModels;

namespace ZapretAutoTuner.App.Views;

public sealed partial class BugReportView : UserControl
{
    public BugReportView()
    {
        InitializeComponent();
        CloseButton.Click += (_, _) => (TopLevel.GetTopLevel(this) as Window)?.Close();
    }

    /// <summary>The dialog over <paramref name="owner"/>; nothing leaves the program unless the user presses a button in it.</summary>
    public static Task ShowAsync(Window owner, BugReportViewModel vm)
    {
        var dialog = new Window
        {
            Title = Loc.Loc.I["bugreport.title"],
            Width = 820,
            Height = 680,
            MinWidth = 520,
            MinHeight = 420,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = new BugReportView { DataContext = vm },
        };
        return dialog.ShowDialog(owner);
    }
}
