using Avalonia.Controls;
using Avalonia.Platform.Storage;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.App.Views;

namespace ZapretAutoTuner.App;

public sealed partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => Wire();
    }

    /// <summary>Gives the view models the few things only a window can do: files, clipboard, the yes/no dialog.</summary>
    private void Wire()
    {
        if (DataContext is not MainViewModel m)
            return;
        m.Wizard.SaveFile = m.Reports.SaveFile = SaveFileAsync;
        m.Wizard.CopyText = m.Reports.CopyText = CopyAsync;
        m.Wizard.Confirm = (title, text) => ConfirmDialog.AskAsync(this, title, text);
        m.Expert.OpenFile = OpenFileAsync;
        m.Mcp.Ask = (title, text) => ConfirmDialog.AskAsync(this, title, text);
    }

    private async Task SaveFileAsync(string name, byte[] bytes)
    {
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { SuggestedFileName = name });
        if (file is null)
            return;
        await using var s = await file.OpenWriteAsync();
        await s.WriteAsync(bytes);
    }

    private async Task<(string, byte[])?> OpenFileAsync()
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { AllowMultiple = false });
        if (files.Count == 0)
            return null;
        await using var s = await files[0].OpenReadAsync();
        using var ms = new MemoryStream();
        await s.CopyToAsync(ms);
        return (files[0].Name, ms.ToArray());
    }

    private async Task CopyAsync(string text)
    {
        if (Clipboard is not null)
            await Clipboard.SetTextAsync(text);
    }
}
