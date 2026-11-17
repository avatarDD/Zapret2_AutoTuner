using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.VisualTree;
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
        ApplyScale(App.Scale);
        App.ScaleChanged += ApplyScale;
        Closed += (_, _) => App.ScaleChanged -= ApplyScale;
    }

    private void ApplyScale(int percent)
    {
        var f = percent / 100.0;
        Scaled.LayoutTransform = Math.Abs(f - 1) < 0.001 ? null : new Avalonia.Media.ScaleTransform(f, f);
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
        m.Auto.SaveFile = SaveFileAsync;
        m.Auto.OpenFile = OpenFileAsync;
        m.Auto.CopyText = CopyAsync;
        m.Mcp.Ask = (title, text, ct) => ConfirmDialog.AskAsync(this, title, text, ct);
        m.Resources.Confirm = (title, text) => ConfirmDialog.AskAsync(this, title, text);
        m.Resources.ApproveDialog = r => LuaApprovalDialog.AskAsync(this, r);
        m.Confirm = (title, text) => ConfirmDialog.AskAsync(this, title, text);
        m.EnvironmentPage.OpenFolder = m.Settings.OpenFolder = OpenFolderAsync;
        m.EnvironmentPage.OpenUrl = async url => await Launcher.LaunchUriAsync(url);
        m.Resources.OpenFiles = OpenFilesAsync;
        m.Resources.SaveFile = SaveFileAsync;
        // a new page: the keyboard focus goes into it (it stayed in the menu), so Tab and a screen reader start there
        m.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(MainViewModel.Current))
                Avalonia.Threading.Dispatcher.UIThread.Post(FocusPage, Avalonia.Threading.DispatcherPriority.Loaded);
        };
        m.Reports.ReportProblem = m.Wizard.ReportProblem = m.Monitor.ReportProblem = m.Resources.ReportProblem = input => ReportProblemAsync(m, input);
    }

    /// <summary>"Сообщить о проблеме": the draft dialog; the browser opens only on its GitHub button.</summary>
    private Task ReportProblemAsync(MainViewModel m, Tuning.BugReportInput input)
    {
        var vm = new BugReportViewModel(input)
        {
            CopyText = CopyAsync,
            OpenUrl = async url => await Launcher.LaunchUriAsync(url),
            SaveArchive = m.Reports.SaveArchiveAsync,
        };
        return BugReportView.ShowAsync(this, vm);
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

    /// <summary>The first control of the new page takes the focus (no focus ring: it is not a Tab press).</summary>
    private void FocusPage()
    {
        if (Page.GetVisualDescendants().OfType<InputElement>().FirstOrDefault(c => c.Focusable && c.IsEffectivelyVisible && c.IsEffectivelyEnabled) is { } first
            && FocusManager?.GetFocusedElement() is not TextBox)
            first.Focus(NavigationMethod.Unspecified);
    }

    private async Task OpenFolderAsync(string path)
    {
        if (await StorageProvider.TryGetFolderFromPathAsync(path) is { } folder)
            await Launcher.LaunchFileAsync(folder);
    }

    /// <summary>Several files at once (the resources' import).</summary>
    private async Task<IReadOnlyList<(string Name, byte[] Bytes)>> OpenFilesAsync()
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { AllowMultiple = true });
        var result = new List<(string, byte[])>();
        foreach (var f in files)
        {
            await using var s = await f.OpenReadAsync();
            using var ms = new MemoryStream();
            await s.CopyToAsync(ms);
            result.Add((f.Name, ms.ToArray()));
        }
        return result;
    }

    private async Task CopyAsync(string text)
    {
        if (Clipboard is not null)
            await Clipboard.SetTextAsync(text);
    }
}
