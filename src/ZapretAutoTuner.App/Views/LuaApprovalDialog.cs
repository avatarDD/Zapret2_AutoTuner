using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Layout;
using Avalonia.Media;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.Core.Resources;

namespace ZapretAutoTuner.App.Views;

/// <summary>
/// Approving a Lua script (PLAN 4a.5): it runs with the engine's rights, so the user sees the whole text, the diff with
/// the version in effect and the check's warnings before "Подтвердить". "Отмена" is the default button.
/// </summary>
public static class LuaApprovalDialog
{
    private static readonly IBrush Added = new SolidColorBrush(Color.FromRgb(0x2E, 0x9E, 0x5B));
    private static readonly IBrush Removed = new SolidColorBrush(Color.FromRgb(0xD0, 0x44, 0x3E));

    public static async Task<bool> AskAsync(Window owner, LuaApprovalRequest r)
    {
        var dialog = new Window
        {
            Title = Loc.Loc.I.F("resources.approve_title", r.Name),
            Width = 860,
            Height = 720,
            MinWidth = 520,
            MinHeight = 420,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = Build(r, out var yes, out var no),
        };
        yes.Click += (_, _) => dialog.Close(true);
        no.Click += (_, _) => dialog.Close(false);
        return await dialog.ShowDialog<bool?>(owner) == true;
    }

    /// <summary>The dialog's content (also built by the view tests).</summary>
    public static Control Build(LuaApprovalRequest r, out Button yes, out Button no)
    {
        var L = Loc.Loc.I;
        yes = new Button { Content = L["resources.approve_yes"], Classes = { "accent" } };
        no = new Button { Content = L["resources.approve_no"], IsDefault = true, IsCancel = true };
        var header = new StackPanel
        {
            Spacing = 6,
            Children =
            {
                new TextBlock { Text = L.F("resources.approve_title", r.Name), FontSize = 16, FontWeight = FontWeight.SemiBold },
                new TextBlock
                {
                    Text = L.F("resources.approve_text", r.Version, r.ApprovedVersion is { } a ? L.F("resources.approve_from", a) : L["resources.approve_first"], r.Diff.Added, r.Diff.Removed),
                    TextWrapping = TextWrapping.Wrap,
                },
            },
        };
        foreach (var p in r.Problems)
            header.Children.Add(new TextBlock { Text = (p.IsError ? "✖ " : "⚠ ") + p.Message(!L.English), TextWrapping = TextWrapping.Wrap });

        var diff = new SelectableTextBlock { FontFamily = new FontFamily("monospace"), FontSize = 12 };
        foreach (var line in r.Diff.Lines)
        {
            var run = new Run(line + "\n");
            if (line.Kind == DiffKind.Added)
                run.Foreground = Added;
            else if (line.Kind == DiffKind.Removed)
                run.Foreground = Removed;
            diff.Inlines!.Add(run);
        }
        var tabs = new TabControl
        {
            Items =
            {
                new TabItem { Header = L["resources.approve_diff"], Content = new ScrollViewer { Content = diff, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto } },
                new TabItem
                {
                    Header = L["resources.approve_full"],
                    Content = new ScrollViewer
                    {
                        HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto,
                        Content = new SelectableTextBlock { Text = r.Source, FontFamily = new FontFamily("monospace"), FontSize = 12 },
                    },
                },
            },
        };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Spacing = 8, Children = { no, yes } };
        var panel = new DockPanel { Margin = new(20) };
        DockPanel.SetDock(header, Dock.Top);
        DockPanel.SetDock(buttons, Dock.Bottom);
        buttons.Margin = new(0, 12, 0, 0);
        panel.Children.Add(header);
        panel.Children.Add(buttons);
        panel.Children.Add(tabs);
        return panel;
    }
}
