using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace ZapretAutoTuner.App.Views;

/// <summary>The yes/no dialog with the plan of what will be done (AGENTS.md rule 7). "Нет" is the default button.</summary>
public static class ConfirmDialog
{
    public static async Task<bool> AskAsync(Window owner, string title, string text)
    {
        var L = Loc.Loc.I;
        var yes = new Button { Content = L["common.yes"], Classes = { "accent" } };
        var no = new Button { Content = L["common.no"], IsDefault = true, IsCancel = true };
        var dialog = new Window
        {
            Title = title,
            Width = 560,
            SizeToContent = SizeToContent.Height,
            MaxHeight = 640,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false,
            Content = new StackPanel
            {
                Margin = new(20),
                Spacing = 12,
                Children =
                {
                    new TextBlock { Text = title, FontSize = 16, FontWeight = FontWeight.SemiBold, TextWrapping = TextWrapping.Wrap },
                    new ScrollViewer { MaxHeight = 420, Content = new SelectableTextBlock { Text = text, TextWrapping = TextWrapping.Wrap } },
                    new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Spacing = 8, Children = { no, yes } },
                },
            },
        };
        yes.Click += (_, _) => dialog.Close(true);
        no.Click += (_, _) => dialog.Close(false);
        return await dialog.ShowDialog<bool?>(owner) == true;
    }
}
