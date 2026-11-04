using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;

namespace ZapretAutoTuner.App.Views;

/// <summary>
/// The small "?" next to a section or a button: a click opens a short explanation with an example
/// (<c>Text</c> bound to a <c>help.*</c> text). Lines that start with "Пример:" / "Example:" are shown apart.
/// </summary>
public sealed class HelpButton : Button
{
    public static readonly StyledProperty<string?> TextProperty = AvaloniaProperty.Register<HelpButton, string?>(nameof(Text));

    public HelpButton()
    {
        Content = "?";
        Padding = new Thickness(7, 1);
        MinWidth = 0;
        FontWeight = FontWeight.SemiBold;
        VerticalAlignment = VerticalAlignment.Center;
        CornerRadius = new CornerRadius(10);
        Margin = new Thickness(6, 0, 0, 0);
    }

    protected override Type StyleKeyOverride => typeof(Button);

    public string? Text
    {
        get => GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == TextProperty)
            AutomationName(Text);
    }

    private void AutomationName(string? text) =>
        Avalonia.Automation.AutomationProperties.SetName(this, text is { Length: > 0 } t ? t.Split('\n')[0] : "?");

    protected override void OnClick()
    {
        base.OnClick();
        var panel = new StackPanel { Spacing = 6, MaxWidth = 460 };
        foreach (var line in (Text ?? "").Split('\n'))
        {
            bool example = line.StartsWith("Пример:", StringComparison.Ordinal) || line.StartsWith("Example:", StringComparison.Ordinal);
            panel.Children.Add(new SelectableTextBlock
            {
                Text = line,
                TextWrapping = TextWrapping.Wrap,
                FontFamily = example ? new FontFamily("monospace") : FontFamily.Default,
                FontSize = example ? 12 : 13,
                Opacity = example ? 0.85 : 1,
            });
        }
        var flyout = new Flyout { Content = panel, Placement = PlacementMode.BottomEdgeAlignedLeft };
        flyout.ShowAt(this);
    }

    /// <summary>For tests: what the flyout shows.</summary>
    internal IEnumerable<string> Lines => (Text ?? "").Split('\n');
}
