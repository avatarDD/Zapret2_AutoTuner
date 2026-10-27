using System.ComponentModel;
using System.Globalization;
using System.Reflection;
using System.Text.Json;
using Avalonia.Data;
using Avalonia.Markup.Xaml;

namespace ZapretAutoTuner.App.Loc;

/// <summary>
/// UI texts in Russian (the main language) and English (AGENTS.md rule 9). Keys live in <c>strings.json</c> as
/// a key mapped to <c>[ru, en]</c>; switching the language updates every bound text at once.
/// </summary>
public sealed class Loc : INotifyPropertyChanged
{
    private readonly Dictionary<string, string[]> _texts;
    private bool _english;

    public static Loc I { get; } = new();

    private Loc()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("ZapretAutoTuner.App.strings.json")
            ?? throw new InvalidOperationException("strings.json resource missing");
        _texts = JsonSerializer.Deserialize<Dictionary<string, string[]>>(s) ?? [];
        _english = !CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.Equals("ru", StringComparison.OrdinalIgnoreCase)
            && !CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.Equals("uk", StringComparison.OrdinalIgnoreCase)
            && !CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.Equals("be", StringComparison.OrdinalIgnoreCase);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public bool English
    {
        get => _english;
        set
        {
            if (_english == value)
                return;
            _english = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(English)));
        }
    }

    public IReadOnlyCollection<string> Keys => _texts.Keys;

    public string this[string key] => _texts.TryGetValue(key, out var t) ? t[_english && t.Length > 1 ? 1 : 0] : key;

    /// <summary>A key with {0}… placeholders.</summary>
    public string F(string key, params object?[] args) => string.Format(CultureInfo.CurrentCulture, this[key], args);

    /// <summary>Picks the text of a (ru, en) pair produced by the core.</summary>
    public string Pick(string ru, string en) => _english ? en : ru;

    /// <summary>Every key has both languages (a test checks it).</summary>
    public IEnumerable<string> Incomplete => _texts.Where(kv => kv.Value.Length < 2 || kv.Value.Any(string.IsNullOrWhiteSpace)).Select(kv => kv.Key);
}

/// <summary>In XAML, <c>l:T</c> with a key: a live binding to the text of <c>key</c>.</summary>
public sealed class TExtension(string key) : MarkupExtension
{
    public string Key { get; } = key;

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new Binding($"[{Key}]") { Source = Loc.I, Mode = BindingMode.OneWay };
}
