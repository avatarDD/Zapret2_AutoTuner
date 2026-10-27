using System.Globalization;
using System.Text;

namespace ZapretAutoTuner.Core;

/// <summary>
/// Text from outside (the model, the router) shown in a confirmation: invisible format characters such as the bidi
/// overrides (U+202E…) and other control characters could make it read differently from what it is, so they are shown
/// as <c>&lt;U+XXXX&gt;</c>. Line breaks and tabs stay.
/// </summary>
public static class SafeText
{
    public static string ForDisplay(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return text ?? "";
        bool any = false;
        foreach (var r in text.EnumerateRunes())
            any |= Hidden(r);
        if (!any)
            return text;
        var sb = new StringBuilder(text.Length + 16);
        foreach (var r in text.EnumerateRunes())
        {
            if (Hidden(r))
                sb.Append("<U+").Append(r.Value.ToString("X4", CultureInfo.InvariantCulture)).Append('>');
            else
                sb.Append(r.ToString());
        }
        return sb.ToString();
    }

    private static bool Hidden(Rune r) => r.Value is not ('\n' or '\r' or '\t')
        && (Rune.IsControl(r) || Rune.GetUnicodeCategory(r) is UnicodeCategory.Format or UnicodeCategory.LineSeparator
            or UnicodeCategory.ParagraphSeparator or UnicodeCategory.PrivateUse);
}
