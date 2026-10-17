using System.Globalization;

namespace ZapretAutoTuner.Core.Model;

/// <summary>
/// A position marker (<c>5</c>, <c>-1</c>, <c>midsld+1</c>, <c>host-2</c>) as parsed by <c>posmarker_parse</c>
/// in nfq2/protocol.c: an int16 is an absolute position, otherwise a marker name with an optional signed offset.
/// </summary>
public sealed record PositionMarker(string Name, short Offset)
{
    public const string Absolute = "abs";

    public bool IsAbsolute => Name == Absolute;

    public static bool TryParse(string s, IReadOnlySet<string> names, out PositionMarker? marker)
    {
        marker = null;
        if (TryParseInt16(s, out var abs))
        {
            marker = new PositionMarker(Absolute, abs);
            return true;
        }
        int i = s.IndexOfAny(['+', '-']);
        var name = i < 0 ? s : s[..i];
        if (name.Length == 0 || name.Length >= 32 || !names.Contains(name))
            return false;
        short ofs = 0;
        if (i >= 0 && !TryParseInt16(s[i..], out ofs))
            return false;
        marker = new PositionMarker(name, ofs);
        return true;
    }

    public static bool TryParseList(string s, IReadOnlySet<string> names, out List<PositionMarker> markers)
    {
        markers = [];
        if (s.Length == 0)
            return true;
        foreach (var part in s.Split(','))
        {
            if (!TryParse(part, names, out var m))
                return false;
            markers.Add(m!);
        }
        return true;
    }

    private static bool TryParseInt16(string s, out short v)
    {
        // parse_int16 accepts an optional sign and decimal digits only
        v = 0;
        if (s.Length == 0)
            return false;
        int start = s[0] is '+' or '-' ? 1 : 0;
        if (start == s.Length || !s.AsSpan(start).ToArray().All(char.IsAsciiDigit))
            return false;
        return short.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out v);
    }

    public override string ToString() => IsAbsolute
        ? Offset.ToString(CultureInfo.InvariantCulture)
        : Offset == 0 ? Name : Name + (Offset > 0 ? "+" : "") + Offset.ToString(CultureInfo.InvariantCulture);
}
