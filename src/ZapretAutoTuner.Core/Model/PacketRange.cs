using System.Globalization;

namespace ZapretAutoTuner.Core.Model;

/// <summary>
/// <c>--in-range</c> / <c>--out-range</c> values, ported from <c>packet_range_parse</c> in nfq2/filter.c:
/// <c>mX-mY</c>, <c>mX&lt;mY</c>, <c>-mY</c>, <c>&lt;mY</c>, <c>mX-</c>, <c>a</c>, <c>x</c> with modes n, d, s, p, b.
/// </summary>
public static class PacketRange
{
    private const string Modes = "ndspbxa";

    public static bool IsValid(string s)
    {
        if (s.Length == 0)
            return false;
        int i;
        if (s[0] is '-' or '<')
        {
            i = 0;
        }
        else
        {
            if (!ParsePos(s, out var fromMode, out _))
                return false;
            if (fromMode == 'x')
                return true;
            i = s.IndexOf('-', StringComparison.Ordinal);
            if (i < 0)
                i = s.IndexOf('<', StringComparison.Ordinal);
            if (i < 0)
                return fromMode == 'a';
        }
        var rest = s[(i + 1)..];
        return rest.Length == 0 || ParsePos(rest, out _, out _);
    }

    private static bool ParsePos(string s, out char mode, out uint pos)
    {
        mode = s[0];
        pos = 0;
        if (!Modes.Contains(mode, StringComparison.Ordinal))
            return false;
        if (mode is 'x' or 'a')
            return true;
        // sscanf("%u") reads leading digits and ignores what follows
        var digits = new string(s.Skip(1).TakeWhile(char.IsAsciiDigit).ToArray());
        return digits.Length > 0 && uint.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out pos);
    }
}
