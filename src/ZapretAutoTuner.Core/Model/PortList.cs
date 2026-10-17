using System.Globalization;

namespace ZapretAutoTuner.Core.Model;

/// <summary>Port lists in nfqws2 syntax (<c>80,443,1000-2000</c>) as sorted, merged ranges.</summary>
public static class PortList
{
    public static IEnumerable<int> Parse(string list) => ParseRanges(list).SelectMany(r => Enumerable.Range(r.From, r.To - r.From + 1));

    public static List<(int From, int To)> ParseRanges(string list)
    {
        var ranges = new List<(int, int)>();
        foreach (var raw in list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (raw == "*")
            {
                ranges.Add((1, 65535));
                continue;
            }
            if (raw.StartsWith('~'))
                throw new FormatException($"negated port '{raw}' cannot be merged");
            var sep = raw.IndexOfAny(['-', ':']);
            int a, b;
            if (sep > 0)
            {
                a = ParsePort(raw[..sep]);
                b = ParsePort(raw[(sep + 1)..]);
            }
            else
            {
                a = b = ParsePort(raw);
            }
            if (a > b)
                throw new FormatException($"bad port range '{raw}'");
            ranges.Add((a, b));
        }
        return Merge(ranges);
    }

    public static List<(int From, int To)> Merge(IEnumerable<(int From, int To)> ranges)
    {
        var sorted = ranges.OrderBy(r => r.From).ToList();
        var result = new List<(int From, int To)>();
        foreach (var r in sorted)
        {
            if (result.Count > 0 && r.From <= result[^1].To + 1)
                result[^1] = (result[^1].From, Math.Max(result[^1].To, r.To));
            else
                result.Add(r);
        }
        return result;
    }

    public static string Union(IEnumerable<string?> lists, char rangeSeparator = '-')
    {
        var all = lists.Where(l => !string.IsNullOrEmpty(l)).SelectMany(l => ParseRanges(l!));
        return Format(Merge(all), rangeSeparator);
    }

    public static string Format(IEnumerable<(int From, int To)> ranges, char rangeSeparator = '-') =>
        string.Join(',', ranges.Select(r => r.From == r.To
            ? r.From.ToString(CultureInfo.InvariantCulture)
            : $"{r.From.ToString(CultureInfo.InvariantCulture)}{rangeSeparator}{r.To.ToString(CultureInfo.InvariantCulture)}"));

    private static int ParsePort(string s)
    {
        if (!int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var p) || p is < 0 or > 65535)
            throw new FormatException($"bad port '{s}'");
        return p;
    }
}
