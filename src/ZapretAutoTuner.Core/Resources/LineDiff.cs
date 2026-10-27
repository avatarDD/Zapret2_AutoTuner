using System.Text;

namespace ZapretAutoTuner.Core.Resources;

public enum DiffKind
{
    Same,
    Added,
    Removed,
}

public sealed record DiffLine(DiffKind Kind, string Text, int? OldLine, int? NewLine)
{
    public override string ToString() => (Kind switch { DiffKind.Added => "+", DiffKind.Removed => "-", _ => " " }) + Text;
}

/// <summary>
/// A plain line diff (longest common subsequence) for the Lua approval dialog: the user sees exactly what changed
/// since the version in effect. Very long inputs fall back to "all removed, all added" instead of a quadratic table.
/// </summary>
public sealed class LineDiff
{
    public const int MaxCells = 4_000_000;

    private LineDiff(List<DiffLine> lines)
    {
        Lines = lines;
    }

    public IReadOnlyList<DiffLine> Lines { get; }

    public int Added => Lines.Count(l => l.Kind == DiffKind.Added);

    public int Removed => Lines.Count(l => l.Kind == DiffKind.Removed);

    public bool HasChanges => Lines.Any(l => l.Kind != DiffKind.Same);

    public static LineDiff Compute(string? oldText, string? newText)
    {
        var a = Split(oldText);
        var b = Split(newText);
        var result = new List<DiffLine>();
        // common head and tail first: an edit usually touches a few lines in the middle
        int head = 0;
        while (head < a.Length && head < b.Length && a[head] == b[head])
        {
            result.Add(new(DiffKind.Same, a[head], head + 1, head + 1));
            head++;
        }
        int tail = 0;
        while (tail < a.Length - head && tail < b.Length - head && a[a.Length - 1 - tail] == b[b.Length - 1 - tail])
            tail++;
        int n = a.Length - head - tail, m = b.Length - head - tail;
        if ((long)(n + 1) * (m + 1) > MaxCells)
        {
            for (int i = 0; i < n; i++)
                result.Add(new(DiffKind.Removed, a[head + i], head + i + 1, null));
            for (int j = 0; j < m; j++)
                result.Add(new(DiffKind.Added, b[head + j], null, head + j + 1));
        }
        else
        {
            var len = new int[n + 1, m + 1];
            for (int i = n - 1; i >= 0; i--)
            {
                for (int j = m - 1; j >= 0; j--)
                    len[i, j] = a[head + i] == b[head + j] ? len[i + 1, j + 1] + 1 : Math.Max(len[i + 1, j], len[i, j + 1]);
            }
            int x = 0, y = 0;
            while (x < n || y < m)
            {
                if (x < n && y < m && a[head + x] == b[head + y])
                {
                    result.Add(new(DiffKind.Same, a[head + x], head + x + 1, head + y + 1));
                    x++;
                    y++;
                }
                else if (x < n && (y == m || len[x + 1, y] >= len[x, y + 1]))
                {
                    // removals before additions, like diff -u
                    result.Add(new(DiffKind.Removed, a[head + x], head + x + 1, null));
                    x++;
                }
                else
                {
                    result.Add(new(DiffKind.Added, b[head + y], null, head + y + 1));
                    y++;
                }
            }
        }
        for (int k = 0; k < tail; k++)
            result.Add(new(DiffKind.Same, a[a.Length - tail + k], a.Length - tail + k + 1, b.Length - tail + k + 1));
        return new LineDiff(result);
    }

    /// <summary>Unified-style text: changed lines with <paramref name="context"/> lines around them, hunks headed by @@.</summary>
    public string ToUnified(int context = 3)
    {
        var sb = new StringBuilder();
        var changed = Lines.Select((l, i) => (l, i)).Where(t => t.l.Kind != DiffKind.Same).Select(t => t.i).ToList();
        if (changed.Count == 0)
            return "";
        int idx = 0;
        while (idx < changed.Count)
        {
            int start = Math.Max(0, changed[idx] - context);
            int end = changed[idx];
            while (idx + 1 < changed.Count && changed[idx + 1] - end <= 2 * context + 1)
                end = changed[++idx];
            end = Math.Min(Lines.Count - 1, end + context);
            var oldStart = Lines.Skip(start).Take(end - start + 1).Select(l => l.OldLine).FirstOrDefault(v => v is not null) ?? 0;
            var newStart = Lines.Skip(start).Take(end - start + 1).Select(l => l.NewLine).FirstOrDefault(v => v is not null) ?? 0;
            sb.Append("@@ -").Append(oldStart).Append(" +").Append(newStart).Append(" @@\n");
            for (int i = start; i <= end; i++)
                sb.Append(Lines[i]).Append('\n');
            idx++;
        }
        return sb.ToString();
    }

    private static string[] Split(string? text) =>
        string.IsNullOrEmpty(text) ? [] : text.ReplaceLineEndings("\n").TrimEnd('\n').Split('\n');
}
