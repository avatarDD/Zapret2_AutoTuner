using System.Globalization;

namespace ZapretAutoTuner.Mcp;

/// <summary>One tool call: who, what, with which (masked) arguments and how it ended.</summary>
public sealed record McpAuditEntry(DateTime Time, string Client, string Tool, string Arguments, string Outcome, TimeSpan Duration)
{
    public override string ToString() =>
        string.Create(CultureInfo.InvariantCulture, $"{Time.ToLocalTime():yyyy-MM-dd HH:mm:ss} [{Client}] {Tool} {Arguments} → {Outcome} ({(long)Duration.TotalMilliseconds} ms)");
}

/// <summary>
/// Every MCP call, in memory for the session: shown in the UI and put into "Собрать отчёт". Arguments are masked like
/// the report (the user's addresses) before they get here.
/// </summary>
public sealed class McpAudit
{
    public const int MaxEntries = 2000;
    private readonly List<McpAuditEntry> _entries = [];
    private readonly Lock _lock = new();

    public event Action<McpAuditEntry>? Added;

    public IReadOnlyList<McpAuditEntry> Entries
    {
        get
        {
            lock (_lock)
                return [.. _entries];
        }
    }

    public IReadOnlyList<string> Lines() => [.. Entries.Select(e => e.ToString())];

    public void Add(McpAuditEntry e)
    {
        lock (_lock)
        {
            _entries.Add(e);
            if (_entries.Count > MaxEntries)
                _entries.RemoveAt(0);
        }
        Added?.Invoke(e);
    }
}
