using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// Actions waiting for the user's yes in the AutoTuner window. The tool returns "pending" at once; the dialog runs in
/// the background, and on yes the action runs by itself. Calling the tool again with the same arguments returns the
/// state, and after the decision its result. Nothing here lets the caller answer the dialog.
/// </summary>
public sealed class PendingConfirmations(IUserConfirm confirm)
{
    private sealed class Entry
    {
        public required string Id { get; init; }

        public required string Key { get; init; }

        public string State { get; set; } = "pending";

        public JsonObject? Result { get; set; }

        public CancellationTokenSource Cts { get; } = new();
    }

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly Lock _lock = new();
    private int _next;

    public int PendingCount
    {
        get
        {
            lock (_lock)
                return _entries.Values.Count(e => e.State == "pending");
        }
    }

    /// <summary>
    /// The state of the action keyed by <paramref name="key"/>: asks the user the first time, then reports. A declined
    /// or finished entry is reported once and forgotten, so the same request can be asked again later.
    /// </summary>
    public JsonObject Request(string key, ConfirmRequest request, Func<CancellationToken, Task<JsonObject>> onYes)
    {
        Entry e;
        lock (_lock)
        {
            if (_entries.TryGetValue(key, out var known))
            {
                if (known.State is "pending" or "running")
                    return Pending(known);
                _entries.Remove(key);
                return known.State == "declined"
                    ? new JsonObject { ["ok"] = false, ["status"] = "declined", ["confirmation_id"] = known.Id, ["error"] = "the user declined in the AutoTuner window / пользователь отказался" }
                    : known.Result ?? new JsonObject { ["ok"] = false, ["status"] = known.State };
            }
            e = new Entry { Id = "c-" + (++_next).ToString(System.Globalization.CultureInfo.InvariantCulture), Key = key };
            _entries[key] = e;
        }
        _ = RunAsync(e, request, onYes);
        return Pending(e);
    }

    /// <summary>Cancels every waiting dialog (the Stop button, the session ended).</summary>
    public void CancelAll()
    {
        lock (_lock)
        {
            foreach (var e in _entries.Values)
                e.Cts.Cancel();
            _entries.Clear();
        }
    }

    private static JsonObject Pending(Entry e) => new()
    {
        ["ok"] = false,
        ["status"] = e.State == "running" ? "confirmed_running" : "pending_confirmation",
        ["confirmation_id"] = e.Id,
        ["message"] = e.State == "running"
            ? "the user said yes; the action is running, call again for its result / пользователь подтвердил, действие выполняется"
            : "waiting for the user's decision in the AutoTuner window; you cannot confirm it yourself, call again later / ждёт решения пользователя в окне AutoTuner",
    };

    private async Task RunAsync(Entry e, ConfirmRequest request, Func<CancellationToken, Task<JsonObject>> onYes)
    {
        bool yes;
        try
        {
            yes = await confirm.ConfirmAsync(request, e.Cts.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            yes = false;
        }
        lock (_lock)
        {
            if (!yes || e.Cts.IsCancellationRequested)
            {
                e.State = "declined";
                return;
            }
            e.State = "running";
        }
        JsonObject result;
        try
        {
            result = await onYes(e.Cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            result = new JsonObject { ["ok"] = false, ["error"] = ex.Message };
        }
        result["confirmation_id"] = e.Id;
        lock (_lock)
        {
            e.Result = result;
            e.State = "done";
        }
    }
}
