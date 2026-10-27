namespace ZapretAutoTuner.Mcp;

public sealed record BudgetOptions
{
    /// <summary>Trial series per minute, for trial_run and the search together.</summary>
    public int PerMinute { get; init; } = 12;

    /// <summary>Trial series in one MCP session.</summary>
    public int PerSession { get; init; } = 400;

    /// <summary>Consecutive attempts without a TCP connect that mean the provider punishes the address (the Runner's rule).</summary>
    public int PunishThreshold { get; init; } = 4;

    /// <summary>The pause after a punishment, as the Runner's.</summary>
    public TimeSpan PunishPause { get; init; } = TimeSpan.FromSeconds(60);
}

/// <summary>
/// The shared limiter (MCP design, "Бюджет"): trials per minute and per session, and the Runner's punishment pause per
/// target, so a model can turn AutoTuner neither into a load generator nor into a way to get the user's address banned.
/// </summary>
public sealed class TrialBudget(BudgetOptions options, TimeProvider? time = null)
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Queue<DateTimeOffset> _recent = new();
    private readonly Dictionary<string, (int NoConnect, DateTimeOffset? PausedUntil)> _targets = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();

    public BudgetOptions Options => options;

    public int Used { get; private set; }

    /// <summary>Takes one trial slot, or says why not and when to come back.</summary>
    public (bool Ok, string? Reason, TimeSpan RetryAfter) TryTake(string target)
    {
        lock (_lock)
        {
            var now = _time.GetUtcNow();
            if (_targets.TryGetValue(target, out var t) && t.PausedUntil is { } until && until > now)
                return (false, $"the provider punishes {target} for attempts: pause / провайдер «наказывает» адрес за попытки: пауза", until - now);
            if (Used >= options.PerSession)
                return (false, $"session budget of {options.PerSession} trials is spent / бюджет сеанса ({options.PerSession} испытаний) исчерпан", TimeSpan.Zero);
            while (_recent.Count > 0 && now - _recent.Peek() >= TimeSpan.FromMinutes(1))
                _recent.Dequeue();
            if (_recent.Count >= options.PerMinute)
                return (false, $"at most {options.PerMinute} trials a minute / не больше {options.PerMinute} испытаний в минуту", _recent.Peek() + TimeSpan.FromMinutes(1) - now);
            _recent.Enqueue(now);
            Used++;
            return (true, null, TimeSpan.Zero);
        }
    }

    /// <summary>Waits for a slot (the search); false when the session budget is spent.</summary>
    public async Task<bool> TakeAsync(string target, CancellationToken ct)
    {
        while (true)
        {
            var (ok, _, retry) = TryTake(target);
            if (ok)
                return true;
            if (retry <= TimeSpan.Zero)
                return false;
            await Task.Delay(retry + TimeSpan.FromMilliseconds(50), _time, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Counts attempts without a TCP connect; at the threshold the target is paused.</summary>
    public void Observe(string target, bool noConnect)
    {
        lock (_lock)
        {
            var t = _targets.GetValueOrDefault(target);
            t.NoConnect = noConnect ? t.NoConnect + 1 : 0;
            if (t.NoConnect >= options.PunishThreshold)
            {
                t.PausedUntil = _time.GetUtcNow() + options.PunishPause;
                t.NoConnect = 0;
            }
            _targets[target] = t;
        }
    }

    public void Reset()
    {
        lock (_lock)
        {
            _recent.Clear();
            _targets.Clear();
            Used = 0;
        }
    }
}
