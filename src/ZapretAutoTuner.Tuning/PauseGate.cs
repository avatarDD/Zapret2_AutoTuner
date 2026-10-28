using System.Diagnostics;

namespace ZapretAutoTuner.Tuning;

/// <summary>
/// "Пауза" of a search: the trial in progress finishes (its engine stops with it), the next one waits until
/// <see cref="Resume"/>. Nothing runs while paused, so the app can be closed and the search continued after a restart
/// from the knowledge base.
/// </summary>
public sealed class PauseGate
{
    private readonly object _lock = new();
    private readonly Stopwatch _paused = new();
    private TaskCompletionSource? _gate;

    /// <summary>Raised on every change, from the thread that made it.</summary>
    public event Action<bool>? Changed;

    public bool IsPaused
    {
        get
        {
            lock (_lock)
                return _gate is not null;
        }
    }

    /// <summary>Time spent paused, so the elapsed time and the estimate count only the work.</summary>
    public TimeSpan PausedTime
    {
        get
        {
            lock (_lock)
                return _paused.Elapsed;
        }
    }

    public void Pause()
    {
        lock (_lock)
        {
            if (_gate is not null)
                return;
            _gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _paused.Start();
        }
        Changed?.Invoke(true);
    }

    public void Resume()
    {
        TaskCompletionSource? gate;
        lock (_lock)
        {
            gate = _gate;
            _gate = null;
            _paused.Stop();
        }
        if (gate is null)
            return;
        gate.TrySetResult();
        Changed?.Invoke(false);
    }

    /// <summary>Returns at once when running; while paused, waits for <see cref="Resume"/> or the cancellation (a stop).</summary>
    public async Task WaitAsync(CancellationToken ct)
    {
        while (true)
        {
            Task? gate;
            lock (_lock)
                gate = _gate?.Task;
            if (gate is null)
                return;
            await gate.WaitAsync(ct).ConfigureAwait(false);
        }
    }
}
