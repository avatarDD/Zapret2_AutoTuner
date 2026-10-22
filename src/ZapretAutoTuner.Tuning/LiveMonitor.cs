using ZapretAutoTuner.Core.Monitor;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Programs;

namespace ZapretAutoTuner.Tuning;

public sealed record LiveMonitorOptions
{
    /// <summary>The strategy's domains: sessions to anything else are ignored.</summary>
    public required IReadOnlyCollection<string> Domains { get; init; }

    /// <summary>One capture slice: the Agent's ring buffer must hold it. Windows of the detector span several slices.</summary>
    public TimeSpan Slice { get; init; } = TimeSpan.FromSeconds(60);

    public DetectorOptions Detector { get; init; } = new();

    /// <summary>The pause after a failed slice; it doubles with each failure in a row, up to <see cref="MaxRetryDelay"/>.</summary>
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(5);

    public TimeSpan MaxRetryDelay { get; init; } = TimeSpan.FromMinutes(5);
}

/// <summary>
/// "Защита активна" (PLAN 7.1): the engine keeps running with the final strategy, and this passively watches the
/// strategy's domains. The Agent captures in slices (headers and ClientHello are all that is read), each slice's
/// flows become session samples, and the degradation detector turns them into events.
/// </summary>
public sealed class LiveMonitor(IProgramMonitor capture, LiveMonitorOptions options)
{
    private readonly DegradationDetector _detector = new(options.Detector);

    public DegradationDetector Detector => _detector;

    /// <summary>A domain degraded or recovered.</summary>
    public event Action<HealthEvent>? Changed;

    /// <summary>A window closed (for the "Монитор" chart and the knowledge base).</summary>
    public event Action<WindowStats>? WindowClosed
    {
        add => _detector.WindowClosed += value;
        remove => _detector.WindowClosed -= value;
    }

    /// <summary>
    /// A slice failed (the Agent dropped, the capture could not start, the pcap did not parse); the monitor waits and
    /// tries again. The argument is the failure and the number of failures in a row.
    /// </summary>
    public event Action<Exception, int>? Failed;

    /// <summary>
    /// Runs slice after slice until cancelled; the current capture is always stopped. A failed slice does not end the
    /// watch: it is reported, and the next one starts after a growing pause.
    /// </summary>
    public async Task RunAsync(CancellationToken ct)
    {
        int failures = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await SliceAsync(ct).ConfigureAwait(false);
                failures = 0;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception e)
            {
                failures++;
                Failed?.Invoke(e, failures);
                try
                {
                    await Task.Delay(Backoff(failures), ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    internal TimeSpan Backoff(int failures)
    {
        var ticks = options.RetryDelay.Ticks * Math.Pow(2, Math.Min(failures - 1, 20));
        return TimeSpan.FromTicks((long)Math.Min(ticks, options.MaxRetryDelay.Ticks));
    }

    private async Task SliceAsync(CancellationToken ct)
    {
        var id = await capture.StartCaptureAsync(ct).ConfigureAwait(false);
        byte[] pcap;
        try
        {
            await Task.Delay(options.Slice, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            (pcap, _) = await capture.StopCaptureAsync(id, CancellationToken.None).ConfigureAwait(false);
        }
        Feed(PcapReader.Read(pcap), DateTime.UtcNow);
    }

    /// <summary>One slice: its flows to the strategy's domains go to the detector, then due windows close.</summary>
    public List<HealthEvent> Feed(IReadOnlyList<CapturedPacket> packets, DateTime sliceEnd)
    {
        var names = ProgramEndpoints.DnsNames(packets);
        var events = new List<HealthEvent>();
        foreach (var flow in FlowAnalyzer.Analyze(packets).OrderBy(f => f.FirstSeen))
        {
            if (SessionClassifier.Classify(flow, sliceEnd, a => names.GetValueOrDefault(a)) is not { } s)
                continue;
            if (SessionClassifier.DomainOf(s.Domain, options.Domains) is not { } domain)
                continue;
            events.AddRange(_detector.Add(s with { Domain = domain }));
        }
        events.AddRange(_detector.Tick(sliceEnd));
        foreach (var e in events)
            Changed?.Invoke(e);
        return events;
    }
}
