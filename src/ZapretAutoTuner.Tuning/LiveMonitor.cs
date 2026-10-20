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

    /// <summary>Runs slice after slice until cancelled; the current capture is always stopped.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
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
