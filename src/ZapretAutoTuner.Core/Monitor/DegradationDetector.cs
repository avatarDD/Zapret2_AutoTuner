namespace ZapretAutoTuner.Core.Monitor;

public sealed record DetectorOptions
{
    /// <summary>The window of dpi-diagnostics §9 (5–15 minutes).</summary>
    public TimeSpan Window { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>Failure share above which a window is bad.</summary>
    public double FailureThreshold { get; init; } = 0.5;

    /// <summary>Fewer judged sessions say nothing: the window is neither good nor bad.</summary>
    public int MinSessions { get; init; } = 3;

    /// <summary>Hysteresis: this many bad windows in a row degrade a domain, as many good ones recover it.</summary>
    public int ConsecutiveWindows { get; init; } = 2;
}

public sealed record WindowStats(string Domain, DateTime Start, int Sessions, int Ok, int Reset, int Stalled16k, int Stalled, int NoReply, int Retransmissions)
{
    public int Failures => Reset + Stalled16k + Stalled + NoReply;

    public double FailureRate => Sessions == 0 ? 0 : (double)Failures / Sessions;

    /// <summary>The failure that dominates the window, for the journal and the repair.</summary>
    public SessionOutcome MainFailure => new[] { (SessionOutcome.Reset, Reset), (SessionOutcome.Stalled16k, Stalled16k), (SessionOutcome.Stalled, Stalled), (SessionOutcome.NoReply, NoReply) }
        .OrderByDescending(x => x.Item2).First() is var (o, n) && n > 0 ? o : SessionOutcome.Unknown;

    public static WindowStats Of(string domain, DateTime start, IEnumerable<SessionSample> samples)
    {
        int ok = 0, reset = 0, s16 = 0, stalled = 0, noReply = 0, retrans = 0;
        foreach (var s in samples)
        {
            retrans += s.Retransmissions;
            switch (s.Outcome)
            {
                case SessionOutcome.Ok: ok++; break;
                case SessionOutcome.Reset: reset++; break;
                case SessionOutcome.Stalled16k: s16++; break;
                case SessionOutcome.Stalled: stalled++; break;
                case SessionOutcome.NoReply: noReply++; break;
            }
        }
        return new WindowStats(domain, start, ok + reset + s16 + stalled + noReply, ok, reset, s16, stalled, noReply, retrans);
    }
}

public enum HealthChange
{
    Degraded,
    Recovered,
}

public sealed record HealthEvent(string Domain, HealthChange Change, DateTime Time, IReadOnlyList<WindowStats> Windows);

/// <summary>
/// The degradation detector of PLAN 7.2: sessions are grouped by domain into fixed windows; a window with enough
/// sessions is bad when its failure share is above the threshold. Two bad windows in a row degrade the domain, two
/// good ones recover it; windows with too few sessions keep the state.
/// </summary>
public sealed class DegradationDetector(DetectorOptions options)
{
    private sealed class DomainState
    {
        public readonly List<SessionSample> Current = [];
        public DateTime WindowStart;
        public int BadRun;
        public int GoodRun;
        public bool Degraded;
        public readonly List<WindowStats> History = [];
    }

    private readonly Dictionary<string, DomainState> _domains = new(StringComparer.OrdinalIgnoreCase);

    public DetectorOptions Options => options;

    /// <summary>A window with enough sessions closed (for the chart and the knowledge base).</summary>
    public event Action<WindowStats>? WindowClosed;

    public bool IsDegraded(string domain) => _domains.TryGetValue(domain, out var s) && s.Degraded;

    public IReadOnlyList<WindowStats> History(string domain) => _domains.TryGetValue(domain, out var s) ? s.History : [];

    public IEnumerable<string> Domains => _domains.Keys;

    /// <summary>Adds a session; windows that ended before it are closed first.</summary>
    public List<HealthEvent> Add(SessionSample sample)
    {
        if (!_domains.TryGetValue(sample.Domain, out var st))
            _domains[sample.Domain] = st = new DomainState { WindowStart = Align(sample.Time) };
        var events = CloseWindows(sample.Domain, st, sample.Time);
        if (sample.Time >= st.WindowStart)
            st.Current.Add(sample);
        return events;
    }

    /// <summary>Closes every window that ended by <paramref name="now"/> (a timer calls it when traffic stops).</summary>
    public List<HealthEvent> Tick(DateTime now) => _domains.SelectMany(kv => CloseWindows(kv.Key, kv.Value, now)).ToList();

    /// <summary>Forgets a domain's state, e.g. after its strategy was replaced.</summary>
    public void Reset(string domain) => _domains.Remove(domain);

    private DateTime Align(DateTime t) => new(t.Ticks - t.Ticks % options.Window.Ticks, t.Kind);

    private List<HealthEvent> CloseWindows(string domain, DomainState st, DateTime now)
    {
        var events = new List<HealthEvent>();
        while (now >= st.WindowStart + options.Window)
        {
            var w = WindowStats.Of(domain, st.WindowStart, st.Current);
            st.Current.Clear();
            st.WindowStart += options.Window;
            if (w.Sessions < options.MinSessions)
            {
                // an empty stretch: jump over it instead of closing window after window
                if (st.Current.Count == 0 && now >= st.WindowStart + options.Window)
                    st.WindowStart = Align(now);
                continue;
            }
            st.History.Add(w);
            WindowClosed?.Invoke(w);
            if (st.History.Count > 288)
                st.History.RemoveAt(0);
            bool bad = w.FailureRate > options.FailureThreshold;
            st.BadRun = bad ? st.BadRun + 1 : 0;
            st.GoodRun = bad ? 0 : st.GoodRun + 1;
            var recent = st.History.TakeLast(options.ConsecutiveWindows).ToList();
            if (!st.Degraded && st.BadRun >= options.ConsecutiveWindows)
            {
                st.Degraded = true;
                events.Add(new HealthEvent(domain, HealthChange.Degraded, st.WindowStart, recent));
            }
            else if (st.Degraded && st.GoodRun >= options.ConsecutiveWindows)
            {
                st.Degraded = false;
                events.Add(new HealthEvent(domain, HealthChange.Recovered, st.WindowStart, recent));
            }
        }
        return events;
    }
}
