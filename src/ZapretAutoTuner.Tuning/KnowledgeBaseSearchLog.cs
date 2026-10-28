using System.Globalization;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.Tuning;

/// <summary>
/// Writes what the search learns into the knowledge base (PLAN 3.2): every attempt, every refinement step and the
/// checkpoint, so an interrupted search continues where it stopped and the next one starts from what worked here.
/// <paramref name="source"/> overrides the candidates' own source (the router's trials are stored as
/// <see cref="CandidateSource.Router"/>), <paramref name="clientProfile"/> is where they were measured.
/// </summary>
public sealed class KnowledgeBaseSearchLog(KnowledgeBase kb, long sessionId, TrialTarget target, long? networkId = null, string? blockLabel = null,
    string? source = null, string clientProfile = "default") : ISearchLog
{
    public long SessionId => sessionId;

    public void Trial(StrategyCandidate candidate, TrialOutcome outcome) =>
        kb.RecordTrial(new TrialRecord
        {
            Strategy = candidate.Strategy,
            Family = candidate.Family,
            Host = target.Host,
            Port = target.Port,
            L4 = candidate.L4 == L4Kind.Udp ? "udp" : "tcp",
            Ok = outcome.Ok,
            Error = outcome.Ok ? null : outcome.Detail is null ? outcome.Failure.ToString() : $"{outcome.Failure}: {outcome.Detail}",
            BytesIn = outcome.BytesIn,
            Duration = outcome.Duration,
            SessionId = sessionId,
            NetworkId = networkId,
            BlockLabel = blockLabel,
            Source = source ?? candidate.Source,
            ClientProfile = clientProfile,
        });

    public void Tuning(Strategy parent, Mutation child, Efficiency efficiency, bool accepted) =>
        kb.AddTuningStep(sessionId, parent, child.Strategy, child.What, efficiency, accepted);

    public void Checkpoint(int index) => kb.UpdateSession(sessionId, checkpoint: index.ToString(CultureInfo.InvariantCulture));
}

/// <summary>Starting, resuming and closing a search against the knowledge base.</summary>
public static class TuningSession
{
    /// <summary>
    /// Search options for a new or resumed session: strategies that worked on this provider go first (§6.2), and on
    /// resume the strategies already tried in the session keep their efficiency instead of being run again.
    /// </summary>
    public static SearchOptions Prepare(KnowledgeBase kb, SearchOptions options, long sessionId, int? asn, L4Kind l4 = L4Kind.Tcp)
    {
        var priors = kb.WorkedOnNetwork(asn, l4 == L4Kind.Udp ? "udp" : "tcp")
            .Select(p => new StrategyCandidate(p.Strategy, p.Family ?? "prior", 0, ["prior"], l4) { Source = CandidateSource.Prior })
            .ToList();
        return options with
        {
            Priors = [.. options.Priors, .. priors],
            AlreadyTried = kb.SessionTrials(sessionId),
        };
    }

    /// <summary>
    /// Takes up a session of an interrupted run (paused, or the app closed or the PC restarted mid-search): it goes on
    /// when it is this host's and the block is the same, so <see cref="Prepare"/> skips what it already tried; a
    /// session that finished is replayed from its trials just as well. Null when it does not fit: a new one starts.
    /// </summary>
    public static long? Resume(KnowledgeBase kb, long sessionId, string host, string? blockLabel)
    {
        if (kb.Session(sessionId) is not { } s || !string.Equals(s.Host, host, StringComparison.OrdinalIgnoreCase) || s.BlockLabel != blockLabel)
            return null;
        kb.UpdateSession(sessionId, "running");
        return sessionId;
    }

    /// <summary>
    /// The learned search order (PLAN 4a.1) from this base's trials of the last year; the decay makes older ones
    /// count for next to nothing anyway.
    /// </summary>
    public static SearchLearning Learning(KnowledgeBase kb, LearningContext context, DateTimeOffset? now = null) => new()
    {
        History = kb.LearningHistory((now ?? DateTimeOffset.UtcNow) - TimeSpan.FromDays(365)),
        Context = context,
        Now = now,
    };

    /// <summary>Stores the ranking of the found strategies and closes the session.</summary>
    public static void Finish(KnowledgeBase kb, long sessionId, string host, SearchResult result, long? networkId = null, string clientProfile = "default")
    {
        foreach (var f in result.Working)
            kb.SetScore(f.Candidate.Strategy, host, f.Score.Total, networkId, clientProfile);
        if (result.BestPartial is { } p)
            kb.SetScore(p.Candidate.Strategy, host, p.Score.Total, networkId, clientProfile);
        kb.UpdateSession(sessionId, result.Reason switch
        {
            SearchStopReason.Cancelled => "paused",
            SearchStopReason.Punished => "paused",
            _ => "done",
        });
    }
}
