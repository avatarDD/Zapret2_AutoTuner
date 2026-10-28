using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Probes.Browser;
using ZapretAutoTuner.Probes.Diagnostics;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.Services;

/// <summary>
/// The pipeline on this PC: probes from the UI, the engine in the Agent, the knowledge base for memory. <paramref name="resume"/>
/// holds the sessions of an interrupted run to go on with; <paramref name="sessionStarted"/> hears each domain's session so
/// the run can be continued after a restart.
/// </summary>
public sealed class PcPipelineServices(AppHost host, IEngineControl engine, bool openPages, SearchContext? context = null,
    IReadOnlyDictionary<string, long>? resume = null, Action<string, long>? sessionStarted = null) : IPipelineServices
{
    private readonly Dictionary<string, (long Session, TrialTarget Target)> _sessions = new(StringComparer.OrdinalIgnoreCase);

    public async Task<ClassifierVerdict> ClassifyAsync(string domain, IProgress<(string Ru, string En)> progress, CancellationToken ct)
    {
        var run = await ClassifierRunner.RunAsync(domain, new ClassifierOptions(), new Progress<ClassifierStep>(s => progress.Report((s.MessageRu, s.MessageEn))), ct).ConfigureAwait(false);
        return run.Verdict;
    }

    public ITrialExecutor ExecutorFor(string domain, IReadOnlyList<IPAddress> addresses)
    {
        var target = new TrialTarget { Host = domain, Addresses = addresses };
        _sessions[domain] = (0, target);
        return new AgentTrialExecutor(engine, target, new AgentTrialOptions { LuaDir = host.Bundle.LuaDir, UserLua = host.Resources.ApprovedLuaPaths() });
    }

    public Task<IReadOnlyList<FinalCheckResult>>? FinalCheckAsync(string domain, ITrialExecutor executor, IReadOnlyList<FoundStrategy> found, CancellationToken ct)
    {
        if (executor is not AgentTrialExecutor agent)
            return null;
        Func<CancellationToken, Task<PageLoad>>? open = openPages
            ? c => BrowserProbe.RunAsync(new BrowserProbeOptions { Url = "https://" + domain + "/" }, c)
            : null;
        return FinalCheck.RunAsync(agent, found.Take(3), domain, open, 5, ct);
    }

    public ISearchLog? LogFor(string domain, ClassifierVerdict verdict)
    {
        var target = _sessions.TryGetValue(domain, out var s) ? s.Target : new TrialTarget { Host = domain, Addresses = [] };
        var label = verdict.Primary.ToString();
        var id = resume?.FirstOrDefault(kv => string.Equals(kv.Key, domain, StringComparison.OrdinalIgnoreCase)) is { Value: > 0 } r
            && TuningSession.Resume(host.Kb, r.Value, domain, label) is { } resumed
            ? resumed
            : host.Kb.StartSession(domain, host.Settings.SearchMode, context?.NetworkId, label);
        _sessions[domain] = (id, target);
        sessionStarted?.Invoke(domain, id);
        return new KnowledgeBaseSearchLog(host.Kb, id, target, context?.NetworkId, verdict.Primary.ToString());
    }

    /// <summary>What worked on this provider goes in as priors (§6.2); the learned order decides where they stand.</summary>
    public SearchOptions OptionsFor(string domain, ClassifierVerdict verdict, SearchOptions options) =>
        _sessions.TryGetValue(domain, out var s) && s.Session != 0 ? TuningSession.Prepare(host.Kb, options, s.Session, context?.Asn) : options;

    public void Finished(string domain, SearchResult result)
    {
        if (_sessions.TryGetValue(domain, out var s) && s.Session != 0)
            TuningSession.Finish(host.Kb, s.Session, domain, result, context?.NetworkId);
    }
}
