using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Probes.Browser;
using ZapretAutoTuner.Probes.Diagnostics;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.Services;

/// <summary>The pipeline on this PC: probes from the UI, the engine in the Agent, the knowledge base for memory.</summary>
public sealed class PcPipelineServices(AppHost host, IEngineControl engine, bool openPages) : IPipelineServices
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
        return new AgentTrialExecutor(engine, target, new AgentTrialOptions { LuaDir = host.Bundle.LuaDir });
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
        var id = host.Kb.StartSession(domain, host.Settings.SearchMode, blockLabel: verdict.Primary.ToString());
        _sessions[domain] = (id, target);
        return new KnowledgeBaseSearchLog(host.Kb, id, target, blockLabel: verdict.Primary.ToString());
    }

    public void Finished(string domain, SearchResult result)
    {
        if (_sessions.TryGetValue(domain, out var s) && s.Session != 0)
            TuningSession.Finish(host.Kb, s.Session, domain, result);
    }
}
