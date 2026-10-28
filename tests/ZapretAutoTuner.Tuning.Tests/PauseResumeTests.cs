using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>"Пауза" of the wizard's search and its continuation after a restart from the knowledge base.</summary>
public sealed class PauseResumeTests
{
    private sealed class Services : IPipelineServices
    {
        public Task<ClassifierVerdict> ClassifyAsync(string host, IProgress<(string Ru, string En)> progress, CancellationToken ct) =>
            Task.FromResult(new ClassifierVerdict
            {
                Host = host,
                Findings = [new LabelFinding(BlockLabel.SniBlock, "203.0.113.5", ["reset"])],
                LiveAddresses = ["203.0.113.5"],
                Next = NextStep.SearchStrategy,
                Primary = BlockLabel.SniBlock,
            });

        public Counting Executor { get; } = new();

        public ITrialExecutor ExecutorFor(string host, IReadOnlyList<IPAddress> addresses) => Executor;
    }

    private sealed class Counting : ITrialExecutor
    {
        private int _runs;

        public int Runs => Volatile.Read(ref _runs);

        public Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
        {
            Interlocked.Increment(ref _runs);
            return Task.FromResult<IReadOnlyList<TrialOutcome>>([.. Enumerable.Range(0, attempts).Select(_ => TrialOutcome.Success())]);
        }

        public Task<bool> TargetReachableAsync(CancellationToken ct) => Task.FromResult(true);
    }

    private static PipelineOptions Options(PauseGate gate) => new()
    {
        Unify = false,
        Pause = gate,
        Search = new SearchOptions { Generator = new GeneratorOptions { Mode = SearchMode.Quick }, StopAfterFound = 1, PunishPause = TimeSpan.FromMilliseconds(1) },
    };

    [Fact]
    public async Task The_gate_holds_until_resumed_and_counts_the_paused_time()
    {
        var gate = new PauseGate();
        var changes = new List<bool>();
        gate.Changed += changes.Add;
        await gate.WaitAsync(CancellationToken.None); // running: no wait
        gate.Pause();
        gate.Pause();
        var wait = gate.WaitAsync(CancellationToken.None);
        await Task.Delay(50);
        Assert.False(wait.IsCompleted);
        gate.Resume();
        await wait.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(gate.PausedTime >= TimeSpan.FromMilliseconds(40));
        Assert.Equal([true, false], changes);
    }

    [Fact]
    public async Task No_trial_runs_while_paused_and_the_run_goes_on_after_resume()
    {
        var gate = new PauseGate();
        var services = new Services();
        gate.Pause();
        var run = new TuningPipeline(services, Options(gate)).RunAsync(["a.com"]);
        await Task.Delay(100);
        Assert.Equal(0, services.Executor.Runs);
        Assert.False(run.IsCompleted);

        gate.Resume();
        var r = await run.WaitAsync(TimeSpan.FromSeconds(20));
        Assert.True(services.Executor.Runs > 0);
        Assert.NotNull(r.Targets[0].Best);
    }

    [Fact]
    public async Task A_stop_while_paused_ends_the_run_quietly()
    {
        var gate = new PauseGate();
        gate.Pause();
        using var cts = new CancellationTokenSource();
        var run = new TuningPipeline(new Services(), Options(gate)).RunAsync(["a.com", "b.com"], cts.Token);
        await Task.Delay(50);
        await cts.CancelAsync();
        var r = await run.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Null(r.Solution);
        Assert.All(r.Targets, t => Assert.Null(t.Error));
    }

    [Fact]
    public void A_session_of_an_interrupted_run_is_taken_up_and_skips_what_it_tried()
    {
        using var kb = KnowledgeBase.OpenInMemory();
        var target = new TrialTarget { Host = "www.youtube.com", Addresses = [IPAddress.Parse("203.0.113.5")] };
        long id = kb.StartSession("www.youtube.com", "Standard", blockLabel: "SniBlock");
        var log = new KnowledgeBaseSearchLog(kb, id, target, blockLabel: "SniBlock");
        var tried = new StrategyCandidate(Strategy.Parse("--payload=tls_client_hello --lua-desync=multidisorder:pos=midsld"), "multidisorder", 0, [], L4Kind.Tcp);
        log.Trial(tried, TrialOutcome.Success());
        log.Trial(tried, TrialOutcome.Success());
        kb.UpdateSession(id, "paused");

        Assert.Equal(id, TuningSession.Resume(kb, id, "WWW.youtube.com", "SniBlock"));
        Assert.Equal("running", kb.Session(id)!.State);
        Assert.Equal(new Efficiency(2, 2), TuningSession.Prepare(kb, new SearchOptions(), id, null).AlreadyTried[tried.Key]);
        // another block or another host: a new session
        Assert.Null(TuningSession.Resume(kb, id, "www.youtube.com", "Cutoff16K"));
        Assert.Null(TuningSession.Resume(kb, id, "i.ytimg.com", "SniBlock"));
        Assert.Null(TuningSession.Resume(kb, id + 100, "www.youtube.com", "SniBlock"));
    }
}
