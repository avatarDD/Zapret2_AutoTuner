using System.Net;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Monitor;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>An engine that, like the Agent on Linux, refuses a queue another running instance holds.</summary>
internal sealed class QueueEngine : IEngineControl
{
    private int _seq;

    public Dictionary<string, (int Queue, Solution? Solution)> Running { get; } = [];

    public List<string> Log { get; } = [];

    /// <summary>When set, the next start waits for it (a swap held in flight).</summary>
    public TaskCompletionSource? StartGate { get; set; }

    /// <summary>The solution each argv was built from (the test launcher puts its key in argv[0]).</summary>
    public Dictionary<string, Solution> Solutions { get; } = [];

    public async Task<string> StartAsync(IReadOnlyList<string> argv, QueueRule? queue, string tag, CancellationToken ct)
    {
        Assert.False(ct.CanBeCanceled);
        if (StartGate is { } gate)
        {
            StartGate = null;
            await gate.Task;
        }
        lock (Running)
        {
            if (Running.Values.Any(r => r.Queue == queue!.QueueNum))
                throw EngineRefusedException.FromAgent($"firewall: очередь {queue!.QueueNum} уже занята другим экземпляром");
            var id = "p" + ++_seq;
            Running[id] = (queue!.QueueNum, Solutions.GetValueOrDefault(argv[0]));
            Log.Add($"start {id} q{queue.QueueNum}");
            return id;
        }
    }

    public Task StopAsync(string engineId, CancellationToken ct)
    {
        lock (Running)
        {
            Running.Remove(engineId);
            Log.Add("stop " + engineId);
        }
        return Task.CompletedTask;
    }
}

public sealed class ProtectionControllerTests
{
    private static readonly StrategyCandidate Fix = ProgramFixtures.Candidate("--payload=tls_client_hello --lua-desync=multisplit:pos=midsld+1", L4Kind.Tcp);

    private static Solution Sample()
    {
        var s = new Solution();
        s.Profiles.Add(new Profile { Name = "a", TcpPorts = "443", HostlistDomains = ["example.com", "other.com"], Strategy = Strategy.Parse("--lua-desync=multisplit:pos=1") });
        return s;
    }

    private static HealthEvent Degraded(string domain) => new(domain, HealthChange.Degraded, DateTime.UtcNow, []);

    private static (ProtectionController C, QueueEngine E, List<string> Problems, List<RepairResult> Finished) Make(IRepairSteps steps, ApplyPolicy policy = ApplyPolicy.Ask)
    {
        var e = new QueueEngine();
        var c = new ProtectionController(e, steps, (s, q) =>
        {
            var key = Guid.NewGuid().ToString("N");
            e.Solutions[key] = s;
            return ([key], new QueueRule { QueueNum = q });
        }, () => policy);
        if (steps is StrategySteps st)
            st.Getter = () => c.Solution;
        var problems = new List<string>();
        var finished = new List<RepairResult>();
        c.Problem += (_, m) => problems.Add(m);
        c.Finished += finished.Add;
        return (c, e, problems, finished);
    }

    [Fact]
    public async Task Repair_runs_with_the_strategy_the_domain_had_before_it_was_isolated()
    {
        var steps = new StrategySteps { Local = Fix };
        var (c, e, problems, finished) = Make(steps);
        await c.StartAsync(Sample());
        var r = await c.HandleAsync(Degraded("example.com"));

        Assert.NotNull(r);
        Assert.Equal(RepairVerdict.Replaced, r.Verdict);
        Assert.Equal("--lua-desync=multisplit:pos=1", steps.CurrentSeen!.Strategy.ToString());
        // while probing, the running protection did not serve the domain
        Assert.Null(Protection.CurrentOf(steps.RunningDuringRepair!, "example.com"));
        Assert.NotNull(Protection.CurrentOf(steps.RunningDuringRepair!, "other.com"));
        // Ask: offered, and the domain is back under its old strategy
        Assert.Same(r, Assert.Single(finished));
        Assert.Equal("--lua-desync=multisplit:pos=1", Protection.CurrentOf(c.Solution!, "example.com")!.Strategy.ToString());
        Assert.Empty(problems);
        Assert.Single(e.Running);
    }

    [Fact]
    public async Task User_report_also_repairs()
    {
        var steps = new StrategySteps { Check = new(5, 5) };
        var (c, _, _, _) = Make(steps);
        await c.StartAsync(Sample());
        var r = await c.HandleAsync(Degraded("example.com"), RepairCoordinator.UserReport);
        Assert.Equal(RepairVerdict.StillWorks, r!.Verdict);
        Assert.Contains("check example.com", steps.Calls);
    }

    [Fact]
    public async Task Each_swap_takes_the_other_protection_queue()
    {
        var (c, e, problems, _) = Make(new StrategySteps { Local = Fix });
        await c.StartAsync(Sample());
        Assert.Equal(Protection.QueueNum, c.Queue);
        await c.HandleAsync(Degraded("example.com"));      // isolate + restore: two swaps
        Assert.Empty(problems);
        Assert.Equal(["start p1 q310", "start p2 q311", "stop p1", "start p3 q310", "stop p2"], e.Log);
        Assert.Equal(Protection.QueueNum, c.Queue);
        Assert.Equal(311, Protection.NextQueue(310));
        Assert.Equal(310, Protection.NextQueue(311));
    }

    [Fact]
    public async Task Auto_policy_applies_the_fix_and_does_not_restore()
    {
        var steps = new StrategySteps { Local = Fix };
        var (c, e, _, finished) = Make(steps, ApplyPolicy.Auto);
        var applied = new List<(RepairResult R, Solution S)>();
        c.Applied += (r, s) => applied.Add((r, s));
        await c.StartAsync(Sample());
        await c.HandleAsync(Degraded("example.com"));
        Assert.Empty(finished);
        var (_, s) = Assert.Single(applied);
        Assert.Same(c.Solution, s);
        Assert.Equal(Fix.Strategy.ToString(), Protection.CurrentOf(s, "example.com")!.Strategy.ToString());
        Assert.Same(s, e.Running.Values.Single().Solution);
    }

    [Fact]
    public async Task A_failing_repair_reports_and_restores_the_domain()
    {
        var steps = new StrategySteps { Throw = new IOException("agent dropped") };
        var (c, e, problems, finished) = Make(steps);
        var original = Sample();
        await c.StartAsync(original);
        Assert.Null(await c.HandleAsync(Degraded("example.com")));
        Assert.Equal("agent dropped", Assert.Single(problems));
        Assert.Empty(finished);
        // nothing else changed meanwhile: the very original solution runs again
        Assert.Same(original, c.Solution);
        Assert.Same(original, e.Running.Values.Single().Solution);
    }

    [Fact]
    public async Task A_refused_isolation_leaves_the_protection_as_it_was()
    {
        var (c, e, problems, _) = Make(new StrategySteps());
        var original = Sample();
        await c.StartAsync(original);
        // another instance holds the alternate queue: the swap is refused, the old instance keeps running
        await e.StartAsync(["x"], new QueueRule { QueueNum = Protection.AltQueueNum }, "foreign", CancellationToken.None);
        Assert.Null(await c.HandleAsync(Degraded("example.com")));
        Assert.Contains("311", Assert.Single(problems), StringComparison.Ordinal);
        Assert.Same(original, c.Solution);
        Assert.Equal("p1", c.EngineId);
    }

    [Fact]
    public async Task Apply_builds_on_the_latest_solution()
    {
        var steps = new StrategySteps { Local = Fix };
        var (c, _, _, finished) = Make(steps);
        await c.StartAsync(Sample());
        await c.HandleAsync(Degraded("example.com"));
        await c.HandleAsync(Degraded("other.com"));
        Assert.Equal(2, finished.Count);
        Assert.True(await c.ApplyAsync(finished[0]));
        Assert.True(await c.ApplyAsync(finished[1]));
        // both fixes run: the second apply did not start from a copy without the first
        Assert.Equal(Fix.Strategy.ToString(), Protection.CurrentOf(c.Solution!, "example.com")!.Strategy.ToString());
        Assert.Equal(Fix.Strategy.ToString(), Protection.CurrentOf(c.Solution!, "other.com")!.Strategy.ToString());
    }

    [Fact]
    public async Task Stop_waits_for_a_swap_in_flight_and_leaves_no_instance()
    {
        var (c, e, _, _) = Make(new StrategySteps { Local = Fix });
        await c.StartAsync(Sample());
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        e.StartGate = gate;
        var repair = Task.Run(() => c.HandleAsync(Degraded("example.com")));
        while (e.StartGate is not null)
            await Task.Delay(5);
        var stop = c.StopAsync();
        await Task.Delay(50);
        Assert.False(stop.IsCompleted);         // the swap holds the gate
        gate.SetResult();
        await stop;
        await repair;
        Assert.Empty(e.Running);
        Assert.Null(c.EngineId);
        Assert.False(c.Running);
        // nothing swaps after the stop
        Assert.False(await c.ApplyAsync(new RepairResult("other.com", RepairVerdict.Replaced, Fix, "", "")));
        Assert.Empty(e.Running);
    }

    [Fact]
    public async Task Recovery_is_journalled_without_a_swap()
    {
        var (c, e, _, _) = Make(new StrategySteps());
        var journal = new List<(string Kind, string Ru, string En)>();
        c.Journal += (_, k, ru, en) => journal.Add((k, ru, en));
        await c.StartAsync(Sample());
        await c.HandleAsync(new HealthEvent("example.com", HealthChange.Recovered, DateTime.UtcNow, []));
        Assert.Equal("recovered", Assert.Single(journal).Kind);
        Assert.NotEqual(journal[0].Ru, journal[0].En);
        Assert.Single(e.Log);
    }

    /// <summary>Repair steps that also record what the coordinator handed them and what ran meanwhile.</summary>
    private sealed class StrategySteps : IRepairSteps
    {
        public List<string> Calls { get; } = [];

        public StrategyCandidate? CurrentSeen { get; private set; }

        public Solution? RunningDuringRepair { get; private set; }

        public Efficiency Check { get; set; } = new(0, 5);

        public StrategyCandidate? Local { get; set; }

        public Exception? Throw { get; set; }

        public Task<bool> BaselineWorksAsync(string domain, CancellationToken ct)
        {
            Calls.Add("baseline " + domain);
            if (Throw is not null)
                throw Throw;
            return Task.FromResult(false);
        }

        public Task<bool> ReachableAsync(string domain, CancellationToken ct) => Task.FromResult(true);

        public Task<Efficiency> CheckAsync(string domain, StrategyCandidate current, CancellationToken ct)
        {
            Calls.Add("check " + domain);
            CurrentSeen = current;
            return Task.FromResult(Check);
        }

        public Task<StrategyCandidate?> LocalSearchAsync(string domain, StrategyCandidate current, CancellationToken ct)
        {
            RunningDuringRepair = Running;
            return Task.FromResult(Local);
        }

        public Task<StrategyCandidate?> FullSearchAsync(string domain, CancellationToken ct) => Task.FromResult<StrategyCandidate?>(null);

        /// <summary>The solution the protection runs (set by the test helper).</summary>
        public Func<Solution?>? Getter { get; set; }

        private Solution? Running => Getter?.Invoke();
    }
}

public sealed class LiveAddressesTests
{
    private static readonly IPAddress V4a = IPAddress.Parse("203.0.113.1"), V4b = IPAddress.Parse("203.0.113.2"), V6 = IPAddress.Parse("2001:db8::1");

    [Fact]
    public async Task Ipv4_only_and_only_the_ones_that_connect()
    {
        var tried = new List<IPAddress>();
        var live = await LiveAddresses.ResolveAsync("example.com", CancellationToken.None,
            resolve: (_, _) => Task.FromResult(new[] { V6, V4a, V4b, V4a }),
            connects: (a, _) =>
            {
                lock (tried)
                    tried.Add(a);
                return Task.FromResult(a.Equals(V4b));
            });
        Assert.Equal([V4b], live);
        Assert.DoesNotContain(V6, tried);
        Assert.Equal(2, tried.Count);
    }

    [Fact]
    public async Task Ipv6_only_site_and_nothing_connecting()
    {
        var live = await LiveAddresses.ResolveAsync("v6.example", CancellationToken.None,
            resolve: (_, _) => Task.FromResult(new[] { V6 }), connects: (_, _) => Task.FromResult(false));
        // none connects: the candidates stay, so the reachability step says "site down"
        Assert.Equal([V6], live);
        Assert.Empty(await LiveAddresses.ResolveAsync("none.example", CancellationToken.None,
            resolve: (_, _) => Task.FromResult(Array.Empty<IPAddress>()), connects: (_, _) => Task.FromResult(true)));
    }

    [Fact]
    public async Task At_most_four_candidates()
    {
        var many = Enumerable.Range(1, 9).Select(i => IPAddress.Parse("198.51.100." + i)).ToArray();
        var live = await LiveAddresses.ResolveAsync("big.example", CancellationToken.None, max: 4,
            resolve: (_, _) => Task.FromResult(many), connects: (_, _) => Task.FromResult(true));
        Assert.Equal(many.Take(4), live);
    }
}
