using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Unify;
using ZapretAutoTuner.Core.Validation;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning;

/// <summary>How one domain did under the combined config.</summary>
public sealed record ConfigDomainResult(string Domain, Efficiency L2, bool? PageOk, IReadOnlyList<SecondaryDomain> Domains)
{
    public bool Passed => L2.Attempts > 0 && L2.Successes == L2.Attempts && PageOk != false;
}

/// <param name="Unchecked">
/// Profiles the check could not probe: QUIC ones, since the probes are TCP (L2 is a TLS handshake plus a download).
/// They are in the engine run, so they are shown to catch nothing else, but not shown to work.
/// </param>
public sealed record ConfigCheckResult(IReadOnlyList<ConfigDomainResult> Domains, IReadOnlyList<string> Argv, IReadOnlyList<string> Unchecked)
{
    public bool Passed => Domains.Count > 0 && Domains.All(d => d.Passed);
}

/// <summary>
/// The check of the combined config (PLAN 4.2, dpi-diagnostics §7.7): one engine instance with every profile, then
/// each domain probed N/N at L2 and, when a page opener is given, at L3. Only this shows that the profiles do not
/// catch each other's traffic. Hostlists are passed inline (<c>--hostlist-domains</c>), so no list files are needed.
/// </summary>
public static class ConfigCheck
{
    public static async Task<ConfigCheckResult> RunAsync(IEngineControl engine, Solution solution, IReadOnlyList<TrialTarget> targets, AgentTrialOptions options,
        Func<string, CancellationToken, Task<PageLoad>>? openPage = null, int attempts = 3, CancellationToken ct = default)
    {
        var (argv, queue) = BuildLaunch(solution, targets, options);
        var id = await engine.StartAsync(argv, queue, "config-check", CancellationToken.None).ConfigureAwait(false);
        var results = new List<ConfigDomainResult>();
        try
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(options.Warmup, ct).ConfigureAwait(false);
            foreach (var t in targets)
            {
                var probe = new AgentTrialExecutor(engine, t, options);
                var series = await probe.ProbeSeriesAsync(attempts, o => o.Any(x => !x.Ok), ct).ConfigureAwait(false);
                var l2 = new Efficiency(series.Count(o => o.Ok), series.Count);
                if (openPage is null || l2.Successes < attempts)
                {
                    results.Add(new ConfigDomainResult(t.Host, l2, null, []));
                    continue;
                }
                var load = await openPage(t.Host, ct).ConfigureAwait(false);
                var domains = SecondaryDomains.Analyze(load, t.Host);
                results.Add(new ConfigDomainResult(t.Host, l2, SecondaryDomains.PagePasses(load, domains), domains));
            }
        }
        finally
        {
            await engine.StopAsync(id, CancellationToken.None).ConfigureAwait(false);
        }
        var notProbed = solution.Profiles.Where(p => p.UdpPorts is not null && p.TcpPorts is null).Select(p => p.Name).ToList();
        return new ConfigCheckResult(results, argv, notProbed);
    }

    internal static (List<string> Argv, QueueRule? Queue) BuildLaunch(Solution solution, IReadOnlyList<TrialTarget> targets, AgentTrialOptions options)
    {
        var profiles = solution.Profiles.Select(p =>
        {
            var c = p.Clone();
            foreach (var list in p.Hostlists)
            {
                if (solution.Hostlists.TryGetValue(list.Name, out var domains))
                    c.HostlistDomains.AddRange(domains);
            }
            c.Hostlists = [.. p.Hostlists.Where(l => !solution.Hostlists.ContainsKey(l.Name))];
            return c;
        }).ToList();
        var used = profiles.SelectMany(p => p.Strategy.Calls).SelectMany(c => c.Args).Select(a => a.Value).Where(v => v is not null).ToHashSet(StringComparer.Ordinal);
        var addresses = targets.SelectMany(t => t.Addresses).Distinct().ToList();
        var launch = new EngineLaunch
        {
            Platform = options.Platform,
            LuaDir = options.LuaDir,
            Blobs = options.Blobs.Where(b => used.Contains(b.Key)).ToDictionary(b => b.Key, b => b.Value, StringComparer.Ordinal),
            ExtraLuaPaths = Core.Resources.ResourceRefs.LuaPathsFor(profiles.Select(p => p.Strategy), options.UserLua),
            Profiles = profiles,
            QueueNum = options.QueueNum,
            TargetAddresses = addresses,
            IpcacheHostname = Unifier.NeedsIpcacheHostname(solution),
        };
        var argv = EngineArgsBuilder.Build(launch);
        if (options.Platform == EnginePlatform.Windows)
            return (argv, null);
        argv.RemoveAll(a => a.StartsWith("--qnum=", StringComparison.Ordinal) || a.StartsWith("--fwmark=", StringComparison.Ordinal));
        var tcp = PortList.Union(profiles.Select(p => p.TcpPorts));
        var udp = PortList.Union(profiles.Select(p => p.UdpPorts));
        var queue = new QueueRule
        {
            QueueNum = options.QueueNum,
            TcpPorts = tcp,
            UdpPorts = udp,
            Incoming = profiles.Any(EngineArgsBuilder.NeedsIncoming),
        };
        queue.Targets.AddRange(addresses.Select(a => a.ToString()));
        return (argv, queue);
    }
}
