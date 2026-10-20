using System.Globalization;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Validation;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning;

/// <summary>A strategy found for one endpoint of a program.</summary>
public sealed record EndpointStrategy(ProgramEndpoint Endpoint, StrategyCandidate Candidate);

/// <summary>An endpoint before and after: <see cref="After"/> is null when the rerun did not reach it.</summary>
public sealed record EndpointCheck(ProgramEndpoint Before, ProgramEndpoint? After)
{
    public bool Fixed => After is { Health: FlowHealth.Ok };
}

public sealed record ProgramCheckResult(IReadOnlyList<EndpointCheck> Endpoints, IReadOnlyList<ProgramEndpoint> StillBroken, ProgramRecording Recording, string? Error)
{
    /// <summary>
    /// Every endpoint with a strategy that the rerun reached works, at least one of them was reached, and nothing the
    /// program used is broken now (PLAN 6.3: the program itself is the check, not the replay probe).
    /// </summary>
    public bool Passed => Error is null && Endpoints.Any(e => e.After is not null) && Endpoints.All(e => e.After is null || e.Fixed) && StillBroken.Count == 0;
}

/// <summary>
/// The final check for a program (PLAN 6.3): one engine instance with a profile per endpoint strategy, the program
/// started again and recorded, and its endpoints compared with the first recording.
/// </summary>
public static class ProgramCheck
{
    public static async Task<ProgramCheckResult> RunAsync(IEngineControl engine, IProgramMonitor monitor, IReadOnlyList<EndpointStrategy> found,
        Func<RecordOptions> startProgram, AgentTrialOptions options, string tag, IProgress<double>? progress = null, CancellationToken ct = default)
    {
        var (argv, queue) = BuildLaunch(found, options);
        string id;
        try
        {
            id = await engine.StartAsync(argv, queue, "program:" + tag, CancellationToken.None).ConfigureAwait(false);
        }
        catch (EngineRefusedException e)
        {
            return new ProgramCheckResult([], [], new ProgramRecording([], [], 0, 0, 0), e.Message);
        }
        try
        {
            await Task.Delay(options.Warmup, ct).ConfigureAwait(false);
            var recording = await ProgramRecorder.RecordAsync(monitor, startProgram(), progress, ct).ConfigureAwait(false);
            return Compare(found, recording);
        }
        finally
        {
            await engine.StopAsync(id, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>Matches the rerun's endpoints with the strategies' endpoints: the same address and port, else the same name.</summary>
    public static ProgramCheckResult Compare(IReadOnlyList<EndpointStrategy> found, ProgramRecording rerun)
    {
        var checks = new List<EndpointCheck>();
        var matched = new HashSet<ProgramEndpoint>();
        foreach (var f in found)
        {
            var e = f.Endpoint;
            var after = rerun.Endpoints.FirstOrDefault(r => r.Protocol == e.Protocol && r.Remote.Equals(e.Remote))
                ?? (e.Host is null ? null : rerun.Endpoints.FirstOrDefault(r => r.Protocol == e.Protocol && r.Remote.Port == e.Remote.Port
                    && string.Equals(r.Host, e.Host, StringComparison.OrdinalIgnoreCase)));
            if (after is not null)
                matched.Add(after);
            checks.Add(new EndpointCheck(e, after));
        }
        var stillBroken = rerun.Broken.Where(r => !matched.Contains(r)).ToList();
        return new ProgramCheckResult(checks, stillBroken, rerun, null);
    }

    /// <summary>
    /// A profile per endpoint: by name for TLS, QUIC and HTTP (a CDN may answer from another address next time), by
    /// address for the rest. The Linux queue takes the ports, and the addresses unless a profile filters by name.
    /// </summary>
    internal static (List<string> Argv, QueueRule? Queue) BuildLaunch(IReadOnlyList<EndpointStrategy> found, AgentTrialOptions options)
    {
        if (found.Count == 0)
            throw new ArgumentException("нет стратегий для проверки / nothing to check", nameof(found));
        var profiles = new List<Profile>();
        foreach (var (f, i) in found.Select((f, i) => (f, i)))
        {
            var e = f.Endpoint;
            var port = e.Remote.Port.ToString(CultureInfo.InvariantCulture);
            var p = new Profile { Name = $"ep{i}", Strategy = f.Candidate.Strategy };
            if (f.Candidate.L4 == L4Kind.Udp)
                p.UdpPorts = port;
            else
                p.TcpPorts = port;
            if (ByName(e))
                p.HostlistDomains.Add(e.Host!);
            else
                p.IpsetIps.Add(e.Remote.Address.ToString());
            profiles.Add(p);
        }
        var names = found.SelectMany(f => f.Candidate.Strategy.Calls).SelectMany(c => c.Args).Select(a => a.Value).Where(v => v is not null).ToHashSet(StringComparer.Ordinal);
        var anyName = found.Any(f => ByName(f.Endpoint));
        var launch = new EngineLaunch
        {
            Platform = options.Platform,
            LuaDir = options.LuaDir,
            Blobs = options.Blobs.Where(b => names.Contains(b.Key)).ToDictionary(b => b.Key, b => b.Value, StringComparer.Ordinal),
            Profiles = profiles,
            QueueNum = options.QueueNum,
            TargetAddresses = anyName ? [] : found.Select(f => f.Endpoint.Remote.Address).Distinct().ToList(),
        };
        var argv = EngineArgsBuilder.Build(launch);
        if (options.Platform == EnginePlatform.Windows)
            return (argv, null);
        argv.RemoveAll(a => a.StartsWith("--qnum=", StringComparison.Ordinal) || a.StartsWith("--fwmark=", StringComparison.Ordinal));
        var queue = new QueueRule
        {
            QueueNum = options.QueueNum,
            Incoming = profiles.Any(EngineArgsBuilder.NeedsIncoming),
            TcpPorts = PortList.Union(profiles.Select(p => p.TcpPorts)),
            UdpPorts = PortList.Union(profiles.Select(p => p.UdpPorts)),
        };
        if (!anyName)
            queue.Targets.AddRange(launch.TargetAddresses.Select(a => a.ToString()));
        return (argv, queue);
    }

    private static bool ByName(ProgramEndpoint e) => e.Host is not null && e.App is AppProtocol.Tls or AppProtocol.Quic or AppProtocol.Http;
}
