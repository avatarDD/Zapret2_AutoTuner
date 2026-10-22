using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Engine;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Core.Validation;
using ZapretAutoTuner.Probes.Http;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning;

/// <summary>What a trial checks: one resource of a blocked site at fixed addresses (DNS is decided before the search).</summary>
public sealed record TrialTarget
{
    public required string Host { get; init; }

    public required IReadOnlyList<IPAddress> Addresses { get; init; }

    public int Port { get; init; } = 443;

    public bool Tls { get; init; } = true;

    /// <summary>The resource for L2: the largest response of the page (SecondaryDomains.LargestResponse) or "/".</summary>
    public string Path { get; init; } = "/";

    /// <summary>L2 threshold: 64 KB, 128 KB for the 16 KB cut-off (dpi-diagnostics §3).</summary>
    public long MinBytes { get; init; } = 64 * 1024;

    /// <summary>Padding for a small resource behind a volume cut-off.</summary>
    public int PadBytes { get; init; }
}

public sealed record AgentTrialOptions
{
    /// <summary>The engine's lua directory as the Agent sees it.</summary>
    public required string LuaDir { get; init; }

    /// <summary>Blobs the candidates use (<see cref="GeneratedSet.Blobs"/>): name → 0x… or a file.</summary>
    public IReadOnlyDictionary<string, string> Blobs { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// Functions of the user's approved Lua scripts → the script file (ResourceStore.ApprovedLuaPaths, PLAN 4a.5);
    /// a launch adds <c>--lua-init=@file</c> for the ones its strategy calls.
    /// </summary>
    public IReadOnlyDictionary<string, string> UserLua { get; init; } = new Dictionary<string, string>();

    public EnginePlatform Platform { get; init; } = OperatingSystem.IsWindows() ? EnginePlatform.Windows : EnginePlatform.Linux;

    /// <summary>Linux: the NFQUEUE number of the trial instance.</summary>
    public int QueueNum { get; init; } = 300;

    /// <summary>Time for the engine to open its queue (or WinDivert handle) before the first probe.</summary>
    public TimeSpan Warmup { get; init; } = TimeSpan.FromMilliseconds(400);

    /// <summary>Pause between attempts of a series: a DPI may rate-limit an address (PLAN 3.2).</summary>
    public TimeSpan Pause { get; init; } = TimeSpan.FromMilliseconds(100);

    public TimeSpan ReachTimeout { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>Adjusts the probe (timeouts, trusted roots on the stand).</summary>
    public Func<HttpProbeOptions, HttpProbeOptions>? TweakHttp { get; init; }
}

/// <summary>
/// Runs a strategy for real (PLAN 3.2): one engine instance per series, limited to the target's addresses, then the
/// native L2 probe N times, then the instance is stopped. The Agent validates every argv (AGENTS.md rule 4) and owns
/// the firewall rule; this side never runs anything privileged.
/// </summary>
public sealed class AgentTrialExecutor(IEngineControl engine, TrialTarget target, AgentTrialOptions options) : ITrialExecutor
{
    public async Task<IReadOnlyList<TrialOutcome>> RunAsync(StrategyCandidate candidate, int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
    {
        try
        {
            return await WithEngineAsync(candidate, ct => ProbeSeriesAsync(attempts, stopEarly, ct), ct).ConfigureAwait(false);
        }
        catch (EngineRefusedException e) when (!e.Infrastructure)
        {
            // the strategy itself is wrong for this engine: it fails without a single probe. A busy queue or a missing
            // firewall would fail every strategy, so that refusal stops the search instead of marking them all dead.
            return [TrialOutcome.Fail(TrialFailure.Other, e.Message)];
        }
    }

    /// <summary>
    /// Runs <paramref name="body"/> while an engine instance with the strategy is up (the final check opens the page
    /// in a browser this way). Throws <see cref="EngineRefusedException"/> when the Agent refuses the argv.
    /// </summary>
    public async Task<T> WithEngineAsync<T>(StrategyCandidate candidate, Func<CancellationToken, Task<T>> body, CancellationToken ct)
    {
        var (argv, queue) = BuildLaunch(candidate);
        // not cancellable: the Agent may start the engine after the client gave up, and then nobody would stop it
        var id = await engine.StartAsync(argv, queue, "trial:" + target.Host, CancellationToken.None).ConfigureAwait(false);
        try
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(options.Warmup, ct).ConfigureAwait(false);
            return await body(ct).ConfigureAwait(false);
        }
        finally
        {
            await engine.StopAsync(id, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>The L2 probe up to <paramref name="attempts"/> times against the target's addresses in turn.</summary>
    public async Task<IReadOnlyList<TrialOutcome>> ProbeSeriesAsync(int attempts, Func<IReadOnlyList<TrialOutcome>, bool> stopEarly, CancellationToken ct)
    {
        var outcomes = new List<TrialOutcome>();
        for (int i = 0; i < attempts; i++)
        {
            if (i > 0)
                await Task.Delay(options.Pause, ct).ConfigureAwait(false);
            var address = target.Addresses[i % target.Addresses.Count];
            var r = await HttpProbe.RunAsync(ProbeOptions(address), ct).ConfigureAwait(false);
            outcomes.Add(ToOutcome(r, target.MinBytes));
            if (stopEarly(outcomes))
                break;
        }
        return outcomes;
    }

    public async Task<bool> TargetReachableAsync(CancellationToken ct)
    {
        foreach (var address in target.Addresses)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(options.ReachTimeout);
            using var s = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await s.ConnectAsync(address, target.Port, cts.Token).ConfigureAwait(false);
                return true;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
            }
            catch (SocketException)
            {
            }
        }
        return false;
    }

    internal HttpProbeOptions ProbeOptions(IPAddress address)
    {
        var o = new HttpProbeOptions
        {
            Host = target.Host,
            Address = address,
            Port = target.Port,
            Tls = target.Tls,
            Path = target.Path,
            MinBytes = target.MinBytes,
            PadBytes = target.PadBytes,
        };
        return options.TweakHttp?.Invoke(o) ?? o;
    }

    /// <summary>The argv and the Linux queue rule of one trial instance; the Agent adds --qnum and --fwmark itself.</summary>
    internal (List<string> Argv, QueueRule? Queue) BuildLaunch(StrategyCandidate candidate)
    {
        var profile = new Profile { Name = "trial", Strategy = candidate.Strategy };
        if (candidate.L4 == L4Kind.Udp)
            profile.UdpPorts = target.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        else
            profile.TcpPorts = target.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var launch = new EngineLaunch
        {
            Platform = options.Platform,
            LuaDir = options.LuaDir,
            Blobs = UsedBlobs(candidate.Strategy),
            ExtraLuaPaths = Core.Resources.ResourceRefs.LuaPathsFor([candidate.Strategy], options.UserLua),
            Profiles = [profile],
            QueueNum = options.QueueNum,
            TargetAddresses = target.Addresses,
        };
        var argv = EngineArgsBuilder.Build(launch);
        if (options.Platform == EnginePlatform.Windows)
            return (argv, null);
        argv.RemoveAll(a => a.StartsWith("--qnum=", StringComparison.Ordinal) || a.StartsWith("--fwmark=", StringComparison.Ordinal));
        var queue = new QueueRule { QueueNum = options.QueueNum, Incoming = EngineArgsBuilder.NeedsIncoming(profile) };
        if (candidate.L4 == L4Kind.Udp)
            queue.UdpPorts = profile.UdpPorts;
        else
            queue.TcpPorts = profile.TcpPorts;
        queue.Targets.AddRange(target.Addresses.Select(a => a.ToString()));
        return (argv, queue);
    }

    /// <summary>Only the blobs the strategy names: an unused --blob costs a file read and a policy check.</summary>
    private Dictionary<string, string> UsedBlobs(Strategy s)
    {
        var names = s.Calls.SelectMany(c => c.Args).Select(a => a.Value).Where(v => v is not null).ToHashSet(StringComparer.Ordinal);
        return options.Blobs.Where(b => names.Contains(b.Key)).ToDictionary(b => b.Key, b => b.Value, StringComparer.Ordinal);
    }

    /// <summary>A probe result in the search's terms (dpi-diagnostics §3: success is L2, not a handshake).</summary>
    internal static TrialOutcome ToOutcome(ProbeResult r, long minBytes)
    {
        if (r.Passes(ProbeLevel.L2Body, minBytes))
            return new TrialOutcome(true, TrialFailure.None, null, r.BodyBytes, r.Duration);
        var failure = r.Error switch
        {
            ProbeError.ConnectTimeout or ProbeError.ConnectRefused or ProbeError.Unreachable => TrialFailure.NoConnect,
            ProbeError.TlsReset or ProbeError.HttpReset => TrialFailure.Reset,
            ProbeError.TlsTimeout or ProbeError.HttpTimeout => TrialFailure.Timeout,
            ProbeError.Stalled or ProbeError.Truncated or ProbeError.TimeLimit => TrialFailure.Stalled,
            _ when r.TlsOk && !r.CertValid => TrialFailure.BadCertificate,
            _ => TrialFailure.Other,
        };
        return new TrialOutcome(false, failure, r.Error == ProbeError.None ? r.CertError ?? $"HTTP {r.HttpStatus}" : $"{r.Error}: {r.ErrorDetail}", r.BodyBytes, r.Duration);
    }
}
