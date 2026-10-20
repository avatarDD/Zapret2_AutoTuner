using System.Diagnostics;
using System.Net;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Probes.Programs;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning;

/// <summary>Capture and socket listing for a program recording; the Agent does it for real, tests fake it.</summary>
public interface IProgramMonitor
{
    Task<string> StartCaptureAsync(CancellationToken ct);

    /// <summary>Stops the capture and returns its pcapng and the packets the ring buffer evicted.</summary>
    Task<(byte[] Pcapng, long Dropped)> StopCaptureAsync(string captureId, CancellationToken ct);

    Task<IReadOnlyList<ObservedSocket>> ListConnectionsAsync(int pid, CancellationToken ct);
}

/// <summary><see cref="IProgramMonitor"/> over the Agent (AGENTS.md rule 6: capture needs rights, the UI has none).</summary>
public sealed class AgentProgramMonitor(Agent.AgentClient client) : IProgramMonitor
{
    /// <summary>Ring buffer: a few minutes of a voice call or a game fit; older packets are evicted, not the newest.</summary>
    public long MaxBytes { get; init; } = 64L << 20;

    public async Task<string> StartCaptureAsync(CancellationToken ct) =>
        (await client.StartCaptureAsync(new StartCaptureRequest { MaxBytes = MaxBytes }, cancellationToken: ct)).CaptureId;

    public async Task<(byte[] Pcapng, long Dropped)> StopCaptureAsync(string captureId, CancellationToken ct)
    {
        using var call = client.StopCapture(new StopCaptureRequest { CaptureId = captureId }, cancellationToken: ct);
        using var ms = new MemoryStream();
        long dropped = 0;
        while (await call.ResponseStream.MoveNext(ct).ConfigureAwait(false))
        {
            call.ResponseStream.Current.Data.WriteTo(ms);
            dropped = call.ResponseStream.Current.Dropped;
        }
        return (ms.ToArray(), dropped);
    }

    public async Task<IReadOnlyList<ObservedSocket>> ListConnectionsAsync(int pid, CancellationToken ct)
    {
        var reply = await client.ListConnectionsAsync(new ListConnectionsRequest { Pid = pid }, cancellationToken: ct);
        var list = new List<ObservedSocket>();
        foreach (var c in reply.Connections)
        {
            if (!IPAddress.TryParse(c.LocalAddress, out var local))
                continue;
            IPEndPoint? remote = IPAddress.TryParse(c.RemoteAddress, out var r) && c.RemotePort != 0 && !r.Equals(IPAddress.Any) && !r.Equals(IPAddress.IPv6Any)
                ? new IPEndPoint(r, c.RemotePort) : null;
            list.Add(new ObservedSocket(c.Protocol == "udp" ? L4Kind.Udp : L4Kind.Tcp, new IPEndPoint(local, c.LocalPort), remote));
        }
        return list;
    }
}

public sealed record RecordOptions
{
    /// <summary>"Запустить и записать N секунд" (PLAN 6.2).</summary>
    public TimeSpan Duration { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How often the program's processes and sockets are listed: a socket that lives shorter is missed.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>The program's processes now; by default the launched process tree plus processes started from its folder.</summary>
    public Func<IReadOnlySet<int>>? Pids { get; init; }
}

public sealed record ProgramRecording(IReadOnlyList<ProgramEndpoint> Endpoints, IReadOnlyCollection<int> Pids, int Sockets, int Packets, long Dropped)
{
    /// <summary>Endpoints worth a search: the program got no answer, a reset or a stall there.</summary>
    public IEnumerable<ProgramEndpoint> Broken => Endpoints.Where(e => e.Health is not (Core.Diagnostics.FlowHealth.Ok or Core.Diagnostics.FlowHealth.Unknown));
}

/// <summary>
/// Records what a program does on the network (PLAN 6.2): the capture runs in the Agent, the program's processes are
/// polled for their sockets, and the captured flows on those sockets become the program's endpoints. The program is
/// started here, as the user, never by the Agent.
/// </summary>
public static class ProgramRecorder
{
    /// <summary>Starts the program as the current user. Throws when it has nothing to start.</summary>
    public static Process Launch(ProgramInfo program)
    {
        if (program.Executable is null)
            throw new InvalidOperationException($"{program.Name}: неизвестен исполняемый файл / no executable");
        var psi = new ProcessStartInfo(program.Executable) { UseShellExecute = false };
        foreach (var a in program.Arguments)
            psi.ArgumentList.Add(a);
        return Process.Start(psi) ?? throw new InvalidOperationException($"{program.Name}: не запустилась / did not start");
    }

    /// <summary>
    /// The launched tree, plus processes started from the program's own folder: launchers (Discord's Update.exe, a
    /// Steam game) exit and leave the real process to their children. A shared folder (on PATH, the Windows folder) is
    /// not the program's own and is left out.
    /// </summary>
    public static Func<IReadOnlySet<int>> DefaultPids(ProgramInfo program, int rootPid)
    {
        var dir = program.Executable is null || program.Source == ProgramSource.Uwp ? null : Path.GetDirectoryName(Path.GetFullPath(program.Executable));
        if (dir is not null && IsSharedDirectory(dir))
            dir = null;
        var seen = new HashSet<int> { rootPid };
        return () =>
        {
            var parents = ProcessTree.Parents();
            // a process that left the tree (its parent exited) stays in it: its pid is remembered
            foreach (var root in seen.ToList())
                seen.UnionWith(ProcessTree.Closure(root, parents));
            if (dir is not null)
                seen.UnionWith(ProcessTree.UnderDirectory(dir));
            seen.IntersectWith(parents.Keys.Append(rootPid));
            return seen.ToHashSet();
        };
    }

    public static bool IsSharedDirectory(string dir)
    {
        var cmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var norm = dir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var path = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        if (path.Any(p => string.Equals(p, norm, cmp)))
            return true;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return windows.Length > 0 && norm.StartsWith(windows, cmp);
    }

    /// <summary>Records for <see cref="RecordOptions.Duration"/>; the capture is always stopped.</summary>
    public static async Task<ProgramRecording> RecordAsync(IProgramMonitor monitor, RecordOptions options, IProgress<double>? progress = null, CancellationToken ct = default)
    {
        var pidsOf = options.Pids ?? throw new ArgumentException("Pids: укажите процессы программы", nameof(options));
        var sockets = new HashSet<ObservedSocket>();
        var pids = new HashSet<int>();
        var id = await monitor.StartCaptureAsync(ct).ConfigureAwait(false);
        byte[] pcap;
        long dropped;
        try
        {
            var sw = Stopwatch.StartNew();
            while (sw.Elapsed < options.Duration && !ct.IsCancellationRequested)
            {
                foreach (var pid in pidsOf())
                {
                    pids.Add(pid);
                    try
                    {
                        sockets.UnionWith(await monitor.ListConnectionsAsync(pid, ct).ConfigureAwait(false));
                    }
                    catch (Grpc.Core.RpcException)
                    {
                        // the process exited between the listing and the call
                    }
                }
                progress?.Report(Math.Min(1, sw.Elapsed / options.Duration));
                try
                {
                    await Task.Delay(options.PollInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
        finally
        {
            // not cancellable: an abandoned capture keeps the Agent's buffer and filter
            (pcap, dropped) = await monitor.StopCaptureAsync(id, CancellationToken.None).ConfigureAwait(false);
        }
        ct.ThrowIfCancellationRequested();
        var packets = PcapReader.Read(pcap);
        var flows = FlowAnalyzer.Analyze(packets);
        return new ProgramRecording(ProgramEndpoints.FromRecording(sockets, flows, packets), pids, sockets.Count, packets.Count, dropped);
    }
}
