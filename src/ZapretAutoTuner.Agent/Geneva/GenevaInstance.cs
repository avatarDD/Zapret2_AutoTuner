using System.Diagnostics;
using System.Threading.Channels;
using ZapretAutoTuner.Agent.Engine;
using ZapretAutoTuner.Agent.Os;

namespace ZapretAutoTuner.Agent.Geneva;

/// <summary>One line of a geneva process: an event (stdout), a log line (stderr), or the exit.</summary>
internal readonly record struct GenevaLine(string? Event, string? Log, bool Exited = false, int ExitCode = 0);

/// <summary>
/// One running geneva process. stdout carries the JSON Lines events, stderr the log; both are buffered (bounded) so a
/// watcher that subscribes late still sees the start. A search reads the UI's answers on stdin, so it runs without
/// the Linux supervisor: geneva stops by itself (rules removed, checkpoint saved) when its stdin closes, which is
/// also what happens when the Agent dies. A run goes through <see cref="EngineInstance.LinuxSupervisor"/> like nfqws2.
/// </summary>
internal sealed class GenevaInstance : IDisposable
{
    public const int MaxBufferedLines = 20000;

    private readonly Process _process;
    private readonly Lock _lock = new();
    private readonly List<GenevaLine> _lines = [];
    private readonly List<Channel<GenevaLine>> _watchers = [];
    private readonly TaskCompletionSource<int> _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _stdin = new(1, 1);
    private int _pendingStreams = 2;

    private GenevaInstance(string id, string mode, Process process)
    {
        Id = id;
        Mode = mode;
        _process = process;
    }

    public string Id { get; }

    /// <summary>"run" or "evolve".</summary>
    public string Mode { get; }

    public int Pid => _process.Id;

    public DateTime StartTimeUtc { get; private set; }

    public Task<int> Exited => _exited.Task;

    public bool HasExited => _exited.Task.IsCompleted;

    /// <summary>run: the control socket's port and token (the token is never on the command line).</summary>
    public int ControlPort { get; init; }

    public string ControlToken { get; init; } = "";

    /// <summary>run: the ports, for <c>geneva fw down</c> after a hard kill.</summary>
    public string Ports { get; init; } = "";

    public int Queue { get; init; }

    public static GenevaInstance Start(string id, string mode, string geneva, IReadOnlyList<string> argv, IReadOnlyDictionary<string, string> env,
        bool supervise, WindowsJob? job, int controlPort = 0, string controlToken = "", string ports = "", int queue = 0)
    {
        ProcessStartInfo psi;
        if (supervise && !OperatingSystem.IsWindows())
        {
            psi = new ProcessStartInfo("/bin/sh");
            psi.ArgumentList.Add("-c");
            // the supervisor merges stderr into stdout; geneva's events stay recognisable (they are JSON objects)
            psi.ArgumentList.Add(EngineInstance.LinuxSupervisor);
            psi.ArgumentList.Add(geneva);
        }
        else
        {
            psi = new ProcessStartInfo(geneva);
        }
        foreach (var a in argv)
            psi.ArgumentList.Add(a);
        foreach (var (k, v) in env)
            psi.Environment[k] = v;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.RedirectStandardInput = true;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.WorkingDirectory = Path.GetDirectoryName(geneva) ?? Environment.CurrentDirectory;

        var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var inst = new GenevaInstance(id, mode, p) { ControlPort = controlPort, ControlToken = controlToken, Ports = ports, Queue = queue };
        p.OutputDataReceived += (_, e) => inst.OnLine(e.Data);
        p.ErrorDataReceived += (_, e) => inst.OnLine(e.Data);
        if (!p.Start())
            throw new InvalidOperationException($"could not start {geneva}");
        inst.StartTimeUtc = DateTime.UtcNow;
        if (job is not null && OperatingSystem.IsWindows())
            job.Assign(p);
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        return inst;
    }

    private void OnLine(string? line)
    {
        lock (_lock)
        {
            if (line is null)
            {
                if (--_pendingStreams == 0)
                    _ = FinishAsync();
                return;
            }
            // events are JSON objects on either stream (the supervisor merges them); the rest is the log and the final
            // "fitness<TAB>strategy" lines of evolve on stdout
            Add(line.StartsWith('{') ? new GenevaLine(line, null) : new GenevaLine(null, line));
        }
    }

    private void Add(GenevaLine l)
    {
        if (_lines.Count < MaxBufferedLines)
            _lines.Add(l);
        else if (l.Event is not null)
        {
            // keep the start, drop the oldest of the rest: a long run must not stop showing its stats
            _lines.RemoveAt(MaxBufferedLines / 2);
            _lines.Add(l);
        }
        foreach (var w in _watchers)
            w.Writer.TryWrite(l);
    }

    private async Task FinishAsync()
    {
        await _process.WaitForExitAsync();
        int code = _process.ExitCode;
        lock (_lock)
        {
            foreach (var w in _watchers)
            {
                w.Writer.TryWrite(new GenevaLine(null, null, true, code));
                w.Writer.TryComplete();
            }
            _watchers.Clear();
        }
        _exited.TrySetResult(code);
    }

    /// <summary>Buffered lines followed by live ones; ends with the exit line when the process exits.</summary>
    public async IAsyncEnumerable<GenevaLine> WatchAsync([global::System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var ch = Channel.CreateUnbounded<GenevaLine>(new UnboundedChannelOptions { SingleReader = true });
        lock (_lock)
        {
            foreach (var l in _lines)
                ch.Writer.TryWrite(l);
            if (HasExited)
            {
                ch.Writer.TryWrite(new GenevaLine(null, null, true, Exited.Result));
                ch.Writer.TryComplete();
            }
            else
            {
                _watchers.Add(ch);
            }
        }
        try
        {
            await foreach (var l in ch.Reader.ReadAllAsync(ct))
                yield return l;
        }
        finally
        {
            lock (_lock)
                _watchers.Remove(ch);
        }
    }

    /// <summary>One line to geneva's stdin (the answer to an eval_request).</summary>
    public async Task WriteLineAsync(string line, CancellationToken ct)
    {
        await _stdin.WaitAsync(ct);
        try
        {
            await _process.StandardInput.WriteLineAsync(line.AsMemory(), ct);
            await _process.StandardInput.FlushAsync(ct);
        }
        finally
        {
            _stdin.Release();
        }
    }

    /// <summary>
    /// Asks geneva to stop (stdin closed: the search saves its checkpoint, the Linux supervisor sends SIGTERM to a run),
    /// waits <paramref name="grace"/>, then kills the tree. On Windows a run is stopped over its control socket first
    /// (<see cref="GenevaManager"/>); WinDivert's handle closes with the process either way.
    /// </summary>
    public async Task<int> StopAsync(TimeSpan grace)
    {
        if (!HasExited)
        {
            try
            {
                await _stdin.WaitAsync();
                try
                {
                    _process.StandardInput.Close();
                }
                finally
                {
                    _stdin.Release();
                }
            }
            catch (Exception e) when (e is InvalidOperationException or IOException or ObjectDisposedException)
            {
            }
            var done = await Task.WhenAny(Exited, Task.Delay(grace));
            if (done != Exited)
            {
                try
                {
                    _process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                }
                await Task.WhenAny(Exited, Task.Delay(TimeSpan.FromSeconds(2)));
            }
        }
        return HasExited ? Exited.Result : -1;
    }

    public void Dispose()
    {
        _process.Dispose();
        _stdin.Dispose();
    }
}
