using System.Diagnostics;
using System.Threading.Channels;
using ZapretAutoTuner.Agent.Os;

namespace ZapretAutoTuner.Agent.Engine;

/// <summary>
/// One running engine process with its output. Output lines are kept (bounded) so a watcher that subscribes late
/// still sees the startup messages, and are pushed to every live watcher.
/// </summary>
internal sealed class EngineInstance : IDisposable
{
    public const int MaxBufferedLines = 20000;

    /// <summary>
    /// Linux supervisor: runs the engine in the background and kills it when its stdin (a pipe from the Agent)
    /// closes. nfqws2 drops root right after start, which clears PR_SET_PDEATHSIG, so this is what guarantees the
    /// engine dies with the Agent even on SIGKILL. The shell stays root and can signal the engine.
    /// </summary>
    internal const string LinuxSupervisor =
        "exec 3<&0; \"$0\" \"$@\" </dev/null 3<&- 2>&1 & p=$!; " +
        "( read -r _ <&3; kill -TERM $p; sleep 2; kill -KILL $p ) >/dev/null 2>&1 & w=$!; " +
        "exec 3<&-; wait $p; rc=$?; kill $w 2>/dev/null; exit $rc";

    private readonly Process _process;
    private readonly Lock _lock = new();
    private readonly List<string> _lines = [];
    private readonly List<Channel<string>> _watchers = [];
    private readonly TaskCompletionSource<int> _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _pendingStreams = 2;

    private EngineInstance(string id, string tag, Process process)
    {
        Id = id;
        Tag = tag;
        _process = process;
    }

    public string Id { get; }

    public string Tag { get; }

    public int Pid => _process.Id;

    public DateTime StartTimeUtc { get; private set; }

    public Task<int> Exited => _exited.Task;

    public bool HasExited => _exited.Task.IsCompleted;

    public static EngineInstance Start(string id, string tag, string engine, IReadOnlyList<string> argv, WindowsJob? job)
    {
        ProcessStartInfo psi;
        if (OperatingSystem.IsWindows())
        {
            psi = new ProcessStartInfo(engine);
            foreach (var a in argv)
                psi.ArgumentList.Add(a);
        }
        else
        {
            psi = new ProcessStartInfo("/bin/sh");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(LinuxSupervisor);
            psi.ArgumentList.Add(engine);
            foreach (var a in argv)
                psi.ArgumentList.Add(a);
        }
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.RedirectStandardInput = true;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.WorkingDirectory = Path.GetDirectoryName(engine) ?? Environment.CurrentDirectory;

        var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var inst = new EngineInstance(id, tag, p);
        p.OutputDataReceived += (_, e) => inst.OnLine(e.Data);
        p.ErrorDataReceived += (_, e) => inst.OnLine(e.Data);
        if (!p.Start())
            throw new InvalidOperationException($"could not start {engine}");
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
                // both streams closed: the process is gone (or about to be)
                if (--_pendingStreams == 0)
                    _ = FinishAsync();
                return;
            }
            if (_lines.Count < MaxBufferedLines)
                _lines.Add(line);
            foreach (var w in _watchers)
                w.Writer.TryWrite(line);
        }
    }

    private async Task FinishAsync()
    {
        await _process.WaitForExitAsync();
        int code = _process.ExitCode;
        lock (_lock)
        {
            foreach (var w in _watchers)
                w.Writer.TryComplete();
            _watchers.Clear();
        }
        _exited.TrySetResult(code);
    }

    /// <summary>Buffered lines followed by live ones; completes when the engine exits.</summary>
    public async IAsyncEnumerable<string> WatchAsync([global::System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var ch = Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true });
        lock (_lock)
        {
            foreach (var l in _lines)
                ch.Writer.TryWrite(l);
            if (HasExited || _pendingStreams == 0)
                ch.Writer.TryComplete();
            else
                _watchers.Add(ch);
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

    public IReadOnlyList<string> Snapshot()
    {
        lock (_lock)
            return [.. _lines];
    }

    /// <summary>Asks the engine to stop and waits; kills the whole tree after <paramref name="grace"/>.</summary>
    public async Task<int> StopAsync(TimeSpan grace)
    {
        if (!HasExited)
        {
            try
            {
                if (OperatingSystem.IsWindows())
                    _process.Kill(entireProcessTree: true);
                else
                    _process.StandardInput.Close(); // supervisor sends SIGTERM to the engine
            }
            catch (Exception e) when (e is InvalidOperationException or IOException)
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

    public void Dispose() => _process.Dispose();
}
