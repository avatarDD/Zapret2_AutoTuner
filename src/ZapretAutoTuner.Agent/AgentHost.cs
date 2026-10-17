using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Grpc.Core;
using Grpc.Core.Interceptors;
using ZapretAutoTuner.Agent.Capture;
using ZapretAutoTuner.Agent.Engine;
using ZapretAutoTuner.Agent.Firewall;
using ZapretAutoTuner.Agent.Os;

namespace ZapretAutoTuner.Agent;

/// <summary>
/// The Agent's privileged state and its cleanup guarantee: engines, captures, firewall rules and sysctls are all
/// undone by <see cref="CleanupAsync"/>, which runs on UI loss, Shutdown, SIGTERM/SIGINT and process exit, and the
/// next start undoes what a crashed Agent left behind (<see cref="RecoverLeftovers"/>).
/// </summary>
internal sealed class AgentHost : IAsyncDisposable
{
    private readonly Lock _hbLock = new();
    private long _lastHeartbeat = Stopwatch.GetTimestamp();
    private int _cleanedUp;

    public AgentHost(AgentOptions options)
    {
        Options = options;
        Directory.CreateDirectory(options.DataDir!);
        State = new AgentStateStore(options.DataDir!);
        Sysctl = new Sysctl(State);
        Firewall = OperatingSystem.IsLinux() ? new FirewallManager(State, Sysctl, EngineManager.FwMark) : null;
        Engines = new EngineManager(options, State, Firewall);
        Captures = new CaptureManager();
    }

    public AgentOptions Options { get; }

    public AgentStateStore State { get; }

    public Sysctl Sysctl { get; }

    public FirewallManager? Firewall { get; }

    public EngineManager Engines { get; }

    public CaptureManager Captures { get; }

    /// <summary>Set when the Agent should exit (UI lost, Shutdown).</summary>
    public CancellationTokenSource Stopping { get; } = new();

    public string? StopReason { get; private set; }

    public void Heartbeat()
    {
        lock (_hbLock)
            _lastHeartbeat = Stopwatch.GetTimestamp();
    }

    public TimeSpan SinceHeartbeat
    {
        get
        {
            lock (_hbLock)
                return Stopwatch.GetElapsedTime(_lastHeartbeat);
        }
    }

    public void RequestStop(string reason)
    {
        StopReason ??= reason;
        Stopping.Cancel();
    }

    /// <summary>Undoes what an earlier Agent recorded in the state file but did not clean up.</summary>
    public void RecoverLeftovers()
    {
        var s = State.Load();
        foreach (var e in s.Engines)
        {
            try
            {
                using var p = Process.GetProcessById(e.Pid);
                // only kill it if it is really the engine started back then, not a recycled pid
                if (Math.Abs((p.StartTime.ToUniversalTime() - e.StartTimeUtc).TotalSeconds) < 5)
                    p.Kill(entireProcessTree: true);
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or global::System.ComponentModel.Win32Exception)
            {
            }
        }
        if (s.Engines.Count > 0)
            State.Update(x => x.Engines.Clear());
        // remove our table/chains even if the state file was lost: they are ours by name
        Firewall?.RemoveAll();
        Sysctl.RestoreAll();
    }

    public async Task CleanupAsync()
    {
        if (Interlocked.Exchange(ref _cleanedUp, 1) != 0)
            return;
        try
        {
            await Engines.StopAllAsync();
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("stop engines: " + e.Message);
        }
        Captures.StopAll();
        Firewall?.RemoveAll();
        Sysctl.RestoreAll();
        try
        {
            State.Delete();
        }
        catch (IOException)
        {
        }
    }

    /// <summary>Synchronous last resort for ProcessExit, where async continuations may not run.</summary>
    public void CleanupSync() => CleanupAsync().GetAwaiter().GetResult();

    public async ValueTask DisposeAsync()
    {
        await CleanupAsync();
        Engines.Dispose();
        Stopping.Dispose();
    }
}

/// <summary>Rejects calls without the session token (constant-time comparison).</summary>
internal sealed class TokenInterceptor : Interceptor
{
    public const string Header = "x-ztuner-token";
    private readonly byte[] _token;

    public TokenInterceptor(string token)
    {
        _token = Encoding.UTF8.GetBytes(token);
    }

    private void Check(ServerCallContext ctx)
    {
        var got = ctx.RequestHeaders.GetValue(Header);
        if (got is null || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(got), _token))
            throw new RpcException(new Status(StatusCode.Unauthenticated, "bad session token"));
    }

    public override Task<TResponse> UnaryServerHandler<TRequest, TResponse>(TRequest request, ServerCallContext context, UnaryServerMethod<TRequest, TResponse> continuation)
    {
        Check(context);
        return continuation(request, context);
    }

    public override Task ServerStreamingServerHandler<TRequest, TResponse>(TRequest request, IServerStreamWriter<TResponse> responseStream, ServerCallContext context, ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        Check(context);
        return continuation(request, responseStream, context);
    }

    public override Task<TResponse> ClientStreamingServerHandler<TRequest, TResponse>(IAsyncStreamReader<TRequest> requestStream, ServerCallContext context, ClientStreamingServerMethod<TRequest, TResponse> continuation)
    {
        Check(context);
        return continuation(requestStream, context);
    }

    public override Task DuplexStreamingServerHandler<TRequest, TResponse>(IAsyncStreamReader<TRequest> requestStream, IServerStreamWriter<TResponse> responseStream, ServerCallContext context, DuplexStreamingServerMethod<TRequest, TResponse> continuation)
    {
        Check(context);
        return continuation(requestStream, responseStream, context);
    }
}

/// <summary>Stops the Agent when heartbeats stop or the UI process exits (PLAN 1.1: everything off within 5 s).</summary>
internal sealed class Watchdog : BackgroundService
{
    private readonly AgentHost _host;

    public Watchdog(AgentHost host)
    {
        _host = host;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Process? ui = null;
        try
        {
            ui = Process.GetProcessById(_host.Options.UiPid);
        }
        catch (ArgumentException)
        {
            _host.RequestStop("UI process not found");
        }
        using (ui)
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(250));
            try
            {
                while (!_host.Stopping.IsCancellationRequested && await timer.WaitForNextTickAsync(stoppingToken))
                {
                    if (ui is not null && HasExited(ui))
                        _host.RequestStop("UI process exited");
                    else if (_host.SinceHeartbeat > _host.Options.HeartbeatTimeout)
                        _host.RequestStop("no heartbeat");
                }
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    private static bool HasExited(Process p)
    {
        try
        {
            return p.HasExited;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }
}
