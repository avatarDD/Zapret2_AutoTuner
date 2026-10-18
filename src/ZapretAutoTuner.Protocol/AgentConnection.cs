using System.Diagnostics;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Security.Cryptography;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Grpc.Net.Client;

namespace ZapretAutoTuner.Protocol;

/// <summary>How the UI starts the Agent.</summary>
public enum AgentElevation
{
    /// <summary>UAC on Windows, pkexec on Linux; none if the UI is already elevated.</summary>
    Auto,

    /// <summary>Start without elevation (tests, or a UI already running as root).</summary>
    None,
}

public sealed class AgentLaunchOptions
{
    /// <summary>Path to <c>ztuner-agent</c>; default — next to the UI executable.</summary>
    public string? AgentPath { get; init; }

    /// <summary>Directory for engine logs, captures and the Agent state; created if missing.</summary>
    public required string DataDir { get; init; }

    public string? EnginePath { get; init; }

    public AgentElevation Elevation { get; init; } = AgentElevation.Auto;

    public TimeSpan HeartbeatInterval { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>The Agent cleans up after this long without heartbeats.</summary>
    public TimeSpan HeartbeatTimeout { get; init; } = TimeSpan.FromSeconds(3);

    public TimeSpan StartTimeout { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>The process the Agent watches; default — the current one.</summary>
    public int? UiPid { get; init; }

    /// <summary>Hosts file the Agent edits; default — the system one (tests use a copy).</summary>
    public string? HostsFile { get; init; }
}

/// <summary>
/// The UI side of the Agent IPC (PLAN 1.1): starts the privileged Agent with a fresh session token, connects over a
/// unix socket or named pipe, and keeps it alive with heartbeats. Disposing asks the Agent to shut down; if the UI
/// dies instead, the missing heartbeats make the Agent clean up on its own.
/// </summary>
public sealed class AgentConnection : IAsyncDisposable
{
    public const string TokenHeader = "x-ztuner-token";

    private readonly GrpcChannel _channel;
    private readonly CancellationTokenSource _cts = new();
    private readonly Process? _process;
    private Task? _heartbeatLoop;

    private AgentConnection(GrpcChannel channel, string token, Process? process, string endpoint)
    {
        Endpoint = endpoint;
        _channel = channel;
        _process = process;
        var invoker = channel.Intercept(m =>
        {
            m.Add(TokenHeader, token);
            return m;
        });
        Client = new Agent.AgentClient(invoker);
    }

    private void StartHeartbeats(TimeSpan interval) => _heartbeatLoop = HeartbeatLoopAsync(interval, _cts.Token);

    public Agent.AgentClient Client { get; }

    /// <summary>The unix socket path or pipe name the Agent listens on.</summary>
    public string Endpoint { get; }

    /// <summary>The last heartbeat reply (agent version, firewall backend, running engines).</summary>
    public HeartbeatReply? LastHeartbeat { get; private set; }

    /// <summary>Raised when heartbeats fail: the Agent died or was stopped.</summary>
    public event EventHandler<Exception>? Lost;

    /// <summary>Starts the Agent and connects. Throws <see cref="AgentStartException"/> with a Russian message.</summary>
    public static async Task<AgentConnection> LaunchAsync(AgentLaunchOptions o, CancellationToken ct = default)
    {
        Directory.CreateDirectory(o.DataDir);
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var tokenFile = Path.Combine(o.DataDir, $"agent-{Guid.NewGuid():N}.token");
        await WriteSecretAsync(tokenFile, token, ct);

        string? socket = null, pipe = null;
        if (OperatingSystem.IsWindows())
            pipe = $"ztuner-agent-{Guid.NewGuid():N}";
        else
        {
            socket = Path.Combine(o.DataDir, $"agent-{Environment.ProcessId}.sock");
            // sun_path holds 108 bytes; a deep home directory does not fit
            if (System.Text.Encoding.UTF8.GetByteCount(socket) > 100)
                socket = Path.Combine(Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR") is { Length: > 0 } run ? run : Path.GetTempPath(), $"ztuner-{Environment.ProcessId}.sock");
        }

        var agentPath = o.AgentPath ?? DefaultAgentPath();
        if (!File.Exists(agentPath))
            throw new AgentStartException($"не найден {agentPath}");
        var args = new List<string>
        {
            socket is not null ? "--socket=" + socket : "--pipe=" + pipe,
            "--token-file=" + tokenFile,
            "--ui-pid=" + (o.UiPid ?? Environment.ProcessId),
            "--data-dir=" + o.DataDir,
            "--heartbeat-timeout=" + (int)o.HeartbeatTimeout.TotalMilliseconds,
        };
        if (o.EnginePath is not null)
            args.Add("--engine=" + o.EnginePath);
        if (o.HostsFile is not null)
            args.Add("--hosts-file=" + o.HostsFile);
        if (!OperatingSystem.IsWindows())
            args.Add("--owner-uid=" + GetUid());

        Process? process;
        try
        {
            process = StartAgent(agentPath, args, o.Elevation);
        }
        catch (System.ComponentModel.Win32Exception e)
        {
            File.Delete(tokenFile);
            // ERROR_CANCELLED: the user declined the UAC prompt; ENOENT for pkexec: polkit is not installed
            throw new AgentStartException(e.NativeErrorCode switch
            {
                1223 when OperatingSystem.IsWindows() => "запуск с правами администратора отменён",
                2 when !OperatingSystem.IsWindows() => "не найден pkexec: установите polkit (пакет policykit-1 или polkit) или запустите программу от root",
                _ => "не удалось запустить Agent: " + e.Message,
            });
        }

        var channel = CreateChannel(socket, pipe);
        var conn = new AgentConnection(channel, token, process, socket ?? pipe!);
        var deadline = Stopwatch.StartNew();
        Exception? last = null;
        while (deadline.Elapsed < o.StartTimeout)
        {
            ct.ThrowIfCancellationRequested();
            if (process is { HasExited: true })
            {
                File.Delete(tokenFile);
                await conn.DisposeTransportAsync();
                // pkexec: 126 — the user dismissed the dialog, 127 — not authorized
                var why = process.ExitCode switch
                {
                    126 => "запуск с правами root отменён",
                    127 => "нет прав на запуск Agent (polkit)",
                    _ => $"Agent завершился с кодом {process.ExitCode}",
                };
                throw new AgentStartException(why);
            }
            try
            {
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
                attempt.CancelAfter(TimeSpan.FromSeconds(2));
                conn.LastHeartbeat = await conn.Client.HeartbeatAsync(new HeartbeatRequest { UiPid = Environment.ProcessId }, cancellationToken: attempt.Token);
                break;
            }
            catch (RpcException e) when (e.StatusCode is StatusCode.Unavailable or StatusCode.Cancelled or StatusCode.DeadlineExceeded)
            {
                last = e;
                await Task.Delay(200, ct);
            }
        }
        if (conn.LastHeartbeat is null)
        {
            await conn.DisposeTransportAsync();
            File.Delete(tokenFile);
            throw new AgentStartException("Agent не ответил: " + last?.Message);
        }
        conn.StartHeartbeats(o.HeartbeatInterval);
        return conn;
    }

    /// <summary>Connects to an Agent that is already running (tests, a systemd-started Agent).</summary>
    public static AgentConnection Connect(string? socket, string? pipe, string token, TimeSpan heartbeatInterval)
    {
        var c = new AgentConnection(CreateChannel(socket, pipe), token, null, socket ?? pipe!);
        c.StartHeartbeats(heartbeatInterval);
        return c;
    }

    private async Task HeartbeatLoopAsync(TimeSpan interval, CancellationToken ct)
    {
        int failures = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(interval, ct);
                LastHeartbeat = await Client.HeartbeatAsync(new HeartbeatRequest { UiPid = Environment.ProcessId }, deadline: DateTime.UtcNow.AddSeconds(2), cancellationToken: ct);
                failures = 0;
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (RpcException e) when (e.StatusCode == StatusCode.Cancelled && ct.IsCancellationRequested)
            {
                return;
            }
            catch (RpcException e)
            {
                if (++failures >= 3)
                {
                    Lost?.Invoke(this, e);
                    return;
                }
            }
        }
    }

    private static Process? StartAgent(string path, List<string> args, AgentElevation elevation)
    {
        bool elevated = Environment.IsPrivilegedProcess;
        ProcessStartInfo psi;
        if (elevation == AgentElevation.None || elevated)
        {
            psi = new ProcessStartInfo(path) { UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in args)
                psi.ArgumentList.Add(a);
        }
        else if (OperatingSystem.IsWindows())
        {
            // runas shows the UAC prompt; ShellExecute cannot redirect output
            psi = new ProcessStartInfo(path)
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
                Arguments = string.Join(' ', args.Select(QuoteWindows)),
            };
        }
        else
        {
            psi = new ProcessStartInfo("pkexec") { UseShellExecute = false };
            psi.ArgumentList.Add(path);
            foreach (var a in args)
                psi.ArgumentList.Add(a);
        }
        return Process.Start(psi);
    }

    private static string QuoteWindows(string a) =>
        a.Length > 0 && a.IndexOfAny([' ', '\t', '"']) < 0 ? a : "\"" + a.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    public static string DefaultAgentPath() =>
        Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "ztuner-agent.exe" : "ztuner-agent");

    private static GrpcChannel CreateChannel(string? socket, string? pipe)
    {
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (_, ct) =>
            {
                if (socket is not null)
                {
                    var s = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                    try
                    {
                        await s.ConnectAsync(new UnixDomainSocketEndPoint(socket), ct);
                        return new NetworkStream(s, ownsSocket: true);
                    }
                    catch
                    {
                        s.Dispose();
                        throw;
                    }
                }
                var p = new NamedPipeClientStream(".", pipe!, PipeDirection.InOut, PipeOptions.WriteThrough | PipeOptions.Asynchronous);
                try
                {
                    await p.ConnectAsync(ct);
                    return p;
                }
                catch
                {
                    await p.DisposeAsync();
                    throw;
                }
            },
        };
        return GrpcChannel.ForAddress("http://localhost", new GrpcChannelOptions
        {
            HttpHandler = handler,
            MaxReceiveMessageSize = 4 << 20,
        });
    }

    private static async Task WriteSecretAsync(string path, string content, CancellationToken ct)
    {
        if (OperatingSystem.IsWindows())
        {
            await File.WriteAllTextAsync(path, content, ct);
            return;
        }
        var opts = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        };
        await using var fs = new FileStream(path, opts);
        await using var w = new StreamWriter(fs);
        await w.WriteAsync(content.AsMemory(), ct);
    }

    private static int GetUid()
    {
        // /proc/self/status: "Uid:\treal\teffective\t…"
        try
        {
            foreach (var line in File.ReadLines("/proc/self/status"))
            {
                if (line.StartsWith("Uid:", StringComparison.Ordinal))
                    return int.Parse(line.Split('\t', StringSplitOptions.RemoveEmptyEntries)[1], System.Globalization.CultureInfo.InvariantCulture);
            }
        }
        catch (IOException)
        {
        }
        return -1;
    }

    private Task DisposeTransportAsync()
    {
        _channel.Dispose();
        _cts.Dispose();
        return Task.CompletedTask;
    }

    /// <summary>Asks the Agent to stop everything and exit, then closes the channel.</summary>
    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        if (_heartbeatLoop is not null)
        {
            try
            {
                await _heartbeatLoop;
            }
            catch (OperationCanceledException)
            {
            }
        }
        try
        {
            await Client.ShutdownAsync(new ShutdownRequest(), deadline: DateTime.UtcNow.AddSeconds(3));
        }
        catch (RpcException)
        {
        }
        if (_process is not null)
        {
            try
            {
                using var wait = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await _process.WaitForExitAsync(wait.Token);
            }
            catch (Exception e) when (e is OperationCanceledException or InvalidOperationException)
            {
            }
            _process.Dispose();
        }
        _channel.Dispose();
        _cts.Dispose();
    }
}

public sealed class AgentStartException : Exception
{
    public AgentStartException(string message)
        : base(message)
    {
    }
}
