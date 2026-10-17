using Google.Protobuf;
using Grpc.Core;
using ZapretAutoTuner.Agent.Engine;
using ZapretAutoTuner.Agent.Os;
using ZapretAutoTuner.Core;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Agent;

/// <summary>gRPC implementation of <c>ztuner.agent.v1.Agent</c>.</summary>
internal sealed class AgentService : Protocol.Agent.AgentBase
{
    private readonly AgentHost _host;
    private static string? s_engineVersion;

    public AgentService(AgentHost host)
    {
        _host = host;
    }

    public override async Task<HeartbeatReply> Heartbeat(HeartbeatRequest request, ServerCallContext context)
    {
        _host.Heartbeat();
        s_engineVersion ??= await ReadEngineVersionAsync();
        var reply = new HeartbeatReply
        {
            AgentVersion = AppInfo.Version,
            AgentPid = Environment.ProcessId,
            Elevated = Environment.IsPrivilegedProcess,
            Platform = OperatingSystem.IsWindows() ? "windows" : "linux",
            FirewallBackend = OperatingSystem.IsWindows() ? "windivert" : _host.Firewall?.BackendName ?? "none",
            Zapret2Version = s_engineVersion,
        };
        reply.Engines.AddRange(_host.Engines.Running);
        reply.Captures.AddRange(_host.Captures.Running);
        return reply;
    }

    private async Task<string> ReadEngineVersionAsync()
    {
        if (!File.Exists(_host.Engines.EnginePath))
            return "";
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var r = await Cmd.RunAsync(_host.Engines.EnginePath, ["--version"], ct: cts.Token);
            return Tools.Zapret2Bundle.ParseVersion(r.Stdout + r.Stderr).Version ?? "";
        }
        catch (Exception e) when (e is OperationCanceledException or InvalidOperationException)
        {
            return "";
        }
    }

    public override async Task<CheckEngineArgsReply> CheckEngineArgs(CheckEngineArgsRequest request, ServerCallContext context)
    {
        var r = await _host.Engines.CheckAsync(request.Argv, context.CancellationToken);
        var reply = new CheckEngineArgsReply { Ok = r.Ok, Stage = r.Stage };
        reply.Output.AddRange(r.Output);
        return reply;
    }

    public override Task<StartEngineReply> StartEngine(StartEngineRequest request, ServerCallContext context)
    {
        try
        {
            var queue = request.Queue is null ? null : EngineManager.ToRule(request.Queue);
            var inst = _host.Engines.Start(request.Argv, queue, request.Tag);
            return Task.FromResult(new StartEngineReply { EngineId = inst.Id, Pid = inst.Pid });
        }
        catch (EngineStartException e)
        {
            throw new RpcException(new Status(StatusCode.FailedPrecondition, e.Message));
        }
        catch (FormatException e)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, e.Message));
        }
    }

    public override async Task<StopEngineReply> StopEngine(StopEngineRequest request, ServerCallContext context)
    {
        var (was, code) = await _host.Engines.StopAsync(request.EngineId);
        return new StopEngineReply { WasRunning = was, ExitCode = code };
    }

    public override async Task WatchEngine(WatchEngineRequest request, IServerStreamWriter<EngineOutput> responseStream, ServerCallContext context)
    {
        var inst = _host.Engines.Find(request.EngineId)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "no such engine"));
        await foreach (var line in inst.WatchAsync(context.CancellationToken))
            await responseStream.WriteAsync(new EngineOutput { Line = line }, context.CancellationToken);
        if (inst.HasExited)
            await responseStream.WriteAsync(new EngineOutput { Exited = true, ExitCode = inst.Exited.Result }, context.CancellationToken);
    }

    public override Task<StartCaptureReply> StartCapture(StartCaptureRequest request, ServerCallContext context)
    {
        try
        {
            var id = _host.Captures.Start(Capture.CaptureFilter.From(request), request.MaxBytes, request.Snaplen, request.Interface);
            return Task.FromResult(new StartCaptureReply { CaptureId = id });
        }
        catch (Exception e) when (e is InvalidOperationException or FormatException or PlatformNotSupportedException or global::System.Net.Sockets.SocketException)
        {
            throw new RpcException(new Status(StatusCode.FailedPrecondition, e.Message));
        }
    }

    public override async Task StopCapture(StopCaptureRequest request, IServerStreamWriter<CaptureChunk> responseStream, ServerCallContext context)
    {
        var result = _host.Captures.Stop(request.CaptureId)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "no such capture"));
        const int chunk = 1 << 20;
        for (int ofs = 0; ofs < result.Pcapng.Length || ofs == 0; ofs += chunk)
        {
            int n = Math.Min(chunk, result.Pcapng.Length - ofs);
            bool last = ofs + n >= result.Pcapng.Length;
            var msg = new CaptureChunk { Data = ByteString.CopyFrom(result.Pcapng, ofs, n) };
            if (last)
            {
                msg.Packets = result.Packets;
                msg.Dropped = result.Dropped;
            }
            await responseStream.WriteAsync(msg, context.CancellationToken);
            if (last)
                break;
        }
    }

    public override Task<ListConnectionsReply> ListConnections(ListConnectionsRequest request, ServerCallContext context)
    {
        var reply = new ListConnectionsReply();
        reply.Connections.AddRange(Connections.List(request.Pid));
        return Task.FromResult(reply);
    }

    public override async Task<PinHostsReply> PinHosts(PinHostsRequest request, ServerCallContext context)
    {
        var pins = new List<Core.Hosts.HostsPin>();
        foreach (var p in request.Pins)
        {
            if (!System.Net.IPAddress.TryParse(p.Address, out var ip))
                throw new RpcException(new Status(StatusCode.InvalidArgument, $"не IP-адрес: {p.Address}"));
            pins.Add(new Core.Hosts.HostsPin(p.Host, ip));
        }
        try
        {
            var (backup, flushed, result) = await _host.Hosts.SetAsync(pins, context.CancellationToken);
            var reply = new PinHostsReply { BackupPath = backup, DnsFlushed = flushed };
            reply.Pins.AddRange(result.Select(ToProto));
            return reply;
        }
        catch (ArgumentException e)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, e.Message));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new RpcException(new Status(StatusCode.FailedPrecondition, $"не удалось записать {_host.Hosts.Path}: {e.Message}"));
        }
    }

    public override async Task<ListHostsPinsReply> ListHostsPins(ListHostsPinsRequest request, ServerCallContext context)
    {
        var reply = new ListHostsPinsReply { Path = _host.Hosts.Path };
        reply.Pins.AddRange((await _host.Hosts.ListAsync(context.CancellationToken)).Select(ToProto));
        return reply;
    }

    private static Protocol.HostsPin ToProto(Core.Hosts.HostsPin p) => new() { Host = p.Host, Address = p.Address.ToString() };

    public override async Task<ServiceReply> InstallService(InstallServiceRequest request, ServerCallContext context)
    {
        if (!OperatingSystem.IsWindows())
            throw new RpcException(new Status(StatusCode.FailedPrecondition, "служба winws2 есть только в Windows"));
        var files = request.Files.ToDictionary(kv => kv.Key, kv => kv.Value.ToByteArray(), StringComparer.Ordinal);
        try
        {
            var output = await WinwsService.InstallAsync(files, _host.Engines.EnginePath,
                argv => _host.Engines.Precheck(argv, [WinwsService.Directory + ".new"]) is { } bad ? $"{bad.Stage}: {string.Join("; ", bad.Output)}" : null,
                context.CancellationToken);
            var (installed, running, _) = await WinwsService.QueryAsync(context.CancellationToken);
            return new ServiceReply { Installed = installed, Running = running, Directory = WinwsService.Directory, Output = output };
        }
        catch (ArgumentException e)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, e.Message));
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            throw new RpcException(new Status(StatusCode.FailedPrecondition, e.Message));
        }
    }

    public override async Task<ServiceReply> RemoveService(RemoveServiceRequest request, ServerCallContext context)
    {
        if (!OperatingSystem.IsWindows())
            throw new RpcException(new Status(StatusCode.FailedPrecondition, "служба winws2 есть только в Windows"));
        var output = await WinwsService.RemoveAsync(context.CancellationToken);
        if (Directory.Exists(WinwsService.Directory))
            Directory.Delete(WinwsService.Directory, true);
        return new ServiceReply { Directory = WinwsService.Directory, Output = output };
    }

    public override async Task<ServiceReply> QueryService(QueryServiceRequest request, ServerCallContext context)
    {
        if (!OperatingSystem.IsWindows())
            return new ServiceReply();
        var (installed, running, output) = await WinwsService.QueryAsync(context.CancellationToken);
        return new ServiceReply { Installed = installed, Running = running, Directory = WinwsService.Directory, Output = output };
    }

    public override Task<ShutdownReply> Shutdown(ShutdownRequest request, ServerCallContext context)
    {
        _host.RequestStop("shutdown requested");
        return Task.FromResult(new ShutdownReply());
    }
}
