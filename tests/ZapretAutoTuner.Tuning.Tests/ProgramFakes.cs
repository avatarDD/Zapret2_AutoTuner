using System.Buffers.Binary;
using System.Net;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Protocol;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>Records what an executor asks the Agent for (the phase 6 executors and the program check).</summary>
internal sealed class RecordingEngine : IEngineControl
{
    public List<(IReadOnlyList<string> Argv, QueueRule? Queue, string Tag)> Started { get; } = [];

    public List<string> Stopped { get; } = [];

    public string? Refuse { get; set; }

    public Task<string> StartAsync(IReadOnlyList<string> argv, QueueRule? queue, string tag, CancellationToken ct)
    {
        if (Refuse is not null)
            throw EngineRefusedException.FromAgent(Refuse);
        Started.Add((argv, queue, tag));
        return Task.FromResult("e" + Started.Count);
    }

    public Task StopAsync(string engineId, CancellationToken ct)
    {
        Stopped.Add(engineId);
        return Task.CompletedTask;
    }
}

/// <summary>A capture and socket listing played back from prepared packets.</summary>
internal sealed class FakeMonitor(IReadOnlyList<CapturedPacket> packets, IReadOnlyDictionary<int, ObservedSocket[]> sockets) : IProgramMonitor
{
    public int Starts { get; private set; }

    public List<(string Id, bool Cancellable)> Stops { get; } = [];

    public List<int> Listed { get; } = [];

    public long Dropped { get; init; }

    public Task<string> StartCaptureAsync(CancellationToken ct)
    {
        Starts++;
        return Task.FromResult("cap" + Starts);
    }

    public Task<(byte[] Pcapng, long Dropped)> StopCaptureAsync(string captureId, CancellationToken ct)
    {
        Stops.Add((captureId, ct.CanBeCanceled));
        return Task.FromResult((PcapNgWriter.ToBytes(packets), Dropped));
    }

    public Task<IReadOnlyList<ObservedSocket>> ListConnectionsAsync(int pid, CancellationToken ct)
    {
        Listed.Add(pid);
        if (!sockets.TryGetValue(pid, out var list))
            throw new Grpc.Core.RpcException(new Grpc.Core.Status(Grpc.Core.StatusCode.NotFound, "no such process"));
        return Task.FromResult<IReadOnlyList<ObservedSocket>>(list);
    }
}

internal static class ProgramFixtures
{
    private static readonly DateTime T0 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public static StrategyCandidate Candidate(string s, L4Kind l4) => new(Strategy.Parse(s), "test", 1, [], l4);

    public static ProgramEndpoint Endpoint(string address, int port, L4Kind l4, AppProtocol app, string? host = null,
        Core.Diagnostics.FlowHealth health = Core.Diagnostics.FlowHealth.NoReply) => new()
    {
        Protocol = l4,
        Remote = new IPEndPoint(IPAddress.Parse(address), port),
        Host = host,
        App = app,
        Health = health,
        InitialPayloads = [new byte[] { 1, 2, 3 }],
    };

    public static byte[] Udp(string src, int sport, string dst, int dport, byte[] payload)
    {
        var p = new byte[28 + payload.Length];
        p[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
        p[8] = 64;
        p[9] = 17;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(p, 12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(p, 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), (ushort)dport);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(24), (ushort)(8 + payload.Length));
        payload.CopyTo(p, 28);
        return p;
    }

    public static List<CapturedPacket> Capture(params byte[][] packets) =>
        packets.Select((p, i) => new CapturedPacket(T0.AddMilliseconds(i), p, p.Length, PacketDirection.Unknown)).ToList();

    public static byte[] Stun()
    {
        var b = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(b, 1);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), 0x2112A442);
        return b;
    }
}
