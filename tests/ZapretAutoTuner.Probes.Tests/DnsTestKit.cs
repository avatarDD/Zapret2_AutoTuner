using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ZapretAutoTuner.Core.Dns;
using ZapretAutoTuner.Probes.Dns;

namespace ZapretAutoTuner.Probes.Tests;

/// <summary>Hand-written DNS wire bytes with absolute offsets, for compression pointers.</summary>
internal sealed class Wire
{
    private readonly List<byte> _b = [];

    public int Pos => _b.Count;

    public Wire U8(int v)
    {
        _b.Add((byte)v);
        return this;
    }

    public Wire U16(int v)
    {
        _b.Add((byte)(v >> 8));
        _b.Add((byte)v);
        return this;
    }

    public Wire U32(uint v) => U16((int)(v >> 16)).U16((int)(v & 0xFFFF));

    public Wire Bytes(ReadOnlySpan<byte> b)
    {
        foreach (var x in b)
            _b.Add(x);
        return this;
    }

    public Wire Hex(string hex) => Bytes(Convert.FromHexString(hex.Replace(" ", "", StringComparison.Ordinal)));

    /// <summary>Full uncompressed name.</summary>
    public Wire Name(string name) => Bytes(DnsMessage.EncodeName(name));

    /// <summary>One label without terminator (to be followed by a pointer).</summary>
    public Wire Label(string l) => U8(l.Length).Bytes(Encoding.ASCII.GetBytes(l));

    public Wire Ptr(int offset) => U16(0xC000 | offset);

    public Wire Ip(string ip) => Bytes(IPAddress.Parse(ip).GetAddressBytes());

    /// <summary>RDLENGTH placeholder, body, then the length is patched.</summary>
    public Wire Rdata(Action<Wire> body)
    {
        int at = Pos;
        U16(0);
        body(this);
        int len = Pos - at - 2;
        _b[at] = (byte)(len >> 8);
        _b[at + 1] = (byte)len;
        return this;
    }

    public byte[] ToArray() => [.. _b];
}

internal static class DnsKit
{
    /// <summary>A response to <paramref name="query"/> with A/AAAA answers owned by the question name.</summary>
    public static byte[] Respond(byte[] query, IEnumerable<string> addresses, int rcode = 0, bool truncated = false, int? id = null)
    {
        var q = DnsMessage.Parse(query);
        var question = q.Questions[0];
        var ips = addresses.Select(IPAddress.Parse).ToList();
        var w = new Wire();
        w.U16(id ?? q.Id).U16(0x8180 | rcode | (truncated ? 0x0200 : 0)).U16(1).U16(ips.Count).U16(0).U16(0);
        w.Name(question.Name).U16((int)question.Type).U16(1);
        foreach (var ip in ips)
        {
            bool v4 = ip.AddressFamily == AddressFamily.InterNetwork;
            w.Ptr(12).U16(v4 ? 1 : 28).U16(1).U32(60).Rdata(r => r.Bytes(ip.GetAddressBytes()));
        }
        return w.ToArray();
    }

    /// <summary>A parsed response for <paramref name="name"/>/<paramref name="type"/> with the given addresses of the matching family.</summary>
    public static DnsMessage Message(string name, DnsRecordType type, int rcode, params string[] addresses)
    {
        var query = DnsMessage.BuildQuery(7, name, type, new DnsQueryOptions { UseEdns = false });
        var fam = type == DnsRecordType.AAAA ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        var matching = addresses.Where(a => IPAddress.Parse(a).AddressFamily == fam && type is DnsRecordType.A or DnsRecordType.AAAA);
        return DnsMessage.Parse(Respond(query, matching, rcode));
    }

    public static DnsResolverAnswer Ans(DnsResolverKind kind, string name, DnsAnswerStatus status, params string[] addrs) => new()
    {
        Resolver = name,
        Kind = kind,
        Status = status,
        Addresses = [.. addrs.Select(IPAddress.Parse)],
    };
}

/// <summary>A transport answering from a delegate, for probe tests.</summary>
internal sealed class FakeTransport(string name, DnsResolverKind kind, Func<string, DnsRecordType, DnsQueryOptions?, CancellationToken, Task<DnsMessage>> answer) : IDnsTransport
{
    public string Name => name;

    public DnsResolverKind Kind => kind;

    public string Server => "fake";

    public int Calls;

    public bool Disposed { get; private set; }

    public Task<DnsMessage> QueryAsync(string n, DnsRecordType type, DnsQueryOptions? options, CancellationToken ct)
    {
        Interlocked.Increment(ref Calls);
        return answer(n, type, options, ct);
    }

    public void Dispose() => Disposed = true;

    public static FakeTransport Addresses(string name, DnsResolverKind kind, params string[] addrs) =>
        new(name, kind, (n, t, _, _) => Task.FromResult(DnsKit.Message(n, t, 0, addrs)));
}

internal sealed class FakeSystemResolver(Func<string, CancellationToken, Task<IPAddress[]>> resolve) : IAddressResolver
{
    public string Name => "system";

    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken ct) => resolve(host, ct);
}

/// <summary>
/// A DNS server on 127.0.0.1 (random port) answering over UDP and, on the same port, over TCP. The UDP handler gets
/// the query and the 1-based datagram number and returns the datagrams to send back (none = drop).
/// </summary>
internal sealed class LocalDnsServer : IAsyncDisposable
{
    private readonly UdpClient _udp;
    private readonly TcpListener _tcp;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _udpLoop;
    private readonly Task _tcpLoop;
    private int _udpCount;
    private int _tcpCount;

    public LocalDnsServer(Func<byte[], int, IEnumerable<byte[]>> udp, Func<byte[], byte[]>? tcp = null)
    {
        (_udp, _tcp) = BindPair();
        Endpoint = (IPEndPoint)_udp.Client.LocalEndPoint!;
        _udpLoop = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                UdpReceiveResult r;
                try
                {
                    r = await _udp.ReceiveAsync(_cts.Token);
                }
                catch (Exception)
                {
                    return;
                }
                foreach (var d in udp(r.Buffer, Interlocked.Increment(ref _udpCount)))
                    await _udp.SendAsync(d, r.RemoteEndPoint, _cts.Token);
            }
        });
        _tcpLoop = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    using var c = await _tcp.AcceptTcpClientAsync(_cts.Token);
                    Interlocked.Increment(ref _tcpCount);
                    var s = c.GetStream();
                    var len = new byte[2];
                    await s.ReadExactlyAsync(len, _cts.Token);
                    var q = new byte[BinaryPrimitives.ReadUInt16BigEndian(len)];
                    await s.ReadExactlyAsync(q, _cts.Token);
                    var resp = tcp?.Invoke(q) ?? [];
                    var framed = new byte[resp.Length + 2];
                    BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)resp.Length);
                    resp.CopyTo(framed, 2);
                    await s.WriteAsync(framed, _cts.Token);
                }
                catch (Exception)
                {
                    if (_cts.IsCancellationRequested)
                        return;
                }
            }
        });
    }

    public IPEndPoint Endpoint { get; }

    public int UdpCount => Volatile.Read(ref _udpCount);

    public int TcpCount => Volatile.Read(ref _tcpCount);

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _udp.Dispose();
        _tcp.Stop();
        await Task.WhenAll(_udpLoop, _tcpLoop);
        _cts.Dispose();
    }

    private static (UdpClient, TcpListener) BindPair()
    {
        for (int i = 0; ; i++)
        {
            var u = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var t = new TcpListener(IPAddress.Loopback, ((IPEndPoint)u.Client.LocalEndPoint!).Port);
            try
            {
                t.Start();
                return (u, t);
            }
            catch (SocketException) when (i < 20)
            {
                u.Dispose();
            }
        }
    }
}

/// <summary>An HttpMessageHandler stub that records the request and answers from a delegate.</summary>
internal sealed class StubHandler(Func<HttpRequestMessage, byte[], CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    public HttpRequestMessage? Request { get; private set; }

    public byte[]? Body { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Request = request;
        Body = request.Content is null ? null : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        return await respond(request, Body ?? [], cancellationToken);
    }
}
