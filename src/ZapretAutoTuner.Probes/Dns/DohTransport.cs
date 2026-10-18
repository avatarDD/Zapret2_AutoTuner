using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Dns;

namespace ZapretAutoTuner.Probes.Dns;

/// <summary>
/// DNS over HTTPS, RFC 8484 POST with <c>application/dns-message</c>. The DoH host is never looked up: every TCP
/// connection goes to the configured bootstrap IP (<see cref="DohBootstrap"/>), while TLS still uses the URL host
/// for SNI and certificate validation. The system proxy is bypassed on purpose: the probe measures the direct path.
/// </summary>
public sealed class DohTransport : DnsTransportBase
{
    public const string MediaType = "application/dns-message";

    private readonly HttpClient _http;

    public DohTransport(Uri endpoint, IPAddress bootstrap, string? name = null, TimeSpan? timeout = null)
        : this(endpoint, CreateHandler(endpoint, bootstrap), name, timeout)
    {
        Bootstrap = bootstrap;
    }

    /// <summary>Uses the given handler (tests, or a caller-managed connection policy). The handler is disposed with the transport.</summary>
    public DohTransport(Uri endpoint, HttpMessageHandler handler, string? name = null, TimeSpan? timeout = null)
        : base(name ?? endpoint?.Host ?? "", timeout ?? TimeSpan.FromSeconds(4))
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(handler);
        if (endpoint.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("DoH: нужен https-адрес", nameof(endpoint));
        Endpoint = endpoint;
        _http = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = System.Threading.Timeout.InfiniteTimeSpan, // per-request timeout below
            MaxResponseContentBufferSize = 65535,
        };
    }

    public Uri Endpoint { get; }

    /// <summary>The IP connections go to, when created with a bootstrap address.</summary>
    public IPAddress? Bootstrap { get; }

    public override DnsResolverKind Kind => DnsResolverKind.Doh;

    public override string Server => Bootstrap is null ? Endpoint.ToString() : $"{Endpoint} @{Bootstrap}";

    protected override bool UseZeroId => true;

    protected override async Task<byte[]> ExchangeAsync(byte[] query, ushort id, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        using var req = new HttpRequestMessage(HttpMethod.Post, Endpoint)
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
            Content = new ByteArrayContent(query),
        };
        req.Content.Headers.ContentType = new MediaTypeHeaderValue(MediaType);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaType));
        try
        {
            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseContentRead, cts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                throw new DnsTransportException($"DoH {Name}: HTTP {(int)resp.StatusCode}");
            var ctype = resp.Content.Headers.ContentType?.MediaType;
            if (ctype is not null && !string.Equals(ctype, MediaType, StringComparison.OrdinalIgnoreCase))
                throw new DnsTransportException($"DoH {Name}: неожиданный Content-Type {ctype}");
            return await resp.Content.ReadAsByteArrayAsync(cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException(string.Format(CultureInfo.InvariantCulture,
                "DoH {0} не ответил за {1} мс", Name, (int)Timeout.TotalMilliseconds));
        }
        catch (HttpRequestException e)
        {
            throw new DnsTransportException($"DoH {Name}: {e.Message}", e);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _http.Dispose();
        base.Dispose(disposing);
    }

    private static SocketsHttpHandler CreateHandler(Uri endpoint, IPAddress bootstrap)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(bootstrap);
        return new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectCallback = DohBootstrap.CreateConnectCallback(endpoint.IdnHost, bootstrap),
        };
    }
}

/// <summary>Connection policy of <see cref="DohTransport"/>: the DoH host name maps to the bootstrap IP, nothing else is reachable.</summary>
public static class DohBootstrap
{
    /// <summary>
    /// Maps the endpoint HttpClient asks for to the socket endpoint: the bootstrap IP with the requested port. Any
    /// other host (a redirect, a mistake) is refused rather than resolved through the system DNS.
    /// </summary>
    public static IPEndPoint MapEndpoint(DnsEndPoint requested, string expectedHost, IPAddress bootstrap)
    {
        ArgumentNullException.ThrowIfNull(requested);
        ArgumentNullException.ThrowIfNull(bootstrap);
        if (!DnsMessage.NameEquals(requested.Host, expectedHost))
            throw new DnsTransportException($"DoH: подключение к «{requested.Host}» запрещено, ожидался «{expectedHost}»");
        return new IPEndPoint(bootstrap, requested.Port);
    }

    public static Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>> CreateConnectCallback(string expectedHost, IPAddress bootstrap) =>
        (ctx, ct) => ConnectAsync(MapEndpoint(ctx.DnsEndPoint, expectedHost, bootstrap), ct);

    /// <summary>Opens a TCP connection to <paramref name="ep"/>; the socket is owned by the returned stream.</summary>
    public static async ValueTask<Stream> ConnectAsync(IPEndPoint ep, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(ep);
        var s = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await s.ConnectAsync(ep, ct).ConfigureAwait(false);
            return new NetworkStream(s, ownsSocket: true);
        }
        catch
        {
            s.Dispose();
            throw;
        }
    }
}
