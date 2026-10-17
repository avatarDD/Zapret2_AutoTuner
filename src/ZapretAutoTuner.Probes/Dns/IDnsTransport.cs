using System.Net;
using System.Security.Cryptography;
using ZapretAutoTuner.Core.Dns;

namespace ZapretAutoTuner.Probes.Dns;

/// <summary>Where an answer came from. System and plain UDP can be spoofed on path; DoH is the trusted reference.</summary>
public enum DnsResolverKind
{
    /// <summary>The OS resolver (getaddrinfo / DnsQuery): what browsers and programs actually get.</summary>
    System,

    /// <summary>A public resolver over plain UDP/TCP port 53.</summary>
    Udp,

    /// <summary>DNS over HTTPS (RFC 8484).</summary>
    Doh,
}

/// <summary>A transport-level DNS failure (bad response, unexpected id, HTTP error).</summary>
public sealed class DnsTransportException : IOException
{
    public DnsTransportException(string message)
        : base(message)
    {
    }

    public DnsTransportException(string message, Exception inner)
        : base(message, inner)
    {
    }
}

/// <summary>A resolver that speaks the DNS wire format (UDP/TCP 53 or DoH).</summary>
public interface IDnsTransport : IDisposable
{
    /// <summary>Display name, e.g. "Cloudflare".</summary>
    string Name { get; }

    DnsResolverKind Kind { get; }

    /// <summary>Server address as shown in the report: <c>1.1.1.1:53</c> or the DoH URL.</summary>
    string Server { get; }

    /// <summary>
    /// Sends one query and returns the parsed response. Throws <see cref="TimeoutException"/> when the server does
    /// not answer in time, <see cref="DnsTransportException"/> or <see cref="FormatException"/> for a bad response
    /// and <see cref="OperationCanceledException"/> only when <paramref name="ct"/> is cancelled.
    /// </summary>
    Task<DnsMessage> QueryAsync(string name, DnsRecordType type, DnsQueryOptions? options, CancellationToken ct);
}

/// <summary>Common part of the wire transports: query id, building the query and checking the response matches it.</summary>
public abstract class DnsTransportBase : IDnsTransport
{
    protected DnsTransportBase(string name, TimeSpan timeout)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);
        Name = name;
        Timeout = timeout;
    }

    public string Name { get; }

    public abstract DnsResolverKind Kind { get; }

    public abstract string Server { get; }

    /// <summary>Per-exchange timeout.</summary>
    public TimeSpan Timeout { get; }

    /// <summary>RFC 8484 §4.1: DoH uses id 0 so answers stay cacheable.</summary>
    protected virtual bool UseZeroId => false;

    public async Task<DnsMessage> QueryAsync(string name, DnsRecordType type, DnsQueryOptions? options, CancellationToken ct)
    {
        ushort id = UseZeroId ? (ushort)0 : (ushort)RandomNumberGenerator.GetInt32(0, 65536);
        var query = DnsMessage.BuildQuery(id, name, type, options);
        var raw = await ExchangeAsync(query, id, ct).ConfigureAwait(false);
        var msg = DnsMessage.Parse(raw);
        if (msg.Id != id || !msg.IsResponse)
            throw new DnsTransportException($"{Name}: ответ не соответствует запросу (id {msg.Id})");
        // servers may omit the question in error responses (FORMERR, REFUSED)
        if (msg.Questions.Count > 0 && (msg.Questions.Count != 1 || msg.Questions[0].Type != type || !DnsMessage.NameEquals(msg.Questions[0].Name, name)))
            throw new DnsTransportException($"{Name}: вопрос в ответе не совпадает с запросом");
        return msg;
    }

    /// <summary>Sends <paramref name="query"/> and returns the raw response bytes.</summary>
    protected abstract Task<byte[]> ExchangeAsync(byte[] query, ushort id, CancellationToken ct);

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
    }

    public override string ToString() => $"{Name} ({Server})";

    /// <summary>Formats an endpoint as <c>1.1.1.1:53</c> or <c>[2606:4700::1111]:53</c>.</summary>
    protected static string Format(IPEndPoint ep) => ep.ToString();
}
