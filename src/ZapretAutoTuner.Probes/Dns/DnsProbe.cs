using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Dns;

namespace ZapretAutoTuner.Probes.Dns;

public sealed class DnsProbeOptions
{
    /// <summary>Include the OS resolver.</summary>
    public bool IncludeSystem { get; init; } = true;

    /// <summary>OS resolver; null means <see cref="SystemDnsResolver"/>.</summary>
    public IAddressResolver? SystemResolver { get; init; }

    /// <summary>
    /// Wire resolvers to ask. Null means the defaults from <see cref="DnsResolverCatalog"/> (public UDP, then DoH),
    /// created and disposed by the probe; transports passed here stay owned by the caller.
    /// </summary>
    public IReadOnlyList<IDnsTransport>? Transports { get; init; }

    /// <summary>Stub/sinkhole lists and default resolvers; null means <see cref="DnsResolverCatalog.Default"/>.</summary>
    public DnsResolverCatalog? Catalog { get; init; }

    /// <summary>Overall deadline per resolver (all its queries, retries included).</summary>
    public TimeSpan ResolverTimeout { get; init; } = TimeSpan.FromSeconds(6);

    /// <summary>Per-attempt timeout of default UDP transports.</summary>
    public TimeSpan UdpTimeout { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Per-request timeout of default DoH transports.</summary>
    public TimeSpan DohTimeout { get; init; } = TimeSpan.FromSeconds(4);

    public bool QueryIpv6 { get; init; } = true;

    /// <summary>Ask DoH resolvers for the HTTPS RR (type 65): HTTP/3, ECH, address hints.</summary>
    public bool QueryHttps { get; init; } = true;
}

/// <summary>
/// DNS diagnostics of one host (PLAN 2.1, dpi-diagnostics §1, §2.1): the system resolver, public resolvers over UDP 53
/// and DoH are asked in parallel, the HTTPS RR is read via DoH, and <see cref="DnsVerdictRules"/> decides
/// <c>DNS_POISON</c>. A failing or slow resolver only marks its own answer; the probe itself fails only on cancellation.
/// </summary>
public static class DnsProbe
{
    public static async Task<DnsReport> RunAsync(string host, DnsProbeOptions? options, CancellationToken ct)
    {
        options ??= new DnsProbeOptions();
        var name = NormalizeHost(host);
        var catalog = options.Catalog ?? DnsResolverCatalog.Default;
        List<IDnsTransport>? owned = null;
        var transports = options.Transports ?? (owned = catalog.CreateTransports(options.UdpTimeout, options.DohTimeout));
        var sw = Stopwatch.StartNew();
        try
        {
            var answerTasks = new List<Task<DnsResolverAnswer>>();
            if (options.IncludeSystem)
                answerTasks.Add(QuerySystemAsync(options.SystemResolver ?? new SystemDnsResolver(), name, options.ResolverTimeout, ct));
            foreach (var t in transports)
                answerTasks.Add(QueryTransportAsync(t, name, options, ct));
            var httpsTasks = options.QueryHttps
                ? transports.Where(t => t.Kind == DnsResolverKind.Doh).Select(t => QueryHttpsAsync(t, name, options.ResolverTimeout, ct)).ToList()
                : [];
            await Task.WhenAll(answerTasks.Cast<Task>().Concat(httpsTasks)).ConfigureAwait(false);

            var answers = answerTasks.Select(t => t.Result).ToList();
            var verdict = DnsVerdictRules.Evaluate(answers, catalog);
            var trusted = new List<IPAddress>();
            foreach (var a in answers.Where(a => a.Kind == DnsResolverKind.Doh && a.HasAddresses).SelectMany(a => a.Addresses))
            {
                if (!catalog.IsSinkhole(a, out _) && !catalog.IsBlockPage(a, out _) && !trusted.Contains(a))
                    trusted.Add(a);
            }
            return new DnsReport
            {
                Host = name,
                Answers = answers,
                Https = httpsTasks.Select(t => t.Result).FirstOrDefault(s => s is not null),
                TrustedAddresses = trusted,
                Verdict = verdict,
                Duration = sw.Elapsed,
            };
        }
        finally
        {
            if (owned is not null)
            {
                foreach (var t in owned)
                    t.Dispose();
            }
        }
    }

    /// <summary>
    /// Asks <paramref name="transport"/> (normally a DoH resolver that forwards ECS, e.g. Google) for the host once per
    /// client subnet, so a CDN reveals the edges it serves to other regions (dpi-diagnostics §2a). Failures are
    /// reported per subnet.
    /// </summary>
    public static async Task<IReadOnlyList<DnsSubnetAnswer>> QueryWithSubnetsAsync(string host, IReadOnlyList<DnsClientSubnet> subnets, IDnsTransport transport, bool includeIpv6, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(subnets);
        ArgumentNullException.ThrowIfNull(transport);
        var name = NormalizeHost(host);
        using var gate = new SemaphoreSlim(4);
        var tasks = subnets.Select(async subnet =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var opts = new DnsQueryOptions { ClientSubnet = subnet };
                var types = includeIpv6 ? new[] { DnsRecordType.A, DnsRecordType.AAAA } : [DnsRecordType.A];
                var addrs = new List<IPAddress>();
                int? scope = null;
                var errors = new List<string>();
                foreach (var type in types)
                {
                    try
                    {
                        var msg = await transport.QueryAsync(name, type, opts, ct).ConfigureAwait(false);
                        foreach (var a in msg.ResolveChain(name).Addresses.Select(DnsResolverCatalog.Normalize))
                        {
                            if (!addrs.Contains(a))
                                addrs.Add(a);
                        }
                        scope ??= msg.Edns?.ClientSubnet?.ScopePrefix;
                    }
                    catch (Exception e) when (!ct.IsCancellationRequested)
                    {
                        errors.Add(e.Message);
                    }
                }
                return new DnsSubnetAnswer(subnet, addrs, scope, errors.Count == 0 ? null : string.Join("; ", errors.Distinct()));
            }
            finally
            {
                gate.Release();
            }
        }).ToList();
        return await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    /// <summary>ECS search through the first ECS-capable DoH resolver of the default catalog.</summary>
    public static async Task<IReadOnlyList<DnsSubnetAnswer>> QueryWithSubnetsAsync(string host, IReadOnlyList<DnsClientSubnet> subnets, CancellationToken ct)
    {
        var spec = DnsResolverCatalog.Default.Data.Doh.FirstOrDefault(d => d.Ecs)
            ?? throw new InvalidOperationException("в каталоге нет DoH-резолвера с поддержкой ECS");
        using var doh = DnsResolverCatalog.CreateDoh(spec, TimeSpan.FromSeconds(4));
        return await QueryWithSubnetsAsync(host, subnets, doh, includeIpv6: true, ct).ConfigureAwait(false);
    }

    /// <summary>Host for DNS: trimmed, without the trailing dot, IDN converted to punycode, lower case.</summary>
    public static string NormalizeHost(string host)
    {
        ArgumentNullException.ThrowIfNull(host);
        var h = host.Trim().TrimEnd('.');
        if (h.Length == 0)
            throw new ArgumentException("пустое имя хоста", nameof(host));
        if (IPAddress.TryParse(h, out _))
            throw new ArgumentException($"«{h}» — IP-адрес, а DNS-проба ожидает доменное имя", nameof(host));
        try
        {
            h = new IdnMapping().GetAscii(h);
        }
        catch (ArgumentException e)
        {
            throw new ArgumentException($"недопустимое имя хоста «{host}»", nameof(host), e);
        }
        return h.ToLowerInvariant();
    }

    private static async Task<DnsResolverAnswer> QuerySystemAsync(IAddressResolver resolver, string name, TimeSpan timeout, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        DnsAnswerStatus status;
        IReadOnlyList<IPAddress> addrs = [];
        string? error = null;
        try
        {
            var list = await resolver.ResolveAsync(name, cts.Token).ConfigureAwait(false);
            addrs = [.. list.Select(DnsResolverCatalog.Normalize).Distinct()];
            status = addrs.Count > 0 ? DnsAnswerStatus.Ok : DnsAnswerStatus.NoData;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.HostNotFound)
        {
            status = DnsAnswerStatus.NxDomain;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.NoData)
        {
            status = DnsAnswerStatus.NoData;
        }
        catch (Exception e) when (e is OperationCanceledException or TimeoutException && !ct.IsCancellationRequested)
        {
            status = DnsAnswerStatus.Timeout;
            error = Timeout(timeout);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            status = DnsAnswerStatus.Error;
            error = e.Message;
        }
        return new DnsResolverAnswer
        {
            Resolver = resolver.Name,
            Kind = DnsResolverKind.System,
            Server = "OS",
            Status = status,
            Addresses = addrs,
            Error = error,
            Duration = sw.Elapsed,
        };
    }

    private sealed record Outcome(DnsMessage? Message, DnsAnswerStatus? Failure, string? Error);

    private static async Task<DnsResolverAnswer> QueryTransportAsync(IDnsTransport t, string name, DnsProbeOptions options, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(options.ResolverTimeout);
        var types = options.QueryIpv6 ? new[] { DnsRecordType.A, DnsRecordType.AAAA } : [DnsRecordType.A];
        var outcomes = await Task.WhenAll(types.Select(type => QueryOneAsync(t, name, type, options.ResolverTimeout, cts.Token, ct))).ConfigureAwait(false);

        var addrs = new List<IPAddress>();
        IReadOnlyList<string> chain = [];
        foreach (var o in outcomes.Where(o => o.Message is not null))
        {
            var r = o.Message!.ResolveChain(name);
            if (r.Chain.Count > chain.Count)
                chain = r.Chain;
            foreach (var a in r.Addresses.Select(DnsResolverCatalog.Normalize))
            {
                if (!addrs.Contains(a))
                    addrs.Add(a);
            }
        }
        var msgs = outcomes.Where(o => o.Message is not null).Select(o => o.Message!).ToList();
        DnsAnswerStatus status;
        if (addrs.Count > 0)
            status = DnsAnswerStatus.Ok;
        else if (msgs.Any(m => m.ResponseCode == DnsResponseCode.NxDomain))
            status = DnsAnswerStatus.NxDomain;
        else if (msgs.Any(m => m.ResponseCode == DnsResponseCode.NoError))
            status = DnsAnswerStatus.NoData;
        else if (msgs.Count > 0)
            status = DnsAnswerStatus.ServerError;
        else if (outcomes.Any(o => o.Failure == DnsAnswerStatus.Timeout))
            status = DnsAnswerStatus.Timeout;
        else
            status = DnsAnswerStatus.Error;

        var errors = outcomes.Where(o => o.Error is not null).Select(o => o.Error!).Distinct().ToList();
        if (status == DnsAnswerStatus.ServerError)
            errors.Insert(0, "RCODE " + msgs[0].ResponseCode);
        return new DnsResolverAnswer
        {
            Resolver = t.Name,
            Kind = t.Kind,
            Server = t.Server,
            Status = status,
            Addresses = addrs,
            CnameChain = chain,
            ResponseCode = outcomes[0].Message?.ResponseCode ?? msgs.FirstOrDefault()?.ResponseCode,
            Error = errors.Count == 0 ? null : string.Join("; ", errors),
            Duration = sw.Elapsed,
        };
    }

    private static async Task<Outcome> QueryOneAsync(IDnsTransport t, string name, DnsRecordType type, TimeSpan deadline, CancellationToken token, CancellationToken outer)
    {
        try
        {
            return new Outcome(await t.QueryAsync(name, type, null, token).ConfigureAwait(false), null, null);
        }
        catch (Exception e) when (e is OperationCanceledException or TimeoutException && !outer.IsCancellationRequested)
        {
            return new Outcome(null, DnsAnswerStatus.Timeout, e is TimeoutException ? e.Message : Timeout(deadline));
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return new Outcome(null, DnsAnswerStatus.Error, e.Message);
        }
    }

    private static async Task<HttpsRecordSummary?> QueryHttpsAsync(IDnsTransport t, string name, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            var msg = await t.QueryAsync(name, DnsRecordType.HTTPS, null, cts.Token).ConfigureAwait(false);
            return HttpsRecordSummary.From(t.Name, msg.AnswersFor(name, DnsRecordType.HTTPS));
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            return null;
        }
    }

    private static string Timeout(TimeSpan t) =>
        string.Format(CultureInfo.InvariantCulture, "нет ответа за {0} мс", (int)t.TotalMilliseconds);
}
