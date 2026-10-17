using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Dns;
using ZapretAutoTuner.Probes.Dns;
using ZapretAutoTuner.Probes.Http;

namespace ZapretAutoTuner.Probes.Diagnostics;

/// <summary>An address that might serve the host, and where it came from.</summary>
public sealed record AltIpCandidate(IPAddress Address, string Source);

/// <summary>Extra candidate sources: CDN anycast ranges of the provider catalog, the knowledge base history.</summary>
public interface IAltIpCandidateSource
{
    Task<IReadOnlyList<AltIpCandidate>> GetAsync(string host, CancellationToken ct);
}

public sealed record AltIpCheck
{
    public required AltIpCandidate Candidate { get; init; }

    /// <summary>TLS with the host's SNI: the certificate must be valid for the host.</summary>
    public required ProbeResult L1 { get; init; }

    /// <summary>Full download, when L1 passed.</summary>
    public ProbeResult? L2 { get; init; }

    public bool Accepted => L1.Passes(ProbeLevel.L1Handshake);

    /// <summary>Opens fully without bypass; otherwise a strategy is still needed for this address (§2a step 4).</summary>
    public bool OpensFully => L2?.Passes(ProbeLevel.L2Body) == true;

    public string? RejectReason => Accepted ? null : L1 switch
    {
        { ConnectOk: false } => "адрес тоже заблокирован или не отвечает",
        { TlsOk: true, CertValid: false } => $"сертификат не подходит: {L1.CertError}",
        _ => $"{L1.Error}: {L1.ErrorDetail}",
    };

    public override string ToString() => $"{Candidate.Address} ({Candidate.Source}): {(Accepted ? OpensFully ? "opens" : "needs strategy" : RejectReason)}";
}

public sealed record AlternateIpOptions
{
    public int Port { get; init; } = 443;

    public string Path { get; init; } = "/";

    /// <summary>Addresses already known to be blocked.</summary>
    public IReadOnlyList<IPAddress> Exclude { get; init; } = [];

    public bool Ipv6 { get; init; } = true;

    /// <summary>Client subnets for the ECS search; null means the regional list from Data/ecs-subnets.json, empty turns it off.</summary>
    public IReadOnlyList<DnsClientSubnet>? Subnets { get; init; }

    /// <summary>The DoH resolver for ECS queries; null means the first ECS-capable one of the catalog.</summary>
    public IDnsTransport? EcsTransport { get; init; }

    public IReadOnlyList<IAltIpCandidateSource> Sources { get; init; } = [];

    public int MaxCandidates { get; init; } = 32;

    public int Parallel { get; init; } = 4;

    /// <summary>How many addresses to propose (§2a: 1–3 best).</summary>
    public int Pick { get; init; } = 3;

    public Func<HttpProbeOptions, HttpProbeOptions>? TweakHttp { get; init; }

    /// <summary>Which addresses may be candidates; null drops stub and private addresses (sinkhole list).</summary>
    public Func<IPAddress, bool>? AddressFilter { get; init; }
}

public sealed record AltIpSearchResult
{
    public required string Host { get; init; }

    public IReadOnlyList<AltIpCheck> Checked { get; init; } = [];

    /// <summary>Accepted addresses, best first: full download without bypass, then fastest connect.</summary>
    public IReadOnlyList<AltIpCheck> Best { get; init; } = [];

    public bool Found => Best.Count > 0;

    /// <summary>What the user is told when nothing was found (§0 rule 5).</summary>
    public string SummaryRu => Found
        ? $"Найден незаблокированный адрес {Best[0].Candidate.Address}{(Best[0].OpensFully ? ", сайт открывается напрямую" : ", для него подберём стратегию")}"
        : "Другого незаблокированного адреса не нашлось. Нужен VPN или прокси";

    public string SummaryEn => Found
        ? $"Found an unblocked address {Best[0].Candidate.Address}{(Best[0].OpensFully ? ", the site opens directly" : ", a strategy will be tuned for it")}"
        : "No other unblocked address found. A VPN or proxy is needed";
}

/// <summary>
/// Looks for another address of a resource whose addresses are all blocked by IP or port (dpi-diagnostics §2a):
/// answers of every resolver, HTTPS RR hints, IPv6, EDNS Client Subnet answers for other regions and the extra sources.
/// An address is accepted only if the certificate is valid for the host (otherwise it is someone else's server or a
/// MITM).
/// </summary>
public static class AlternateIpSearch
{
    public static async Task<AltIpSearchResult> RunAsync(string host, DnsReport? dns, AlternateIpOptions? options = null,
        IProgress<ClassifierStep>? progress = null, CancellationToken ct = default)
    {
        var o = options ?? new AlternateIpOptions();
        void Step(string ru, string en, string? addr = null) => progress?.Report(new ClassifierStep("other-ip", addr, ru, en));

        IReadOnlyList<DnsSubnetAnswer> ecs = [];
        var subnets = o.Subnets ?? DefaultSubnets();
        if (subnets.Count > 0)
        {
            Step($"Спрашиваю адреса {host} для других регионов (EDNS Client Subnet)", $"Asking for {host} addresses of other regions (EDNS Client Subnet)");
            try
            {
                ecs = o.EcsTransport is not null
                    ? await DnsProbe.QueryWithSubnetsAsync(host, subnets, o.EcsTransport, o.Ipv6, ct).ConfigureAwait(false)
                    : await DnsProbe.QueryWithSubnetsAsync(host, subnets, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is InvalidOperationException or DnsTransportException or TimeoutException)
            {
                Step($"ECS-поиск не удался: {e.Message}", $"ECS search failed: {e.Message}");
            }
        }

        var extra = new List<AltIpCandidate>();
        foreach (var s in o.Sources)
            extra.AddRange(await s.GetAsync(host, ct).ConfigureAwait(false));

        var candidates = Gather(dns, ecs, extra, o);
        Step($"Кандидатов: {candidates.Count}, проверяю сертификат и загрузку", $"{candidates.Count} candidates, checking the certificate and the download");

        using var gate = new SemaphoreSlim(Math.Max(1, o.Parallel));
        var checks = await Task.WhenAll(candidates.Select(async c =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                Step($"Проверяю {c.Address} ({c.Source})", $"Checking {c.Address} ({c.Source})", c.Address.ToString());
                return await CheckAsync(host, c, o, ct).ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }
        })).ConfigureAwait(false);

        var best = checks.Where(c => c.Accepted)
            .OrderByDescending(c => c.OpensFully)
            .ThenBy(c => c.L1.ConnectTime ?? TimeSpan.MaxValue)
            .Take(o.Pick)
            .ToList();
        var result = new AltIpSearchResult { Host = host, Checked = checks, Best = best };
        Step(result.SummaryRu, result.SummaryEn);
        return result;
    }

    /// <summary>Candidates in order of trust: DoH answers, other resolvers, HTTPS hints, ECS, extra sources.</summary>
    public static List<AltIpCandidate> Gather(DnsReport? dns, IEnumerable<DnsSubnetAnswer> ecs, IEnumerable<AltIpCandidate> extra, AlternateIpOptions o)
    {
        var list = new List<AltIpCandidate>();
        void Add(IPAddress a, string source)
        {
            a = DnsResolverCatalog.Normalize(a);
            if (!o.Ipv6 && a.AddressFamily == AddressFamily.InterNetworkV6)
                return;
            bool allowed = o.AddressFilter?.Invoke(a) ?? !DnsResolverCatalog.Default.IsSinkhole(a, out _);
            if (!allowed || o.Exclude.Contains(a) || list.Any(c => c.Address.Equals(a)))
                return;
            list.Add(new AltIpCandidate(a, source));
        }
        if (dns is not null)
        {
            foreach (var ans in dns.Answers.OrderBy(x => x.Kind == DnsResolverKind.Doh ? 0 : 1))
            {
                foreach (var a in ans.Addresses)
                    Add(a, ans.Resolver);
            }
            if (dns.Https is { } h)
            {
                foreach (var a in h.Ipv4Hints.Concat(h.Ipv6Hints))
                    Add(a, "HTTPS RR hint");
            }
        }
        foreach (var e in ecs)
        {
            foreach (var a in e.Addresses)
                Add(a, $"ECS {e.Subnet}");
        }
        foreach (var c in extra)
            Add(c.Address, c.Source);
        return list.Take(o.MaxCandidates).ToList();
    }

    private static async Task<AltIpCheck> CheckAsync(string host, AltIpCandidate c, AlternateIpOptions o, CancellationToken ct)
    {
        HttpProbeOptions P(ProbeLevel level)
        {
            var p = new HttpProbeOptions { Host = host, Address = c.Address, Port = o.Port, Path = o.Path, Level = level };
            return o.TweakHttp?.Invoke(p) ?? p;
        }
        var l1 = await HttpProbe.RunAsync(P(ProbeLevel.L1Handshake), ct).ConfigureAwait(false);
        var check = new AltIpCheck { Candidate = c, L1 = l1 };
        if (!check.Accepted)
            return check;
        return check with { L2 = await HttpProbe.RunAsync(P(ProbeLevel.L2Body), ct).ConfigureAwait(false) };
    }

    private static readonly Lazy<IReadOnlyList<DnsClientSubnet>> Subnets = new(() =>
    {
        using var s = typeof(AlternateIpSearch).Assembly.GetManifestResourceStream("ZapretAutoTuner.Probes.Data.ecs-subnets.json")
            ?? throw new InvalidOperationException("ecs-subnets.json is missing");
        var f = JsonSerializer.Deserialize(s, AltIpJsonContext.Default.EcsSubnetFile) ?? new EcsSubnetFile();
        return [.. f.Subnets.Select(x => DnsClientSubnet.Parse(x.Subnet))];
    });

    public static IReadOnlyList<DnsClientSubnet> DefaultSubnets() => Subnets.Value;
}

internal sealed class EcsSubnetFile
{
    public List<EcsSubnetEntry> Subnets { get; set; } = [];
}

internal sealed class EcsSubnetEntry
{
    public string Region { get; set; } = "";

    public string Operator { get; set; } = "";

    public string Subnet { get; set; } = "";
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true)]
[JsonSerializable(typeof(EcsSubnetFile))]
internal sealed partial class AltIpJsonContext : JsonSerializerContext;
