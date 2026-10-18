using System.Net;
using System.Net.Sockets;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Probes.Dns;
using ZapretAutoTuner.Probes.Http;
using ZapretAutoTuner.Probes.Net;
using ZapretAutoTuner.Probes.Quic;
using ZapretAutoTuner.Probes.Tls;

namespace ZapretAutoTuner.Probes.Diagnostics;

public sealed record ClassifierOptions
{
    public int Port { get; init; } = 443;

    public string Path { get; init; } = "/";

    /// <summary>Addresses to test instead of resolving the host (pinned IP, stand tests).</summary>
    public IReadOnlyList<IPAddress>? Addresses { get; init; }

    public DnsProbeOptions? Dns { get; init; }

    public int MaxAddresses { get; init; } = 4;

    public bool Ipv6 { get; init; }

    /// <summary>Baseline attempts per address (§0 rule 3: DPI often sits behind a load balancer).</summary>
    public int BaselineAttempts { get; init; } = 3;

    /// <summary>Pause between requests to one address (§0 rule 4: do not hammer).</summary>
    public TimeSpan Pause { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>The neutral domain of the cross-SNI test (blockcheck2's UNBLOCKED_DOM).</summary>
    public string NeutralDomain { get; init; } = "iana.org";

    /// <summary>Its address for the control probe; resolved through the system DNS when null.</summary>
    public IPAddress? NeutralAddress { get; init; }

    /// <summary>Client profiles whose ClientHello shapes are tried; null means the built-in ones.</summary>
    public IReadOnlyList<ClientProfile>? Profiles { get; init; }

    public bool CheckHttp { get; init; } = true;

    public int HttpPort { get; init; } = 80;

    public bool CheckQuic { get; init; } = true;

    public int QuicPort { get; init; } = 443;

    /// <summary>Adjusts every HTTP probe (timeouts, trust anchors for tests).</summary>
    public Func<HttpProbeOptions, HttpProbeOptions>? TweakHttp { get; init; }

    public TimeSpan HelloTimeout { get; init; } = TimeSpan.FromSeconds(4);

    public TimeSpan QuicTimeout { get; init; } = TimeSpan.FromSeconds(3);
}

/// <summary>One step of the diagnosis, for the "what is happening now" line of the UI.</summary>
public sealed record ClassifierStep(string Stage, string? Address, string MessageRu, string MessageEn)
{
    public override string ToString() => Address is null ? $"[{Stage}] {MessageEn}" : $"[{Stage}] {Address}: {MessageEn}";
}

public sealed record ClassifierRun(ClassifierVerdict Verdict, TargetObservation Observation, DnsReport? Dns);

/// <summary>
/// Runs the probes in the order of dpi-diagnostics §2 and hands the observations to <see cref="Classifier"/>: DNS,
/// port test (a dead address is not tested further), baseline full download, cross-SNI, volume cut-off, TLS versions,
/// client fingerprints, plain HTTP and QUIC. No engine is involved.
/// </summary>
public static class ClassifierRunner
{
    public static async Task<ClassifierRun> RunAsync(string host, ClassifierOptions? options = null, IProgress<ClassifierStep>? progress = null, CancellationToken ct = default)
    {
        var o = options ?? new ClassifierOptions();
        void Step(string stage, string? addr, string ru, string en) => progress?.Report(new ClassifierStep(stage, addr, ru, en));

        DnsReport? dns = null;
        IReadOnlyList<IPAddress> addresses;
        if (o.Addresses is { Count: > 0 } given)
        {
            addresses = given;
        }
        else
        {
            Step("dns", null, $"Проверяю DNS {host}: системный, публичные и DoH", $"Checking DNS of {host}: system, public and DoH");
            dns = await DnsProbe.RunAsync(host, o.Dns, ct).ConfigureAwait(false);
            var system = dns.SystemAnswer?.Addresses ?? [];
            // a spoofed system answer is replaced by DoH; otherwise test what the user's browser gets
            addresses = dns.Verdict.Poisoned || system.Count == 0 ? dns.TrustedAddresses : system;
            Step("dns", null, $"DNS: {Ru(dns.Verdict.Kind)}, адреса: {string.Join(", ", addresses)}", $"DNS: {dns.Verdict.Kind}, addresses: {string.Join(", ", addresses)}");
        }
        var list = addresses
            .Where(a => o.Ipv6 || a.AddressFamily == AddressFamily.InterNetwork)
            .Distinct()
            .Take(o.MaxAddresses)
            .ToList();

        var profiles = (o.Profiles ?? ClientProfile.BuiltIn).Where(p => p.HelloSpec is not null).ToList();
        IPAddress? neutralIp = o.NeutralAddress;
        var observations = new List<AddressObservation>();
        bool extrasDone = false;
        foreach (var ip in list)
        {
            ct.ThrowIfCancellationRequested();
            var obs = await ProbeAddressAsync(host, ip, o, profiles, Step, ct).ConfigureAwait(false);

            if (obs.NeutralSni is { } n && !n.TlsOk && n.Error != ProbeError.TlsFailed && obs.NeutralControl is null)
            {
                neutralIp ??= await ResolveAsync(o.NeutralDomain, ct).ConfigureAwait(false);
                if (neutralIp is not null)
                {
                    Step("control", neutralIp.ToString(), $"Контроль: {o.NeutralDomain} на своём адресе", $"Control: {o.NeutralDomain} on its own address");
                    obs = obs with { NeutralControl = await HttpAsync(o, o.NeutralDomain, neutralIp, o.Port, ProbeLevel.L1Handshake, null, ct).ConfigureAwait(false) };
                }
            }

            // plain HTTP and QUIC once per target, on the first address that connects
            if (!extrasDone && obs.Connect?.ConnectOk == true)
            {
                extrasDone = true;
                if (o.CheckHttp && o.Port != o.HttpPort)
                {
                    Step("http", ip.ToString(), $"HTTP на порт {o.HttpPort}", $"HTTP on port {o.HttpPort}");
                    obs = obs with { Http = await HttpAsync(o, host, ip, o.HttpPort, ProbeLevel.L1Handshake, null, ct, tls: false).ConfigureAwait(false) };
                }
                if (o.CheckQuic && dns?.Https?.SupportsHttp3 != false)
                {
                    Step("quic", ip.ToString(), "QUIC (HTTP/3): Initial-пакет с ClientHello", "QUIC (HTTP/3): Initial with a ClientHello");
                    var spec = profiles.FirstOrDefault(p => p.Quic)?.HelloSpec ?? "chrome141";
                    obs = obs with
                    {
                        Quic = await QuicProbe.RunAsync(new QuicProbeOptions { Address = ip, Port = o.QuicPort, Sni = host, Spec = ClientHelloSpec.Get(spec), Timeout = o.QuicTimeout }, ct).ConfigureAwait(false),
                    };
                }
            }
            observations.Add(obs);
        }

        var target = new TargetObservation
        {
            Host = host,
            Port = o.Port,
            SupportsHttp3 = dns?.Https?.SupportsHttp3,
            Dns = dns is null ? null : new DnsObservation
            {
                Poisoned = dns.Verdict.Poisoned,
                Suspicious = dns.Verdict.Kind == DnsVerdictKind.Suspicious,
                Evidence = [.. dns.Verdict.Reasons.Select(r => r.MessageRu)],
            },
            Addresses = observations,
        };
        var verdict = Classifier.Classify(target);
        Step("verdict", null, verdict.SummaryRu, verdict.SummaryEn);
        return new ClassifierRun(verdict, target, dns);
    }

    private static async Task<AddressObservation> ProbeAddressAsync(string host, IPAddress ip, ClassifierOptions o, List<ClientProfile> profiles,
        Action<string, string?, string, string> step, CancellationToken ct)
    {
        string a = ip.ToString();
        step("port", a, $"Порт-тест: TCP {o.Port}", $"Port test: TCP {o.Port}");
        var connect = await ConnectAsync(host, ip, o.Port, ct).ConfigureAwait(false);
        var obs = new AddressObservation { Address = a, Connect = connect };
        if (!connect.ConnectOk)
        {
            int other = o.Port == 80 ? 443 : 80;
            step("port", a, $"Порт {o.Port} не соединяется, проверяю порт {other}", $"Port {o.Port} does not connect, trying port {other}");
            return obs with { ConnectOtherPort = await ConnectAsync(host, ip, other, ct).ConfigureAwait(false) };
        }

        var baseline = new List<ProbeResult>();
        for (int i = 0; i < o.BaselineAttempts; i++)
        {
            if (i > 0)
                await Task.Delay(o.Pause, ct).ConfigureAwait(false);
            step("baseline", a, $"Без обхода: полная загрузка, попытка {i + 1} из {o.BaselineAttempts}", $"No bypass: full download, attempt {i + 1} of {o.BaselineAttempts}");
            baseline.Add(await HttpAsync(o, host, ip, o.Port, ProbeLevel.L2Body, null, ct).ConfigureAwait(false));
        }
        obs = obs with { Baseline = baseline };

        bool tlsFailed = baseline.Any(b => b.ConnectOk && !b.TlsOk) || baseline.Any(b => b.TlsOk && !b.CertValid);
        if (tlsFailed)
        {
            step("cross-sni", a, $"Кросс-SNI: этот адрес с SNI {o.NeutralDomain}", $"Cross-SNI: this address with SNI {o.NeutralDomain}");
            await Task.Delay(o.Pause, ct).ConfigureAwait(false);
            obs = obs with { NeutralSni = await HttpAsync(o, host, ip, o.Port, ProbeLevel.L1Handshake, o.NeutralDomain, ct).ConfigureAwait(false) };
        }
        else if (baseline.Count > 0 && baseline.All(b => b.Passes(ProbeLevel.L2Body) && b.Complete) && baseline.Max(b => b.BodyBytes) < 128 * 1024)
        {
            // the page is small: inflate the request so a volume cut-off has a chance to show (§3)
            step("16k", a, "Страница маленькая: проверяю обрыв на 16 KB раздутым запросом", "Small page: checking the 16 KB cut-off with a padded request");
            await Task.Delay(o.Pause, ct).ConfigureAwait(false);
            obs = obs with { Padded = await HttpAsync(o, host, ip, o.Port, ProbeLevel.L2Body, null, ct, padBytes: 24_000, minBytes: 128 * 1024).ConfigureAwait(false) };
        }

        step("tls", a, "TLS 1.2 и TLS 1.3 по отдельности", "TLS 1.2 and TLS 1.3 separately");
        obs = obs with
        {
            Tls12 = await HttpAsync(o, host, ip, o.Port, ProbeLevel.L1Handshake, null, ct, version: TlsVersionLimit.Tls12).ConfigureAwait(false),
            Tls13 = await HttpAsync(o, host, ip, o.Port, ProbeLevel.L1Handshake, null, ct, version: TlsVersionLimit.Tls13).ConfigureAwait(false),
        };

        var hellos = new List<HelloProbeResult>();
        foreach (var (spec, kyber, ech) in HelloVariants(profiles))
        {
            step("fingerprint", a, $"Отпечаток клиента: {spec.Name}{(kyber ? ", kyber" : "")}{(ech ? ", ECH" : "")}", $"Client fingerprint: {spec.Name}{(kyber ? ", kyber" : "")}{(ech ? ", ECH" : "")}");
            await Task.Delay(o.Pause, ct).ConfigureAwait(false);
            hellos.Add(await HelloProbe.RunAsync(new HelloProbeOptions
            {
                Address = ip,
                Port = o.Port,
                Spec = spec,
                Hello = new ClientHelloOptions { Sni = host, Kyber = kyber, Ech = ech },
                ReplyTimeout = o.HelloTimeout,
            }, ct).ConfigureAwait(false));
        }
        return obs with { Hellos = hellos };
    }

    /// <summary>
    /// Hello shapes to try: each profile's spec as the client sends it, plus the same spec without kyber and without
    /// ECH, so that KYBER_MULTIPKT and ECH can be told from a plain fingerprint block.
    /// </summary>
    internal static List<(ClientHelloSpec Spec, bool Kyber, bool Ech)> HelloVariants(IEnumerable<ClientProfile> profiles)
    {
        var set = new List<(ClientHelloSpec, bool, bool)>();
        void Add(ClientHelloSpec s, bool k, bool e)
        {
            if (!set.Any(x => x.Item1.Id == s.Id && x.Item2 == k && x.Item3 == e))
                set.Add((s, k, e));
        }
        foreach (var p in profiles)
        {
            var spec = ClientHelloSpec.Get(p.HelloSpec!);
            Add(spec, p.Kyber, p.Ech);
            if (p.Kyber)
                Add(spec, false, p.Ech);
            if (p.Ech)
                Add(spec, p.Kyber, false);
        }
        return set;
    }

    private static async Task<ProbeResult> ConnectAsync(string host, IPAddress ip, int port, CancellationToken ct)
    {
        var c = await TcpConnector.ConnectAsync(ip, port, TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
        c.Socket?.Dispose();
        return new ProbeResult
        {
            Host = host,
            Address = ip.ToString(),
            Port = port,
            ConnectOk = c.Ok,
            ConnectTime = c.Ok ? c.Elapsed : null,
            Duration = c.Elapsed,
            Error = c.Error,
            ErrorDetail = c.Detail,
            RstSeen = c.Rst,
        };
    }

    private static Task<ProbeResult> HttpAsync(ClassifierOptions o, string host, IPAddress ip, int port, ProbeLevel level, string? sni, CancellationToken ct,
        bool tls = true, TlsVersionLimit version = TlsVersionLimit.Any, int padBytes = 0, long minBytes = 64 * 1024)
    {
        var p = new HttpProbeOptions
        {
            Host = host,
            Address = ip,
            Port = port,
            Tls = tls,
            Sni = sni,
            Path = o.Path,
            Level = level,
            TlsVersion = version,
            PadBytes = padBytes,
            MinBytes = minBytes,
        };
        return HttpProbe.RunAsync(o.TweakHttp?.Invoke(p) ?? p, ct);
    }

    private static async Task<IPAddress?> ResolveAsync(string host, CancellationToken ct)
    {
        try
        {
            var a = await System.Net.Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, ct).ConfigureAwait(false);
            return a.FirstOrDefault();
        }
        catch (SocketException)
        {
            return null;
        }
    }

    private static string Ru(DnsVerdictKind k) => k switch
    {
        DnsVerdictKind.Clean => "чисто",
        DnsVerdictKind.Suspicious => "подозрительно",
        DnsVerdictKind.Poisoned => "подмена",
        _ => "не определено",
    };
}
