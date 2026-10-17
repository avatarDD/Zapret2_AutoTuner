namespace ZapretAutoTuner.Core.Diagnostics;

/// <summary>Block types of dpi-diagnostics §2 (the table numbers are in the comments).</summary>
public enum BlockLabel
{
    /// <summary>Nothing blocks: the resource opens without bypass.</summary>
    Open,
    DnsPoison,      // 2.1
    IpBlock,        // 2.2
    PortBlock,      // 2.3
    SniBlock,       // 2.4
    PartialIp,      // 2.5
    HttpBlock,      // 2.6
    QuicBlock,      // 2.7
    Cutoff16K,      // 2.8
    Punish,         // 2.9
    Unstable,       // 2.10
    Fingerprint,    // 2.11
    KyberMultiPkt,  // 2.12
    Ech,            // 2.13
    Tls13Block,     // 2.14

    /// <summary>The tests did not agree on anything (network trouble, server down).</summary>
    Unknown,
}

/// <summary>What the classifier suggests doing next.</summary>
public enum NextStep
{
    /// <summary>The resource opens: nothing to tune.</summary>
    Nothing,

    /// <summary>Search a strategy on the addresses listed in <see cref="ClassifierVerdict.LiveAddresses"/>.</summary>
    SearchStrategy,

    /// <summary>Every address is blocked by IP or port: look for another address of the resource (§2a).</summary>
    FindOtherIp,

    /// <summary>Only DNS is spoofed: DoH in the OS or browser fixes it, a strategy does not.</summary>
    UseDoh,

    /// <summary>No working path found: a VPN or proxy is needed.</summary>
    NeedVpn,
}

/// <summary>DNS findings as the classifier needs them (from the DNS probe).</summary>
public sealed record DnsObservation
{
    public bool Poisoned { get; init; }

    public bool Suspicious { get; init; }

    public IReadOnlyList<string> Evidence { get; init; } = [];
}

/// <summary>Everything measured on one address of the target, without the engine.</summary>
public sealed record AddressObservation
{
    public required string Address { get; init; }

    /// <summary>TCP connect to the target port (only connect and error matter).</summary>
    public ProbeResult? Connect { get; init; }

    /// <summary>TCP connect to another port (80 for 443) — tells PORT_BLOCK from IP_BLOCK.</summary>
    public ProbeResult? ConnectOtherPort { get; init; }

    /// <summary>Baseline attempts: the target's own SNI, full download (L2). Several for stability.</summary>
    public IReadOnlyList<ProbeResult> Baseline { get; init; } = [];

    /// <summary>A neutral SNI (blockcheck2's iana.org) sent to this address.</summary>
    public ProbeResult? NeutralSni { get; init; }

    /// <summary>The neutral domain on its own address: if it fails too, the network is the problem.</summary>
    public ProbeResult? NeutralControl { get; init; }

    /// <summary>Download with padded request headers and a 128 KB threshold (volume cut-off check).</summary>
    public ProbeResult? Padded { get; init; }

    public ProbeResult? Tls12 { get; init; }

    public ProbeResult? Tls13 { get; init; }

    /// <summary>Plain HTTP on port 80.</summary>
    public ProbeResult? Http { get; init; }

    /// <summary>Crafted hellos of the client profiles.</summary>
    public IReadOnlyList<HelloProbeResult> Hellos { get; init; } = [];

    public QuicProbeResult? Quic { get; init; }
}

public sealed record TargetObservation
{
    public required string Host { get; init; }

    public int Port { get; init; } = 443;

    public DnsObservation? Dns { get; init; }

    /// <summary>The target announces HTTP/3 (HTTPS RR alpn or Alt-Svc); null when unknown.</summary>
    public bool? SupportsHttp3 { get; init; }

    public IReadOnlyList<AddressObservation> Addresses { get; init; } = [];
}

/// <summary>A label with the facts behind it (§0 rule 6: every conclusion is backed by an artifact).</summary>
public sealed record LabelFinding(BlockLabel Label, string? Address, IReadOnlyList<string> Evidence)
{
    public override string ToString() => $"{Label}{(Address is null ? "" : " @ " + Address)}: {string.Join("; ", Evidence)}";
}

public sealed record ClassifierVerdict
{
    public required string Host { get; init; }

    public IReadOnlyList<LabelFinding> Findings { get; init; } = [];

    public IReadOnlySet<BlockLabel> Labels => Findings.Select(f => f.Label).ToHashSet();

    /// <summary>Addresses that are not blocked by IP or port: the strategy search runs on them only.</summary>
    public IReadOnlyList<string> LiveAddresses { get; init; } = [];

    /// <summary>Addresses blocked by IP or port.</summary>
    public IReadOnlyList<string> DeadAddresses { get; init; } = [];

    public NextStep Next { get; init; }

    /// <summary>The label the user sees first (traffic light of §4b).</summary>
    public BlockLabel Primary { get; init; }

    public string SummaryRu => Texts.Ru(Primary);

    public string SummaryEn => Texts.En(Primary);

    public override string ToString() => $"{Host}: {Primary} → {Next} [{string.Join(", ", Labels)}]";
}

/// <summary>Plain-words names of the labels for the traffic light (§4b).</summary>
public static class Texts
{
    public static string Ru(BlockLabel l) => l switch
    {
        BlockLabel.Open => "Открывается",
        BlockLabel.DnsPoison => "Подмена DNS",
        BlockLabel.IpBlock => "Блок по IP — нужен VPN или другой IP",
        BlockLabel.PortBlock => "Порт закрыт — нужен VPN или другой IP",
        BlockLabel.SniBlock => "Блок по SNI — обходится",
        BlockLabel.PartialIp => "Блок по диапазону IP — пробуем белый SNI",
        BlockLabel.HttpBlock => "Блок HTTP — обходится",
        BlockLabel.QuicBlock => "QUIC режется",
        BlockLabel.Cutoff16K => "Обрыв на 16 KB — обходится",
        BlockLabel.Punish => "DPI «наказывает» за попытки — пауза",
        BlockLabel.Unstable => "Работает через раз",
        BlockLabel.Fingerprint => "Блок по отпечатку клиента",
        BlockLabel.KyberMultiPkt => "Блок большого ClientHello (kyber)",
        BlockLabel.Ech => "Блок ECH",
        BlockLabel.Tls13Block => "Блок TLS 1.3",
        _ => "Не удалось определить",
    };

    public static string En(BlockLabel l) => l switch
    {
        BlockLabel.Open => "Opens",
        BlockLabel.DnsPoison => "DNS spoofing",
        BlockLabel.IpBlock => "Blocked by IP — needs a VPN or another IP",
        BlockLabel.PortBlock => "Port closed — needs a VPN or another IP",
        BlockLabel.SniBlock => "Blocked by SNI — can be bypassed",
        BlockLabel.PartialIp => "IP range rule — trying a whitelisted SNI",
        BlockLabel.HttpBlock => "HTTP blocked — can be bypassed",
        BlockLabel.QuicBlock => "QUIC is cut",
        BlockLabel.Cutoff16K => "Cut off at 16 KB — can be bypassed",
        BlockLabel.Punish => "DPI punishes retries — pausing",
        BlockLabel.Unstable => "Works now and then",
        BlockLabel.Fingerprint => "Blocked by client fingerprint",
        BlockLabel.KyberMultiPkt => "Large (kyber) ClientHello blocked",
        BlockLabel.Ech => "ECH blocked",
        BlockLabel.Tls13Block => "TLS 1.3 blocked",
        _ => "Could not tell",
    };
}

/// <summary>
/// The block classifier of dpi-diagnostics §2, as pure rules over probe results (no I/O, no engine). The runner in
/// ZapretAutoTuner.Probes collects the observations in the order the skill gives: DNS, port test, baseline, cross-SNI,
/// 16 KB, TLS versions, client fingerprints, HTTP, QUIC.
/// </summary>
public static class Classifier
{
    /// <summary>Incoming bytes where the "16 KB" cut-off usually bites (§2.8).</summary>
    public const long CutoffMin = 8 * 1024, CutoffMax = 32 * 1024;

    public static ClassifierVerdict Classify(TargetObservation t)
    {
        var findings = new List<LabelFinding>();
        if (t.Dns?.Poisoned == true)
            findings.Add(new LabelFinding(BlockLabel.DnsPoison, null, t.Dns.Evidence));

        var live = new List<string>();
        var dead = new List<string>();
        foreach (var a in t.Addresses)
        {
            var f = ClassifyAddress(t, a);
            findings.AddRange(f);
            if (f.Any(x => x.Label is BlockLabel.IpBlock or BlockLabel.PortBlock))
                dead.Add(a.Address);
            else
                live.Add(a.Address);
        }

        var labels = findings.Select(f => f.Label).ToHashSet();
        NextStep next;
        if (t.Addresses.Count > 0 && live.Count == 0)
            next = NextStep.FindOtherIp;
        else if (labels.Count == 0 || labels.All(l => l == BlockLabel.Open))
            next = NextStep.Nothing;
        else if (labels.All(l => l is BlockLabel.Open or BlockLabel.DnsPoison))
            next = NextStep.UseDoh;
        else if (labels.All(l => l is BlockLabel.Unknown or BlockLabel.Open or BlockLabel.DnsPoison))
            next = NextStep.NeedVpn;
        else
            next = NextStep.SearchStrategy;

        return new ClassifierVerdict
        {
            Host = t.Host,
            Findings = findings,
            LiveAddresses = live,
            DeadAddresses = dead,
            Next = next,
            Primary = PickPrimary(labels, live.Count == 0 && t.Addresses.Count > 0),
        };
    }

    private static readonly BlockLabel[] Priority =
    [
        BlockLabel.IpBlock, BlockLabel.PortBlock, BlockLabel.Punish, BlockLabel.SniBlock, BlockLabel.PartialIp, BlockLabel.Cutoff16K,
        BlockLabel.Tls13Block, BlockLabel.KyberMultiPkt, BlockLabel.Ech, BlockLabel.Fingerprint, BlockLabel.HttpBlock,
        BlockLabel.QuicBlock, BlockLabel.Unstable, BlockLabel.DnsPoison, BlockLabel.Unknown, BlockLabel.Open,
    ];

    private static BlockLabel PickPrimary(HashSet<BlockLabel> labels, bool allDead)
    {
        if (allDead)
            return labels.Contains(BlockLabel.IpBlock) ? BlockLabel.IpBlock : BlockLabel.PortBlock;
        // with live addresses, the IP block of some addresses is not what the user must act on
        foreach (var l in Priority.Where(l => l is not (BlockLabel.IpBlock or BlockLabel.PortBlock)))
        {
            if (labels.Contains(l))
                return l;
        }
        return labels.Contains(BlockLabel.IpBlock) ? BlockLabel.IpBlock : labels.Contains(BlockLabel.PortBlock) ? BlockLabel.PortBlock : BlockLabel.Unknown;
    }

    private static List<LabelFinding> ClassifyAddress(TargetObservation t, AddressObservation a)
    {
        var r = new List<LabelFinding>();
        void Add(BlockLabel l, params string[] ev) => r.Add(new LabelFinding(l, a.Address, ev));

        // 2.2 / 2.3: the port test comes first; a dead address is not tested further
        var connect = a.Connect ?? (a.Baseline.Count > 0 ? a.Baseline[0] : null);
        if (connect is { ConnectOk: false })
        {
            bool other = a.ConnectOtherPort?.ConnectOk == true;
            var ev = connect.Error == ProbeError.ConnectRefused ? "на SYN к порту пришёл RST" : $"SYN к порту {t.Port} без ответа";
            if (other)
                Add(BlockLabel.PortBlock, ev, $"порт {a.ConnectOtherPort!.Port} соединяется");
            else
                Add(BlockLabel.IpBlock, ev, a.ConnectOtherPort is null ? "другие порты не проверялись" : $"порт {a.ConnectOtherPort.Port} тоже не соединяется");
            return r;
        }

        var baseline = a.Baseline;
        int ok = baseline.Count(b => b.Passes(ProbeLevel.L2Body));
        bool baselineOk = baseline.Count > 0 && ok == baseline.Count;

        // 2.9 / 2.10: several attempts disagree
        if (baseline.Count >= 3 && ok > 0 && ok < baseline.Count)
        {
            int firstFail = baseline.ToList().FindIndex(b => !b.Passes(ProbeLevel.L2Body));
            bool punished = baseline.Take(firstFail).All(b => b.Passes(ProbeLevel.L2Body)) && firstFail > 0
                && baseline.Skip(firstFail).All(b => !b.Passes(ProbeLevel.L2Body) && b is { ConnectOk: false } or { Error: ProbeError.ConnectTimeout });
            if (punished)
                Add(BlockLabel.Punish, $"первые {firstFail} попытки прошли, затем адрес перестал отвечать даже на SYN");
            else
                Add(BlockLabel.Unstable, $"успешно {ok} из {baseline.Count} попыток");
        }

        var main = baseline.FirstOrDefault(b => !b.Passes(ProbeLevel.L2Body)) ?? (baseline.Count > 0 ? baseline[0] : null);
        if (main is not null && !baselineOk && !r.Any(x => x.Label == BlockLabel.Punish))
            ClassifyFailure(a, main, Add);

        // 2.8 also when the page itself is small: the padded download crosses the threshold
        if (a.Padded is { } pad && IsCutoff(pad, 128 * 1024) && !r.Any(x => x.Label == BlockLabel.Cutoff16K))
            Add(BlockLabel.Cutoff16K, [$"загрузка с раздутым запросом остановилась на {pad.StalledAt ?? pad.BytesIn} B", .. Evidence(pad)]);

        // 2.14
        if (a.Tls12 is { } t12 && a.Tls13 is { } t13 && t12.TlsOk && !t13.TlsOk && t13.ConnectOk)
            Add(BlockLabel.Tls13Block, ["TLS 1.2 проходит, TLS 1.3 нет", .. Evidence(t13)]);

        ClassifyHellos(a, baseline.Any(b => b.TlsOk), Add);

        // 2.6
        if (a.Http is { ConnectOk: true } http && IsHttpBlock(t.Host, http, out var why))
            Add(BlockLabel.HttpBlock, why);

        // 2.7: only when the target is known (or not known not) to speak HTTP/3
        if (a.Quic is { } q && q.Outcome == QuicOutcome.NoResponse && t.SupportsHttp3 != false)
            Add(BlockLabel.QuicBlock, $"на {q.Sent} Initial-пакета не пришло ни одного ответа",
                t.SupportsHttp3 == true ? "сайт объявляет HTTP/3" : "поддержка HTTP/3 не подтверждена");

        if (r.Count == 0)
        {
            if (baselineOk)
                Add(BlockLabel.Open, $"полная загрузка: {baseline[0].BodyBytes} B, HTTP {baseline[0].HttpStatus}");
            else if (baseline.Count == 0)
                Add(BlockLabel.Unknown, "baseline не измерен");
        }
        return r;
    }

    private static void ClassifyFailure(AddressObservation a, ProbeResult b, Action<BlockLabel, string[]> add)
    {
        // TLS-stage failure: a reset, silence or FIN after the ClientHello, or a forged certificate
        bool tlsBlocked = b.Error is ProbeError.TlsReset or ProbeError.TlsTimeout or ProbeError.TlsClosed
            || (b.TlsOk && !b.CertValid && b.CertError is not null);
        if (tlsBlocked)
        {
            var neutral = a.NeutralSni;
            bool neutralAnswered = neutral is not null && ServerAnswered(neutral);
            if (neutral is null || neutralAnswered)
            {
                var ev = new List<string> { Describe(b) };
                if (neutralAnswered)
                    ev.Add($"тот же IP с SNI {neutral!.Sni ?? "(без SNI)"} отвечает");
                else
                    ev.Add("кросс-SNI тест не проводился");
                ev.AddRange(Evidence(b));
                add(BlockLabel.SniBlock, [.. ev]);
            }
            else if (a.NeutralControl is { } control && ServerAnswered(control))
            {
                add(BlockLabel.PartialIp, [Describe(b), $"SNI {neutral!.Sni} на этом IP тоже не проходит", $"а на своём IP {control.Address} проходит"]);
            }
            else
            {
                add(BlockLabel.Unknown, [Describe(b), $"SNI {neutral!.Sni} тоже не проходит, контрольный домен не подтвердил связь"]);
            }
            return;
        }

        if (IsCutoff(b, 64 * 1024))
        {
            add(BlockLabel.Cutoff16K, [$"TLS прошёл, входящие данные остановились на {b.StalledAt ?? b.BytesIn} B", .. Evidence(b)]);
            return;
        }

        if (b.Error is ProbeError.HttpReset or ProbeError.HttpTimeout or ProbeError.Stalled or ProbeError.Truncated)
            add(BlockLabel.Unknown, [Describe(b)]);
        else if (b.Error is ProbeError.TlsFailed)
            add(BlockLabel.Unknown, [$"TLS не согласован: {b.ErrorDetail}"]);
    }

    private static void ClassifyHellos(AddressObservation a, bool nativeTlsOk, Action<BlockLabel, string[]> add)
    {
        var hs = a.Hellos.Where(h => h.Outcome != HelloOutcome.ConnectFailed).ToList();
        if (hs.Count == 0)
            return;

        // 2.12: the same client shape passes without the post-quantum share and fails with it
        var kyberFail = hs.FirstOrDefault(h => h.Kyber && !h.PassedDpi);
        var kyberPass = hs.FirstOrDefault(h => !h.Kyber && h.PassedDpi && kyberFail is not null && h.Spec == kyberFail.Spec)
            ?? hs.FirstOrDefault(h => !h.Kyber && h.PassedDpi);
        if (kyberFail is not null && kyberPass is not null && !hs.Any(h => h.Kyber && h.PassedDpi))
        {
            add(BlockLabel.KyberMultiPkt, [$"{kyberFail.Spec} с kyber ({kyberFail.HelloBytes} B): {kyberFail.Outcome}", $"{kyberPass.Spec} без kyber ({kyberPass.HelloBytes} B): ответ сервера"]);
            return;
        }

        // 2.13
        var echFail = hs.FirstOrDefault(h => h.Ech && !h.PassedDpi);
        var echPass = hs.FirstOrDefault(h => !h.Ech && h.PassedDpi && echFail is not null && h.Spec == echFail.Spec && h.Kyber == echFail.Kyber);
        if (echFail is not null && echPass is not null)
        {
            add(BlockLabel.Ech, [$"{echFail.Spec} с ECH: {echFail.Outcome}", $"{echPass.Spec} без ECH: ответ сервера"]);
            return;
        }

        // 2.11: some client shapes pass, others do not, or the platform client and the browsers disagree
        var failed = hs.Where(h => !h.PassedDpi).Select(h => h.Spec).Distinct().ToList();
        var passed = hs.Where(h => h.PassedDpi).Select(h => h.Spec).Distinct().ToList();
        if (failed.Count > 0 && (passed.Count > 0 || nativeTlsOk))
            add(BlockLabel.Fingerprint, [$"не проходят: {string.Join(", ", failed)}", passed.Count > 0 ? $"проходят: {string.Join(", ", passed)}" : "системный TLS-клиент проходит"]);
        else if (passed.Count > 0 && failed.Count == 0 && !nativeTlsOk && a.Baseline.Any(b => b.Error is ProbeError.TlsReset or ProbeError.TlsTimeout))
            add(BlockLabel.Fingerprint, [$"проходят отпечатки {string.Join(", ", passed)}", "системный TLS-клиент блокируется"]);
    }

    /// <summary>The server (not a DPI) answered the TLS hello: a handshake, or a TLS alert/error from the server.</summary>
    private static bool ServerAnswered(ProbeResult p) => p.TlsOk || p.Error == ProbeError.TlsFailed;

    private static bool IsCutoff(ProbeResult p, long need) =>
        p.TlsOk && !p.Passes(ProbeLevel.L2Body, need) && p.Error is ProbeError.Stalled or ProbeError.HttpReset or ProbeError.Truncated
        && (p.StalledAt ?? p.BytesIn) is >= CutoffMin and <= CutoffMax;

    /// <summary>
    /// HTTP block (§2.6): a redirect to another registrable domain, or a reset or silence on the request. A redirect to
    /// HTTPS on the same domain is normal.
    /// </summary>
    internal static bool IsHttpBlock(string host, ProbeResult http, out string why)
    {
        why = "";
        if (http.Error is ProbeError.HttpReset)
        {
            why = "RST в ответ на HTTP-запрос";
            return true;
        }
        if (http.Error is ProbeError.HttpTimeout)
        {
            why = "нет ответа на HTTP-запрос при живом TCP";
            return true;
        }
        if (http.HttpStatus is >= 300 and < 400 && http.Location is { } loc && Uri.TryCreate(loc, UriKind.Absolute, out var u)
            && !string.Equals(Registrable(u.Host), Registrable(host), StringComparison.OrdinalIgnoreCase))
        {
            why = $"HTTP {http.HttpStatus} на чужой домен {u.Host}";
            return true;
        }
        return false;
    }

    /// <summary>Approximate registrable domain: the last two labels, three for known second-level suffixes.</summary>
    internal static string Registrable(string host)
    {
        var parts = host.TrimEnd('.').Split('.');
        if (parts.Length <= 2)
            return host;
        var sld = parts[^2];
        bool twoLevelSuffix = parts[^1].Length == 2 && sld is "com" or "net" or "org" or "co" or "gov" or "edu" or "ac" or "msk" or "spb";
        return string.Join('.', parts[^(twoLevelSuffix ? 3 : 2)..]);
    }

    private static string Describe(ProbeResult p) => p.Error switch
    {
        ProbeError.TlsReset => "RST после ClientHello",
        ProbeError.TlsTimeout => "ClientHello остался без ответа",
        ProbeError.TlsClosed => "соединение закрыто после ClientHello",
        _ when p.TlsOk && !p.CertValid => $"подменённый сертификат: {p.CertIssuer} ({p.CertError})",
        _ => $"{p.Error}: {p.ErrorDetail}",
    };

    private static string[] Evidence(ProbeResult p)
    {
        var e = new List<string>();
        if (p.RstOrigin == RstOrigin.Injected)
            e.Add("RST подделан: TTL/IPID не как у сервера или пришёл быстрее RTT");
        else if (p.RstOrigin == RstOrigin.Server)
            e.Add("RST похож на серверный");
        return [.. e];
    }
}
