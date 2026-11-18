using System.Globalization;
using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Geneva;

/// <summary>
/// Which engine bypasses the blocks on this PC: zapret2's nfqws2/winws2 (the wizard, the monitor) or geneva_c
/// (Geneva's strategy language and genetic search, skill <c>geneva</c>). Only one of them runs the protection at a time:
/// both on one port would pass every packet through both.
/// </summary>
public enum BypassEngine
{
    Nfqws2,
    Geneva,
}

/// <summary>A Geneva strategy as text (<c>docs/STRATEGY.md</c> of geneva_c): a cheap shape check before <c>geneva check</c>.</summary>
public static class GenevaStrategyText
{
    public const int MaxLength = 2048;

    /// <summary>Why the text cannot be a strategy, or null. The real parse is <c>geneva check</c> (the Agent runs it before a start).</summary>
    public static string? Problem(string? s)
    {
        if (string.IsNullOrWhiteSpace(s))
            return "пустая стратегия / empty strategy";
        if (s.Length > MaxLength)
            return $"стратегия длиннее {MaxLength} символов / longer than {MaxLength} characters";
        foreach (var c in s)
        {
            // one line of printable ASCII: the strategy goes into a file and a command line
            if (c < 0x20 || c > 0x7E)
                return "стратегия — одна строка печатных ASCII-символов / one line of printable ASCII";
        }
        if (!s.Contains("\\/", StringComparison.Ordinal))
            return "нет разделителя \\/ между исходящими и входящими деревьями / no \\/ between outbound and inbound trees";
        return null;
    }

    /// <summary>geneva's baseline request: <c>eval_request</c> with no strategy at all (<c>src/evaluator.c</c>, <c>external_run</c>).</summary>
    public static bool IsEmpty(string? s) => string.IsNullOrWhiteSpace(s);

    private static readonly System.Text.RegularExpressions.Regex XAction = new(
        @"(?:^|[-(,])x[a-z0-9]+(?=[{(,)-]|$)|\[(?:L7|FLOW|META):", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>
    /// The strategy uses geneva_c 2.0's extensions (x-actions such as <c>xsplit{...}</c>, triggers <c>L7:</c>,
    /// <c>FLOW:</c>, <c>META:</c>): <c>check</c>, <c>run</c> and <c>evolve</c> need <c>--ext</c> for it. Geneva's own
    /// actions (tamper, duplicate, fragment, drop, sleep, trace) never start with an x.
    /// </summary>
    public static bool NeedsExt(string? s) => !string.IsNullOrEmpty(s) && XAction.IsMatch(s);
}

/// <summary>What the user (or the model over MCP) chose for a search; the Agent turns it into the command line.</summary>
public sealed record GenevaSearchSettings
{
    public required string Host { get; init; }

    public int Port { get; init; } = 443;

    /// <summary>TLS (HTTPS) or plain HTTP: the probe the UI runs for every strategy.</summary>
    public bool Tls { get; init; } = true;

    public int Population { get; init; } = 30;

    public int Generations { get; init; } = 15;

    /// <summary>Continue the saved search of this target (checkpoint) instead of starting over.</summary>
    public bool Resume { get; init; }

    /// <summary>Strategies to start the population from (the library, the found ones); at most <see cref="GenevaArgv.MaxSeeds"/>.</summary>
    public IReadOnlyList<string> Seeds { get; init; } = [];

    /// <summary>The packet layers the search may use (geneva's <c>--protos</c>): TCP for sites, UDP and IP for the rest.</summary>
    public string Protos { get; init; } = "TCP";

    /// <summary>
    /// What the UI's probe checks: <c>web</c> (the page's full download, the default) or <c>replay</c> (the program's
    /// first packets sent again, the "Авто" mode's probe for protocols without a page). Part of the target key.
    /// </summary>
    public string Probe { get; init; } = GenevaArgv.WebProbe;

    /// <summary>
    /// Strategies judged at once (geneva's <c>--workers</c>), each from its own block of local ports. More than one
    /// needs geneva_c with the feature <c>external_workers</c>; the Agent runs one otherwise.
    /// </summary>
    public int Workers { get; init; } = 1;

    public static (int Min, int Max) WorkersRange => (1, 8);

    public static IReadOnlySet<string> Layers { get; } = new HashSet<string>(StringComparer.Ordinal) { "IP", "TCP", "UDP", "DNS", "DNSQR" };

    public static (int Min, int Max) PopulationRange => (4, 500);

    public static (int Min, int Max) GenerationsRange => (1, 500);

    public IReadOnlyList<string> Problems()
    {
        var p = new List<string>();
        // a server without a name (the "Авто" mode's WireGuard, DNS) is searched by its address
        if (!Target.IsValidHostName(Host) && !(Probe == GenevaArgv.ReplayProbe && IPAddress.TryParse(Host, out _)))
            p.Add($"не имя сайта: {Host} / not a host name");
        if (Probe is not (GenevaArgv.WebProbe or GenevaArgv.ReplayProbe))
            p.Add($"неизвестная проба {Probe} / unknown probe");
        var layers = Protos.Split(',');
        if (layers.Length == 0 || layers.Any(l => !Layers.Contains(l)))
            p.Add($"слои {Protos}: только {string.Join(",", Layers)} / layers out of {string.Join(",", Layers)}");
        if (Port is < 1 or > 65535)
            p.Add($"порт {Port} вне 1–65535 / port out of range");
        if (Population < PopulationRange.Min || Population > PopulationRange.Max)
            p.Add($"популяция {Population} вне {PopulationRange.Min}–{PopulationRange.Max} / population out of range");
        if (Generations < GenerationsRange.Min || Generations > GenerationsRange.Max)
            p.Add($"поколений {Generations} вне {GenerationsRange.Min}–{GenerationsRange.Max} / generations out of range");
        if (Workers < WorkersRange.Min || Workers > WorkersRange.Max)
            p.Add($"потоков {Workers} вне {WorkersRange.Min}–{WorkersRange.Max} / workers out of range");
        if (Seeds.Count > GenevaArgv.MaxSeeds)
            p.Add($"больше {GenevaArgv.MaxSeeds} стратегий для засева / too many seeds");
        foreach (var s in Seeds)
        {
            if (GenevaStrategyText.Problem(s) is { } bad)
                p.Add(bad);
        }
        return p;
    }

    /// <summary>The target profile in geneva's strategy database: the same host and port share their results.</summary>
    public string TargetKey => GenevaArgv.TargetKey(Host, Port, Probe);

    /// <summary>
    /// geneva_c 2.0's extensions (<c>--ext</c>): a seed or the saved population holds x-actions, or geneva makes x-actions
    /// and changes their parameters itself (<see cref="XGen"/>).
    /// </summary>
    public bool Ext => Seeds.Any(GenevaStrategyText.NeedsExt) || ResumeExt || XGen;

    /// <summary>
    /// geneva_c has the feature <c>ext_xgen</c>: with <c>--ext</c> its search makes new x-actions of zapret2 and mutates
    /// their parameters (without it the x-actions of the seeds are only crossed over). The search then always runs with
    /// <c>--ext</c>, so every kind of strategy with every parameter takes part.
    /// </summary>
    public bool XGen { get; init; }

    /// <summary>The search being continued was started with <c>--ext</c> (its checkpoint may hold x-actions).</summary>
    public bool ResumeExt { get; init; }

    /// <summary>
    /// What the page must show for a strategy to count (dpi-diagnostics §3): 128 KB with padding behind the 16 KB
    /// cut-off, the speed behind a shaper. The search's baseline can tighten it (<c>PageCheck</c>). Not sent to the Agent.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public ProbeCriteria Criteria { get; init; } = ProbeCriteria.Default;
}

/// <summary>The strategy that bypasses on this PC: one strategy for every connection to the ports (geneva has no hostlist).</summary>
public sealed record GenevaRunSettings
{
    public required string Strategy { get; init; }

    public string Ports { get; init; } = "80,443";

    /// <summary>
    /// Subnets no packet of the bypass is applied to (a VPN or proxy server): geneva_c 2.0's
    /// <c>--ipset-exclude-ip</c>. Needs the feature <c>ext_lists</c>; the Agent leaves them out otherwise.
    /// </summary>
    public IReadOnlyList<string> ExcludeSubnets { get; init; } = [];

    /// <summary>Names (with subdomains) the bypass leaves alone: <c>--hostlist-exclude-domains</c>.</summary>
    public IReadOnlyList<string> ExcludeDomains { get; init; } = [];

    public IReadOnlyList<string> Problems()
    {
        var p = new List<string>();
        if (GenevaStrategyText.Problem(Strategy) is { } bad)
            p.Add(bad);
        foreach (var e in ExcludeSubnets.Concat(ExcludeDomains))
        {
            if (Auto.AutoNameList.Problem(e) is { } wrong)
                p.Add(wrong);
            else if (e.Contains(',', StringComparison.Ordinal) || e.Trim().Length == 0)
                p.Add($"исключение не разобрано / an exclusion not understood: {e}");
        }
        try
        {
            var ranges = PortList.ParseRanges(Ports);
            if (ranges.Count == 0 || ranges.Count > 16 || ranges.Any(r => r.From < 1 || r.To > 65535 || r.From > r.To))
                p.Add($"порты {Ports}: 1–16 диапазонов в 1–65535 / ports: 1–16 ranges in 1–65535");
        }
        catch (FormatException)
        {
            p.Add($"порты {Ports} не разобраны / ports not understood");
        }
        return p;
    }
}

/// <summary>
/// The command lines the Agent runs (<c>docs/INTEGRATION.md</c> of geneva_c, "Zapret2_AutoTuner"). Only typed settings
/// come from the UI; the paths, queues and the control token are the Agent's. Queues are apart from zapret2's (300–321)
/// and from geneva's defaults (310, 311), which this program's protection already uses.
/// </summary>
public static class GenevaArgv
{
    public const int RunQueue = 330;
    public const int EvalQueue = 331;
    public const int LocalPortsBase = 30000;

    /// <summary>The block of local ports of one worker: the probe connects from these, the strategy applies only to them.</summary>
    public const int LocalPortsCount = 64;

    public const int MaxSeeds = 50;

    /// <summary>Seconds between stats events of <c>geneva run</c>: the page's telemetry.</summary>
    public const int StatsInterval = 2;

    public const string WebProbe = "web";

    public const string ReplayProbe = "replay";

    /// <summary>The profile in geneva's database and the checkpoint's folder: a replay of a server is another target than its page.</summary>
    public static string TargetKey(string host, int port, string probe = WebProbe) =>
        $"external:{(probe == ReplayProbe ? "replay:" : "")}{host.ToLowerInvariant()}:{port.ToString(CultureInfo.InvariantCulture)}";

    /// <summary><c>geneva run</c> with events on stdout and the control socket on loopback (the token goes in the environment).</summary>
    /// <param name="lists">geneva_c has the feature <c>ext_lists</c>: the exclusions go in; without it they cannot.</param>
    public static List<string> Run(GenevaRunSettings s, int controlPort, bool lists = false)
    {
        var bad = s.Problems();
        if (bad.Count > 0)
            throw new FormatException(string.Join("; ", bad));
        var a = new List<string> { "run" };
        bool exclude = lists && (s.ExcludeSubnets.Count > 0 || s.ExcludeDomains.Count > 0);
        // the extensions only when needed: without them geneva behaves exactly as before
        if (exclude || GenevaStrategyText.NeedsExt(s.Strategy))
            a.Add("--ext");
        a.AddRange(
        [
            "-s", s.Strategy, "-p", NormalizePorts(s.Ports),
            "-q", RunQueue.ToString(CultureInfo.InvariantCulture),
            "-c", "tcp:" + controlPort.ToString(CultureInfo.InvariantCulture),
            "-e", "-", "--stats-interval", StatsInterval.ToString(CultureInfo.InvariantCulture),
            "--quiet",
        ]);
        if (exclude && s.ExcludeSubnets.Count > 0)
            a.AddRange(["--ipset-exclude-ip", string.Join(',', s.ExcludeSubnets)]);
        if (exclude && s.ExcludeDomains.Count > 0)
            a.AddRange(["--hostlist-exclude-domains", string.Join(',', s.ExcludeDomains)]);
        return a;
    }

    /// <summary>
    /// <c>geneva evolve --probe external</c>: geneva puts each strategy on the probe's local ports and asks the UI, which
    /// loads the page from those ports and answers (success is the full download, AGENTS.md rule 5). With several
    /// workers each asks from its own block, and the answers go back by id.
    /// </summary>
    public static List<string> Evolve(GenevaSearchSettings s, string checkpoint, string db, string? seedsFile)
    {
        var bad = s.Problems();
        if (bad.Count > 0)
            throw new FormatException(string.Join("; ", bad));
        var a = new List<string> { "evolve" };
        if (s.Ext)
            a.Add("--ext");
        a.AddRange(new[]
        {
            "--probe", "external", "--host", s.Host.ToLowerInvariant(), "--port", s.Port.ToString(CultureInfo.InvariantCulture),
            "--population", s.Population.ToString(CultureInfo.InvariantCulture),
            "--generations", s.Generations.ToString(CultureInfo.InvariantCulture),
            "--workers", s.Workers.ToString(CultureInfo.InvariantCulture), "--local-ports", LocalPortsBase.ToString(CultureInfo.InvariantCulture),
            "-q", EvalQueue.ToString(CultureInfo.InvariantCulture),
            "--checkpoint", checkpoint, "--db", db, "--target", s.TargetKey,
            "--top", "10", "-e", "-", "--quiet",
        });
        if (s.Protos != "TCP")
        {
            a.Add("--protos");
            a.Add(s.Protos);
        }
        if (s.Resume)
            a.Add("--resume");
        if (seedsFile is not null && !s.Resume)
        {
            a.Add("--load-from");
            a.Add(seedsFile);
        }
        return a;
    }

    /// <summary>The ports as geneva takes them: "80,443", "8000-8100".</summary>
    public static string NormalizePorts(string ports) => PortList.Format(PortList.Merge(PortList.ParseRanges(ports)));

    /// <summary>The local port the probe uses for its <paramref name="n"/>-th connection inside the block (rotated: TIME_WAIT).</summary>
    public static int LocalPort(string lports, int n)
    {
        var (from, to) = ParseLocalPorts(lports);
        return from + (int)((uint)n % (uint)(to - from + 1));
    }

    public static (int From, int To) ParseLocalPorts(string lports)
    {
        var parts = lports.Split('-');
        if (parts.Length == 2 && int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var a)
            && int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var b) && a >= 1024 && b <= 65535 && a <= b)
            return (a, b);
        throw new FormatException($"lports {lports}");
    }
}

/// <summary>
/// Geneva's fitness for the UI's probe (<c>docs/EVAL.md</c> of geneva_c): +400 for the full download, the client plugins'
/// penalties for the ways it failed. geneva subtracts its own punishments (actions, idle trees) after that.
/// </summary>
public static class GenevaFitness
{
    public static (int Fitness, string Outcome) FromProbe(ProbeResult r, ProbeLevel level = ProbeLevel.L2Body, long minBytes = 64 * 1024)
    {
        if (r.Passes(level, minBytes))
            return (400, "ok");
        return r.Error switch
        {
            ProbeError.ConnectTimeout or ProbeError.Unreachable => (-400, "connect_timeout"),
            ProbeError.ConnectRefused or ProbeError.TlsReset or ProbeError.HttpReset => (-360, "reset"),
            ProbeError.TlsTimeout or ProbeError.HttpTimeout or ProbeError.Stalled => (-480, "timeout"),
            ProbeError.Truncated or ProbeError.BadResponse or ProbeError.TlsClosed or ProbeError.TimeLimit => (-480, "broken"),
            // a shaper: the page came, but on the shelf (dpi-diagnostics §2.16)
            ProbeError.Throttled => (-480, "throttled"),
            // a certificate for another name is a block page or a forged answer
            ProbeError.None when r.Tls && r.TlsOk && !r.CertValid => (-360, "injected"),
            ProbeError.None => (-480, "broken"),
            _ => (-400, "failed"),
        };
    }
}
