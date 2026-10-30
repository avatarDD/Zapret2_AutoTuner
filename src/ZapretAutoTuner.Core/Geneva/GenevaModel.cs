using System.Globalization;
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

    public static (int Min, int Max) PopulationRange => (4, 500);

    public static (int Min, int Max) GenerationsRange => (1, 500);

    public IReadOnlyList<string> Problems()
    {
        var p = new List<string>();
        if (!Target.IsValidHostName(Host))
            p.Add($"не имя сайта: {Host} / not a host name");
        if (Port is < 1 or > 65535)
            p.Add($"порт {Port} вне 1–65535 / port out of range");
        if (Population < PopulationRange.Min || Population > PopulationRange.Max)
            p.Add($"популяция {Population} вне {PopulationRange.Min}–{PopulationRange.Max} / population out of range");
        if (Generations < GenerationsRange.Min || Generations > GenerationsRange.Max)
            p.Add($"поколений {Generations} вне {GenerationsRange.Min}–{GenerationsRange.Max} / generations out of range");
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
    public string TargetKey => GenevaArgv.TargetKey(Host, Port);
}

/// <summary>The strategy that bypasses on this PC: one strategy for every connection to the ports (geneva has no hostlist).</summary>
public sealed record GenevaRunSettings
{
    public required string Strategy { get; init; }

    public string Ports { get; init; } = "80,443";

    public IReadOnlyList<string> Problems()
    {
        var p = new List<string>();
        if (GenevaStrategyText.Problem(Strategy) is { } bad)
            p.Add(bad);
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

    /// <summary>The block of local ports of the one worker: the probe connects from these, the strategy applies only to them.</summary>
    public const int LocalPortsCount = 64;

    public const int MaxSeeds = 50;

    /// <summary>Seconds between stats events of <c>geneva run</c>: the page's telemetry.</summary>
    public const int StatsInterval = 2;

    public static string TargetKey(string host, int port) => $"external:{host.ToLowerInvariant()}:{port.ToString(CultureInfo.InvariantCulture)}";

    /// <summary><c>geneva run</c> with events on stdout and the control socket on loopback (the token goes in the environment).</summary>
    public static List<string> Run(GenevaRunSettings s, int controlPort)
    {
        var bad = s.Problems();
        if (bad.Count > 0)
            throw new FormatException(string.Join("; ", bad));
        return
        [
            "run", "-s", s.Strategy, "-p", NormalizePorts(s.Ports),
            "-q", RunQueue.ToString(CultureInfo.InvariantCulture),
            "-c", "tcp:" + controlPort.ToString(CultureInfo.InvariantCulture),
            "-e", "-", "--stats-interval", StatsInterval.ToString(CultureInfo.InvariantCulture),
            "--quiet",
        ];
    }

    /// <summary>
    /// <c>geneva evolve --probe external</c>: geneva puts each strategy on the probe's local ports and asks the UI, which
    /// loads the page from those ports and answers (success is the full download, AGENTS.md rule 5). One worker.
    /// </summary>
    public static List<string> Evolve(GenevaSearchSettings s, string checkpoint, string db, string? seedsFile)
    {
        var bad = s.Problems();
        if (bad.Count > 0)
            throw new FormatException(string.Join("; ", bad));
        var a = new List<string>
        {
            "evolve", "--probe", "external", "--host", s.Host.ToLowerInvariant(), "--port", s.Port.ToString(CultureInfo.InvariantCulture),
            "--population", s.Population.ToString(CultureInfo.InvariantCulture),
            "--generations", s.Generations.ToString(CultureInfo.InvariantCulture),
            "--workers", "1", "--local-ports", LocalPortsBase.ToString(CultureInfo.InvariantCulture),
            "-q", EvalQueue.ToString(CultureInfo.InvariantCulture),
            "--checkpoint", checkpoint, "--db", db, "--target", s.TargetKey,
            "--top", "10", "-e", "-", "--quiet",
        };
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
    public static (int Fitness, string Outcome) FromProbe(ProbeResult r, ProbeLevel level = ProbeLevel.L2Body)
    {
        if (r.Passes(level))
            return (400, "ok");
        return r.Error switch
        {
            ProbeError.ConnectTimeout or ProbeError.Unreachable => (-400, "connect_timeout"),
            ProbeError.ConnectRefused or ProbeError.TlsReset or ProbeError.HttpReset => (-360, "reset"),
            ProbeError.TlsTimeout or ProbeError.HttpTimeout or ProbeError.Stalled => (-480, "timeout"),
            ProbeError.Truncated or ProbeError.BadResponse or ProbeError.TlsClosed or ProbeError.TimeLimit => (-480, "broken"),
            // a certificate for another name is a block page or a forged answer
            ProbeError.None when r.Tls && r.TlsOk && !r.CertValid => (-360, "injected"),
            ProbeError.None => (-480, "broken"),
            _ => (-400, "failed"),
        };
    }
}
