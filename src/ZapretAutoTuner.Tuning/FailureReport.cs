using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Tuning;

public sealed record ReportOptions
{
    /// <summary>Replace the domains with d1, d2… (the user's choice).</summary>
    public bool MaskDomains { get; init; }

    /// <summary>The engine's --debug lines of the run (only a tail goes in).</summary>
    public IReadOnlyList<string> EngineLog { get; init; } = [];

    /// <summary>A capture of the failing attempts, summarised (RST, retransmissions, where it stopped).</summary>
    public IReadOnlyList<Flow> Flows { get; init; } = [];

    /// <summary>Extra environment lines: VM, antivirus, DoH (from the UI).</summary>
    public IReadOnlyList<string> Environment { get; init; } = [];

    public int MaxLogLines { get; init; } = 300;

    /// <summary>The MCP audit log: every call an external agent made (already masked).</summary>
    public IReadOnlyList<string> McpAudit { get; init; } = [];
}

/// <summary>
/// "Собрать отчёт" (PLAN, release 1): everything needed to see why no strategy was found, as one archive and as text
/// for a chat, with a ready prompt for Claude. The user's addresses are masked always, domains on request. Nothing is
/// sent anywhere: the user decides what to do with the file.
/// </summary>
public static partial class FailureReport
{
    public static string Text(IReadOnlyList<TargetOutcome> targets, ReportOptions o)
    {
        var mask = new Masker(o.MaskDomains);
        var sb = new StringBuilder();
        sb.AppendLine(CultureInfo.InvariantCulture, $"# Отчёт {AppInfo.Name} {AppInfo.Version} / report");
        sb.AppendLine();
        sb.AppendLine("## Окружение / environment");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- ОС: {RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture})");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- zapret2: {AppInfo.Zapret2Version}");
        foreach (var e in o.Environment)
            sb.AppendLine(CultureInfo.InvariantCulture, $"- {mask.Line(e)}");
        foreach (var t in targets)
        {
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"## {mask.Domain(t.Host)}");
            if (t.Error is not null)
                sb.AppendLine(CultureInfo.InvariantCulture, $"Ошибка / error: {mask.Line(t.Error)}");
            if (t.Verdict is { } v)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"Вердикт / verdict: {v.Primary} → {v.Next}");
                foreach (var f in v.Findings)
                    sb.AppendLine(CultureInfo.InvariantCulture, $"- {f.Label}{(f.Address is null ? "" : " @ " + mask.Address(f.Address))}: {mask.Line(string.Join("; ", f.Evidence))}");
            }
            if (t.Search is { } s)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"Перебор / search: {s.Tried} стратегий, {s.Reason}, {s.Elapsed:hh\\:mm\\:ss}, рабочих {s.Working.Count}");
                if (s.BestPartial is { } p)
                    sb.AppendLine(CultureInfo.InvariantCulture, $"Лучшая частичная / best partial: {p.Efficiency.Successes}/{p.Efficiency.Attempts} `{p.Candidate.Strategy}`");
            }
            foreach (var f in t.Final)
                sb.AppendLine(CultureInfo.InvariantCulture, $"Финальная проверка / final: {(f.Passed ? "OK" : "FAIL")} L2 {f.L2.Successes}/{f.L2.Attempts} page={f.PageOk?.ToString() ?? "-"} {mask.Line(f.Error ?? "")} `{f.Strategy.Candidate.Strategy}`");
        }
        if (o.Flows.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("## Захват / capture");
            foreach (var f in o.Flows.Take(50))
            {
                var rst = f.Rsts.Count == 0 ? "" : " RST:" + string.Join(',', f.Rsts.Select(r => r.Origin));
                sb.AppendLine(CultureInfo.InvariantCulture,
                    $"- {f.Protocol} → {mask.Address(f.Server.Address.ToString())}:{f.Server.Port} sni={mask.Domain(f.ClientHello?.Sni ?? "-")} out={f.BytesOut} in={f.BytesIn} retrans={f.Retransmissions}{rst}");
            }
        }
        if (o.McpAudit.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("## Журнал MCP / MCP audit");
            sb.AppendLine("```");
            foreach (var l in o.McpAudit.TakeLast(o.MaxLogLines))
                sb.AppendLine(mask.Line(l));
            sb.AppendLine("```");
        }
        if (o.EngineLog.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("## Лог движка / engine log (хвост / tail)");
            sb.AppendLine("```");
            foreach (var l in o.EngineLog.TakeLast(o.MaxLogLines))
                sb.AppendLine(mask.Line(l));
            sb.AppendLine("```");
        }
        return sb.ToString();
    }

    /// <summary>The prompt that goes with the report.</summary>
    public static string Prompt { get; } = """
        Вот отчёт AutoTuner (подбор стратегий zapret2 / nfqws2, синтаксис --lua-desync). Рабочая стратегия не нашлась.
        Найди вероятную причину по вердикту классификатора, таблице попыток, захвату и логу движка и предложи
        конкретную правку стратегии (аргументы --lua-desync) или объясни, почему стратегия здесь не поможет.

        Here is an AutoTuner report (zapret2 / nfqws2 strategy search, --lua-desync syntax). No working strategy was
        found. Find the likely cause from the verdict, the attempts, the capture and the engine log, and suggest a
        concrete strategy change or explain why no strategy can help.
        """;

    /// <summary>The archive: report.md, prompt.txt and attempts.csv.</summary>
    public static byte[] Archive(IReadOnlyList<TargetOutcome> targets, IReadOnlyList<(string Host, StrategyCandidate Candidate, TrialOutcome Outcome)> attempts, ReportOptions o)
    {
        var mask = new Masker(o.MaskDomains);
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            Add(zip, "report.md", Text(targets, o));
            Add(zip, "prompt.txt", Prompt);
            var csv = new StringBuilder("host;family;strategy;ok;failure;detail;bytes_in;ms\n");
            foreach (var (host, c, r) in attempts)
                csv.AppendLine(CultureInfo.InvariantCulture,
                    $"{Csv(mask.Domain(host))};{Csv(c.Family)};{Csv(c.Strategy.ToString())};{(r.Ok ? 1 : 0)};{r.Failure};{Csv(mask.Line(r.Detail ?? ""))};{r.BytesIn};{(long)r.Duration.TotalMilliseconds}");
            Add(zip, "attempts.csv", csv.ToString());
        }
        return ms.ToArray();
    }

    private static void Add(ZipArchive zip, string name, string text)
    {
        using var w = new StreamWriter(zip.CreateEntry(name).Open(), new UTF8Encoding(false));
        w.Write(text);
    }

    private static string Csv(string s) => s.Contains(';', StringComparison.Ordinal) || s.Contains('"', StringComparison.Ordinal) ? "\"" + s.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : s;

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")]
    private static partial Regex AddressRe();

    /// <summary>
    /// Private and CGNAT addresses (the user's own) become "lan-N", public ones keep their prefix only
    /// (a.b.c.x): the server matters for the diagnosis, the exact host rarely does. Domains become d1, d2… when asked.
    /// </summary>
    internal sealed class Masker(bool domains)
    {
        private readonly Dictionary<string, string> _map = new(StringComparer.OrdinalIgnoreCase);

        public string Address(string a)
        {
            if (!IPAddress.TryParse(a, out var ip))
                return a;
            if (!Core.Programs.ProgramEndpoints.IsInternet(ip))
                return Map("lan:" + a, "lan-");
            var b = ip.GetAddressBytes();
            return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                ? $"{b[0]}.{b[1]}.{b[2]}.x"
                : $"{b[0]:x2}{b[1]:x2}:{b[2]:x2}{b[3]:x2}:{b[4]:x2}{b[5]:x2}::x";
        }

        public string Domain(string d) => domains && d != "-" && d.Length > 0 ? Map("d:" + d, "d") : d;

        public string Line(string line)
        {
            var s = AddressRe().Replace(line, m => Address(m.Value));
            if (domains)
                foreach (var (k, v) in _map.Where(kv => kv.Key.StartsWith("d:", StringComparison.Ordinal)).ToList())
                    s = s.Replace(k[2..], v, StringComparison.OrdinalIgnoreCase);
            return s;
        }

        private string Map(string key, string prefix)
        {
            if (!_map.TryGetValue(key, out var v))
                _map[key] = v = prefix + (_map.Count(kv => kv.Value.StartsWith(prefix, StringComparison.Ordinal)) + 1).ToString(CultureInfo.InvariantCulture);
            return v;
        }
    }
}
