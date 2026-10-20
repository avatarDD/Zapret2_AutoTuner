using System.Text;
using YamlDotNet.RepresentationModel;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Search;

/// <summary>How deep the search goes (PLAN 3.1).</summary>
public enum SearchMode
{
    Quick,
    Standard,
    Full,
}

/// <summary>What the target speaks: picks the payload filter and the families.</summary>
public enum TargetProtocol
{
    Tls,
    Http,
    Quic,
}

/// <summary>One strategy the search will try, with where it came from.</summary>
public sealed record StrategyCandidate(Strategy Strategy, string Family, int Order, IReadOnlyList<string> Tags, L4Kind L4)
{
    public string Key => Strategy.ToString();

    public override string ToString() => $"[{Family}] {Strategy}";
}

/// <summary>A strategy family from <c>Search/Data/families.yaml</c>.</summary>
public sealed class StrategyFamily
{
    public required string Id { get; init; }

    public int Order { get; init; }

    public L4Kind L4 { get; init; } = L4Kind.Tcp;

    public IReadOnlyList<TargetProtocol> Protocols { get; init; } = [];

    /// <summary><c>tls_client_hello</c>, <c>http_req</c>, <c>quic_initial</c>, <c>auto</c> (by protocol) or <c>none</c>.</summary>
    public string Payload { get; init; } = "auto";

    public IReadOnlyList<SearchMode> Modes { get; init; } = [SearchMode.Quick, SearchMode.Standard, SearchMode.Full];

    public IReadOnlyList<BlockLabel> FirstFor { get; init; } = [];

    public IReadOnlyList<BlockLabel> SkipFor { get; init; } = [];

    public IReadOnlyList<string> SkipIfWorking { get; init; } = [];

    public IReadOnlyList<string> Tags { get; init; } = [];

    public IReadOnlyList<string> Templates { get; init; } = [];

    /// <summary>Axis name → per-mode values (or a <c>@set</c> reference), in file order.</summary>
    public IReadOnlyList<(string Name, AxisValues Values)> Axes { get; init; } = [];
}

/// <summary>Values of an axis for each mode, or a reference to a shared set.</summary>
public sealed class AxisValues
{
    public string? SetRef { get; init; }

    public IReadOnlyDictionary<SearchMode, IReadOnlyList<string>> ByMode { get; init; } = new Dictionary<SearchMode, IReadOnlyList<string>>();
}

/// <summary>The families file, parsed. Data, not code (AGENTS.md rule 3).</summary>
public sealed class FamilyCatalog
{
    public IReadOnlyList<StrategyFamily> Families { get; init; } = [];

    public IReadOnlyDictionary<string, AxisValues> Sets { get; init; } = new Dictionary<string, AxisValues>();

    private static readonly Lazy<FamilyCatalog> DefaultLazy = new(() =>
    {
        using var s = typeof(FamilyCatalog).Assembly.GetManifestResourceStream("ZapretAutoTuner.Core.Search.families.yaml")
            ?? throw new InvalidOperationException("families.yaml is missing");
        using var r = new StreamReader(s, Encoding.UTF8);
        return Parse(r.ReadToEnd());
    });

    public static FamilyCatalog Default => DefaultLazy.Value;

    public StrategyFamily this[string id] => Families.Single(f => f.Id == id);

    public static FamilyCatalog Parse(string yaml)
    {
        var stream = new YamlStream();
        stream.Load(new StringReader(yaml));
        var root = (YamlMappingNode)stream.Documents[0].RootNode;
        var sets = new Dictionary<string, AxisValues>(StringComparer.Ordinal);
        if (root.Children.TryGetValue(new YamlScalarNode("sets"), out var setsNode))
        {
            foreach (var (k, v) in ((YamlMappingNode)setsNode).Children)
                sets[Str(k)] = Axis(v);
        }
        var families = new List<StrategyFamily>();
        foreach (var node in ((YamlSequenceNode)root.Children[new YamlScalarNode("families")]).Children.Cast<YamlMappingNode>())
        {
            string Get(string key, string def) => node.Children.TryGetValue(new YamlScalarNode(key), out var v) ? Str(v) : def;
            List<string> List(string key) => node.Children.TryGetValue(new YamlScalarNode(key), out var v) ? Strs(v) : [];
            var axes = new List<(string, AxisValues)>();
            if (node.Children.TryGetValue(new YamlScalarNode("axes"), out var axesNode))
            {
                foreach (var (k, v) in ((YamlMappingNode)axesNode).Children)
                    axes.Add((Str(k), Axis(v)));
            }
            var f = new StrategyFamily
            {
                Id = Get("id", ""),
                Order = int.Parse(Get("order", "100"), System.Globalization.CultureInfo.InvariantCulture),
                L4 = Get("l4", "tcp") == "udp" ? L4Kind.Udp : L4Kind.Tcp,
                Protocols = List("protocols").Select(p => Enum.Parse<TargetProtocol>(p, ignoreCase: true)).ToList(),
                Payload = Get("payload", "auto"),
                Modes = List("modes") is { Count: > 0 } m ? m.Select(x => Enum.Parse<SearchMode>(x, ignoreCase: true)).ToList() : [SearchMode.Quick, SearchMode.Standard, SearchMode.Full],
                FirstFor = List("first_for").Select(x => Enum.Parse<BlockLabel>(x)).ToList(),
                SkipFor = List("skip_for").Select(x => Enum.Parse<BlockLabel>(x)).ToList(),
                SkipIfWorking = List("skip_if_working"),
                Tags = List("tags"),
                Templates = List("templates"),
                Axes = axes,
            };
            if (f.Id.Length == 0 || f.Templates.Count == 0)
                throw new FormatException("a family needs an id and templates");
            families.Add(f);
        }
        return new FamilyCatalog { Families = families, Sets = sets };
    }

    private static AxisValues Axis(YamlNode n)
    {
        if (n is YamlScalarNode s && Str(s).StartsWith('@'))
            return new AxisValues { SetRef = Str(s)[1..] };
        if (n is YamlSequenceNode)
        {
            var all = Strs(n);
            return new AxisValues { ByMode = Enum.GetValues<SearchMode>().ToDictionary(m => m, _ => (IReadOnlyList<string>)all) };
        }
        var map = (YamlMappingNode)n;
        var d = new Dictionary<SearchMode, IReadOnlyList<string>>();
        IReadOnlyList<string>? prev = null;
        string? prevRef = null;
        foreach (var mode in Enum.GetValues<SearchMode>())
        {
            if (map.Children.TryGetValue(new YamlScalarNode(mode.ToString().ToLowerInvariant()), out var v))
            {
                if (v is YamlScalarNode r && Str(r).StartsWith('@'))
                {
                    prevRef = Str(r)[1..];
                    d[mode] = ["@" + prevRef];
                    prev = d[mode];
                    continue;
                }
                prev = Strs(v);
            }
            if (prev is null)
                throw new FormatException("an axis map must start with quick");
            d[mode] = prev;
        }
        return new AxisValues { ByMode = d };
    }

    private static string Str(YamlNode n) => ((YamlScalarNode)n).Value ?? "";

    private static List<string> Strs(YamlNode n) => n is YamlSequenceNode seq ? seq.Children.Select(Str).ToList() : [Str(n)];
}

public sealed record GeneratorOptions
{
    public SearchMode Mode { get; init; } = SearchMode.Standard;

    public TargetProtocol Protocol { get; init; } = TargetProtocol.Tls;

    /// <summary>Labels from the classifier: they reorder and cut the families (dpi-diagnostics §6.2).</summary>
    public IReadOnlyCollection<BlockLabel> Labels { get; init; } = [];

    /// <summary>A domain the DPI lets through, for fakes and the overlap pattern.</summary>
    public string WhiteSni { get; init; } = "www.google.com";

    public EnginePlatform Platform { get; init; } = OperatingSystem.IsWindows() ? EnginePlatform.Windows : EnginePlatform.Linux;

    /// <summary>The client sends TCP timestamps; without them <c>tcp_ts</c> fooling is useless and is not generated.</summary>
    public bool TcpTimestamps { get; init; } = !OperatingSystem.IsWindows();

    /// <summary>Families to leave out entirely (for example <c>wssize</c> when the user refuses slow strategies).</summary>
    public IReadOnlyCollection<string> ExcludeFamilies { get; init; } = [];
}

public sealed record GeneratedSet(
    IReadOnlyList<StrategyCandidate> Candidates,
    IReadOnlyList<(string Strategy, string Family, IReadOnlyList<ValidationIssue> Issues)> Rejected,
    IReadOnlyDictionary<string, string> Blobs)
{
    public IEnumerable<StrategyCandidate> OfFamily(string id) => Candidates.Where(c => c.Family == id);
}

/// <summary>
/// Expands the families into an ordered list of candidates for one target (PLAN 3.1): families in blockcheck2 order,
/// the ones the block label calls for first, the pointless ones cut; every candidate validated (AGENTS.md rule 4).
/// </summary>
public static class StrategyGenerator
{
    /// <summary>Name of the declared blob holding a real ClientHello of <see cref="GeneratorOptions.WhiteSni"/>.</summary>
    public const string WhiteBlob = "tls_white";

    public static GeneratedSet Generate(GeneratorOptions o, FamilyCatalog? catalog = null)
    {
        catalog ??= FamilyCatalog.Default;
        var blobs = new Dictionary<string, string>(StringComparer.Ordinal) { [WhiteBlob] = WhiteHelloHex(o.WhiteSni) };
        var validator = new StrategyValidator(new ValidationContext
        {
            Platform = o.Platform,
            DeclaredBlobs = blobs.ToDictionary(kv => kv.Key, kv => (long?)((kv.Value.Length - 2) / 2)),
        });

        var families = catalog.Families
            .Where(f => f.Protocols.Contains(o.Protocol) && f.Modes.Contains(o.Mode))
            .Where(f => !f.SkipFor.Any(o.Labels.Contains) && !o.ExcludeFamilies.Contains(f.Id))
            .OrderBy(f => f.FirstFor.Any(o.Labels.Contains) || FirstForLabel(f, o.Labels) ? 0 : 1)
            .ThenBy(f => f.Order)
            .ThenBy(f => f.Id, StringComparer.Ordinal)
            .ToList();

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var candidates = new List<StrategyCandidate>();
        var rejected = new List<(string, string, IReadOnlyList<ValidationIssue>)>();
        foreach (var f in families)
        {
            var familyCandidates = new List<StrategyCandidate>();
            foreach (var text in Expand(f, o, catalog))
            {
                if (!o.TcpTimestamps && text.Contains("tcp_ts=", StringComparison.Ordinal))
                    continue;
                Strategy s;
                try
                {
                    s = Strategy.Parse(text);
                }
                catch (FormatException e)
                {
                    rejected.Add((text, f.Id, [new ValidationIssue(Severity.Error, "parse", e.Message, e.Message)]));
                    continue;
                }
                if (!seen.Add(s.ToString()))
                    continue;
                var v = validator.ValidateStrategy(s, f.L4);
                if (!v.Ok)
                {
                    rejected.Add((s.ToString(), f.Id, v.Errors.ToList()));
                    continue;
                }
                familyCandidates.Add(new StrategyCandidate(s, f.Id, f.Order, f.Tags, f.L4));
            }
            // a volume cut-off is passed by fakes that look like a white domain: those go first within the family
            if (o.Labels.Contains(BlockLabel.Cutoff16K))
                familyCandidates = [.. familyCandidates.OrderBy(c => UsesWhite(c, o.WhiteSni) ? 0 : 1)];
            candidates.AddRange(familyCandidates);
        }
        return new GeneratedSet(candidates, rejected, blobs);
    }

    /// <summary>Global <c>--blob=</c> options for the candidates' blobs.</summary>
    public static IEnumerable<string> BlobArgs(GeneratedSet set) => set.Blobs.Select(kv => $"--blob={kv.Key}:{kv.Value}");

    internal static IEnumerable<string> Expand(StrategyFamily f, GeneratorOptions o, FamilyCatalog catalog)
    {
        var protocol = o.Protocol == TargetProtocol.Http ? "http" : "tls";
        var axes = f.Axes.Select(a => (a.Name, Values: Resolve(a.Values, o.Mode, protocol, catalog))).ToList();
        string payload = f.Payload switch
        {
            "none" => "",
            "auto" => o.Protocol switch { TargetProtocol.Http => "--payload=http_req ", TargetProtocol.Quic => "--payload=quic_initial ", _ => "--payload=tls_client_hello " },
            var p => $"--payload={p} ",
        };
        foreach (var template in f.Templates)
        {
            var used = axes.Where(a => template.Contains("{" + a.Name + "}", StringComparison.Ordinal)).ToList();
            foreach (var combo in Product(used.Select(a => a.Values).ToList()))
            {
                var text = template;
                for (int i = 0; i < used.Count; i++)
                    text = text.Replace("{" + used[i].Name + "}", combo[i], StringComparison.Ordinal);
                text = text.Replace("{white}", o.WhiteSni, StringComparison.Ordinal); // also inside axis values
                // an empty fooling or tls_mod value leaves "::" or a trailing ":" behind
                while (text.Contains("::", StringComparison.Ordinal))
                    text = text.Replace("::", ":", StringComparison.Ordinal);
                text = text.Replace(": ", " ", StringComparison.Ordinal).TrimEnd(':');
                // the payload filter goes after an --in-range that must come first
                yield return text.StartsWith("--in-range", StringComparison.Ordinal) || payload.Length == 0 ? text : payload + text;
            }
        }
    }

    private static IReadOnlyList<string> Resolve(AxisValues a, SearchMode mode, string protocol, FamilyCatalog catalog, int depth = 0)
    {
        if (depth > 4)
            throw new FormatException("set references nest too deep");
        if (a.SetRef is { } r)
            return Resolve(SetOf(r, protocol, catalog), mode, protocol, catalog, depth + 1);
        var values = a.ByMode[mode];
        if (values.Count == 1 && values[0].StartsWith('@'))
            return Resolve(SetOf(values[0][1..], protocol, catalog), mode, protocol, catalog, depth + 1);
        return values;
    }

    private static AxisValues SetOf(string name, string protocol, FamilyCatalog catalog) =>
        catalog.Sets.TryGetValue(name, out var s) ? s
        : catalog.Sets.TryGetValue($"{name}_{protocol}", out s) ? s
        : throw new FormatException($"unknown set @{name}");

    private static IEnumerable<string[]> Product(IReadOnlyList<IReadOnlyList<string>> lists)
    {
        if (lists.Count == 0)
        {
            yield return [];
            yield break;
        }
        var idx = new int[lists.Count];
        if (lists.Any(l => l.Count == 0))
            yield break;
        while (true)
        {
            yield return idx.Select((v, i) => lists[i][v]).ToArray();
            int k = lists.Count - 1;
            while (k >= 0 && ++idx[k] == lists[k].Count)
            {
                idx[k] = 0;
                k--;
            }
            if (k < 0)
                yield break;
        }
    }

    private static bool FirstForLabel(StrategyFamily f, IReadOnlyCollection<BlockLabel> labels) =>
        labels.Contains(BlockLabel.Cutoff16K) && f.Templates.Any(t => t.Contains(WhiteBlob, StringComparison.Ordinal));

    private static bool UsesWhite(StrategyCandidate c, string white)
    {
        var s = c.Key;
        return s.Contains(WhiteBlob, StringComparison.Ordinal) || s.Contains(white, StringComparison.Ordinal);
    }

    /// <summary>A real single-packet ClientHello for the white domain (no kyber, so it fits one segment).</summary>
    internal static string WhiteHelloHex(string sni)
    {
        var rec = ClientHelloBuilder.BuildRecord(ClientHelloSpec.Get("chrome_legacy"), new ClientHelloOptions { Sni = sni, Kyber = false, Ech = false, Seed = 1 });
        return "0x" + Convert.ToHexStringLower(rec);
    }
}
