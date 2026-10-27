using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace ZapretAutoTuner.Core.Providers;

public sealed class ProviderRangeSource
{
    public string Url { get; set; } = "";

    /// <summary>text, aws, google, fastly, oracle, ripestat, geofeed, azure (see <see cref="RangeParsers"/>).</summary>
    public string Format { get; set; } = "text";

    /// <summary>
    /// When set, <see cref="Url"/> is a page and the list is the first link on it matching this regex: Azure's Service
    /// Tags file has a new dated name every week (<c>ServiceTags_Public_YYYYMMDD.json</c>), only its download page
    /// is stable.
    /// </summary>
    public string? Link { get; set; }

    /// <summary>Used only when no other source of the provider loaded (it is broader or less precise).</summary>
    public bool Fallback { get; set; }

    /// <summary>Shown when this source is used: what is wrong with it (for example an ASN shared with other services).</summary>
    public string? Warning { get; set; }
}

public sealed class ProviderEndpoint
{
    public string Url { get; set; } = "";

    /// <summary>A name the certificate must carry.</summary>
    public string San { get; set; } = "";

    public long MinBytes { get; set; } = 128 * 1024;
}

public sealed class Provider
{
    public string Id { get; set; } = "";

    public string Name { get; set; } = "";

    /// <summary>Part of "All major".</summary>
    public bool Major { get; set; }

    public List<int> Asn { get; set; } = [];

    public List<ProviderRangeSource> Ranges { get; set; } = [];

    public List<ProviderEndpoint> TestEndpoints { get; set; } = [];

    /// <summary>The ipset name in the exports, the zapret-gui form <c>&lt;provider&gt;-ipset</c> (strategy-export §4b).</summary>
    public string IpsetName => Id + "-ipset";
}

/// <summary>The provider catalog (dpi-diagnostics §4a): data, not code.</summary>
public sealed class ProviderCatalog
{
    public List<Provider> Providers { get; set; } = [];

    private static readonly Lazy<ProviderCatalog> DefaultLazy = new(() =>
    {
        using var s = typeof(ProviderCatalog).Assembly.GetManifestResourceStream("ZapretAutoTuner.Core.Providers.providers.json")
            ?? throw new InvalidOperationException("providers.json is missing");
        return Parse(s);
    });

    public static ProviderCatalog Default => DefaultLazy.Value;

    public Provider? Find(string id) => Providers.FirstOrDefault(p => p.Id == id);

    public IEnumerable<Provider> Major => Providers.Where(p => p.Major);

    public static ProviderCatalog Parse(Stream json) => JsonSerializer.Deserialize(json, ProvidersJsonContext.Default.ProviderCatalog) ?? new ProviderCatalog();
}

/// <summary>Parsers for the providers' published range lists; each returns CIDR strings.</summary>
public static class RangeParsers
{
    public static List<string> Parse(string format, string text) => format switch
    {
        "text" => Lines(text).ToList(),
        "geofeed" => Lines(text).Select(l => l.Split(',')[0].Trim()).Where(l => l.Contains('/', StringComparison.Ordinal)).ToList(),
        "aws" => Json(text, j => Strings(j["prefixes"], "ip_prefix").Concat(Strings(j["ipv6_prefixes"], "ipv6_prefix"))),
        "google" => Json(text, j => Strings(j["prefixes"], "ipv4Prefix").Concat(Strings(j["prefixes"], "ipv6Prefix"))),
        "fastly" => Json(text, j => Values(j["addresses"]).Concat(Values(j["ipv6_addresses"]))),
        "oracle" => Json(text, j => (j["regions"] as JsonArray ?? []).SelectMany(r => Strings(r?["cidrs"], "cidr"))),
        "ripestat" => Json(text, j => Strings(j["data"]?["prefixes"], "prefix")),
        "azure" => Json(text, j => (j["values"] as JsonArray ?? []).SelectMany(v => Values(v?["properties"]?["addressPrefixes"]))),
        _ => throw new FormatException($"unknown range format {format}"),
    };

    private static IEnumerable<string> Lines(string text) =>
        text.ReplaceLineEndings("\n").Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && l[0] != '#');

    private static List<string> Json(string text, Func<JsonNode, IEnumerable<string>> pick) =>
        JsonNode.Parse(text) is { } j ? pick(j).Where(s => s.Length > 0).Distinct(StringComparer.Ordinal).ToList() : [];

    private static IEnumerable<string> Strings(JsonNode? array, string key) =>
        (array as JsonArray ?? []).Select(x => x?[key] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null).OfType<string>();

    private static IEnumerable<string> Values(JsonNode? array) =>
        (array as JsonArray ?? []).Select(x => x is JsonValue v && v.TryGetValue<string>(out var s) ? s : null).OfType<string>();
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true)]
[JsonSerializable(typeof(ProviderCatalog))]
internal sealed partial class ProvidersJsonContext : JsonSerializerContext;
