using System.Text.Json.Serialization;

namespace ZapretAutoTuner.Tools;

/// <summary><c>zapret2/bundle.json</c>, written by <c>tools/bundle/bundle.ps1</c> next to the engine files.</summary>
public sealed class BundleManifest
{
    public string Tag { get; set; } = "";

    public string Version { get; set; } = "";

    public string Rid { get; set; } = "";

    [JsonPropertyName("lua_compat")]
    public int LuaCompat { get; set; }

    [JsonPropertyName("source_sha256")]
    public string SourceSha256 { get; set; } = "";

    /// <summary>Relative path (forward slashes) → SHA-256 hex.</summary>
    public SortedDictionary<string, string> Files { get; set; } = new(StringComparer.Ordinal);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, WriteIndented = true)]
[JsonSerializable(typeof(BundleManifest))]
internal sealed partial class ToolsJsonContext : JsonSerializerContext;
