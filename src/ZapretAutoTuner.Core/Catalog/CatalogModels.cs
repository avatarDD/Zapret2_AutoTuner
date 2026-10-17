using System.Text.Json.Serialization;

namespace ZapretAutoTuner.Core.Catalog;

/// <summary>How an argument value is validated and mutated.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ArgKind>))]
public enum ArgKind
{
    [JsonStringEnumMemberName("flag")] Flag,
    [JsonStringEnumMemberName("int")] Int,
    [JsonStringEnumMemberName("int_signed")] IntSigned,
    [JsonStringEnumMemberName("string")] String,
    [JsonStringEnumMemberName("enum")] Enum,
    [JsonStringEnumMemberName("blob")] Blob,
    [JsonStringEnumMemberName("blob_name_out")] BlobNameOut,
    [JsonStringEnumMemberName("marker")] Marker,
    [JsonStringEnumMemberName("marker_optional")] MarkerOptional,
    [JsonStringEnumMemberName("marker_list")] MarkerList,
    [JsonStringEnumMemberName("marker_or_be")] MarkerOrBe,
    [JsonStringEnumMemberName("payload_list")] PayloadList,
    [JsonStringEnumMemberName("tls_mod")] TlsMod,
    [JsonStringEnumMemberName("tcp_flags")] TcpFlags,
    [JsonStringEnumMemberName("hex_optional")] HexOptional,
    [JsonStringEnumMemberName("autottl")] AutoTtl,
    [JsonStringEnumMemberName("function")] Function,
    [JsonStringEnumMemberName("function_optional")] FunctionOptional,
    [JsonStringEnumMemberName("iff")] Iff,
    [JsonStringEnumMemberName("lua_code")] LuaCode,
}

public sealed class ArgSpec
{
    public required string Name { get; init; }

    public ArgKind Kind { get; init; }

    public List<string>? Values { get; init; }

    public string? Default { get; init; }

    public bool Required { get; init; }

    public long? Min { get; init; }

    public long? Max { get; init; }

    [JsonPropertyName("multiple_of")]
    public int? MultipleOf { get; init; }

    public int? Length { get; init; }

    public int? Count { get; init; }

    public string? File { get; init; }

    public string? Ru { get; init; }

    public string? En { get; init; }

    public override string ToString() => Name;
}

public sealed class FunctionSpec
{
    public required string Name { get; init; }

    public required string File { get; init; }

    public List<string> Blocks { get; init; } = [];

    public List<ArgSpec> Args { get; init; } = [];

    /// <summary>Payload types the function acts on (null — any allowed by the payload block).</summary>
    public List<string>? Payloads { get; init; }

    public string Category { get; init; } = "";

    [JsonPropertyName("needs_fooling")]
    public bool NeedsFooling { get; init; }

    [JsonPropertyName("needs_in_range")]
    public string? NeedsInRange { get; init; }

    [JsonPropertyName("needs_incoming")]
    public bool NeedsIncoming { get; init; }

    public bool Phase0 { get; init; }

    public bool Slow { get; init; }

    [JsonPropertyName("breaks_nat")]
    public bool BreaksNat { get; init; }

    [JsonPropertyName("server_side")]
    public bool ServerSide { get; init; }

    [JsonPropertyName("two_sided")]
    public bool TwoSided { get; init; }

    public bool Orchestrator { get; init; }

    [JsonPropertyName("last_of_http")]
    public bool LastOfHttp { get; init; }

    public string Ru { get; init; } = "";

    public string En { get; init; } = "";

    public override string ToString() => Name;
}

public sealed class FunctionCatalogData
{
    [JsonPropertyName("zapret2_version")]
    public string Zapret2Version { get; init; } = "";

    [JsonPropertyName("lua_compat")]
    public int LuaCompat { get; init; }

    [JsonPropertyName("lua_init_order")]
    public List<string> LuaInitOrder { get; init; } = [];

    [JsonPropertyName("builtin_blobs")]
    public List<string> BuiltinBlobs { get; init; } = [];

    public Dictionary<string, List<ArgSpec>> Blocks { get; init; } = [];

    [JsonPropertyName("fooling_keys")]
    public List<string> FoolingKeys { get; init; } = [];

    public List<FunctionSpec> Functions { get; init; } = [];

    [JsonPropertyName("instance_args")]
    public List<ArgSpec> InstanceArgs { get; init; } = [];

    /// <summary>Functions with the desync signature that are library helpers, not strategy steps.</summary>
    [JsonPropertyName("helper_functions")]
    public List<string> HelperFunctions { get; init; } = [];

    [JsonPropertyName("iff_functions")]
    public List<string> IffFunctions { get; init; } = [];
}

public sealed class ProtocolCatalogData
{
    public string Source { get; init; } = "";

    public List<string> L7 { get; init; } = [];

    public List<string> Payloads { get; init; } = [];

    [JsonPropertyName("position_markers")]
    public List<string> PositionMarkers { get; init; } = [];

    [JsonPropertyName("tls_mods")]
    public List<string> TlsMods { get; init; } = [];
}

/// <summary>One nfqws2 command-line option (nfq2/nfqws.c <c>long_options</c>).</summary>
public sealed class EngineOptionSpec
{
    public required string Name { get; init; }

    /// <summary><c>none</c>, <c>optional</c> or <c>required</c> (getopt has_arg).</summary>
    public string Arg { get; init; } = "required";

    /// <summary><c>global</c>, <c>profile</c>, <c>action</c> (ordered inside a profile) or <c>separator</c> (<c>--new</c>).</summary>
    public string Scope { get; init; } = "global";

    /// <summary><c>all</c>, <c>linux</c>, <c>windows</c>, <c>posix</c> (not Windows), <c>bsd</c> or <c>keenetic</c>.</summary>
    public string Platform { get; init; } = "all";

    public string? Note { get; init; }

    public override string ToString() => Name;
}

public sealed class EngineOptionsData
{
    public string Source { get; init; } = "";

    public List<EngineOptionSpec> Options { get; init; } = [];
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, ReadCommentHandling = System.Text.Json.JsonCommentHandling.Skip, AllowTrailingCommas = true)]
[JsonSerializable(typeof(FunctionCatalogData))]
[JsonSerializable(typeof(ProtocolCatalogData))]
[JsonSerializable(typeof(EngineOptionsData))]
internal sealed partial class CatalogJsonContext : JsonSerializerContext;
