using System.Text.Json;

namespace ZapretAutoTuner.Core.Catalog;

/// <summary>
/// Machine-readable copy of the zapret2 Lua library and protocol names (skills nfqws2-lua, nfqws2-engine §5).
/// Data, not code: the JSON is checked against the bundled <c>lua/*.lua</c> and <c>protocol.c</c> by tests.
/// </summary>
public sealed class LuaCatalog
{
    private static readonly Lazy<LuaCatalog> DefaultInstance = new(Load);

    private readonly Dictionary<string, FunctionSpec> _functions;

    private LuaCatalog(FunctionCatalogData functions, ProtocolCatalogData protocols, EngineOptionsData options)
    {
        EngineOptions = options.Options.ToDictionary(o => o.Name, StringComparer.Ordinal);
        Data = functions;
        Protocols = protocols;
        _functions = functions.Functions.ToDictionary(f => f.Name, StringComparer.Ordinal);
        L7 = protocols.L7.ToHashSet(StringComparer.Ordinal);
        Payloads = protocols.Payloads.ToHashSet(StringComparer.Ordinal);
        PositionMarkers = protocols.PositionMarkers.ToHashSet(StringComparer.Ordinal);
        TlsMods = protocols.TlsMods.ToHashSet(StringComparer.Ordinal);
        BuiltinBlobs = functions.BuiltinBlobs.ToHashSet(StringComparer.Ordinal);
        FoolingKeys = functions.FoolingKeys.ToHashSet(StringComparer.Ordinal);
    }

    public static LuaCatalog Default => DefaultInstance.Value;

    public FunctionCatalogData Data { get; }

    public ProtocolCatalogData Protocols { get; }

    public IReadOnlyCollection<FunctionSpec> Functions => _functions.Values;

    /// <summary>nfqws2 / winws2 options by name without the leading <c>--</c>.</summary>
    public IReadOnlyDictionary<string, EngineOptionSpec> EngineOptions { get; }

    public IReadOnlySet<string> L7 { get; }

    public IReadOnlySet<string> Payloads { get; }

    public IReadOnlySet<string> PositionMarkers { get; }

    public IReadOnlySet<string> TlsMods { get; }

    public IReadOnlySet<string> BuiltinBlobs { get; }

    /// <summary>Arguments that count as "fooling" for the fake invariant (nfqws2-lua §10.1).</summary>
    public IReadOnlySet<string> FoolingKeys { get; }

    public FunctionSpec? Find(string name) => _functions.GetValueOrDefault(name);

    /// <summary>All arguments a function accepts: its own, its standard blocks and the orchestrator instance args.</summary>
    public IEnumerable<ArgSpec> ArgsOf(FunctionSpec f)
    {
        foreach (var a in f.Args)
            yield return a;
        foreach (var b in f.Blocks)
        {
            foreach (var a in Data.Blocks[b])
                yield return a;
        }
        foreach (var a in Data.InstanceArgs)
            yield return a;
    }

    public ArgSpec? FindArg(FunctionSpec f, string arg) => ArgsOf(f).FirstOrDefault(a => a.Name == arg);

    public static LuaCatalog Load()
    {
        var f = Read("functions.json", CatalogJsonContext.Default.FunctionCatalogData);
        var p = Read("protocols.json", CatalogJsonContext.Default.ProtocolCatalogData);
        var o = Read("options.json", CatalogJsonContext.Default.EngineOptionsData);
        return new LuaCatalog(f, p, o);
    }

    private static T Read<T>(string name, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info)
    {
        using var s = typeof(LuaCatalog).Assembly.GetManifestResourceStream("ZapretAutoTuner.Core.Catalog." + name)
            ?? throw new InvalidOperationException($"catalog resource {name} is missing");
        return JsonSerializer.Deserialize(s, info) ?? throw new InvalidOperationException($"catalog {name} is empty");
    }
}
