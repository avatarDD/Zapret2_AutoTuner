using System.Text.RegularExpressions;

namespace ZapretAutoTuner.Core.Catalog;

/// <summary>
/// Compares the catalog with a zapret2 tree (lua files and, when available, nfq2/protocol.c). Used by tests
/// against the bundled release and at runtime before accepting an updated zapret2.
/// </summary>
public static partial class CatalogVerifier
{
    public static List<string> Verify(LuaCatalog catalog, LuaSourceIndex lua, string? protocolC)
    {
        var problems = new List<string>();
        foreach (var spec in catalog.Functions)
        {
            if (!lua.Functions.TryGetValue(spec.Name, out var info))
            {
                problems.Add($"функция {spec.Name} отсутствует в lua ({spec.File})");
                continue;
            }
            if (info.File != spec.File)
                problems.Add($"функция {spec.Name} переехала из {spec.File} в {info.File}");
            if (!info.IsDesync)
                problems.Add($"функция {spec.Name} больше не имеет сигнатуры (ctx, desync)");
            var blocks = info.StandardBlocks ?? [];
            if (!blocks.Order().SequenceEqual(spec.Blocks.Order()))
                problems.Add($"{spec.Name}: стандартные блоки в lua [{string.Join(", ", blocks)}], в каталоге [{string.Join(", ", spec.Blocks)}]");

            var docInFile = lua.Functions.Values.Where(f => f.File == spec.File).SelectMany(f => f.DocumentedArgs).ToHashSet(StringComparer.Ordinal);
            foreach (var a in spec.Args)
            {
                if (!info.DocumentedArgs.Contains(a.Name) && !docInFile.Contains(a.Name) && !lua.CodeArgReferences.Contains(a.Name))
                    problems.Add($"{spec.Name}: аргумент {a.Name} не найден в lua");
            }
            var known = catalog.ArgsOf(spec).Select(a => a.Name).ToHashSet(StringComparer.Ordinal);
            foreach (var doc in info.DocumentedArgs)
            {
                if (!known.Contains(doc))
                    problems.Add($"{spec.Name}: lua описывает аргумент {doc}, которого нет в каталоге");
            }
        }

        foreach (var (block, args) in catalog.Data.Blocks)
        {
            foreach (var a in args)
            {
                if (!lua.StandardArgNames.Contains(a.Name))
                    problems.Add($"блок {block}: аргумент {a.Name} не описан в STANDARD FUNCTION ARGS");
            }
        }
        foreach (var a in catalog.Data.InstanceArgs)
        {
            if (!lua.CodeArgReferences.Contains(a.Name))
                problems.Add($"аргумент инстанса {a.Name} не читается в lua");
        }
        foreach (var f in catalog.Data.IffFunctions)
        {
            if (!lua.Functions.ContainsKey(f))
                problems.Add($"iff-функция {f} отсутствует в lua");
        }
        var helpers = catalog.Data.HelperFunctions.ToHashSet(StringComparer.Ordinal);
        foreach (var f in lua.Functions.Values.Where(f => f.IsDesync && catalog.Find(f.Name) is null && !helpers.Contains(f.Name)))
            problems.Add($"в lua есть функция {f.Name} ({f.File}), которой нет в каталоге");

        if (lua.CompatVersion is { } compat && compat != catalog.Data.LuaCompat)
            problems.Add($"NFQWS2_COMPAT_VER_REQUIRED={compat}, каталог рассчитан на {catalog.Data.LuaCompat}");

        if (protocolC is not null)
        {
            Compare(problems, "l7proto_name", CArray(protocolC, "l7proto_name"), catalog.Protocols.L7);
            Compare(problems, "l7payload_name", CArray(protocolC, "l7payload_name"), catalog.Protocols.Payloads);
            Compare(problems, "posmarker_names", CArray(protocolC, "posmarker_names"), catalog.Protocols.PositionMarkers);
            var mods = TlsModRegex().Matches(protocolC).Select(m => m.Groups[1].Value).Order(StringComparer.Ordinal).ToList();
            Compare(problems, "tls_mod", mods, catalog.Protocols.TlsMods.Order(StringComparer.Ordinal).ToList());
        }
        return problems;
    }

    private static void Compare(List<string> problems, string what, List<string>? expected, List<string> actual)
    {
        if (expected is null)
            problems.Add($"в protocol.c не найден массив {what}");
        else if (!expected.SequenceEqual(actual))
            problems.Add($"{what}: в protocol.c [{string.Join(",", expected)}], в каталоге [{string.Join(",", actual)}]");
    }

    private static List<string>? CArray(string src, string name)
    {
        var m = Regex.Match(src, @"static const char \*" + Regex.Escape(name) + @"\[\]\s*=\s*\{(.*?)\};", RegexOptions.Singleline);
        return m.Success ? QuotedRegex().Matches(m.Groups[1].Value).Select(x => x.Groups[1].Value).ToList() : null;
    }

    [GeneratedRegex("\"([^\"]+)\"")]
    private static partial Regex QuotedRegex();

    [GeneratedRegex("strcmp\\(opt, \"([a-z]+)\"\\)")]
    private static partial Regex TlsModRegex();
}
