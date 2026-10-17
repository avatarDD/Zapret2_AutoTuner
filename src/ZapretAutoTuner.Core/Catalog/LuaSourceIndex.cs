using System.Text.RegularExpressions;

namespace ZapretAutoTuner.Core.Catalog;

/// <summary>What one Lua function declares in its source and comments.</summary>
public sealed class LuaFunctionInfo
{
    public required string Name { get; init; }

    public required string File { get; init; }

    /// <summary>True for the <c>(ctx, desync)</c> signature: callable from <c>--lua-desync</c>.</summary>
    public bool IsDesync { get; init; }

    /// <summary>Names from the <c>-- arg :</c> comment lines above the function.</summary>
    public HashSet<string> DocumentedArgs { get; } = new(StringComparer.Ordinal);

    /// <summary>Blocks from the <c>-- standard args :</c> line, null if the line is absent.</summary>
    public List<string>? StandardBlocks { get; set; }
}

/// <summary>
/// Index of the zapret2 Lua files: functions (<c>^function name(</c>), their <c>-- arg</c> docs, the
/// standard argument blocks from the antidpi header and every <c>arg.name</c> the code reads.
/// Used by the catalog sync test and by the Validator to know which functions the loaded files define.
/// </summary>
public sealed partial class LuaSourceIndex
{
    public Dictionary<string, LuaFunctionInfo> Functions { get; } = new(StringComparer.Ordinal);

    /// <summary>Names listed as <c>* name</c> in the "STANDARD FUNCTION ARGS" header.</summary>
    public HashSet<string> StandardArgNames { get; } = new(StringComparer.Ordinal);

    /// <summary>Every identifier read as <c>arg.name</c>, <c>options.name</c> or <c>arg["name"]</c>.</summary>
    public HashSet<string> CodeArgReferences { get; } = new(StringComparer.Ordinal);

    /// <summary><c>NFQWS2_COMPAT_VER_REQUIRED</c> from zapret-lib.lua, null if not found.</summary>
    public int? CompatVersion { get; private set; }

    [GeneratedRegex(@"^function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")]
    private static partial Regex FunctionRegex();

    [GeneratedRegex(@"^--\s*arg\s*:\s*(.*)$")]
    private static partial Regex ArgDocRegex();

    [GeneratedRegex(@"^([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)")]
    private static partial Regex ArgNamesRegex();

    [GeneratedRegex(@"^--\s*standard args\s*:\s*([a-z_,\s]+)")]
    private static partial Regex StandardArgsRegex();

    [GeneratedRegex(@"^\*\s*(?:[a-z0-9_]+\s*:\s*)?([a-z0-9_]+)")]
    private static partial Regex HeaderArgRegex();

    [GeneratedRegex(@"(?:\barg|_options|\boptions)\.([A-Za-z_][A-Za-z0-9_]*)|arg\[""([A-Za-z_][A-Za-z0-9_]*)""\]")]
    private static partial Regex CodeArgRegex();

    [GeneratedRegex(@"^\s*NFQWS2_COMPAT_VER_REQUIRED\s*=\s*(\d+)")]
    private static partial Regex CompatRegex();

    public static LuaSourceIndex FromDirectory(string luaDir, IEnumerable<string>? files = null)
    {
        var idx = new LuaSourceIndex();
        var names = files?.ToList() ?? Directory.GetFiles(luaDir, "*.lua").Select(Path.GetFileName).OfType<string>()
            .Where(n => n != "zapret-tests.lua").Order(StringComparer.Ordinal).ToList();
        foreach (var name in names)
        {
            var path = Path.Combine(luaDir, name);
            if (!File.Exists(path) && File.Exists(path + ".gz"))
                throw new NotSupportedException($"{name}.gz: compressed lua is not indexed");
            idx.AddFile(name, File.ReadAllLines(path));
        }
        return idx;
    }

    public void AddFile(string fileName, IReadOnlyList<string> lines)
    {
        var pendingArgs = new List<string>();
        List<string>? pendingBlocks = null;
        bool inHeader = false;
        for (int i = 0; i < lines.Count; i++)
        {
            var line = lines[i].TrimEnd();
            if (i == 0 && CompatRegex().Match(line) is { Success: true } cm)
                CompatVersion = int.Parse(cm.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);

            if (line.StartsWith("--[[", StringComparison.Ordinal))
            {
                inHeader = true;
                continue;
            }
            if (inHeader)
            {
                var t = line.TrimStart();
                if (t.StartsWith("]]", StringComparison.Ordinal) || t.StartsWith("--]]", StringComparison.Ordinal))
                    inHeader = false;
                else if (HeaderArgRegex().Match(t) is { Success: true } hm)
                    StandardArgNames.Add(hm.Groups[1].Value);
                else if (ArgDocRegex().Match("--" + t) is { Success: true } bam && ArgNamesRegex().Match(bam.Groups[1].Value) is { Success: true } bnm)
                    pendingArgs.AddRange(bnm.Groups[1].Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
                continue;
            }

            foreach (Match m in CodeArgRegex().Matches(line))
                CodeArgReferences.Add(m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value);

            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("--", StringComparison.Ordinal))
            {
                if (ArgDocRegex().Match(trimmed) is { Success: true } am && ArgNamesRegex().Match(am.Groups[1].Value) is { Success: true } nm)
                    pendingArgs.AddRange(nm.Groups[1].Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
                else if (StandardArgsRegex().Match(trimmed) is { Success: true } sm)
                    pendingBlocks = sm.Groups[1].Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList();
                // header-style option docs inside lib functions (ipfrag2) count as standard arg names
                else if (trimmed.StartsWith("-- option :", StringComparison.Ordinal) || trimmed.StartsWith("-- option:", StringComparison.Ordinal))
                {
                    var rest = trimmed[(trimmed.IndexOf(':', StringComparison.Ordinal) + 1)..].Trim();
                    if (ArgNamesRegex().Match(rest) is { Success: true } om)
                        StandardArgNames.Add(om.Groups[1].Value);
                }
                continue;
            }

            if (FunctionRegex().Match(line) is { Success: true } fm)
            {
                var info = new LuaFunctionInfo
                {
                    Name = fm.Groups[1].Value,
                    File = fileName,
                    IsDesync = fm.Groups[2].Value.Replace(" ", "", StringComparison.Ordinal) == "ctx,desync",
                    StandardBlocks = pendingBlocks,
                };
                foreach (var a in pendingArgs)
                    info.DocumentedArgs.Add(a);
                Functions[info.Name] = info;
            }
            if (trimmed.Length > 0)
            {
                pendingArgs.Clear();
                pendingBlocks = null;
            }
        }
    }
}
