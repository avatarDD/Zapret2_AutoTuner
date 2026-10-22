using System.Text.RegularExpressions;
using ZapretAutoTuner.Core.Catalog;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Resources;

/// <summary>
/// Which resources a solution uses (PLAN 4a.5: a resource a strategy refers to cannot be deleted), and which user Lua
/// files a launch needs.
/// </summary>
public static partial class ResourceRefs
{
    /// <summary>Arguments whose value names a blob (nfqws2-engine §9.1).</summary>
    public static readonly IReadOnlyList<string> BlobArgs = ["blob", "pattern", "seqovl_pattern", "fallback"];

    [GeneratedRegex(@"(?<!\\)[%#]([A-Za-z_][A-Za-z0-9_]*)")]
    private static partial Regex SubstitutionRe();

    /// <summary>
    /// Every resource the solution refers to: its lists by name, the blobs it declares or names in an argument, its
    /// <c>zt-*.lua</c> files and, through <paramref name="scriptOfFunction"/>, the scripts whose functions it calls.
    /// </summary>
    public static List<ResourceRef> Of(Solution s, IReadOnlyDictionary<string, string>? scriptOfFunction = null, LuaCatalog? catalog = null)
    {
        var refs = new HashSet<ResourceRef>();
        foreach (var name in s.Hostlists.Keys)
            refs.Add(new(ResourceKind.Hostlist, name));
        foreach (var name in s.Ipsets.Keys)
            refs.Add(new(ResourceKind.Ipset, name));
        foreach (var p in s.Profiles)
        {
            foreach (var l in p.Hostlists.Concat(p.HostlistExcludes).Where(l => l.Path is null))
                refs.Add(new(ResourceKind.Hostlist, l.Name));
            foreach (var l in p.Ipsets.Concat(p.IpsetExcludes).Where(l => l.Path is null))
                refs.Add(new(ResourceKind.Ipset, l.Name));
        }
        foreach (var name in s.Blobs.Keys.Concat(BlobNamesUsed(s.Profiles.Select(p => p.Strategy), catalog)))
            refs.Add(new(ResourceKind.Blob, name));
        foreach (var file in s.LuaFiles.Keys)
        {
            if (ResourceNames.LuaNameOf(file) is { } script)
                refs.Add(new(ResourceKind.LuaScript, script));
        }
        if (scriptOfFunction is not null)
        {
            foreach (var f in FunctionsUsed(s.Profiles.Select(p => p.Strategy), catalog))
            {
                if (scriptOfFunction.TryGetValue(f, out var script))
                    refs.Add(new(ResourceKind.LuaScript, script));
            }
        }
        return [.. refs.OrderBy(r => r.Kind).ThenBy(r => r.Name, StringComparer.Ordinal)];
    }

    /// <summary>Blob names the strategies use, built-in blobs and inline hex left out.</summary>
    public static IEnumerable<string> BlobNamesUsed(IEnumerable<Strategy> strategies, LuaCatalog? catalog = null)
    {
        catalog ??= LuaCatalog.Default;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var arg in strategies.SelectMany(s => s.Calls).SelectMany(c => c.Args).Where(a => a.Value is not null))
        {
            var names = new List<string>();
            if (BlobArgs.Contains(arg.Name) && Identifiers.IsLuaIdentifier(arg.Value))
                names.Add(arg.Value!);
            names.AddRange(SubstitutionRe().Matches(arg.Value!).Select(m => m.Groups[1].Value));
            foreach (var n in names)
            {
                if (!catalog.BuiltinBlobs.Contains(n) && seen.Add(n))
                    yield return n;
            }
        }
    }

    /// <summary>Functions the strategies call that are not in the zapret2 library: user functions.</summary>
    public static IEnumerable<string> FunctionsUsed(IEnumerable<Strategy> strategies, LuaCatalog? catalog = null)
    {
        catalog ??= LuaCatalog.Default;
        return strategies.SelectMany(s => s.Calls).Select(c => c.Function).Where(f => catalog.Find(f) is null).Distinct(StringComparer.Ordinal);
    }

    /// <summary>
    /// The <c>--lua-init=@path</c> files (in a stable order) for the user functions the strategies call;
    /// <paramref name="pathOfFunction"/> maps an approved function to its script file.
    /// </summary>
    public static List<string> LuaPathsFor(IEnumerable<Strategy> strategies, IReadOnlyDictionary<string, string> pathOfFunction)
    {
        var list = strategies.ToList();
        return [.. FunctionsUsed(list).Select(f => pathOfFunction.GetValueOrDefault(f)).OfType<string>().Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    }
}
