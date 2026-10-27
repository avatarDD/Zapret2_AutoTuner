using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core.Catalog;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// AGENTS.md rules 1 and 4 for the router's relayed gui_* tools: their arguments are zapret-gui's, but a string in them
/// that is engine option text (a profile, a strategy) goes to nfqws2 on the router as it is. So every string value is
/// scanned: <c>--dpi-desync</c> is refused, a custom <c>--lua-init</c> too (Lua runs as root there), every
/// <c>--lua-desync</c> passes <see cref="StrategyPolicy"/>'s rules, and the whole text passes the Validator for Linux,
/// as <see cref="RouterExperimentRunner"/> checks its own profiles.
/// </summary>
public static partial class GuiArgumentPolicy
{
    [GeneratedRegex(@"--dpi-desync", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DpiDesync();

    /// <summary>An engine option at the start of the text or after a blank: the text is meant for nfqws2.</summary>
    [GeneratedRegex(@"(^|\s)--[A-Za-z]", RegexOptions.CultureInvariant)]
    private static partial Regex EngineOption();

    /// <summary>The refusal, or null when nothing in the arguments is a problem.</summary>
    public static JsonObject? Check(JsonObject args)
    {
        foreach (var (path, text) in Strings(args, "arguments"))
        {
            if (DpiDesync().IsMatch(text))
                return Refuse(path, "--dpi-desync is the old zapret syntax: only nfqws2's --lua-desync is used",
                    "--dpi-desync — синтаксис старого zapret: используется только --lua-desync nfqws2");
            if (!EngineOption().IsMatch(text))
                continue;
            if (Problem(text) is { } why)
                return Refuse(path, why.En, why.Ru);
        }
        return null;
    }

    private static (string En, string Ru)? Problem(string text)
    {
        List<string> tokens;
        try
        {
            tokens = ArgTokenizer.Split(text);
        }
        catch (FormatException e)
        {
            return ("not valid engine options: " + e.Message, "это не опции движка: " + e.Message);
        }
        var cat = LuaCatalog.Default;
        var issues = new List<ValidationIssue>();
        foreach (var t in tokens)
        {
            var (name, value) = ArgTokenizer.SplitOption(t);
            if (name == "--lua-init")
                return ("--lua-init is not accepted over MCP: zapret-gui loads the standard Lua files itself",
                    "--lua-init через MCP не принимается: стандартные файлы Lua zapret-gui подключает сам");
            if (name != "--lua-desync")
                continue;
            if (value is null || !LuaCall.TryParse(value, out var call) || call is null)
                return ($"{t}: not a valid --lua-desync", $"{t}: неверный --lua-desync");
            StrategyPolicy.CallIssues(call, cat, issues);
        }
        // zapret-gui adds the standard --lua-init files itself: the functions are those of the catalog
        var r = new StrategyValidator(new ValidationContext
        {
            Platform = EnginePlatform.Linux,
            Catalog = cat,
            LoadedFunctions = cat.Functions.Select(f => f.Name).ToHashSet(StringComparer.Ordinal),
        }).ValidateArgv(tokens);
        issues.AddRange(r.Issues);
        var errors = issues.Where(i => i.Severity == Severity.Error).ToList();
        if (errors.Count == 0)
            return null;
        return (string.Join("; ", errors.Select(i => (i.Where is null ? "" : i.Where + ": ") + i.En)),
            string.Join("; ", errors.Select(i => (i.Where is null ? "" : i.Where + ": ") + i.Ru)));
    }

    private static JsonObject Refuse(string path, string en, string ru) => new()
    {
        ["ok"] = false,
        ["error"] = $"refused before forwarding to the router: {path} carries engine options the Validator refused: {en} / не отправлено на роутер: {path} содержит опции движка, отклонённые Validator: {ru}",
        ["where"] = path,
        ["hint"] = "router profiles use nfqws2 syntax (--lua-desync) with catalog functions; check a strategy with strategy_validate",
    };

    private static IEnumerable<(string Path, string Text)> Strings(JsonNode? node, string path)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var (k, v) in o)
                {
                    yield return (path + "." + k + " (name)", k);
                    foreach (var s in Strings(v, path + "." + k))
                        yield return s;
                }
                break;
            case JsonArray a:
                for (int i = 0; i < a.Count; i++)
                    foreach (var s in Strings(a[i], $"{path}[{i}]"))
                        yield return s;
                break;
            case JsonValue v when v.TryGetValue<string>(out var text):
                yield return (path, text);
                break;
        }
    }
}
