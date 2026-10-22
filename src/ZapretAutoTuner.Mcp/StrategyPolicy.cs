using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Catalog;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;
using ZapretAutoTuner.Storage;

namespace ZapretAutoTuner.Mcp;

/// <summary>A strategy from the model, checked: the strategy, or the errors that refused it.</summary>
public sealed record CheckedStrategy(Strategy? Strategy, L4Kind L4, IReadOnlyList<ValidationIssue> Issues)
{
    public bool Ok => Strategy is not null && Issues.All(i => i.Severity != Severity.Error);

    public string? Id => Strategy is null ? null : StrategyPolicy.IdOf(Strategy);
}

/// <summary>
/// Every strategy from the model passes this before anything runs (AGENTS.md rule 4): the parser accepts only
/// strategy options, the Validator checks the catalog functions and their arguments, and on top of that the model may
/// not use what executes code or touches files: Lua code arguments, debug functions (<c>luaexec</c>, <c>pcap</c>
/// writes a file), two-sided obfuscation, <c>cond_lua</c>, arbitrary function names, an output interface. Lua in
/// nfqws2 runs with the Agent's rights, so this is the boundary, not a convenience.
/// </summary>
public static class StrategyPolicy
{
    public static readonly IReadOnlySet<string> ForbiddenCategories = new HashSet<string>(StringComparer.Ordinal) { "debug", "obfs" };

    /// <summary>The standard detectors of <c>circular</c> (nfqws2-lua §orchestrators): the only function names a model may pass.</summary>
    public static readonly IReadOnlySet<string> AllowedFunctionArgs = new HashSet<string>(StringComparer.Ordinal)
    {
        "standard_hostkey", "standard_failure_detector", "standard_success_detector",
    };

    public static readonly IReadOnlySet<string> ForbiddenArgs = new HashSet<string>(StringComparer.Ordinal) { "ifout" };

    public const int MaxLength = 2048;

    /// <summary>The program id of a strategy: the knowledge base's hash, shortened.</summary>
    public static string IdOf(Strategy s) => "s-" + KnowledgeBase.HashOf(s)[..12];

    /// <param name="platform">Where it will run: the router is <see cref="EnginePlatform.Linux"/> whatever this PC is; null is this PC.</param>
    public static CheckedStrategy Check(string text, L4Kind l4 = L4Kind.Tcp, ClientProfile? client = null, LuaCatalog? catalog = null, EnginePlatform? platform = null)
    {
        var cat = catalog ?? LuaCatalog.Default;
        var issues = new List<ValidationIssue>();
        if (string.IsNullOrWhiteSpace(text) || text.Length > MaxLength)
            return new(null, l4, [Err("policy.length", $"стратегия пуста или длиннее {MaxLength} символов", $"the strategy is empty or longer than {MaxLength} characters")]);
        Strategy s;
        try
        {
            s = Strategy.Parse(text);
        }
        catch (FormatException e)
        {
            return new(null, l4, [Err("policy.syntax", "в стратегии допустимы только --payload=, --in-range=, --out-range= и --lua-desync=: " + e.Message,
                "only --payload=, --in-range=, --out-range= and --lua-desync= are allowed: " + e.Message)]);
        }
        if (s.InstanceCount == 0)
            issues.Add(Err("policy.empty", "нет ни одного --lua-desync", "no --lua-desync at all"));
        foreach (var call in s.Calls)
        {
            var spec = cat.Find(call.Function);
            if (spec is null)
            {
                issues.Add(Err("policy.function", $"функции {call.Function} нет в каталоге: свой Lua передать нельзя", $"{call.Function} is not a catalog function: custom Lua is not accepted", call.Function));
                continue;
            }
            if (ForbiddenCategories.Contains(spec.Category))
                issues.Add(Err("policy.category", $"{call.Function} ({spec.Category}) недоступна через MCP", $"{call.Function} ({spec.Category}) is not available over MCP", call.Function));
            foreach (var a in call.Args)
            {
                var aspec = cat.FindArg(spec, a.Name);
                if (ForbiddenArgs.Contains(a.Name) || aspec?.Kind == ArgKind.LuaCode)
                    issues.Add(Err("policy.arg", $"аргумент {a.Name} недоступен через MCP", $"argument {a.Name} is not available over MCP", call.Function));
                else if (aspec?.Kind == ArgKind.Function && !AllowedFunctionArgs.Contains(a.Value ?? ""))
                    issues.Add(Err("policy.arg", $"{a.Name}: допустимы только {string.Join(", ", AllowedFunctionArgs)}", $"{a.Name}: only {string.Join(", ", AllowedFunctionArgs)} are allowed", call.Function));
                else if (aspec?.Kind == ArgKind.Iff && a.Value == "cond_lua")
                    issues.Add(Err("policy.arg", "cond_lua исполняет код и недоступна через MCP", "cond_lua executes code and is not available over MCP", call.Function));
            }
        }
        var validator = new StrategyValidator(platform is { } pl
            ? new ValidationContext { Catalog = cat, Client = client, Platform = pl }
            : new ValidationContext { Catalog = cat, Client = client });
        issues.AddRange(validator.ValidateStrategy(s, l4).Issues);
        return new(s, l4, issues);
    }

    public static JsonArray Issues(IEnumerable<ValidationIssue> issues, Severity severity) =>
        new([.. issues.Where(i => i.Severity == severity).Select(i => (JsonNode)new JsonObject
        {
            ["code"] = i.Code,
            ["where"] = i.Where,
            ["en"] = i.En,
            ["ru"] = i.Ru,
        })]);

    /// <summary>The refusal the model gets: what is wrong, in its words and the user's.</summary>
    public static JsonObject Refusal(CheckedStrategy c) => new()
    {
        ["ok"] = false,
        ["error"] = "the strategy was refused by the Validator / стратегию отклонил Validator: "
            + string.Join("; ", c.Issues.Where(i => i.Severity == Severity.Error).Select(i => (i.Where is null ? "" : i.Where + ": ") + i.En)),
        ["errors"] = Issues(c.Issues, Severity.Error),
        ["hint"] = "fix the arguments with catalog_functions and the ztuner://skills/nfqws2-lua resource, then check with strategy_validate",
    };

    private static ValidationIssue Err(string code, string ru, string en, string? where = null) => new(Severity.Error, code, ru, en, where);
}
