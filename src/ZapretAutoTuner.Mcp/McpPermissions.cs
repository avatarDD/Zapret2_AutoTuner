using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Mcp;

/// <summary>The permission groups of the tools (MCP design, "Инструменты"). Reading needs no switch.</summary>
public enum McpScope
{
    Read,
    Probes,
    Control,
    Experiments,
    Export,

    /// <summary>Experiments on the router through zapret-gui (router_experiment_*).</summary>
    Router,
    /// <summary>Strategy resources (PLAN 4a.5): hostlists, ipsets, blobs, Lua drafts; never approval of a script.</summary>
    Resources,

    /// <summary>
    /// The router's own zapret-gui tools relayed as <c>gui_*</c> (PLAN 4a.7): AutoTuner forwards them with the address and
    /// token the user entered; every tool not marked read-only waits for the user's yes. No tool of ours has this scope.
    /// </summary>
    RouterProxy,
}

/// <summary>
/// The user's switches, all off by default. <c>experiments</c> works only with <c>control</c> and <c>probes</c>, as in
/// zapret-gui, and <c>router</c> (the router's experiments through zapret-gui) likewise; an unmet dependency is explained,
/// not silently ignored. There is no switch for anything else: the
/// program has no code for a shell, files or the OS, so there is nothing to switch on.
/// </summary>
public sealed record McpPermissions(bool Probes = false, bool Control = false, bool Experiments = false, bool Export = false, bool Router = false, bool Resources = false, bool RouterProxy = false)
{
    public static IReadOnlyDictionary<McpScope, McpScope[]> Requires { get; } = new Dictionary<McpScope, McpScope[]>
    {
        [McpScope.Experiments] = [McpScope.Control, McpScope.Probes],
        [McpScope.Router] = [McpScope.Control, McpScope.Probes],
    };

    public static string Name(McpScope s) => s == McpScope.RouterProxy ? "router_proxy" : s.ToString().ToLowerInvariant();

    /// <summary>The switch as the user set it.</summary>
    public bool IsSet(McpScope s) => s switch
    {
        McpScope.Read => true,
        McpScope.Probes => Probes,
        McpScope.Control => Control,
        McpScope.Experiments => Experiments,
        McpScope.Export => Export,
        McpScope.Router => Router,
        McpScope.Resources => Resources,
        McpScope.RouterProxy => RouterProxy,
        _ => false,
    };

    /// <summary>The dependencies of <paramref name="s"/> that are off.</summary>
    public IReadOnlyList<McpScope> Missing(McpScope s) =>
        Requires.TryGetValue(s, out var req) ? [.. req.Where(r => !IsSet(r))] : [];

    /// <summary>The switch as it acts: set, and every dependency set too.</summary>
    public bool Granted(McpScope s) => IsSet(s) && Missing(s).Count == 0;

    /// <summary>The answer of a tool the permissions do not allow: says exactly what to switch on.</summary>
    public JsonObject Denial(McpScope s)
    {
        var missing = Missing(s).Select(Name).ToList();
        string name = Name(s), error, hint;
        if (IsSet(s) && missing.Count > 0)
        {
            error = $"permission {name} does not act without {string.Join(", ", missing)} / разрешение {name} не действует без {string.Join(", ", missing)}";
            hint = $"«{name}» is on but also needs {string.Join(", ", missing)}: the user switches them on in AutoTuner, Settings → MCP / включите их в настройках MCP AutoTuner";
        }
        else
        {
            error = $"no permission {name} / нет разрешения {name}";
            hint = $"the user switches «{name}» on in AutoTuner, Settings → MCP / включите разрешение «{name}» в настройках MCP AutoTuner"
                + (missing.Count > 0 ? $" (together with {string.Join(", ", missing)} / вместе с ним: {string.Join(", ", missing)})" : "");
        }
        return new JsonObject
        {
            ["ok"] = false,
            ["error"] = error,
            ["permission"] = name,
            ["requires"] = new JsonArray([.. (Requires.TryGetValue(s, out var r) ? r : []).Select(x => (JsonNode)JsonValue.Create(Name(x)))]),
            ["missing"] = new JsonArray([.. missing.Select(m => (JsonNode)JsonValue.Create(m))]),
            ["hint"] = hint,
        };
    }
}
