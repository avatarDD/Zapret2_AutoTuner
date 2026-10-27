using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Mcp;

/// <summary>The answers that refuse something; each says what to do instead.</summary>
internal static class McpErrors
{
    public static JsonObject Error(string message) => new() { ["ok"] = false, ["error"] = message };

    public static JsonObject NotATarget(string host) => new()
    {
        ["ok"] = false,
        ["error"] = $"{host} is not in the user's target list / {host} нет в списке целей",
        ["hint"] = "probes go only to targets_list; target_add asks the user to add one",
    };

    public static JsonObject Budget(string why, TimeSpan retry) => new()
    {
        ["ok"] = false,
        ["error"] = why,
        ["retry_after_sec"] = retry > TimeSpan.Zero ? (int)Math.Ceiling(retry.TotalSeconds) : null,
    };

    /// <summary>
    /// The strategy of a call: <c>strategy</c> (text) or <c>strategy_id</c>, exactly one. Either way it passes
    /// <see cref="StrategyPolicy"/> again: an id is a shortcut, not a pass.
    /// </summary>
    public static (CheckedStrategy? Strategy, JsonObject? Refusal) StrategyFrom(McpSession session, JsonObject args, ClientProfile? client = null, Core.Validation.EnginePlatform? platform = null)
    {
        var text = (string?)args["strategy"];
        var id = (string?)args["strategy_id"];
        if ((text is null) == (id is null))
            return (null, Error("give exactly one of strategy and strategy_id / нужна ровно одна из strategy и strategy_id"));
        var l4 = (string?)args["l4"] == "udp" ? L4Kind.Udp : L4Kind.Tcp;
        if (id is not null)
        {
            if (session.Strategy(id) is not { } known)
                return (null, Error($"{id} is unknown in this session: use an id from trials_history, kb_query or search_status, or pass the strategy text"));
            text = known.Strategy.ToString();
            l4 = known.L4;
        }
        var c = StrategyPolicy.Check(text!, l4, client, platform: platform);
        return c.Ok ? (c, null) : (null, StrategyPolicy.Refusal(c));
    }
}
