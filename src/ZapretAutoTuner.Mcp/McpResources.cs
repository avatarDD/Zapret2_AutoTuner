using System.Reflection;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Mcp;

/// <summary>A resource: the skills as reference, and each trial's capture as a summary (never payload bytes).</summary>
public sealed record McpResource(string Uri, string Name, string Title, string Description, string MimeType);

/// <summary>
/// The resources (MCP design, "Ресурсы и промты"): the skills nfqws2-lua, nfqws2-engine and dpi-diagnostics as
/// <c>ztuner://skills/&lt;name&gt;</c>, and <c>ztuner://trials/&lt;id&gt;/capture</c> for a trial that was captured. Only
/// these URIs exist: nothing maps a URI to a file.
/// </summary>
public static class McpResources
{
    public static readonly IReadOnlyList<(string Name, string Title, string Description)> Skills =
    [
        ("nfqws2-lua", "zapret2 Lua library", "Every --lua-desync function, its arguments and defaults, fooling, markers, blobs, orchestrators: read before writing a strategy."),
        ("nfqws2-engine", "nfqws2 / winws2 engine", "The engine's options, profiles, ranges, payloads and limits (the program builds the engine options itself)."),
        ("dpi-diagnostics", "DPI diagnostics", "How AutoTuner classifies blocks, what counts as success (L2/L3), how the search and refinement work."),
    ];

    public static string SkillUri(string name) => "ztuner://skills/" + name;

    public static string CaptureUri(string trialId) => $"ztuner://trials/{trialId}/capture";

    public static IReadOnlyList<McpResource> List(McpSession session) =>
    [
        .. Skills.Select(s => new McpResource(SkillUri(s.Name), s.Name, s.Title, s.Description, "text/markdown")),
        .. session.Trials.Where(t => t.Pcap is not null).Select(t => new McpResource(CaptureUri(t.Id), t.Id + "-capture", $"Capture of {t.Id}",
            $"Packets of trial {t.Id} ({t.Target}): flows, ClientHello, RSTs, the first packets each way. No payload.", "application/json")),
    ];

    /// <summary>The text of a resource, or null when there is no such URI.</summary>
    public static (string Text, string MimeType)? Read(McpSession session, string uri)
    {
        foreach (var s in Skills)
        {
            if (uri == SkillUri(s.Name))
                return (Skill(s.Name), "text/markdown");
        }
        const string prefix = "ztuner://trials/", suffix = "/capture";
        if (uri.StartsWith(prefix, StringComparison.Ordinal) && uri.EndsWith(suffix, StringComparison.Ordinal))
        {
            var id = uri[prefix.Length..^suffix.Length];
            if (session.Trial(id) is { Pcap: { } pcap } t)
                return (CaptureSummary(t.Target, pcap).ToJsonString(), "application/json");
        }
        return null;
    }

    public static string Skill(string name)
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream($"ZapretAutoTuner.Mcp.skills.{name}.md")
            ?? throw new InvalidOperationException($"skill {name} is not embedded");
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }

    /// <summary>The deeper look at a trial: every flow to the target, more packets each way.</summary>
    internal static JsonObject CaptureSummary(string target, byte[] pcap)
    {
        var packets = PcapReader.Read(pcap);
        var flows = FlowAnalyzer.Analyze(packets);
        return new JsonObject
        {
            ["target"] = target,
            ["packets"] = packets.Count,
            ["flows"] = new JsonArray([.. flows.Take(12).Select(f => (JsonNode)new JsonObject
            {
                ["protocol"] = f.Protocol,
                ["server"] = $"{f.Server.Address}:{f.Server.Port}",
                ["sni"] = f.ClientHello?.Sni,
                ["out_packets"] = f.PacketsOut,
                ["out_bytes"] = f.BytesOut,
                ["in_packets"] = f.PacketsIn,
                ["in_bytes"] = f.BytesIn,
                ["handshake_rtt_ms"] = Observation.Ms(f.HandshakeRtt),
                ["retransmissions"] = f.Retransmissions,
                ["rsts"] = f.Rsts.Count,
            })]),
            ["detail"] = Observation.Wire(packets, 443, maxPackets: 48),
        };
    }
}

/// <summary>The prompt "подобрать стратегию для X": the safe order of the tools.</summary>
public static class McpPrompts
{
    public const string TuneName = "tune_strategy";

    public static string Tune(string target) => $"""
        Подбери стратегию zapret2 для {target} с помощью инструментов AutoTuner. / Find a zapret2 strategy for {target} with the AutoTuner tools.

        1. targets_list: the target must be in the user's list; if it is not, target_add asks the user (wait for the decision).
        2. diagnose with refresh=true: what blocks it. A strategy is tried only when the verdict says search (rule: success is a full download, L2/L3, on a resource shown blocked).
        3. Read ztuner://skills/dpi-diagnostics and ztuner://skills/nfqws2-lua; catalog_functions for exact arguments.
        4. kb_query and trials_history: what already worked here and on this provider.
        5. Either search_start (the Runner, poll search_status; put your own candidates first with search_enqueue) or trial_run for a causal fix
           after reading the observation (RST TTL, where it stopped, the 16 KB cut-off). Check strategies with strategy_validate first.
        6. Optionally strategy_experiment_start on live traffic (the user confirms), then export_preview. Applying is the user's decision.

        Only --lua-desync with catalog functions; no custom Lua. Keep trials few: there is a budget and the provider may punish the address.
        """;
}
