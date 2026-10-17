using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZapretAutoTuner.Agent.Os;

/// <summary>
/// What the Agent changed in the system, persisted so that a later Agent (or <c>--cleanup</c>) can undo it after a
/// crash: original sysctl values, the firewall backend in use, engine processes it started.
/// </summary>
internal sealed class AgentState
{
    public Dictionary<string, string> SysctlOriginals { get; set; } = [];

    public string? FirewallBackend { get; set; }

    public List<EngineRecord> Engines { get; set; } = [];

    public sealed record EngineRecord(int Pid, string Path, DateTime StartTimeUtc);
}

[JsonSerializable(typeof(AgentState))]
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
internal sealed partial class AgentJsonContext : JsonSerializerContext;

/// <summary>Atomic load/save of <see cref="AgentState"/> in the data directory.</summary>
internal sealed class AgentStateStore
{
    private readonly Lock _lock = new();

    public AgentStateStore(string dataDir)
    {
        Path = global::System.IO.Path.Combine(dataDir, "agent-state.json");
    }

    public string Path { get; }

    public AgentState Load()
    {
        lock (_lock)
        {
            try
            {
                if (File.Exists(Path))
                    return JsonSerializer.Deserialize(File.ReadAllText(Path), AgentJsonContext.Default.AgentState) ?? new AgentState();
            }
            catch (JsonException)
            {
            }
            return new AgentState();
        }
    }

    public void Update(Action<AgentState> change)
    {
        lock (_lock)
        {
            var s = Load();
            change(s);
            var tmp = Path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(s, AgentJsonContext.Default.AgentState));
            File.Move(tmp, Path, overwrite: true);
        }
    }

    public void Delete()
    {
        lock (_lock)
        {
            File.Delete(Path);
        }
    }
}
