namespace ZapretAutoTuner.Agent.Os;

/// <summary>
/// Sets the sysctls the engine needs (nfqws2-engine §12) and restores the original values on cleanup. The
/// originals are written to the state file before the change, so a crashed Agent's changes are undone too.
/// </summary>
internal sealed class Sysctl
{
    private readonly AgentStateStore _state;
    private readonly string _root;

    public Sysctl(AgentStateStore state, string root = "/proc/sys")
    {
        _state = state;
        _root = root;
    }

    public string? Read(string key)
    {
        var f = Path.Combine(_root, key);
        return File.Exists(f) ? File.ReadAllText(f).Trim() : null;
    }

    /// <summary>Applies values, remembering originals that are not remembered yet. Returns problems.</summary>
    public List<string> Apply(IReadOnlyDictionary<string, string> values)
    {
        var problems = new List<string>();
        foreach (var (key, value) in values)
        {
            var cur = Read(key);
            if (cur is null)
            {
                // nf_conntrack not loaded yet: the module appears when the first ct rule is added
                problems.Add($"sysctl {key} недоступен");
                continue;
            }
            if (cur == value)
                continue;
            _state.Update(s => s.SysctlOriginals.TryAdd(key, cur));
            try
            {
                File.WriteAllText(Path.Combine(_root, key), value);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                problems.Add($"sysctl {key}={value}: {e.Message}");
            }
        }
        return problems;
    }

    /// <summary>Writes back every remembered original and forgets it.</summary>
    public void RestoreAll()
    {
        var originals = _state.Load().SysctlOriginals;
        foreach (var (key, value) in originals)
        {
            try
            {
                File.WriteAllText(Path.Combine(_root, key), value);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"restore sysctl {key}: {e.Message}");
            }
        }
        if (originals.Count > 0)
            _state.Update(s => s.SysctlOriginals.Clear());
    }
}
