using ZapretAutoTuner.Agent.Os;
using ZapretAutoTuner.Core.Engine;

namespace ZapretAutoTuner.Agent.Firewall;

/// <summary>A way to send traffic to NFQUEUE on Linux.</summary>
internal interface IFirewallBackend
{
    string Name { get; }

    /// <summary>Replaces all AutoTuner rules with <paramref name="rules"/>. Returns an error text or null.</summary>
    string? Apply(IReadOnlyList<NftQueueRule> rules, uint fwmark);

    /// <summary>Removes all AutoTuner rules; safe when none exist.</summary>
    void Remove();
}

/// <summary>nftables: one table <c>inet ztuner</c>, replaced atomically by <c>nft -f -</c>.</summary>
internal sealed class NftBackend : IFirewallBackend
{
    private readonly string _nft;

    public NftBackend(string nft)
    {
        _nft = nft;
    }

    public string Name => "nft";

    public string? Apply(IReadOnlyList<NftQueueRule> rules, uint fwmark)
    {
        var r = Cmd.Run(_nft, ["-f", "-"], NftRuleset.Build(rules, fwmark));
        return r.Ok ? null : "nft: " + r.Output;
    }

    public void Remove() => Cmd.Run(_nft, ["-f", "-"], NftRuleset.BuildRemove());
}

/// <summary>iptables/ip6tables with own chains in mangle (fallback when nft or its queue module is missing).</summary>
internal sealed class IptablesBackend : IFirewallBackend
{
    private readonly string _ipt;
    private readonly string? _ip6t;

    public IptablesBackend(string ipt, string? ip6t)
    {
        _ipt = ipt;
        _ip6t = ip6t;
    }

    public string Name => "iptables";

    public string? Apply(IReadOnlyList<NftQueueRule> rules, uint fwmark)
    {
        foreach (var (tool, v6) in Families())
        {
            var restore = tool + "-restore";
            var r = Cmd.Run(restore, ["--noflush"], IptablesRuleset.Build(rules, v6, fwmark));
            if (!r.Ok)
            {
                // ip6tables may be unusable (IPv6 disabled); IPv4 must work
                if (v6 && !rules.Any(x => x.Targets.Any(t => t.AddressFamily == global::System.Net.Sockets.AddressFamily.InterNetworkV6)))
                    continue;
                return $"{Path.GetFileName(restore)}: {r.Output}";
            }
            foreach (var (chain, target) in IptablesRuleset.JumpRules)
            {
                if (!Cmd.Run(tool, ["-t", "mangle", "-C", chain, "-j", target]).Ok)
                {
                    var add = Cmd.Run(tool, ["-t", "mangle", "-I", chain, "1", "-j", target]);
                    if (!add.Ok)
                        return $"{Path.GetFileName(tool)}: {add.Output}";
                }
            }
        }
        return null;
    }

    public void Remove()
    {
        foreach (var (tool, _) in Families())
        {
            foreach (var (chain, target) in IptablesRuleset.JumpRules)
            {
                // the jump could have been inserted twice by an older run
                for (int i = 0; i < 8 && Cmd.Run(tool, ["-t", "mangle", "-D", chain, "-j", target]).Ok; i++)
                {
                }
                Cmd.Run(tool, ["-t", "mangle", "-F", target]);
                Cmd.Run(tool, ["-t", "mangle", "-X", target]);
            }
        }
    }

    private IEnumerable<(string Tool, bool V6)> Families()
    {
        yield return (_ipt, false);
        if (_ip6t is not null)
            yield return (_ip6t, true);
    }
}

/// <summary>
/// Keeps the union of queue rules of all running engines in the firewall. Tries nftables first and falls back to
/// iptables when nft is missing or rejects the ruleset (no <c>nft_queue</c> module, old kernel).
/// </summary>
internal sealed class FirewallManager
{
    private readonly Lock _lock = new();
    private readonly Dictionary<string, NftQueueRule> _rules = [];
    private readonly List<IFirewallBackend> _candidates;
    private readonly AgentStateStore _state;
    private readonly Sysctl _sysctl;
    private readonly uint _fwmark;
    private IFirewallBackend? _active;

    public FirewallManager(AgentStateStore state, Sysctl sysctl, uint fwmark, IEnumerable<IFirewallBackend>? backends = null)
    {
        _state = state;
        _sysctl = sysctl;
        _fwmark = fwmark;
        _candidates = backends?.ToList() ?? DetectBackends();
    }

    public string BackendName => _active?.Name ?? (_candidates.Count > 0 ? _candidates[0].Name : "none");

    public static List<IFirewallBackend> DetectBackends()
    {
        var list = new List<IFirewallBackend>();
        if (!OperatingSystem.IsLinux())
            return list;
        if (Cmd.Which("nft") is { } nft)
            list.Add(new NftBackend(nft));
        if (Cmd.Which("iptables") is { } ipt)
            list.Add(new IptablesBackend(ipt, Cmd.Which("ip6tables")));
        return list;
    }

    /// <summary>Adds or replaces the rule of one engine. Returns an error text or null.</summary>
    public string? Set(string owner, NftQueueRule rule)
    {
        lock (_lock)
        {
            _rules[owner] = rule;
            var err = ApplyLocked();
            if (err is not null)
            {
                _rules.Remove(owner);
                ApplyLocked();
                return err;
            }
            foreach (var p in _sysctl.Apply(NftRuleset.RequiredSysctls))
                Console.Error.WriteLine(p);
            return null;
        }
    }

    public void Unset(string owner)
    {
        lock (_lock)
        {
            if (_rules.Remove(owner))
                ApplyLocked();
        }
    }

    /// <summary>Removes the rules of every backend (also leftovers of an older run with another backend).</summary>
    public void RemoveAll()
    {
        lock (_lock)
        {
            _rules.Clear();
            foreach (var b in _candidates)
                b.Remove();
            _active = null;
            _state.Update(s => s.FirewallBackend = null);
        }
    }

    private string? ApplyLocked()
    {
        if (_rules.Count == 0)
        {
            _active?.Remove();
            return null;
        }
        if (_candidates.Count == 0)
            return "не найден ни nft, ни iptables: установите пакет nftables";
        var rules = _rules.Values.ToList();
        if (_active is not null)
            return _active.Apply(rules, _fwmark);
        var errors = new List<string>();
        foreach (var b in _candidates)
        {
            _state.Update(s => s.FirewallBackend = b.Name);
            var err = b.Apply(rules, _fwmark);
            if (err is null)
            {
                _active = b;
                return null;
            }
            b.Remove();
            errors.Add(err);
        }
        _state.Update(s => s.FirewallBackend = null);
        return string.Join("; ", errors);
    }
}
