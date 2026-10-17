namespace ZapretAutoTuner.Core.Model;

/// <summary>Reference to a hostlist or ipset: by name in the <see cref="Solution"/> or by literal path (imports).</summary>
public sealed record ListRef(string Name, string? Path = null)
{
    public override string ToString() => Path ?? Name;
}

public enum L4Kind
{
    Tcp,
    Udp,
}

/// <summary>
/// One nfqws2 profile (the part between <c>--new</c>): filters plus the <see cref="Strategy"/>.
/// Global options (<c>--blob</c>, <c>--lua-init</c>, <c>--qnum</c>, <c>--wf-*</c>) are never stored here.
/// </summary>
public sealed class Profile
{
    public string Name { get; set; } = "";

    /// <summary><c>ipv4</c>, <c>ipv6</c> or null for both.</summary>
    public string? L3 { get; set; }

    /// <summary><c>--filter-tcp</c> port list (nfqws2 syntax: <c>80,443,1000-2000</c>), null if not filtered by TCP.</summary>
    public string? TcpPorts { get; set; }

    /// <summary><c>--filter-udp</c> port list, null if not filtered by UDP.</summary>
    public string? UdpPorts { get; set; }

    public List<string> L7 { get; set; } = [];

    public List<ListRef> Hostlists { get; set; } = [];

    public List<string> HostlistDomains { get; set; } = [];

    public List<ListRef> HostlistExcludes { get; set; } = [];

    public List<ListRef> Ipsets { get; set; } = [];

    public List<string> IpsetIps { get; set; } = [];

    public List<ListRef> IpsetExcludes { get; set; } = [];

    public ListRef? HostlistAuto { get; set; }

    /// <summary>Other profile-level options kept verbatim (e.g. <c>--hostlist-auto-fail-threshold=3</c>).</summary>
    public List<string> ExtraOptions { get; set; } = [];

    public Strategy Strategy { get; set; } = new([]);

    public bool HasHostFilter => Hostlists.Count > 0 || HostlistDomains.Count > 0 || HostlistAuto is not null;

    public bool HasIpFilter => Ipsets.Count > 0 || IpsetIps.Count > 0;

    public IEnumerable<L4Kind> L4Kinds
    {
        get
        {
            if (TcpPorts is not null)
                yield return L4Kind.Tcp;
            if (UdpPorts is not null)
                yield return L4Kind.Udp;
        }
    }

    public Profile Clone() => new()
    {
        Name = Name,
        L3 = L3,
        TcpPorts = TcpPorts,
        UdpPorts = UdpPorts,
        L7 = [.. L7],
        Hostlists = [.. Hostlists],
        HostlistDomains = [.. HostlistDomains],
        HostlistExcludes = [.. HostlistExcludes],
        Ipsets = [.. Ipsets],
        IpsetIps = [.. IpsetIps],
        IpsetExcludes = [.. IpsetExcludes],
        HostlistAuto = HostlistAuto,
        ExtraOptions = [.. ExtraOptions],
        Strategy = Strategy,
    };

    /// <summary>
    /// Builds the profile's argv (no <c>--new</c>). <paramref name="listPath"/> maps a list reference
    /// to the path written into <c>--hostlist=</c>/<c>--ipset=</c>; by default the literal path or name.
    /// </summary>
    public List<string> ToArgs(Func<ListRef, bool, string>? listPath = null)
    {
        listPath ??= (r, _) => r.ToString();
        var a = new List<string>();
        if (Name.Length > 0)
            a.Add("--name=" + Name);
        if (L3 is not null)
            a.Add("--filter-l3=" + L3);
        if (TcpPorts is not null)
            a.Add("--filter-tcp=" + TcpPorts);
        if (UdpPorts is not null)
            a.Add("--filter-udp=" + UdpPorts);
        if (L7.Count > 0)
            a.Add("--filter-l7=" + string.Join(',', L7));
        foreach (var h in Hostlists)
            a.Add("--hostlist=" + listPath(h, false));
        if (HostlistDomains.Count > 0)
            a.Add("--hostlist-domains=" + string.Join(',', HostlistDomains));
        foreach (var h in HostlistExcludes)
            a.Add("--hostlist-exclude=" + listPath(h, false));
        if (HostlistAuto is not null)
            a.Add("--hostlist-auto=" + listPath(HostlistAuto, false));
        foreach (var s in Ipsets)
            a.Add("--ipset=" + listPath(s, true));
        if (IpsetIps.Count > 0)
            a.Add("--ipset-ip=" + string.Join(',', IpsetIps));
        foreach (var s in IpsetExcludes)
            a.Add("--ipset-exclude=" + listPath(s, true));
        a.AddRange(ExtraOptions);
        a.AddRange(Strategy.ToArgs());
        return a;
    }

    public override string ToString() => string.Join(' ', ToArgs());
}
