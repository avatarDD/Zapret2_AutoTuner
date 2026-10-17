using System.Globalization;
using System.Net;

namespace ZapretAutoTuner.Core.Model;

public enum TargetKind
{
    /// <summary>A host name (from a domain or URL).</summary>
    Domain,

    /// <summary>A literal IP address, optionally with port.</summary>
    Ip,

    /// <summary>An IP network (CIDR).</summary>
    Cidr,

    /// <summary>A hosting provider from the provider catalog.</summary>
    Provider,

    /// <summary>An installed program.</summary>
    Program,
}

/// <summary>What the user wants to open: a site, an address, a network, a provider or a program.</summary>
public sealed record Target
{
    public required TargetKind Kind { get; init; }

    /// <summary>Host name, IP, CIDR, provider id or program id.</summary>
    public required string Value { get; init; }

    public int Port { get; init; } = 443;

    public L4Kind Protocol { get; init; } = L4Kind.Tcp;

    /// <summary>Path of a URL (with query), "/" if none.</summary>
    public string Path { get; init; } = "/";

    public string Scheme => Port == 80 ? "http" : "https";

    public string Url => $"{Scheme}://{HostForUrl}{(Port is 80 or 443 ? "" : ":" + Port.ToString(CultureInfo.InvariantCulture))}{Path}";

    private string HostForUrl => Kind == TargetKind.Ip && Value.Contains(':', StringComparison.Ordinal) ? "[" + Value + "]" : Value;

    public override string ToString() => Kind switch
    {
        TargetKind.Domain => Port == 443 && Protocol == L4Kind.Tcp ? Value : $"{Value}:{Port}/{Protocol.ToString().ToLowerInvariant()}",
        TargetKind.Ip => $"{HostForUrl}:{Port}/{Protocol.ToString().ToLowerInvariant()}",
        _ => Value,
    };

    /// <summary>
    /// Parses one line of the "what does not work" field: URL, domain, <c>host:port[/udp]</c>,
    /// IP, <c>[v6]:port</c> or CIDR. Returns null for empty or comment lines.
    /// </summary>
    public static Target? ParseInput(string line)
    {
        var s = line.Trim();
        if (s.Length == 0 || s[0] == '#')
            return null;

        var proto = L4Kind.Tcp;
        if (s.EndsWith("/udp", StringComparison.OrdinalIgnoreCase))
        {
            proto = L4Kind.Udp;
            s = s[..^4];
        }
        else if (s.EndsWith("/tcp", StringComparison.OrdinalIgnoreCase))
        {
            s = s[..^4];
        }

        if (s.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(s, UriKind.Absolute, out var uri) || uri.Host.Length == 0)
                throw new FormatException($"не удалось разобрать адрес: {line}");
            var host = uri.Host.Trim('[', ']');
            var kind = IPAddress.TryParse(host, out _) ? TargetKind.Ip : TargetKind.Domain;
            return new Target { Kind = kind, Value = NormalizeHost(host), Port = uri.Port, Protocol = proto, Path = uri.PathAndQuery };
        }

        int slash = s.IndexOf('/', StringComparison.Ordinal);
        if (slash > 0 && int.TryParse(s[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var bits)
            && IPAddress.TryParse(s[..slash], out var net))
        {
            int max = net.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
            if (bits > max)
                throw new FormatException($"неверная маска сети: {line}");
            return new Target { Kind = TargetKind.Cidr, Value = $"{net}/{bits}", Protocol = proto };
        }

        string path = "/";
        if (slash > 0)
        {
            path = s[slash..];
            s = s[..slash];
        }

        if (IPAddress.TryParse(s, out var ip) && !s.Contains(']', StringComparison.Ordinal) && (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 || !s.Contains(':', StringComparison.Ordinal)))
            return new Target { Kind = TargetKind.Ip, Value = ip.ToString(), Protocol = proto, Path = path };

        int port = 443;
        string hostPart = s;
        if (s.StartsWith('['))
        {
            int close = s.IndexOf(']', StringComparison.Ordinal);
            if (close < 0)
                throw new FormatException($"не удалось разобрать адрес: {line}");
            hostPart = s[1..close];
            var rest = s[(close + 1)..];
            if (rest.StartsWith(':'))
                port = ParsePort(rest[1..], line);
        }
        else
        {
            int colon = s.LastIndexOf(':');
            if (colon > 0)
            {
                hostPart = s[..colon];
                port = ParsePort(s[(colon + 1)..], line);
            }
        }

        if (IPAddress.TryParse(hostPart, out var ip2))
            return new Target { Kind = TargetKind.Ip, Value = ip2.ToString(), Port = port, Protocol = proto, Path = path };

        var normalized = NormalizeHost(hostPart);
        if (!IsValidHostName(normalized))
            throw new FormatException($"не похоже на имя сайта: {line}");
        return new Target { Kind = TargetKind.Domain, Value = normalized, Port = port, Protocol = proto, Path = path };
    }

    public static List<Target> ParseInputs(string text) =>
        text.Split('\n').Select(ParseInput).OfType<Target>().Distinct().ToList();

    private static int ParsePort(string s, string line)
    {
        if (!int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var p) || p is < 1 or > 65535)
            throw new FormatException($"неверный порт: {line}");
        return p;
    }

    private static string NormalizeHost(string host)
    {
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (h.Any(c => c > 127))
            h = new IdnMapping().GetAscii(h);
        return h;
    }

    public static bool IsValidHostName(string h)
    {
        if (h.Length is 0 or > 253 || !h.Contains('.', StringComparison.Ordinal))
            return false;
        foreach (var label in h.Split('.'))
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-')
                return false;
            if (!label.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
                return false;
        }
        return true;
    }
}
