using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Programs;

namespace ZapretAutoTuner.Core.Geneva.Auto;

/// <summary>
/// The passive half of the "Авто" mode: turns a capture slice of the whole PC into samples, one per flow, each
/// attributed to its service. Only headers, the ClientHello and the first client payload are read (dpi-diagnostics
/// §8–9). LAN, loopback, multicast and the search's own probes (geneva's block of local ports) are left out.
/// </summary>
public static class AutoObserver
{
    public static List<AutoSample> Observe(IReadOnlyList<Flow> flows, DateTime captureEnd, IReadOnlyDictionary<IPAddress, string>? dnsNames = null)
    {
        var samples = new List<AutoSample>();
        foreach (var f in flows)
        {
            if (Sample(f, captureEnd, dnsNames) is { } s)
                samples.Add(s);
        }
        return samples;
    }

    /// <summary>The flow as a sample, or null when it is not the user's internet traffic or too young to judge.</summary>
    public static AutoSample? Sample(Flow f, DateTime captureEnd, IReadOnlyDictionary<IPAddress, string>? dnsNames = null)
    {
        var server = Norm(f.Server);
        if (!ProgramEndpoints.IsInternet(server.Address) || IsProbePort(f.Client.Port))
            return null;
        var transport = f.Protocol == "udp" ? L4Kind.Udp : L4Kind.Tcp;
        var first = f.InitialPayloadsOut.Count > 0 ? f.InitialPayloadsOut[0] : [];
        var app = AppName(f, first);
        var name = f.ClientHello?.Sni;
        if (string.IsNullOrEmpty(name))
            name = dnsNames?.GetValueOrDefault(server.Address);
        name = string.IsNullOrEmpty(name) ? null : name.TrimEnd('.').ToLowerInvariant();

        AutoKind kind;
        string key, shown;
        if (app == "dht")
        {
            // a DHT node asks hundreds of peers from its one port: the port is the service
            kind = AutoKind.LocalPort;
            key = $"port:{Lower(transport)}:{f.Client.Port.ToString(CultureInfo.InvariantCulture)}";
            shown = $"DHT ({Lower(transport).ToUpperInvariant()} {f.Client.Port.ToString(CultureInfo.InvariantCulture)})";
        }
        else if (server.Port == 53 || app == "dns")
        {
            kind = AutoKind.Dns;
            key = "dns:" + server.Address;
            shown = "DNS " + server.Address;
        }
        else if (transport == L4Kind.Tcp && name is not null && (app is "tls" or "http" || server.Port is 443 or 80))
        {
            kind = AutoKind.Web;
            var site = Classifier.Registrable(name);
            key = "web:" + site;
            shown = site;
        }
        else if (transport == L4Kind.Udp && name is not null && app == "quic")
        {
            kind = AutoKind.Quic;
            var site = Classifier.Registrable(name);
            key = "quic:" + site;
            shown = site + " (QUIC)";
        }
        else
        {
            kind = AutoKind.Endpoint;
            var ep = server.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? $"[{server.Address}]:{server.Port.ToString(CultureInfo.InvariantCulture)}"
                : $"{server.Address}:{server.Port.ToString(CultureInfo.InvariantCulture)}";
            key = $"ep:{app}:{Lower(transport)}:{ep}";
            shown = $"{AppTitle(app)} {(name is null ? ep : name + " (" + ep + ")")}";
        }

        if (Judge(f, captureEnd, kind) is not { } judged)
            return null;
        var (health, why) = judged;
        var replay = kind is AutoKind.Web or AutoKind.LocalPort || f.InitialPayloadsTruncated
            || !CanReplay(app, f.AppProtocol, f.InitialPayloadsOut)
            ? (IReadOnlyList<byte[]>)[]
            : f.InitialPayloadsOut.Select(p => p.ToArray()).ToList();
        return new AutoSample
        {
            Key = key,
            Kind = kind,
            Transport = transport,
            Name = shown,
            Host = name,
            App = app,
            Server = server,
            LocalPort = f.Client.Port,
            Time = f.FirstSeen,
            Health = health,
            Why = why,
            Replay = replay,
        };
    }

    /// <summary>How the flow went; null when it says nothing yet (too young, too little traffic).</summary>
    public static (AutoHealth Health, string Why)? Judge(Flow f, DateTime captureEnd, AutoKind kind)
    {
        if (f.Protocol == "tcp" && f.SynTime is { } syn && f.SynAckTime is null)
        {
            // the SYN was sent again and nothing came back: no connection at all
            return f.PacketsOut >= 2 && captureEnd - syn >= TimeSpan.FromSeconds(3) && f.PacketsIn == 0
                ? (AutoHealth.NoConnection, "соединение не устанавливается")
                : null;
        }
        if (kind == AutoKind.LocalPort)
        {
            // one question to one peer: an answer is a success, silence after a few seconds a failure
            if (f.PacketsIn > 0)
                return (AutoHealth.Ok, "");
            return f.PacketsOut > 0 && captureEnd - f.FirstSeen >= TimeSpan.FromSeconds(5) ? (AutoHealth.Failed, "нет ответа") : null;
        }
        if (f.Protocol == "udp")
        {
            // request and answer: one datagram back is an answer (a DNS reply, a WireGuard handshake response);
            // silence counts once the client asked again, or for DNS once its usual retry time passed
            if (f.PacketsIn > 0)
                return (AutoHealth.Ok, "");
            int asked = kind == AutoKind.Dns ? 1 : 2;
            return f.PacketsOut >= asked && captureEnd - f.FirstSeen >= TimeSpan.FromSeconds(5) ? (AutoHealth.Failed, "запросы без ответа") : null;
        }
        return FlowVerdict.Judge(f, captureEnd) switch
        {
            FlowHealth.Ok => (AutoHealth.Ok, ""),
            FlowHealth.Reset => (AutoHealth.Failed, "сброс (RST) не от сервера"),
            FlowHealth.Stalled => (AutoHealth.Failed, "соединение есть, данных нет"),
            FlowHealth.Cutoff => (AutoHealth.Failed, "обрыв на 16 КБ"),
            FlowHealth.NoReply => (AutoHealth.Failed, "запросы без ответа"),
            _ => null,
        };
    }

    /// <summary>
    /// The protocols whose first client message is a handshake that any server answers again and that carries nothing
    /// of the user's: a TLS, QUIC or DTLS hello, a DNS question, a STUN binding request, OpenVPN's hard reset, MTProto's
    /// obfuscated init. Anything else (plain HTTP with its cookies, an unknown protocol that may log in) is neither
    /// kept on disk nor sent again: its service is judged by its own traffic.
    /// </summary>
    public static IReadOnlySet<string> ReplayableApps { get; } = new HashSet<string>(StringComparer.Ordinal) { "tls", "quic", "dtls", "dns", "stun", "openvpn", "mtproto" };

    /// <summary>
    /// Whether the client's first packets, sent again, show a working strategy: stateless first messages are answered
    /// by any server (dpi-diagnostics §8); WireGuard drops a replayed handshake, Discord and ICE are session-bound, and
    /// only the handshakes of <see cref="ReplayableApps"/> are replayed at all.
    /// </summary>
    public static bool CanReplay(string app, AppProtocol detected, IReadOnlyList<byte[]> payloads)
    {
        if (payloads.Count == 0 || !ReplayableApps.Contains(app))
            return false;
        if (detected == AppProtocol.Stun)
            return !IsIceCheck(payloads[0]);
        return true;
    }

    /// <summary>A STUN request with the session's USERNAME or MESSAGE-INTEGRITY: a peer ignores a replay of it.</summary>
    private static bool IsIceCheck(ReadOnlySpan<byte> stun)
    {
        if (!ProtocolDetector.IsStun(stun))
            return false;
        int end = Math.Min(stun.Length, 20 + BinaryPrimitives.ReadUInt16BigEndian(stun[2..]));
        for (int pos = 20; pos + 4 <= end;)
        {
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(stun[pos..]);
            int len = BinaryPrimitives.ReadUInt16BigEndian(stun[(pos + 2)..]);
            if (type is 0x0006 or 0x0008 or 0x001C or 0x8029 or 0x802A)
                return true;
            pos += 4 + ((len + 3) & ~3);
        }
        return false;
    }

    /// <summary>The protocol by the first client payload: the engine's detector, then OpenVPN and DHT.</summary>
    public static string AppName(Flow f, ReadOnlySpan<byte> first)
    {
        if (f.Protocol == "udp" && IsDht(first))
            return "dht";
        if (IsOpenVpn(first, f.Protocol == "tcp"))
            return "openvpn";
        if (f.ClientHellos.Count > 0)
            return f.Protocol == "udp" ? "quic" : "tls";
        return f.AppProtocol switch
        {
            AppProtocol.Unknown => f.Protocol,
            var a => a.ToString().ToLowerInvariant(),
        };
    }

    /// <summary>
    /// OpenVPN's first packet: P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 7) or _V3 (10) with key id 0, then the 8-byte
    /// session id; over TCP after a 2-byte length.
    /// </summary>
    public static bool IsOpenVpn(ReadOnlySpan<byte> p, bool tcp)
    {
        if (tcp)
        {
            if (p.Length < 16 || BinaryPrimitives.ReadUInt16BigEndian(p) != p.Length - 2)
                return false;
            p = p[2..];
        }
        return p.Length >= 14 && (p[0] >> 3) is 7 or 10 && (p[0] & 7) == 0;
    }

    /// <summary>A Mainline DHT message (BEP 5): a bencoded dictionary with a query, a response or an error.</summary>
    public static bool IsDht(ReadOnlySpan<byte> p)
    {
        if (p.Length < 12 || p[0] != (byte)'d' || p[^1] != (byte)'e')
            return false;
        return p.IndexOf("1:y1:q"u8) >= 0 || p.IndexOf("1:y1:r"u8) >= 0 || p.IndexOf("1:y1:e"u8) >= 0;
    }

    /// <summary>The search's probes connect from geneva's block of local ports: not the user's traffic.</summary>
    public static bool IsProbePort(int port) => port >= GenevaArgv.LocalPortsBase && port < GenevaArgv.LocalPortsBase + GenevaArgv.LocalPortsCount;

    public static string AppTitle(string app) => app switch
    {
        "wireguard" => "WireGuard",
        "openvpn" => "OpenVPN",
        "dtls" => "DTLS",
        "stun" => "STUN",
        "mtproto" => "MTProto",
        "discord" => "Discord",
        "quic" => "QUIC",
        "tls" => "TLS",
        "http" => "HTTP",
        "dns" => "DNS",
        "dht" => "DHT",
        _ => app.ToUpperInvariant(),
    };

    private static string Lower(L4Kind t) => t == L4Kind.Udp ? "udp" : "tcp";

    private static IPEndPoint Norm(IPEndPoint e) => e.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(e.Address.MapToIPv4(), e.Port) : e;

    /// <summary>The payloads as text for the state file.</summary>
    public static string ToBase64(IReadOnlyList<byte[]> payloads) => string.Join(',', payloads.Select(Convert.ToBase64String));

    public static List<byte[]> FromBase64(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return [];
        try
        {
            return [.. text.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(Convert.FromBase64String)];
        }
        catch (FormatException)
        {
            return [];
        }
    }
}
