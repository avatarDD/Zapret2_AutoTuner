using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Packets;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// What the model sees after a trial (MCP design, "Что модель видит после испытания"): the level reached, bytes, time,
/// what went out and what came back, the classifier's reading. Never a page body or HTML, only status, size and a hash:
/// a blocked site or a provider's stub page could otherwise put instructions in front of the model.
/// </summary>
public static class Observation
{
    public const int MaxPackets = 16;

    /// <summary>The highest level an attempt reached (dpi-diagnostics §3; L0 is a TCP connect).</summary>
    public static string LevelOf(ProbeResult r, long minBytes)
    {
        if (r.Passes(ProbeLevel.L2Body, minBytes))
            return "L2";
        if (r.Passes(ProbeLevel.L1Handshake, minBytes))
            return "L1";
        return r.ConnectOk ? "L0" : "none";
    }

    /// <summary>The classifier's reading of one attempt in a word, as dpi-diagnostics §2 names the blocks.</summary>
    public static string ReadingOf(ProbeResult r, long minBytes)
    {
        if (r.Passes(ProbeLevel.L2Body, minBytes))
            return "ok";
        return r.Error switch
        {
            ProbeError.ConnectTimeout or ProbeError.Unreachable => "no_tcp_connect (IP block or punishment)",
            ProbeError.ConnectRefused => "connect_refused",
            ProbeError.TlsReset when r.RstOrigin == Core.Diagnostics.RstOrigin.Injected => "dpi_reset_on_client_hello",
            ProbeError.TlsReset => "reset_on_client_hello",
            ProbeError.TlsTimeout => "client_hello_blackholed",
            ProbeError.HttpReset when r.RstOrigin == Core.Diagnostics.RstOrigin.Injected => "dpi_reset_after_handshake",
            ProbeError.HttpReset => "reset_after_handshake",
            ProbeError.Stalled when r.StalledAt is >= Classifier.CutoffMin and <= Classifier.CutoffMax => "cutoff_16k (volume cut-off)",
            ProbeError.Stalled => "stalled",
            ProbeError.Truncated => "truncated",
            ProbeError.TimeLimit => "too_slow",
            ProbeError.HttpTimeout => "no_http_response",
            _ when r.TlsOk && !r.CertValid => "wrong_certificate (a stub or interception)",
            _ when r.HttpStatus is >= 300 and < 400 => "redirect (a stub page?)",
            _ when r.HttpStatus is not null && r.BodyBytes < minBytes => "small_response",
            _ => r.Error.ToString().ToLowerInvariant(),
        };
    }

    public static JsonObject Attempt(int n, ProbeResult r, long minBytes) => new()
    {
        ["n"] = n,
        ["level"] = LevelOf(r, minBytes),
        ["reading"] = ReadingOf(r, minBytes),
        ["error"] = r.Error == ProbeError.None ? null : r.Error.ToString(),
        ["detail"] = Short(r.ErrorDetail ?? r.CertError, 160),
        ["http_status"] = r.HttpStatus,
        ["body_bytes"] = r.BodyBytes,
        ["body_sha256"] = r.BodySha256,
        ["bytes_out"] = r.BytesOut,
        ["stalled_at"] = r.StalledAt,
        ["rst"] = r.RstSeen ? r.RstOrigin.ToString() : null,
        ["tls"] = r.TlsVersion,
        ["connect_ms"] = Ms(r.ConnectTime),
        ["ttfb_ms"] = Ms(r.Ttfb),
        ["time_ms"] = (long)r.Duration.TotalMilliseconds,
    };

    /// <summary>A page load in a real browser: counts and failures by host, no content.</summary>
    public static JsonObject Page(PageLoad p)
    {
        var failed = p.Requests.Where(r => r.Error is not null || r.Status >= 400).ToList();
        return new JsonObject
        {
            ["loaded"] = p.LoadFired && p.Error is null,
            ["load_ms"] = Ms(p.LoadTime),
            ["requests"] = p.Requests.Count,
            ["bytes"] = p.Requests.Sum(r => r.Bytes),
            ["failed"] = new JsonArray([.. failed.GroupBy(r => r.Host).Take(10).Select(g => (JsonNode)new JsonObject
            {
                ["host"] = g.Key,
                ["count"] = g.Count(),
                ["error"] = Short(g.First().Error ?? $"HTTP {g.First().Status}", 80),
            })]),
            ["error"] = Short(p.Error, 160),
        };
    }

    /// <summary>
    /// "Что ушло, что пришло" from the capture: the ClientHello's shape, the first packets each way (offset, length, TTL,
    /// IP ID, flags), the RSTs with their origin, retransmissions. Payload bytes never leave this method.
    /// </summary>
    public static JsonObject Wire(IReadOnlyList<CapturedPacket> packets, int port, int maxPackets = MaxPackets)
    {
        var flows = FlowAnalyzer.Analyze(packets).Where(f => f.Server.Port == port).ToList();
        var flow = flows.FirstOrDefault(f => f.Rsts.Count > 0 || f.BytesIn < 16 * 1024) ?? flows.FirstOrDefault();
        var o = new JsonObject { ["flows"] = flows.Count };
        if (flow is null)
            return o;
        if (flow.ClientHello is { } ch)
        {
            o["client_hello"] = new JsonObject
            {
                ["sni"] = ch.Sni,
                ["segments"] = flow.ClientHelloSegments,
                ["extensions"] = ch.Extensions.Count,
                ["alpn"] = string.Join(",", ch.Alpn),
                ["ech"] = ch.Extensions.Contains(Core.Packets.TlsClientHello.ExtEch),
            };
        }
        var outList = new JsonArray();
        var inList = new JsonArray();
        uint? clientIsn = null, serverIsn = null;
        DateTime? t0 = null;
        foreach (var cp in packets)
        {
            if (cp.Parse() is not { IsTcp: true } ip)
                continue;
            bool outgoing = Equals(ip.Destination, flow.Server.Address) && ip.DestinationPort == flow.Server.Port && ip.SourcePort == flow.Client.Port;
            bool incoming = Equals(ip.Source, flow.Server.Address) && ip.SourcePort == flow.Server.Port && ip.DestinationPort == flow.Client.Port;
            if (!outgoing && !incoming)
                continue;
            t0 ??= cp.TimestampUtc;
            if (ip.Has(TcpFlags.Syn))
            {
                if (outgoing)
                    clientIsn = ip.Seq;
                else
                    serverIsn = ip.Seq;
            }
            var list = outgoing ? outList : inList;
            if (list.Count >= maxPackets)
                continue;
            uint? isn = outgoing ? clientIsn : serverIsn;
            list.Add((JsonNode)new JsonObject
            {
                ["t_ms"] = (long)(cp.TimestampUtc - t0.Value).TotalMilliseconds,
                ["flags"] = Flags(ip.Flags),
                ["seq_off"] = isn is { } i ? (long)unchecked(ip.Seq - i - 1) : null,
                ["len"] = ip.Payload.Length,
                ["ttl"] = ip.Ttl,
                ["ip_id"] = ip.IpId,
            });
        }
        o["sent"] = new JsonObject { ["packets"] = flow.PacketsOut, ["bytes"] = flow.BytesOut, ["first"] = outList };
        o["received"] = new JsonObject
        {
            ["packets"] = flow.PacketsIn,
            ["bytes"] = flow.BytesIn,
            ["syn_ack_ttl"] = flow.SynAckTtl,
            ["retransmissions"] = flow.Retransmissions,
            ["rsts"] = new JsonArray([.. flow.Rsts.Take(4).Select(r => (JsonNode)new JsonObject
            {
                ["ttl"] = r.Ttl,
                ["ip_id"] = r.IpId,
                ["from_server"] = r.FromServer,
                ["origin"] = r.Origin.ToString(),
                ["why"] = string.Join("; ", r.Reasons),
            })]),
            ["first"] = inList,
        };
        return o;
    }

    private static string Flags(TcpFlags f)
    {
        var s = "";
        if ((f & TcpFlags.Syn) != 0)
            s += "S";
        if ((f & TcpFlags.Ack) != 0)
            s += "A";
        if ((f & TcpFlags.Psh) != 0)
            s += "P";
        if ((f & TcpFlags.Fin) != 0)
            s += "F";
        if ((f & TcpFlags.Rst) != 0)
            s += "R";
        return s;
    }

    public static long? Ms(TimeSpan? t) => t is { } v ? (long)v.TotalMilliseconds : null;

    public static string? Short(string? s, int max) => s is null ? null : s.Length <= max ? s : s[..max] + "…";

    public static double Median(IEnumerable<double> values)
    {
        var v = values.Order().ToList();
        return v.Count == 0 ? 0 : v.Count % 2 == 1 ? v[v.Count / 2] : (v[v.Count / 2 - 1] + v[v.Count / 2]) / 2;
    }

    public static string Num(double d) => d.ToString("0.###", CultureInfo.InvariantCulture);

    internal static bool SameAddress(IPAddress a, IPAddress b) => a.Equals(b);
}
