using System.Globalization;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Search;

namespace ZapretAutoTuner.Bench;

/// <summary>How the simulated DPI breaks a connection it blocks (what the probe and the classifier see).</summary>
public enum SimFailure
{
    /// <summary>An injected RST right after the ClientHello.</summary>
    Reset,

    /// <summary>The ClientHello is dropped: the handshake times out.</summary>
    Drop,

    /// <summary>TLS opens, the download stops at about 16 KB.</summary>
    Cutoff,
}

/// <summary>
/// One simulated DPI (PLAN 4a.3, MCP M6): the block the classifier reports with its evidence, and the hidden rule that
/// decides which strategies get through (a success rate per strategy; 0 &lt; rate &lt; 1 is a flaky, balanced DPI).
/// Scenarios of one provider (<see cref="Asn"/>) share a DPI vendor, so what was learned on one helps on its
/// siblings; a scenario alone on its ASN is "cold" for the learned order.
/// </summary>
public sealed record BenchScenario(string Id, int Asn, BlockLabel Primary, IReadOnlyList<BlockLabel> Labels, SimFailure Failure, string Evidence, string Hidden,
    Func<Strategy, double> Rule)
{
    public string Host => Id + ".bench.test";

    /// <summary>The label the knowledge base and the learned order use (the verdict's primary label).</summary>
    public string Label => Primary.ToString();

    public GeneratorOptions Generator(SearchMode mode) => new() { Mode = mode, Labels = [.. Labels] };

    public override string ToString() => Id;
}

/// <summary>The scenario set: four providers with two or three DPIs each and two cold ones.</summary>
public static class BenchScenarios
{
    private const string White = "www.google.com";

    public static IReadOnlyList<BenchScenario> All { get; } =
    [
        // provider A: a DPI that does not reassemble the ClientHello
        new("a-split-midsld", 64501, BlockLabel.SniBlock, [BlockLabel.SniBlock], SimFailure.Reset,
            "RST right after the ClientHello, injected (its TTL differs from the server's)",
            "a split in the middle of the SNI's second-level domain passes",
            s => Calls(s, "multisplit", "multidisorder").Any(c => Pos(c, "midsld")) ? 1 : 0),
        new("a-disorder", 64501, BlockLabel.SniBlock, [BlockLabel.SniBlock], SimFailure.Reset,
            "RST right after the ClientHello, injected (its TTL differs from the server's)",
            "multidisorder at midsld or sniext passes; any multisplit gets through 40% of the time",
            s => Calls(s, "multidisorder").Any(c => Pos(c, "midsld") || Pos(c, "sniext")) ? 1 : Calls(s, "multisplit").Any() ? 0.4 : 0),
        new("a-unstable", 64501, BlockLabel.SniBlock, [BlockLabel.SniBlock, BlockLabel.Unstable], SimFailure.Reset,
            "RST after the ClientHello in about half of the attempts",
            "two DPI boxes behind a balancer: a midsld split passes one of them (60%), a split with a sequence overlap passes both",
            s => Calls(s, "multisplit", "multidisorder").Any(c => c.Has("seqovl")) ? 1 : Calls(s, "multisplit", "multidisorder").Any(c => Pos(c, "midsld")) ? 0.6 : 0),

        // provider B: a reassembling DPI that a fake with a bad MD5 option desynchronises
        new("b-fake-md5", 64502, BlockLabel.SniBlock, [BlockLabel.SniBlock], SimFailure.Reset,
            "RST after the ClientHello, also when the ClientHello is split",
            "splits are reassembled; a fake ClientHello with tcp_md5 (the server drops it) desynchronises the DPI",
            s => Calls(s, "fake").Any(Md5) ? 1 : 0),
        new("b-fake-md5-white", 64502, BlockLabel.SniBlock, [BlockLabel.SniBlock], SimFailure.Reset,
            "RST after the ClientHello, also when the ClientHello is split",
            "as b-fake-md5, but the default fake is recognised: only the white hello with tcp_md5 works",
            s => Calls(s, "fake").Any(c => Md5(c) && c["blob"] == "tls_white") ? 1 : 0),
        new("b-fake-split", 64502, BlockLabel.SniBlock, [BlockLabel.SniBlock], SimFailure.Reset,
            "RST after the ClientHello, also when the ClientHello is split",
            "a fake with tcp_md5 works only when a split of the real ClientHello follows it",
            s => Calls(s, "fake").Any(Md5) && Calls(s, "multisplit", "multidisorder", "fakedsplit", "fakeddisorder").Any() ? 1 : 0),

        // provider C: the server checks MD5 and sequence numbers, the DPI sits a few hops away
        new("c-ttl", 64503, BlockLabel.SniBlock, [BlockLabel.SniBlock], SimFailure.Drop,
            "ClientHello dropped: no ServerHello, the handshake times out",
            "only a fake with a low TTL (autottl or ttl <= 6) reaches the DPI and not the server",
            s => Calls(s, "fake").Any(c => Ttl(c, 6)) ? 1 : 0),
        new("c-ttl-white", 64503, BlockLabel.SniBlock, [BlockLabel.SniBlock], SimFailure.Drop,
            "ClientHello dropped: no ServerHello, the handshake times out",
            "a low-TTL fake that also carries the white hello",
            s => Calls(s, "fake").Any(c => Ttl(c, 6) && c["blob"] == "tls_white") ? 1 : 0),

        // provider D: a volume cut-off with an SNI whitelist
        new("d-cutoff-white", 64504, BlockLabel.Cutoff16K, [BlockLabel.Cutoff16K], SimFailure.Cutoff,
            "TLS opens, the download stops at about 16 KB",
            "anything that shows the DPI a white SNI first: the white hello fake, tls_mod sni=, hostfakesplit with a white host",
            s => s.Calls.Any(c => c["blob"] == "tls_white" || (c["tls_mod"]?.Contains("sni=", StringComparison.Ordinal) ?? false) || (c.Function == "hostfakesplit" && c["host"] == White)) ? 1 : 0),
        new("d-cutoff-hostfake", 64504, BlockLabel.Cutoff16K, [BlockLabel.Cutoff16K], SimFailure.Cutoff,
            "TLS opens, the download stops at about 16 KB",
            "only hostfakesplit with a white host",
            s => Calls(s, "hostfakesplit").Any(c => c["host"] == White) ? 1 : 0),

        // cold: alone on their provider
        new("e-wssize", 64505, BlockLabel.SniBlock, [BlockLabel.SniBlock], SimFailure.Reset,
            "RST after the ClientHello",
            "only a tiny TCP window (wssize) passes",
            s => Calls(s, "wssize").Any() ? 1 : 0),
        new("e-none", 64506, BlockLabel.SniBlock, [BlockLabel.SniBlock], SimFailure.Drop,
            "ClientHello dropped: no ServerHello, the handshake times out",
            "nothing in the standard set works (a VPN or another address is needed)",
            _ => 0),
    ];

    /// <summary>Scenarios by id, in the given order; an unknown id throws.</summary>
    public static IReadOnlyList<BenchScenario> Select(IEnumerable<string> ids) =>
        [.. ids.Select(id => All.FirstOrDefault(s => s.Id == id) ?? throw new ArgumentException($"unknown scenario {id}; known: {string.Join(", ", All.Select(s => s.Id))}"))];

    /// <summary>A scenario with a sibling on its provider: the learned order has something relevant to start from.</summary>
    public static bool Warm(BenchScenario s, IReadOnlyList<BenchScenario> set) => set.Any(o => o != s && o.Asn == s.Asn);

    private static IEnumerable<LuaCall> Calls(Strategy s, params string[] functions) => s.Calls.Where(c => functions.Contains(c.Function));

    private static bool Pos(LuaCall c, string marker) => c["pos"] is { } p && p.Split(',').Any(x => x.StartsWith(marker, StringComparison.Ordinal));

    private static bool Md5(LuaCall c) => c.Has("tcp_md5");

    private static bool Ttl(LuaCall c, int max) =>
        c.Has("ip_autottl") || (c["ip_ttl"] is { } t && int.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ttl) && ttl <= max);
}
