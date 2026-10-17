using System.Globalization;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Search;

/// <summary>A child of a strategy that differs in one or two parameters, and what was changed.</summary>
public sealed record Mutation(Strategy Strategy, string What)
{
    public override string ToString() => $"{What}: {Strategy}";
}

/// <summary>
/// Mutations of the same family for refining a partly working strategy (dpi-diagnostics §6.2a.3): repeats, fooling,
/// TTL, neighbouring positions, seqovl, the fake's blob, tls_mod, a second fake, and the sister split function. Only
/// one or two parameters change per step; every child passes the Validator.
/// </summary>
public static class StrategyMutator
{
    private static readonly int[] RepeatsLadder = [1, 2, 6, 11];

    /// <summary>Fooling alternatives, cheapest and most portable first (nfqws2-lua §2, blockcheck2 FOOLINGS46_TCP).</summary>
    private static readonly string[][] Foolings =
    [
        ["tcp_md5"], ["tcp_seq=-3000"], ["badsum"], ["tcp_seq=1000000"], ["tcp_ack=-66000", "tcp_ts_up"],
        ["tcp_md5", "tcp_seq=-3000"], ["ip_autottl=-2,3-20"],
    ];

    private static readonly string[] FakeBlobs = ["fake_default_tls", StrategyGenerator.WhiteBlob, "0x00000000"];

    private static readonly string[] SplitFunctions = ["multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit", "tcpseg"];

    private static readonly string[] FakeFunctions = ["fake", "rst", "fakedsplit", "fakeddisorder", "hostfakesplit"];

    private static readonly HashSet<string> FoolingKeys = new(StringComparer.Ordinal)
    {
        "ip_ttl", "ip6_ttl", "ip_autottl", "ip6_autottl", "tcp_seq", "tcp_ack", "tcp_ts", "tcp_md5", "tcp_flags_set", "tcp_flags_unset", "badsum",
    };

    public static List<Mutation> Mutate(Strategy parent, GeneratorOptions? options = null, IReadOnlyDictionary<string, string>? blobs = null)
    {
        options ??= new GeneratorOptions();
        blobs ??= new Dictionary<string, string> { [StrategyGenerator.WhiteBlob] = StrategyGenerator.WhiteHelloHex(options.WhiteSni) };
        var validator = new StrategyValidator(new ValidationContext
        {
            Platform = options.Platform,
            DeclaredBlobs = blobs.ToDictionary(kv => kv.Key, kv => (long?)((kv.Value.Length - 2) / 2)),
        });
        var l4 = parent.Actions.OfType<PayloadFilter>().Any(p => p.Types.Contains("quic_initial")) ? L4Kind.Udp : L4Kind.Tcp;

        var raw = new List<Mutation>();
        var actions = parent.Actions;
        for (int i = 0; i < actions.Count; i++)
        {
            if (actions[i] is not LuaDesync { Call: var call })
                continue;
            Mutation With(LuaCall c, string what) => new(Replace(parent, i, c), $"{call.Function}: {what}");

            // repeats 1 → 2 → 6 → 11
            if (call.Function is "fake" or "rst" or "send")
            {
                int rep = int.TryParse(call["repeats"], CultureInfo.InvariantCulture, out var r) ? r : 1;
                foreach (var next in RepeatsLadder.Where(x => x > rep).Take(2))
                    raw.Add(With(call.With("repeats", next.ToString(CultureInfo.InvariantCulture)), $"repeats={next}"));
            }

            if (FakeFunctions.Contains(call.Function))
            {
                var current = call.Args.Where(a => FoolingKeys.Contains(a.Name)).ToList();
                var bare = current.Aggregate(call, (c, a) => c.Without(a.Name));
                bool hadTsUp = call.Has("tcp_ts_up");
                // another fooling instead of the current one
                foreach (var f in Foolings)
                {
                    var c = f.Aggregate(bare.Without("tcp_ts_up"), (acc, kv) => acc.With(Key(kv), Val(kv)));
                    if (hadTsUp && call.Function == "hostfakesplit" && !c.Has("tcp_ts_up"))
                        c = c.With("tcp_ts_up");
                    raw.Add(With(c, "fooling " + string.Join('+', f)));
                }
                // TTL: neighbours of a fixed TTL, or the autottl delta ±1
                if (call["ip_ttl"] is { } ttl && int.TryParse(ttl, CultureInfo.InvariantCulture, out var t))
                {
                    foreach (var d in new[] { -2, -1, 1, 2 }.Where(d => t + d is >= 1 and <= 20))
                        raw.Add(With(call.With("ip_ttl", (t + d).ToString(CultureInfo.InvariantCulture)), $"ip_ttl={t + d}"));
                }
                if (call["ip_autottl"] is { } at && at.Split(',') is [var delta, var range] && int.TryParse(delta, CultureInfo.InvariantCulture, out var dv))
                {
                    foreach (var d in new[] { dv - 1, dv + 1 }.Where(d => d is <= -1 and >= -6))
                        raw.Add(With(call.With("ip_autottl", $"{d.ToString(CultureInfo.InvariantCulture)},{range}"), $"ip_autottl={d}"));
                }
            }

            if (call.Function == "fake")
            {
                foreach (var b in FakeBlobs.Where(b => b != call["blob"] && (b.StartsWith("0x", StringComparison.Ordinal) || blobs.ContainsKey(b) || b.StartsWith("fake_default", StringComparison.Ordinal))))
                    raw.Add(With(call.With("blob", b), $"blob={b}"));
                if (!call.Has("tls_mod") && l4 == L4Kind.Tcp)
                {
                    raw.Add(With(call.With("tls_mod", "rnd,dupsid"), "tls_mod=rnd,dupsid"));
                    raw.Add(With(call.With("tls_mod", $"rnd,dupsid,sni={options.WhiteSni}"), $"tls_mod=…,sni={options.WhiteSni}"));
                }
            }

            if (SplitFunctions.Contains(call.Function) && call.Function != "hostfakesplit")
            {
                var pos = call["pos"] ?? (call.Function == "tcpseg" ? null : "2");
                if (pos is not null && call.Function != "tcpseg")
                {
                    bool single = call.Function is "fakedsplit" or "fakeddisorder";
                    foreach (var p in NeighbourPositions(pos, single))
                        raw.Add(With(call.With("pos", p), $"pos={p}"));
                }
                if (call.Function == "multisplit")
                {
                    if (!call.Has("seqovl"))
                    {
                        raw.Add(With(call.With("seqovl", "1").With("seqovl_pattern", "0x1603030000"), "seqovl=1"));
                        raw.Add(With(call.With("seqovl", "5").With("seqovl_pattern", "0x1603030000"), "seqovl=5"));
                        if (blobs.ContainsKey(StrategyGenerator.WhiteBlob))
                            raw.Add(With(call.With("seqovl", "1").With("seqovl_pattern", StrategyGenerator.WhiteBlob), "seqovl=1 белый CH"));
                    }
                    else if (int.TryParse(call["seqovl"], CultureInfo.InvariantCulture, out var so))
                    {
                        foreach (var n in new[] { 1, 5, 681 }.Where(n => n != so))
                            raw.Add(With(call.With("seqovl", n.ToString(CultureInfo.InvariantCulture)), $"seqovl={n}"));
                    }
                }
                // the sister function: in-order ↔ out-of-order, or with fakes around the parts
                var sister = call.Function switch
                {
                    "multisplit" => "multidisorder",
                    "multidisorder" => "multisplit",
                    "fakedsplit" => "fakeddisorder",
                    "fakeddisorder" => "fakedsplit",
                    _ => null,
                };
                if (sister is not null)
                {
                    var c = new LuaCall(sister, call.Args.Where(a => sister.StartsWith("multi", StringComparison.Ordinal) || a.Name != "seqovl"));
                    if (sister == "multidisorder" && call.Has("seqovl"))
                        c = c.Without("seqovl").Without("seqovl_pattern"); // a disorder overlap is a marker, not a count
                    raw.Add(With(c, $"{call.Function} → {sister}"));
                }
                if (call.Function == "multisplit" && FirstPos(pos) is { } first && !parent.Calls.Any(x => x.Function == "fake"))
                    raw.Add(With(new LuaCall("fakedsplit", [new LuaArg("pos", first), new LuaArg("tcp_md5")]), "multisplit → fakedsplit"));
            }
        }

        // a fake in front of a split-only strategy, or a second fake with another blob
        var fakes = parent.Calls.Where(c => c.Function == "fake").ToList();
        int firstDesync = actions.Select((a, i) => (a, i)).First(x => x.a is LuaDesync).i;
        if (l4 == L4Kind.Tcp && parent.Calls.Any(c => SplitFunctions.Contains(c.Function)) && fakes.Count == 0)
            raw.Add(new Mutation(Insert(parent, firstDesync, LuaCall.Parse("fake:blob=fake_default_tls:tcp_md5")), "+fake"));
        else if (l4 == L4Kind.Tcp && fakes.Count == 1)
        {
            var other = FakeBlobs.First(b => b != fakes[0]["blob"] && (b != StrategyGenerator.WhiteBlob || blobs.ContainsKey(b)));
            var second = fakes[0].With("blob", other).Without("tls_mod");
            raw.Add(new Mutation(Insert(parent, firstDesync + 1, second), $"+второй fake blob={other}"));
        }

        var seen = new HashSet<string>(StringComparer.Ordinal) { parent.ToString() };
        var result = new List<Mutation>();
        foreach (var m in raw)
        {
            if (!options.TcpTimestamps && m.Strategy.ToString().Contains("tcp_ts=", StringComparison.Ordinal))
                continue;
            if (seen.Add(m.Strategy.ToString()) && validator.ValidateStrategy(m.Strategy, l4).Ok)
                result.Add(m);
        }
        return result;
    }

    /// <summary>Positions next to the current ones: each marker ±1, and the usual alternatives.</summary>
    internal static IEnumerable<string> NeighbourPositions(string pos, bool single)
    {
        var parts = pos.Split(',');
        var outList = new List<string>();
        for (int i = 0; i < parts.Length; i++)
        {
            foreach (var n in Shift(parts[i]))
            {
                var copy = (string[])parts.Clone();
                copy[i] = n;
                outList.Add(string.Join(',', copy));
            }
        }
        string[] alternatives = single ? ["1", "2", "midsld", "sniext+1", "host"] : ["1", "2", "midsld", "sniext+1", "1,midsld", "host,endhost"];
        outList.AddRange(alternatives);
        return outList.Where(p => p != pos).Distinct();
    }

    private static IEnumerable<string> Shift(string marker)
    {
        if (int.TryParse(marker, CultureInfo.InvariantCulture, out var n))
        {
            if (n > 0)
                yield return (n + 1).ToString(CultureInfo.InvariantCulture);
            if (n > 1)
                yield return (n - 1).ToString(CultureInfo.InvariantCulture);
            yield break;
        }
        int sign = marker.LastIndexOfAny(['+', '-']);
        var name = sign > 0 ? marker[..sign] : marker;
        int off = sign > 0 && int.TryParse(marker[sign..], CultureInfo.InvariantCulture, out var o) ? o : 0;
        foreach (var d in new[] { 1, -1 })
        {
            int v = off + d;
            yield return v == 0 ? name : v > 0 ? $"{name}+{v}" : $"{name}{v}";
        }
    }

    private static string? FirstPos(string? pos) => pos?.Split(',')[0];

    private static string Key(string kv) => kv.Split('=', 2)[0];

    private static string? Val(string kv) => kv.Split('=', 2) is [_, var v] ? v : null;

    private static Strategy Replace(Strategy s, int index, LuaCall call)
    {
        var list = s.Actions.ToList();
        list[index] = new LuaDesync(call);
        return new Strategy(list);
    }

    private static Strategy Insert(Strategy s, int index, LuaCall call)
    {
        var list = s.Actions.ToList();
        list.Insert(index, new LuaDesync(call));
        return new Strategy(list);
    }
}
