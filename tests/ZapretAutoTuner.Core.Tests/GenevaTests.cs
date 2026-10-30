using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Geneva;

namespace ZapretAutoTuner.Core.Tests;

/// <summary>geneva_c's contract (its docs/PROTOCOL.md, proto 1) and the command lines the Agent builds.</summary>
public sealed class GenevaTests
{
    [Fact]
    public void Events_are_parsed_and_other_lines_are_not()
    {
        var e = GenevaEvent.Parse("""{"ts":1793300414096,"ev":"generation","gen":1,"unique":2,"evaluated":6,"avg_fitness":387.167,"best_fitness":389,"best":"[TCP:ack:87069235]-fragment{tcp:-1:True}-| \\/"}""");
        Assert.NotNull(e);
        Assert.Equal("generation", e.Ev);
        Assert.Equal(1, e.Long("gen"));
        Assert.Equal(389, e.Num("best_fitness"));
        Assert.Equal("[TCP:ack:87069235]-fragment{tcp:-1:True}-| \\/", e.Str("best"));
        Assert.Null(GenevaEvent.Parse("389\t4\t[TCP:flags:PA]-drop-| \\/"));
        Assert.Null(GenevaEvent.Parse("{\"no_ev\":1}"));
        Assert.Null(GenevaEvent.Parse("{broken"));
        Assert.Null(GenevaEvent.Parse(null));
    }

    [Fact]
    public void Stats_read_the_counters_and_the_trees()
    {
        var e = GenevaEvent.Parse("""{"ts":1,"ev":"stats","uptime_ms":60000,"paused":false,"pkts_out":500,"pkts_in":400,"triggered":0,"accepted":900,"modified":0,"dropped":0,"injected":0,"delayed":0,"pending":0,"send_errors":1,"verdict_errors":0,"parse_errors":2,"overruns":0,"out_trees":[{"tree":"[TCP:flags:PA]-drop-|","fired":0}],"in_trees":[]}""")!;
        var s = GenevaStats.From(e);
        Assert.Equal(500, s.PktsOut);
        Assert.Equal(3, s.Errors);
        Assert.Single(s.Trees);
        Assert.Equal("[TCP:flags:PA]-drop-|", s.Trees[0].Tree);
        Assert.True(s.Idle);
    }

    [Theory]
    [InlineData("[TCP:flags:PA]-fragment{tcp:8:True}-| \\/", true)]
    [InlineData("\\/", true)]
    [InlineData("", false)]
    [InlineData("[TCP:flags:PA]-drop-|", false)]
    [InlineData("[TCP:flags:PA]-drop-| \\/\n--evil", false)]
    [InlineData("[TCP:flags:PA]-drop-| \\/ я", false)]
    public void Strategy_text_is_one_printable_line_with_the_separator(string s, bool ok)
    {
        Assert.Equal(ok, GenevaStrategyText.Problem(s) is null);
    }

    [Fact]
    public void Run_argv_has_its_own_queue_and_no_token()
    {
        var argv = GenevaArgv.Run(new GenevaRunSettings { Strategy = "[TCP:flags:PA]-drop-| \\/", Ports = "443,80" }, 47123);
        Assert.Equal(["run", "-s", "[TCP:flags:PA]-drop-| \\/", "-p", "80,443", "-q", "330", "-c", "tcp:47123", "-e", "-", "--stats-interval", "2", "--quiet"], argv);
        Assert.DoesNotContain(argv, a => a.Contains("token", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evolve_argv_asks_the_ui_for_every_strategy()
    {
        var s = new GenevaSearchSettings { Host = "Blocked.Example", Population = 20, Generations = 5 };
        var argv = GenevaArgv.Evolve(s, "/x/search.ckpt", "/x/db.jsonl", "/x/seeds.txt");
        Assert.Equal("external", argv[argv.IndexOf("--probe") + 1]);
        Assert.Equal("blocked.example", argv[argv.IndexOf("--host") + 1]);
        Assert.Equal("1", argv[argv.IndexOf("--workers") + 1]);
        Assert.Equal("331", argv[argv.IndexOf("-q") + 1]);
        Assert.Equal("external:blocked.example:443", argv[argv.IndexOf("--target") + 1]);
        Assert.Equal("/x/seeds.txt", argv[argv.IndexOf("--load-from") + 1]);
        Assert.DoesNotContain("--resume", argv);

        var resumed = GenevaArgv.Evolve(s with { Resume = true }, "/x/search.ckpt", "/x/db.jsonl", "/x/seeds.txt");
        Assert.Contains("--resume", resumed);
        // a resumed search keeps its population: seeds would be refused as a changed search
        Assert.DoesNotContain("--load-from", resumed);
    }

    [Theory]
    [InlineData("not a host", 30, 15)]
    [InlineData("a.example", 2, 15)]
    [InlineData("a.example", 30, 0)]
    [InlineData("a.example", 30, 1000)]
    public void Bad_search_settings_are_refused(string host, int population, int generations)
    {
        var s = new GenevaSearchSettings { Host = host, Population = population, Generations = generations };
        Assert.NotEmpty(s.Problems());
        Assert.Throws<FormatException>(() => GenevaArgv.Evolve(s, "c", "d", null));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("70000")]
    [InlineData("abc")]
    [InlineData("1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33")]
    public void Bad_ports_are_refused(string ports)
    {
        Assert.NotEmpty(new GenevaRunSettings { Strategy = "\\/", Ports = ports }.Problems());
    }

    [Fact]
    public void Local_ports_rotate_inside_the_block()
    {
        Assert.Equal(30000, GenevaArgv.LocalPort("30000-30063", 0));
        Assert.Equal(30063, GenevaArgv.LocalPort("30000-30063", 63));
        Assert.Equal(30000, GenevaArgv.LocalPort("30000-30063", 64));
        Assert.Throws<FormatException>(() => GenevaArgv.LocalPort("80-90", 0));
        Assert.Throws<FormatException>(() => GenevaArgv.LocalPort("junk", 0));
    }

    [Fact]
    public void Fitness_follows_geneva_for_the_ways_a_probe_fails()
    {
        static ProbeResult R(ProbeError e, bool ok = false) => new()
        {
            Host = "a.example",
            Address = "192.0.2.1",
            ConnectOk = ok || e != ProbeError.ConnectTimeout,
            TlsOk = ok,
            CertValid = ok,
            HttpStatus = ok ? 200 : null,
            Complete = ok,
            BodyBytes = ok ? 100_000 : 0,
            Error = e,
        };
        Assert.Equal((400, "ok"), GenevaFitness.FromProbe(R(ProbeError.None, ok: true)));
        Assert.Equal((-360, "reset"), GenevaFitness.FromProbe(R(ProbeError.TlsReset)));
        Assert.Equal((-400, "connect_timeout"), GenevaFitness.FromProbe(R(ProbeError.ConnectTimeout)));
        Assert.Equal((-480, "timeout"), GenevaFitness.FromProbe(R(ProbeError.Stalled)));
        Assert.Equal((-480, "broken"), GenevaFitness.FromProbe(R(ProbeError.Truncated)));
        // a handshake alone is not success (AGENTS.md rule 5)
        var handshakeOnly = R(ProbeError.HttpTimeout) with { TlsOk = true, CertValid = true };
        Assert.True(GenevaFitness.FromProbe(handshakeOnly).Fitness < 0);
        // a certificate for another name: a block page
        var forged = R(ProbeError.None) with { TlsOk = true, CertValid = false, HttpStatus = 200, Complete = true };
        Assert.Equal((-360, "injected"), GenevaFitness.FromProbe(forged));
    }

    [Fact]
    public void Exit_codes_have_texts()
    {
        Assert.Contains("подбирать нечего", GenevaText.Exit(7, "not_blocked").Ru, StringComparison.Ordinal);
        Assert.Equal("stopped", GenevaText.Exit(0, "signal").En);
        Assert.Equal("finished", GenevaText.Exit(0, "done").En);
        Assert.Contains("rights", GenevaText.Exit(4, "error").En, StringComparison.Ordinal);
    }
}
