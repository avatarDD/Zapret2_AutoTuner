using ZapretAutoTuner.Bench;

BenchCli cli;
try
{
    cli = BenchCli.Parse(args, Environment.GetEnvironmentVariable);
}
catch (ArgumentException e)
{
    Console.Error.WriteLine(e.Message);
    Console.Error.WriteLine(BenchCli.Usage);
    return 2;
}
if (cli.Help)
{
    Console.WriteLine(BenchCli.Usage);
    return 0;
}
if (cli.List)
{
    foreach (var s in cli.Options.Scenarios)
        Console.WriteLine($"{s.Id,-20} AS{s.Asn} {s.Label,-10} {(BenchScenarios.Warm(s, cli.Options.Scenarios) ? "warm" : "cold")}  {s.Hidden}");
    return 0;
}

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};
using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
var arms = cli.Arms(http);
Console.Error.WriteLine(arms is null
    ? "model arms: off (no --provider); nothing is sent anywhere"
    : $"model arms: {arms.Name}; the advisor's requests go to that provider only");
var bench = new SearchBenchmark(cli.Options, arms);
var report = await bench.RunAsync(new Progress(r =>
    Console.Error.WriteLine($"{r.Scenario,-20} {BenchFormat.Name(r.Arm),-13} seed {r.Seed}: {(r.Success ? "ok" : "FAILED")} after {r.Strategies} strategies, {r.Attempts} probes {r.Note}")), cts.Token);
var md = BenchFormat.Markdown(report);
Console.WriteLine(md);
if (cli.MarkdownPath is { } mdPath)
    await File.WriteAllTextAsync(mdPath, md);
if (cli.JsonPath is { } jsonPath)
    await File.WriteAllTextAsync(jsonPath, BenchFormat.Json(report));
return 0;

/// <summary>Reports on the calling thread (a console app has no synchronization context to post to anyway).</summary>
internal sealed class Progress(Action<BenchRun> report) : IProgress<BenchRun>
{
    public void Report(BenchRun value) => report(value);
}
