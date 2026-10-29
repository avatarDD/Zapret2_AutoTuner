using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using ZapretAutoTuner.Protocol;
using ZapretAutoTuner.Tuning.Geneva;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>
/// geneva in the Agent as its protocol describes it: a search asks for the baseline, then for each of
/// <see cref="Strategies"/>, waits for every answer, reports a generation and the result; a run reports ready and then
/// whatever the test pushes. Shared with the MCP tests.
/// </summary>
internal sealed class FakeGenevaAgent : IGenevaAgent
{
    private readonly Dictionary<string, Channel<GenevaOutput>> _streams = [];
    private readonly Dictionary<long, TaskCompletionSource<int>> _answers = [];
    private readonly Lock _lock = new();
    private int _next;

    public List<string> Strategies { get; } = ["[TCP:flags:PA]-drop-| \\/", "[TCP:flags:PA]-fragment{tcp:8:True}-| \\/"];

    public List<GenevaStartRequest> Started { get; } = [];

    public List<(long Id, int Fitness, string Detail)> Answers { get; } = [];

    public List<string> Commands { get; } = [];

    public List<string> Stopped { get; } = [];

    /// <summary>The Agent refuses every start with this text.</summary>
    public string? Refuse { get; set; }

    public Task<GenevaStartReply> StartAsync(GenevaStartRequest request, CancellationToken ct)
    {
        if (Refuse is { } why)
            throw new GenevaRefusedException(why);
        string id;
        var ch = Channel.CreateUnbounded<GenevaOutput>();
        lock (_lock)
        {
            id = "g" + ++_next;
            _streams[id] = ch;
            Started.Add(request);
        }
        if (request.Mode == "evolve")
            _ = Task.Run(() => SearchAsync(ch.Writer, request));
        else
        {
            Event(ch.Writer, new JsonObject { ["ev"] = "start", ["proto"] = 1, ["mode"] = "run" });
            Event(ch.Writer, new JsonObject { ["ev"] = "ready", ["backend"] = "nfqueue", ["firewall"] = "nft" });
        }
        return Task.FromResult(new GenevaStartReply { Id = id, Pid = 1000 + _next, Strategy = request.Strategy });
    }

    private static void Event(ChannelWriter<GenevaOutput> w, JsonObject e)
    {
        e["ts"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        w.TryWrite(new GenevaOutput { Event = e.ToJsonString() });
    }

    private async Task<int> AskAsync(ChannelWriter<GenevaOutput> w, long id, string strategy)
    {
        var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_lock)
            _answers[id] = tcs;
        Event(w, new JsonObject { ["ev"] = "eval_request", ["id"] = id, ["strategy"] = strategy, ["run"] = 0, ["lports"] = "30000-30063" });
        return await tcs.Task;
    }

    private async Task SearchAsync(ChannelWriter<GenevaOutput> w, GenevaStartRequest r)
    {
        Event(w, new JsonObject { ["ev"] = "start", ["proto"] = 1, ["mode"] = "evolve", ["population"] = r.Population, ["generations"] = r.Generations, ["resume"] = r.Resume });
        int baseline = await AskAsync(w, 1, "");
        Event(w, new JsonObject { ["ev"] = "baseline", ["blocked"] = baseline < 0, ["fitness"] = baseline, ["outcome"] = baseline < 0 ? "reset" : "ok" });
        if (baseline > 0)
        {
            Event(w, new JsonObject { ["ev"] = "exit", ["code"] = 7, ["reason"] = "not_blocked" });
            w.TryWrite(new GenevaOutput { Exited = true, ExitCode = 7 });
            return;
        }
        var results = new List<(string S, int F)>();
        long id = 2;
        foreach (var s in Strategies)
        {
            int f = await AskAsync(w, id++, s);
            results.Add((s, f));
            Event(w, new JsonObject { ["ev"] = "eval", ["strategy"] = s, ["fitness"] = f, ["runs"] = 1, ["outcome"] = f > 0 ? "ok" : "failed", ["detail"] = "external" });
        }
        var best = results.OrderByDescending(x => x.F).First();
        Event(w, new JsonObject { ["ev"] = "generation", ["gen"] = 0, ["unique"] = results.Count, ["evaluated"] = results.Count, ["avg_fitness"] = results.Average(x => x.F), ["best_fitness"] = best.F, ["best"] = best.S });
        Event(w, new JsonObject
        {
            ["ev"] = "result",
            ["stopped"] = false,
            ["best"] = new JsonArray([.. results.Where(x => x.F > 0).Select(x => (JsonNode)new JsonObject { ["strategy"] = x.S, ["avg_fitness"] = x.F, ["runs"] = 1 })]),
        });
        w.TryWrite(new GenevaOutput { Log = "389\t1\t" + best.S });
        Event(w, new JsonObject { ["ev"] = "exit", ["code"] = 0, ["reason"] = "done" });
        w.TryWrite(new GenevaOutput { Exited = true, ExitCode = 0 });
    }

    /// <summary>A stats event (or any other) of the run with this id.</summary>
    public void Push(string id, JsonObject e)
    {
        lock (_lock)
            Event(_streams[id].Writer, e);
    }

    public Task StopAsync(string id, CancellationToken ct)
    {
        Channel<GenevaOutput>? ch;
        lock (_lock)
        {
            Stopped.Add(id);
            _streams.TryGetValue(id, out ch);
            foreach (var a in _answers.Values)
                a.TrySetCanceled();
        }
        if (ch is not null)
        {
            Event(ch.Writer, new JsonObject { ["ev"] = "exit", ["code"] = 0, ["reason"] = "signal" });
            ch.Writer.TryWrite(new GenevaOutput { Exited = true, ExitCode = 0 });
        }
        return Task.CompletedTask;
    }

    public async IAsyncEnumerable<GenevaOutput> WatchAsync(string id, [EnumeratorCancellation] CancellationToken ct)
    {
        Channel<GenevaOutput> ch;
        lock (_lock)
            ch = _streams[id];
        await foreach (var o in ch.Reader.ReadAllAsync(ct))
        {
            yield return o;
            if (o.Exited)
                yield break;
        }
    }

    public Task AnswerAsync(string id, long requestId, int fitness, string detail, CancellationToken ct)
    {
        TaskCompletionSource<int>? tcs;
        lock (_lock)
        {
            Answers.Add((requestId, fitness, detail));
            _answers.Remove(requestId, out tcs);
        }
        tcs?.TrySetResult(fitness);
        return Task.CompletedTask;
    }

    public Task<GenevaControlReply> ControlAsync(string id, string cmd, string? strategy, CancellationToken ct)
    {
        lock (_lock)
            Commands.Add(cmd);
        return Task.FromResult(new GenevaControlReply { Ok = true, Json = "{\"ok\":true}" });
    }

    public Task<GenevaInfoReply> InfoAsync(CancellationToken ct) => Task.FromResult(new GenevaInfoReply { VersionJson = "{\"version\":\"1.0.0\",\"proto\":1}" });
}

/// <summary>The saved state in memory.</summary>
internal sealed class MemoryGenevaStore : IGenevaStore
{
    public string? Json { get; set; }

    public int Saves { get; private set; }

    public string? Load() => Json;

    public void Save(string json)
    {
        Json = json;
        Saves++;
    }
}
