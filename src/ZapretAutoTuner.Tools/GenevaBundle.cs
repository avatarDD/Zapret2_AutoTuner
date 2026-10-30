using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Tools;

/// <summary><c>geneva version --json</c>.</summary>
public sealed record GenevaVersion(string Version, int Proto, string Os, string Arch, IReadOnlyList<string> Features);

/// <summary>A strategy of Geneva's library (<c>geneva library --json</c>) with its success rate against a country's censor.</summary>
public sealed record GenevaLibraryEntry(string Strategy, int Rate, string Country, string Test, bool ServerSide, string Description);

/// <summary><c>geneva check --json</c> of one strategy: the canonical form, or why it does not parse.</summary>
public sealed record GenevaCheck(bool Ok, string? Strategy, int Actions, string? Error);

/// <summary>
/// geneva_c shipped with the application (<c>&lt;app&gt;/geneva</c>): <c>geneva.exe</c> with WinDivert from its official
/// release on Windows, the static <c>geneva</c> on Linux (skill <c>geneva</c>, <c>tools/bundle/geneva.lock.json</c>). What
/// needs no rights (version, library, check) runs from the UI; everything that touches traffic runs in the Agent.
/// </summary>
public sealed class GenevaBundle
{
    public GenevaBundle(string root)
    {
        Root = root;
    }

    public string Root { get; }

    public static string FileName => OperatingSystem.IsWindows() ? "geneva.exe" : "geneva";

    public string EnginePath => Path.Combine(Root, FileName);

    public string ManifestPath => Path.Combine(Root, "bundle.json");

    public bool Exists => File.Exists(EnginePath);

    /// <summary>The bundle next to the executable, or <c>ZT_GENEVA_DIR</c> when set.</summary>
    public static GenevaBundle Locate()
    {
        var env = Environment.GetEnvironmentVariable("ZT_GENEVA_DIR");
        if (!string.IsNullOrEmpty(env))
            return new GenevaBundle(env);
        return new GenevaBundle(Path.Combine(AppContext.BaseDirectory, "geneva"));
    }

    public BundleManifest? ReadManifest()
    {
        if (!File.Exists(ManifestPath))
            return null;
        return JsonSerializer.Deserialize(File.ReadAllText(ManifestPath), ToolsJsonContext.Default.BundleManifest);
    }

    /// <summary>The binary exists and every file still has the hash of the release it was taken from.</summary>
    public BundleCheck Verify()
    {
        var problems = new List<string>();
        if (!File.Exists(EnginePath))
            problems.Add($"не найден {FileName} в {Root} / geneva is missing");
        var manifest = ReadManifest();
        if (manifest is null)
        {
            problems.Add("нет bundle.json: geneva собрана не скриптом tools/bundle / no bundle.json");
            return new BundleCheck(false, problems);
        }
        if (!manifest.Files.ContainsKey(FileName))
            problems.Add($"bundle.json не содержит {FileName} / does not list the binary");
        foreach (var (rel, hash) in manifest.Files)
        {
            var path = Path.Combine(Root, rel.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(path))
            {
                problems.Add($"файл {rel} пропал (антивирус мог удалить его) / {rel} is missing");
                continue;
            }
            if (!string.Equals(Zapret2Bundle.Sha256File(path), hash, StringComparison.OrdinalIgnoreCase))
                problems.Add($"файл {rel} изменён: хэш не совпадает с релизом / {rel} was changed");
        }
        return new BundleCheck(problems.Count == 0, problems);
    }

    public async Task<GenevaVersion> GetVersionAsync(CancellationToken ct = default)
    {
        var (code, stdout, _) = await RunAsync(["version", "--json"], null, ct).ConfigureAwait(false);
        if (code != 0)
            throw new InvalidOperationException($"geneva version: код {code}");
        return ParseVersion(stdout);
    }

    public static GenevaVersion ParseVersion(string json)
    {
        var o = JsonNode.Parse(json.Trim()) as JsonObject ?? throw new FormatException("geneva version: not an object");
        return new GenevaVersion(
            ((string?)o["version"] ?? "").TrimStart('v'),
            (int?)o["proto"] ?? 0,
            (string?)o["os"] ?? "",
            (string?)o["arch"] ?? "",
            [.. (o["features"] as JsonArray ?? []).Select(f => (string?)f ?? "").Where(f => f.Length > 0)]);
    }

    /// <summary>Geneva's library: needs no rights and no network.</summary>
    public async Task<IReadOnlyList<GenevaLibraryEntry>> LibraryAsync(CancellationToken ct = default)
    {
        var (code, stdout, stderr) = await RunAsync(["library", "--json"], null, ct).ConfigureAwait(false);
        if (code != 0)
            throw new InvalidOperationException($"geneva library: {stderr.Trim()}");
        return ParseLibrary(stdout);
    }

    public static IReadOnlyList<GenevaLibraryEntry> ParseLibrary(string json)
    {
        var a = JsonNode.Parse(json.Trim()) as JsonArray ?? throw new FormatException("geneva library: not an array");
        return [.. a.OfType<JsonObject>().Select(o => new GenevaLibraryEntry(
            (string?)o["strategy"] ?? "", (int?)o["rate"] ?? 0, (string?)o["country"] ?? "", (string?)o["test"] ?? "",
            (bool?)o["server_side"] ?? false, (string?)o["description"] ?? ""))
            .Where(e => e.Strategy.Length > 0)];
    }

    /// <summary>Parses strategies with geneva itself: the canonical form, or why one does not parse.</summary>
    public async Task<IReadOnlyList<GenevaCheck>> CheckAsync(IReadOnlyList<string> strategies, CancellationToken ct = default)
    {
        if (strategies.Count == 0)
            return [];
        // strategies on stdin, not argv: one may start with '-'
        var (_, stdout, _) = await RunAsync(["check", "--json", "-f", "-"], string.Join("\n", strategies) + "\n", ct).ConfigureAwait(false);
        return ParseCheck(stdout);
    }

    public static IReadOnlyList<GenevaCheck> ParseCheck(string output)
    {
        var list = new List<GenevaCheck>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (line[0] != '{')
                continue;
            try
            {
                if (JsonNode.Parse(line) is not JsonObject o)
                    continue;
                bool ok = (bool?)o["ok"] ?? false;
                list.Add(new GenevaCheck(ok, ok ? (string?)o["strategy"] : null, (int?)o["actions"] ?? 0, ok ? null : (string?)o["error"] ?? "?"));
            }
            catch (JsonException)
            {
            }
        }
        return list;
    }

    private async Task<(int Code, string Stdout, string Stderr)> RunAsync(IReadOnlyList<string> args, string? stdin, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(EnginePath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = stdin is not null,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Root,
        };
        foreach (var a in args)
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("не удалось запустить geneva / could not start geneva");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(20));
        try
        {
            var stdout = p.StandardOutput.ReadToEndAsync(cts.Token);
            var stderr = p.StandardError.ReadToEndAsync(cts.Token);
            if (stdin is not null)
            {
                await p.StandardInput.WriteAsync(stdin.AsMemory(), cts.Token).ConfigureAwait(false);
                p.StandardInput.Close();
            }
            await p.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            return (p.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            try
            {
                p.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }
            throw;
        }
    }
}
