using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core;

namespace ZapretAutoTuner.Tools;

/// <summary>Result of checking the bundled engine files.</summary>
public sealed record BundleCheck(bool Ok, IReadOnlyList<string> Problems);

/// <summary>Parsed <c>nfqws2 --version</c> output.</summary>
public sealed record EngineVersion(string Raw, string? Version, int? LuaCompat);

/// <summary>
/// The zapret2 engine shipped with the application (<c>&lt;app&gt;/zapret2</c>): winws2 on Windows, nfqws2 on Linux,
/// with lua and fake blobs from the same release (nfqws2-engine §0.3).
/// </summary>
public sealed partial class Zapret2Bundle
{
    public Zapret2Bundle(string root)
    {
        Root = root;
    }

    public string Root { get; }

    public string LuaDir => Path.Combine(Root, "lua");

    public string FakeDir => Path.Combine(Root, "files", "fake");

    public string EngineFileName => OperatingSystem.IsWindows() ? "winws2.exe" : "nfqws2";

    public string EnginePath => Path.Combine(Root, EngineFileName);

    public string ManifestPath => Path.Combine(Root, "bundle.json");

    /// <summary>The bundle next to the executable, or <c>ZT_ZAPRET2_DIR</c> when set.</summary>
    public static Zapret2Bundle Locate()
    {
        var env = Environment.GetEnvironmentVariable("ZT_ZAPRET2_DIR");
        if (!string.IsNullOrEmpty(env))
            return new Zapret2Bundle(env);
        return new Zapret2Bundle(Path.Combine(AppContext.BaseDirectory, "zapret2"));
    }

    public static string CurrentRid => (OperatingSystem.IsWindows() ? "win" : "linux") + "-" + RuntimeInformation.OSArchitecture switch
    {
        Architecture.X64 => "x64",
        Architecture.Arm64 => "arm64",
        Architecture.X86 => "x86",
        var a => a.ToString().ToLowerInvariant(),
    };

    public BundleManifest? ReadManifest()
    {
        if (!File.Exists(ManifestPath))
            return null;
        return JsonSerializer.Deserialize(File.ReadAllText(ManifestPath), ToolsJsonContext.Default.BundleManifest);
    }

    /// <summary>
    /// Checks that the engine exists and every file still has the hash recorded at build time
    /// (antivirus software likes to quarantine WinDivert).
    /// </summary>
    public BundleCheck Verify()
    {
        var problems = new List<string>();
        if (!File.Exists(EnginePath))
            problems.Add($"не найден движок {EngineFileName} в {Root}");
        var manifest = ReadManifest();
        if (manifest is null)
        {
            problems.Add("нет bundle.json: бандл собран не скриптом tools/bundle");
            return new BundleCheck(problems.Count == 0, problems);
        }
        if (manifest.LuaCompat != AppInfo.LuaCompatVersion)
            problems.Add($"lua бандла рассчитан на compat {manifest.LuaCompat}, приложение — на {AppInfo.LuaCompatVersion}");
        foreach (var (rel, hash) in manifest.Files)
        {
            var path = Path.Combine(Root, rel.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(path))
            {
                problems.Add($"файл {rel} пропал (антивирус мог удалить его, добавьте папку в исключения)");
                continue;
            }
            if (!string.Equals(Sha256File(path), hash, StringComparison.OrdinalIgnoreCase))
                problems.Add($"файл {rel} изменён: хэш не совпадает с бандлом");
        }
        var compat = ReadLuaCompat();
        if (compat is not null && compat != AppInfo.LuaCompatVersion)
            problems.Add($"zapret-lib.lua требует NFQWS2_COMPAT_VER {compat}, ожидается {AppInfo.LuaCompatVersion}");
        return new BundleCheck(problems.Count == 0, problems);
    }

    public int? ReadLuaCompat()
    {
        var lib = Path.Combine(LuaDir, "zapret-lib.lua");
        if (!File.Exists(lib))
            return null;
        using var r = new StreamReader(lib);
        var first = r.ReadLine() ?? "";
        var m = CompatRegex().Match(first);
        return m.Success ? int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) : null;
    }

    /// <summary>Runs <c>nfqws2 --version</c>. winws2 needs no admin rights for that.</summary>
    public async Task<EngineVersion> GetVersionAsync(CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo(EnginePath, "--version")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = Root,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("не удалось запустить движок");
        var stdout = p.StandardOutput.ReadToEndAsync(ct);
        var stderr = p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct).ConfigureAwait(false);
        return ParseVersion((await stdout.ConfigureAwait(false)) + (await stderr.ConfigureAwait(false)));
    }

    public static EngineVersion ParseVersion(string output)
    {
        var raw = output.Trim();
        var v = VersionRegex().Match(raw);
        var c = LuaCompatVerRegex().Match(raw);
        return new EngineVersion(
            raw,
            v.Success ? v.Groups[1].Value : null,
            c.Success ? int.Parse(c.Groups[1].Value, CultureInfo.InvariantCulture) : null);
    }

    public static string Sha256File(string path)
    {
        using var s = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(s));
    }

    [GeneratedRegex(@"^\s*NFQWS2_COMPAT_VER_REQUIRED\s*=\s*(\d+)")]
    private static partial Regex CompatRegex();

    [GeneratedRegex(@"version\s+v?([0-9][0-9A-Za-z.\-]*)")]
    private static partial Regex VersionRegex();

    [GeneratedRegex(@"lua_compat_ver\s+(\d+)")]
    private static partial Regex LuaCompatVerRegex();
}
