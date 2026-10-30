using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Tools.Tests;

/// <summary>The bundled geneva_c: what the program reads from it, and the pinned official release.</summary>
public sealed class GenevaBundleTests
{
    private static string Root([System.Runtime.CompilerServices.CallerFilePath] string here = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(here)!, "..", ".."));

    [Fact]
    public void Version_json_is_read()
    {
        var v = GenevaBundle.ParseVersion("""{"version":"v1.0.0","proto":1,"os":"linux","arch":"x86_64","features":["nfqueue","ipv6","pcap","control"]}""");
        Assert.Equal("1.0.0", v.Version);
        Assert.Equal(1, v.Proto);
        Assert.Contains("control", v.Features);
    }

    [Fact]
    public void Library_and_check_output_are_read()
    {
        var lib = GenevaBundle.ParseLibrary("""[{"strategy":"\\/","rate":3,"country":"china","test":"http","server_side":false,"description":"No strategy"},{"strategy":"[TCP:flags:PA]-duplicate-| \\/","rate":98,"country":"china","test":"http","server_side":false,"description":"x"}]""");
        Assert.Equal(2, lib.Count);
        Assert.Equal(98, lib[1].Rate);
        var checks = GenevaBundle.ParseCheck("""
            {"ok":true,"strategy":"[TCP:flags:PA]-fragment{tcp:8:True}-| \\/","actions":1,"out":[],"in":[]}
            {"ok":false,"input":"garbage","error":"could not identify the trigger"}
            """);
        Assert.True(checks[0].Ok);
        Assert.Equal(1, checks[0].Actions);
        Assert.False(checks[1].Ok);
        Assert.Contains("trigger", checks[1].Error, StringComparison.Ordinal);
    }

    /// <summary>AGENTS.md rule 10: geneva comes from its author's release, every archive pinned by SHA-256.</summary>
    [Fact]
    public void The_lock_pins_the_official_release_for_every_rid_the_program_ships()
    {
        var lockDir = Path.Combine(Root(), "tools", "bundle");
        var geneva = JsonNode.Parse(File.ReadAllText(Path.Combine(lockDir, "geneva.lock.json")))!.AsObject();
        var zapret = JsonNode.Parse(File.ReadAllText(Path.Combine(lockDir, "zapret2.lock.json")))!.AsObject();
        Assert.Equal("avatarDD/geneva_c", (string?)geneva["repo"]);
        Assert.Equal(1, (int?)geneva["proto"]);
        var rids = geneva["rids"]!.AsObject();
        Assert.Equal(zapret["rids"]!.AsObject().Select(kv => kv.Key).Order(), rids.Select(kv => kv.Key).Order());
        foreach (var (rid, spec) in rids)
        {
            Assert.Matches("^[0-9a-f]{64}$", (string?)spec!["sha256"]);
            Assert.StartsWith("geneva-" + (string?)geneva["version"] + "-", (string?)spec["asset"], StringComparison.Ordinal);
            var files = spec["files"]!.AsArray().Select(f => (string?)f).ToList();
            Assert.Equal(rid.StartsWith("win", StringComparison.Ordinal) ? "geneva.exe" : "geneva", files[0]);
            if (rid.StartsWith("win", StringComparison.Ordinal))
                Assert.Contains("WinDivert64.sys", files);
        }
    }

    /// <summary>With the bundle built (tools/bundle/bundle_geneva.py or ZT_GENEVA_DIR): the real binary answers.</summary>
    [Fact]
    public async Task The_bundled_geneva_verifies_and_answers()
    {
        var dir = Environment.GetEnvironmentVariable("ZT_GENEVA_DIR") is { Length: > 0 } env ? env : Path.Combine(Root(), "runtimes", Zapret2Bundle.CurrentRid, "geneva");
        var b = new GenevaBundle(dir);
        if (!b.Exists)
            return;
        var check = b.Verify();
        Assert.True(check.Ok, string.Join("; ", check.Problems));
        var v = await b.GetVersionAsync();
        Assert.Equal(1, v.Proto);
        var lib = await b.LibraryAsync();
        Assert.Contains(lib, l => l.Rate > 90);
        var c = await b.CheckAsync(["[TCP:flags:PA]-fragment{tcp:8:True}-| \\/", "garbage", "-not-an-option"]);
        Assert.Equal(3, c.Count);
        Assert.True(c[0].Ok);
        Assert.False(c[1].Ok);
        Assert.False(c[2].Ok);
    }

    [Fact]
    public void A_changed_file_fails_the_check()
    {
        var dir = Directory.CreateTempSubdirectory("geneva-bundle").FullName;
        try
        {
            File.WriteAllText(Path.Combine(dir, GenevaBundle.FileName), "binary");
            var hash = Zapret2Bundle.Sha256File(Path.Combine(dir, GenevaBundle.FileName));
            var manifest = new JsonObject { ["tag"] = "v1.0.0", ["version"] = "1.0.0", ["rid"] = "x", ["lua_compat"] = 0, ["source_sha256"] = "", ["files"] = new JsonObject { [GenevaBundle.FileName] = hash } };
            File.WriteAllText(Path.Combine(dir, "bundle.json"), manifest.ToJsonString());
            Assert.True(new GenevaBundle(dir).Verify().Ok);
            File.WriteAllText(Path.Combine(dir, GenevaBundle.FileName), "swapped");
            Assert.False(new GenevaBundle(dir).Verify().Ok);
            File.Delete(Path.Combine(dir, "bundle.json"));
            Assert.False(new GenevaBundle(dir).Verify().Ok);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
