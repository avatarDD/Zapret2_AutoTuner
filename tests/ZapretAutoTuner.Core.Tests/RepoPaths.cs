namespace ZapretAutoTuner.Core.Tests;

internal static class RepoPaths
{
    public static string Root { get; } = FindRoot();

    /// <summary>
    /// The zapret2 tree the catalog is checked against: <c>ZT_ZAPRET2_DIR</c> (the downloaded release in CI)
    /// or the vendored copy in <c>third_party/zapret2</c>.
    /// </summary>
    public static string Zapret2 =>
        Environment.GetEnvironmentVariable("ZT_ZAPRET2_DIR") is { Length: > 0 } d ? d : Path.Combine(Root, "third_party", "zapret2");

    /// <summary>Packet corpus with the tshark reference (<c>tools/pcaps/make_corpus.py</c>).</summary>
    public static string Pcaps(params string[] parts) => Path.Combine([Root, "tests", "pcaps", .. parts]);

    public static string Testdata(params string[] parts) => Path.Combine([Root, "tests", "testdata", .. parts]);

    private static string FindRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AGENTS.md")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("repository root not found");
    }
}
