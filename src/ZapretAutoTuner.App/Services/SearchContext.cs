using System.Globalization;
using ZapretAutoTuner.Core.Search;
using ZapretAutoTuner.Storage;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.Services;

/// <summary>
/// The provider a search runs on and the learned order for it (PLAN 4a.1), from the settings and the knowledge base.
/// Offline: the ASN is what the user entered, nothing is looked up.
/// </summary>
public sealed record SearchContext(long? NetworkId, int? Asn, SearchLearning? Learning)
{
    public static SearchContext For(AppHost host, string? label = null)
    {
        var asn = ParseAsn(host.Settings.ProviderAsn);
        long? network = asn is { } a ? host.Kb.Network(new NetworkInfo(a, null)) : null;
        var learning = host.Settings.Learning ? TuningSession.Learning(host.Kb, new LearningContext(asn, label)) : null;
        return new SearchContext(network, asn, learning);
    }

    /// <summary>"AS12389", "as 12389" or "12389"; null for anything else.</summary>
    public static int? ParseAsn(string? text)
    {
        var t = (text ?? "").Trim();
        if (t.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
            t = t[2..].TrimStart();
        return int.TryParse(t, NumberStyles.None, CultureInfo.InvariantCulture, out var asn) && asn > 0 ? asn : null;
    }
}
