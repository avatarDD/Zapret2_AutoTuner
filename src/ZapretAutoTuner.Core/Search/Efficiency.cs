namespace ZapretAutoTuner.Core.Search;

/// <summary>
/// Success rate of a strategy ("КПД", dpi-diagnostics §6.2a): successes out of attempts, with the Wilson score
/// interval, so 2/5 and 2/10 are told apart and one lucky attempt does not count as progress.
/// </summary>
public readonly record struct Efficiency(int Successes, int Attempts)
{
    /// <summary>z for a 90% two-sided interval: strict enough for a search, cheap in attempts.</summary>
    public const double Z = 1.645;

    public double Rate => Attempts == 0 ? 0 : (double)Successes / Attempts;

    public bool Working => Attempts > 0 && Successes == Attempts;

    public bool Partial => Successes > 0 && Successes < Attempts;

    public bool Dead => Attempts > 0 && Successes == 0;

    public double WilsonLower => Wilson(-1);

    public double WilsonUpper => Wilson(+1);

    public Efficiency Add(bool ok) => new(Successes + (ok ? 1 : 0), Attempts + 1);

    public Efficiency Add(Efficiency other) => new(Successes + other.Successes, Attempts + other.Attempts);

    /// <summary>
    /// A mutation is accepted only when it is better with a margin: its lower bound is above the parent's rate, or it
    /// reached N/N where the parent did not.
    /// </summary>
    public bool ClearlyBetterThan(Efficiency parent) =>
        Attempts > 0 && (WilsonLower > parent.Rate || (Working && !parent.Working && Attempts >= parent.Attempts));

    private double Wilson(int sign)
    {
        if (Attempts == 0)
            return sign < 0 ? 0 : 1;
        double n = Attempts, p = Rate, z2 = Z * Z;
        double centre = p + z2 / (2 * n);
        double margin = Z * Math.Sqrt(p * (1 - p) / n + z2 / (4 * n * n));
        return Math.Clamp((centre + sign * margin) / (1 + z2 / n), 0, 1);
    }

    public override string ToString() => $"{Successes}/{Attempts}";
}
