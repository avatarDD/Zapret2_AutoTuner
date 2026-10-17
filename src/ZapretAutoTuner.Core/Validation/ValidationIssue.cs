namespace ZapretAutoTuner.Core.Validation;

public enum Severity
{
    /// <summary>The engine would refuse to start, silently do nothing or break connections.</summary>
    Error,

    /// <summary>Works, but probably not as intended (ignored argument, route-dependent fooling…).</summary>
    Warning,
}

/// <summary>A validator finding with a stable code and a user-facing message in Russian and English.</summary>
public sealed record ValidationIssue(Severity Severity, string Code, string Ru, string En, string? Where = null)
{
    public string Message(bool russian = true) => (Where is null ? "" : Where + ": ") + (russian ? Ru : En);

    public override string ToString() => $"{Severity} {Code}: {Message()}";
}

public sealed class ValidationResult
{
    public List<ValidationIssue> Issues { get; } = [];

    public bool Ok => Issues.All(i => i.Severity != Severity.Error);

    public IEnumerable<ValidationIssue> Errors => Issues.Where(i => i.Severity == Severity.Error);

    public IEnumerable<ValidationIssue> Warnings => Issues.Where(i => i.Severity == Severity.Warning);

    internal void Error(string code, string ru, string en, string? where = null) => Issues.Add(new(Severity.Error, code, ru, en, where));

    internal void Warn(string code, string ru, string en, string? where = null) => Issues.Add(new(Severity.Warning, code, ru, en, where));

    public override string ToString() => string.Join(Environment.NewLine, Issues);
}
