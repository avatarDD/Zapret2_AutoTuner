namespace ZapretAutoTuner.Core.Model;

/// <summary>
/// The desync part of one profile: an ordered list of <c>--payload</c>, <c>--in-range</c>,
/// <c>--out-range</c> and <c>--lua-desync</c> items. Filters (ports, l7, lists) live on <see cref="Profile"/>.
/// </summary>
public sealed class Strategy : IEquatable<Strategy>
{
    public Strategy(IEnumerable<ProfileAction> actions)
    {
        Actions = actions.ToList().AsReadOnly();
    }

    public IReadOnlyList<ProfileAction> Actions { get; }

    public IEnumerable<LuaCall> Calls => Actions.OfType<LuaDesync>().Select(a => a.Call);

    public int InstanceCount => Actions.Count(a => a is LuaDesync);

    public static Strategy Parse(string args) => Parse(ArgTokenizer.Split(args));

    public static Strategy Parse(IEnumerable<string> tokens)
    {
        var actions = new List<ProfileAction>();
        foreach (var t in tokens)
        {
            var (name, value) = ArgTokenizer.SplitOption(t);
            if (value is null)
                throw new FormatException($"option '{t}' must have a value (use --opt=value)");
            actions.Add(name switch
            {
                "--payload" => new PayloadFilter(value.Split(',', StringSplitOptions.RemoveEmptyEntries)),
                "--in-range" => new InRange(value),
                "--out-range" => new OutRange(value),
                "--lua-desync" => new LuaDesync(LuaCall.Parse(value)),
                _ => throw new FormatException($"'{name}' is not a strategy option"),
            });
        }
        return new Strategy(actions);
    }

    public IEnumerable<string> ToArgs() => Actions.Select(a => a.ToArg());

    public override string ToString() => string.Join(' ', ToArgs());

    public bool Equals(Strategy? other) => other is not null && ToString() == other.ToString();

    public override bool Equals(object? obj) => obj is Strategy s && Equals(s);

    public override int GetHashCode() => ToString().GetHashCode(StringComparison.Ordinal);
}
