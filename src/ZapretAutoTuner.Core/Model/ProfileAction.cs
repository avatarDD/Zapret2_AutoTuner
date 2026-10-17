namespace ZapretAutoTuner.Core.Model;

/// <summary>
/// An ordered item inside a profile: <c>--payload</c>, <c>--in-range</c>, <c>--out-range</c> or
/// <c>--lua-desync</c>. The three filters apply to every following <c>--lua-desync</c> of the profile.
/// </summary>
public abstract record ProfileAction
{
    public abstract string ToArg();

    public override string ToString() => ToArg();

    public static ProfileAction Payload(params string[] types) => new PayloadFilter(types);

    public static ProfileAction Desync(string call) => new LuaDesync(LuaCall.Parse(call));
}

public sealed record PayloadFilter(IReadOnlyList<string> Types) : ProfileAction
{
    public override string ToArg() => "--payload=" + string.Join(',', Types);

    public bool Equals(PayloadFilter? other) => other is not null && Types.SequenceEqual(other.Types);

    public override int GetHashCode() => string.Join(',', Types).GetHashCode(StringComparison.Ordinal);
}

public sealed record InRange(string Range) : ProfileAction
{
    public override string ToArg() => "--in-range=" + Range;
}

public sealed record OutRange(string Range) : ProfileAction
{
    public override string ToArg() => "--out-range=" + Range;
}

public sealed record LuaDesync(LuaCall Call) : ProfileAction
{
    public override string ToArg() => "--lua-desync=" + Call;
}
