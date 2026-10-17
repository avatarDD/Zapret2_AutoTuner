using System.Text;

namespace ZapretAutoTuner.Core.Model;

/// <summary>One argument of a <c>--lua-desync</c> call. A null value is a flag (<c>:badsum</c>).</summary>
public sealed record LuaArg(string Name, string? Value = null)
{
    public bool IsFlag => Value is null;

    public override string ToString() =>
        Value is null ? Name : Name + "=" + LuaCall.EscapeValue(Value);
}

/// <summary>
/// A <c>--lua-desync=func[:arg[=val]]…</c> instance. Parsing and formatting follow
/// <c>parse_lua_call</c> in nfq2/nfqws.c: <c>:</c> separates arguments, <c>\:</c> is a literal colon,
/// the first <c>=</c> separates name and value, names are Lua identifiers.
/// </summary>
public sealed class LuaCall : IEquatable<LuaCall>
{
    public LuaCall(string function, IEnumerable<LuaArg>? args = null)
    {
        if (!Identifiers.IsLuaIdentifier(function))
            throw new FormatException($"'{function}' is not a valid Lua function name");
        Function = function;
        Args = (args ?? []).ToList().AsReadOnly();
        foreach (var a in Args)
        {
            if (!Identifiers.IsLuaIdentifier(a.Name))
                throw new FormatException($"'{a.Name}' is not a valid argument name");
        }
    }

    public string Function { get; }

    public IReadOnlyList<LuaArg> Args { get; }

    public string? this[string name] => Args.LastOrDefault(a => a.Name == name)?.Value;

    public bool Has(string name) => Args.Any(a => a.Name == name);

    public LuaCall With(string name, string? value = null)
    {
        var list = Args.Where(a => a.Name != name).ToList();
        list.Add(new LuaArg(name, value));
        return new LuaCall(Function, list);
    }

    public LuaCall Without(string name) => new(Function, Args.Where(a => a.Name != name));

    public static LuaCall Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var parts = SplitUnescaped(text);
        if (parts.Count == 0 || parts[0].Length == 0)
            throw new FormatException("empty --lua-desync value");
        var args = new List<LuaArg>();
        for (int i = 1; i < parts.Count; i++)
        {
            var p = parts[i];
            if (p.Length == 0)
                throw new FormatException($"empty argument in '{text}'");
            int eq = p.IndexOf('=', StringComparison.Ordinal);
            args.Add(eq < 0 ? new LuaArg(p) : new LuaArg(p[..eq], p[(eq + 1)..]));
        }
        return new LuaCall(parts[0], args);
    }

    public static bool TryParse(string text, out LuaCall? call)
    {
        try
        {
            call = Parse(text);
            return true;
        }
        catch (FormatException)
        {
            call = null;
            return false;
        }
    }

    internal static string EscapeValue(string value) => value.Replace(":", "\\:", StringComparison.Ordinal);

    private static List<string> SplitUnescaped(string text)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '\\' && i + 1 < text.Length && text[i + 1] == ':')
            {
                sb.Append(':');
                i++;
            }
            else if (c == ':')
            {
                result.Add(sb.ToString());
                sb.Clear();
            }
            else
            {
                sb.Append(c);
            }
        }
        result.Add(sb.ToString());
        return result;
    }

    public override string ToString()
    {
        var sb = new StringBuilder(Function);
        foreach (var a in Args)
            sb.Append(':').Append(a);
        return sb.ToString();
    }

    public bool Equals(LuaCall? other) => other is not null && ToString() == other.ToString();

    public override bool Equals(object? obj) => obj is LuaCall c && Equals(c);

    public override int GetHashCode() => ToString().GetHashCode(StringComparison.Ordinal);
}
