using System.Text.RegularExpressions;

namespace ZapretAutoTuner.Core.Model;

public static partial class Identifiers
{
    private static readonly HashSet<string> LuaKeywords =
    [
        "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if", "in",
        "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
    ];

    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex LuaIdentRegex();

    [GeneratedRegex("^[A-Za-z0-9_-]{1,64}$")]
    private static partial Regex ListNameRegex();

    /// <summary>Lua identifier that is not a reserved word (blob and function names).</summary>
    public static bool IsLuaIdentifier(string? s) =>
        s is not null && LuaIdentRegex().IsMatch(s) && !LuaKeywords.Contains(s);

    /// <summary>Profile, hostlist and zapret-gui id names: <c>[A-Za-z0-9_-]{1,64}</c>.</summary>
    public static bool IsListName(string? s) => s is not null && ListNameRegex().IsMatch(s);

    /// <summary>Turns arbitrary text into a <c>[A-Za-z0-9_-]</c> name (zapret-gui replaces bad chars with '_').</summary>
    public static string ToListName(string s, int maxLength = 64)
    {
        var chars = s.Select(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' ? c : '_').ToArray();
        var r = new string(chars).Trim('_');
        if (r.Length == 0)
            r = "zt";
        return r.Length > maxLength ? r[..maxLength] : r;
    }

    /// <summary>Turns arbitrary text into a Lua identifier usable as a blob name.</summary>
    public static string ToLuaIdentifier(string s)
    {
        var chars = s.Select(c => char.IsAsciiLetterOrDigit(c) || c == '_' ? c : '_').ToArray();
        var r = new string(chars);
        if (r.Length == 0 || char.IsAsciiDigit(r[0]))
            r = "_" + r;
        if (LuaKeywords.Contains(r))
            r += "_";
        return r;
    }
}
