using System.Text;
using ZapretAutoTuner.Core.Catalog;

namespace ZapretAutoTuner.Core.Resources;

/// <summary>
/// A cheap static check of a user Lua script (PLAN 4a.5); nothing is executed. Size and UTF-8, balanced blocks and
/// brackets (strings and comments skipped), the global functions it defines, and that none of them takes the name of a
/// zapret2 library function (the catalog): a user <c>fake</c> would silently replace the real one for every profile.
/// Calls that reach outside the engine (<c>os.execute</c>, <c>io.popen</c>…) are listed as warnings for the approval
/// dialog.
/// </summary>
public sealed class LuaScriptCheck
{
    private static readonly string[] Risky = ["os.execute", "io.popen", "os.remove", "os.rename", "io.open", "loadstring", "dofile", "require", "load"];

    private LuaScriptCheck()
    {
    }

    /// <summary>Global functions with the <c>(ctx, desync)</c> signature: what <c>--lua-desync</c> can call.</summary>
    public IReadOnlyList<string> DesyncFunctions { get; private init; } = [];

    /// <summary>Every global function the script defines (<c>function name(</c> or <c>name = function(</c>).</summary>
    public IReadOnlyList<string> GlobalFunctions { get; private init; } = [];

    public IReadOnlyList<ResourceProblem> Problems { get; private init; } = [];

    public bool Ok => Problems.All(p => !p.IsError);

    /// <summary>The desync functions of a source that was already checked (stored versions).</summary>
    public static List<string> FindDesyncFunctions(string source) => [.. Scan(source).Functions.Where(f => f.Desync).Select(f => f.Name).Distinct(StringComparer.Ordinal)];

    public static LuaScriptCheck Check(string source, LuaCatalog? catalog = null)
    {
        catalog ??= LuaCatalog.Default;
        var problems = new List<ResourceProblem>();
        if (string.IsNullOrWhiteSpace(source))
        {
            problems.Add(new(true, "lua.empty", "скрипт пустой", "the script is empty"));
            return new LuaScriptCheck { Problems = problems };
        }
        int bytes;
        try
        {
            bytes = new UTF8Encoding(false, true).GetByteCount(source);
        }
        catch (EncoderFallbackException)
        {
            problems.Add(new(true, "lua.utf8", "текст не в UTF-8 (оборванные суррогатные пары)", "the text is not valid UTF-8 (broken surrogate pairs)"));
            return new LuaScriptCheck { Problems = problems };
        }
        if (bytes > ResourceRules.MaxLuaBytes)
            problems.Add(new(true, "lua.size", $"скрипт {bytes} байт, допустимо до {ResourceRules.MaxLuaBytes}", $"the script is {bytes} bytes, at most {ResourceRules.MaxLuaBytes} allowed"));
        if (source.Contains('\0', StringComparison.Ordinal))
            problems.Add(new(true, "lua.nul", "в тексте есть нулевой символ", "the text contains a NUL character"));

        var scan = Scan(source);
        problems.AddRange(scan.Problems);
        var names = scan.Functions.Select(f => f.Name).Distinct(StringComparer.Ordinal).ToList();
        foreach (var f in scan.Functions.DistinctBy(f => f.Name))
        {
            if (catalog.Find(f.Name) is { } spec || catalog.Data.IffFunctions.Contains(f.Name))
                problems.Add(new(true, "lua.collision", $"функция {f.Name} уже есть в zapret2 ({catalog.Find(f.Name)?.File ?? "zapret-auto.lua"}): своё имя не может совпадать с функциями zapret2",
                    $"function {f.Name} already exists in zapret2: a user function must not reuse a zapret2 name", $"строка {f.Line}"));
        }
        var desync = scan.Functions.Where(f => f.Desync).Select(f => f.Name).Distinct(StringComparer.Ordinal).ToList();
        if (desync.Count == 0 && problems.All(p => !p.IsError))
            problems.Add(new(false, "lua.nodesync", "нет ни одной функции function имя(ctx, desync): из --lua-desync вызвать нечего",
                "no function name(ctx, desync): nothing for --lua-desync to call"));
        foreach (var call in scan.Calls.Where(c => Risky.Contains(c.Name)).DistinctBy(c => c.Name))
            problems.Add(new(false, "lua.risky", $"скрипт вызывает {call.Name}: с правами движка это действует вне обхода DPI",
                $"the script calls {call.Name}: with the engine's rights this reaches beyond DPI bypass", $"строка {call.Line}"));
        return new LuaScriptCheck { DesyncFunctions = desync, GlobalFunctions = names, Problems = problems };
    }

    private sealed record Token(string Text, int Line, bool Name);

    private sealed record ScanResult(List<(string Name, bool Desync, int Line)> Functions, List<(string Name, int Line)> Calls, List<ResourceProblem> Problems);

    private static readonly HashSet<string> Keywords =
    [
        "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if", "in",
        "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
    ];

    /// <summary>Tokens without strings and comments, then the block structure and the function definitions.</summary>
    private static ScanResult Scan(string src)
    {
        var problems = new List<ResourceProblem>();
        var tokens = Tokenize(src, problems);
        var functions = new List<(string, bool, int)>();
        var calls = new List<(string, int)>();
        var stack = new Stack<Token>();
        for (int i = 0; i < tokens.Count; i++)
        {
            var t = tokens[i];
            switch (t.Text)
            {
                case "function" or "if" or "do" or "repeat" or "(" or "{" or "[":
                    stack.Push(t);
                    break;
                case "end":
                    if (stack.Count == 0 || stack.Peek().Text is "repeat" or "(" or "{" or "[")
                    {
                        problems.Add(new(true, "lua.syntax", "лишний end", "unexpected end", $"строка {t.Line}"));
                        break;
                    }
                    stack.Pop();
                    break;
                case "until":
                    if (stack.Count == 0 || stack.Peek().Text != "repeat")
                    {
                        problems.Add(new(true, "lua.syntax", "until без repeat", "until without repeat", $"строка {t.Line}"));
                        break;
                    }
                    stack.Pop();
                    break;
                case ")" or "}" or "]":
                    var open = t.Text switch { ")" => "(", "}" => "{", _ => "[" };
                    if (stack.Count == 0 || stack.Peek().Text != open)
                    {
                        problems.Add(new(true, "lua.syntax", $"непарная скобка {t.Text}", $"unbalanced {t.Text}", $"строка {t.Line}"));
                        break;
                    }
                    stack.Pop();
                    break;
            }

            if (t.Text == "function")
            {
                // function name(…) — global unless "local function"; name = function(…) — global unless local/field
                string? name = null;
                int paramsAt = -1;
                if (i + 2 < tokens.Count && tokens[i + 1].Name && tokens[i + 2].Text == "(" && (i == 0 || tokens[i - 1].Text != "local"))
                {
                    name = tokens[i + 1].Text;
                    paramsAt = i + 3;
                }
                else if (i >= 2 && tokens[i - 1].Text == "=" && tokens[i - 2].Name && i + 1 < tokens.Count && tokens[i + 1].Text == "("
                    && (i < 3 || tokens[i - 3].Text is not ("local" or "." or ":" or ",")))
                {
                    name = tokens[i - 2].Text;
                    paramsAt = i + 2;
                }
                if (name is not null)
                {
                    var ps = new List<string>();
                    for (int j = paramsAt; j < tokens.Count && tokens[j].Text != ")"; j++)
                    {
                        if (tokens[j].Text != ",")
                            ps.Add(tokens[j].Text);
                    }
                    functions.Add((name, ps.Count == 2 && ps[0] == "ctx" && ps[1] == "desync", t.Line));
                }
            }
            else if (t.Name && i + 1 < tokens.Count && tokens[i + 1].Text is "(" or "\"" && (i == 0 || tokens[i - 1].Text != "function"))
            {
                var qualified = i >= 2 && tokens[i - 1].Text == "." && tokens[i - 2].Name ? tokens[i - 2].Text + "." + t.Text : t.Text;
                calls.Add((qualified, t.Line));
            }
        }
        foreach (var open in stack)
            problems.Add(new(true, "lua.syntax", $"{open.Text} не закрыт", $"{open.Text} is not closed", $"строка {open.Line}"));
        return new ScanResult(functions, calls, problems);
    }

    private static List<Token> Tokenize(string s, List<ResourceProblem> problems)
    {
        var tokens = new List<Token>();
        int line = 1;
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            if (c == '\n')
            {
                line++;
                i++;
                continue;
            }
            if (char.IsWhiteSpace(c))
            {
                i++;
                continue;
            }
            if (c == '-' && i + 1 < s.Length && s[i + 1] == '-')
            {
                i += 2;
                if (LongBracket(s, i) is int level and >= 0)
                {
                    int start = line;
                    if (!SkipLong(s, ref i, level, ref line))
                        problems.Add(new(true, "lua.syntax", "комментарий --[[ не закрыт", "comment --[[ is not closed", $"строка {start}"));
                    continue;
                }
                while (i < s.Length && s[i] != '\n')
                    i++;
                continue;
            }
            if (c == '[' && LongBracket(s, i) is int lv and >= 0)
            {
                int start = line;
                if (!SkipLong(s, ref i, lv, ref line))
                    problems.Add(new(true, "lua.syntax", "строка [[ не закрыта", "string [[ is not closed", $"строка {start}"));
                tokens.Add(new Token("\"", start, false));
                continue;
            }
            if (c is '"' or '\'')
            {
                int start = line;
                i++;
                bool closed = false;
                while (i < s.Length)
                {
                    if (s[i] == '\\' && i + 1 < s.Length)
                    {
                        if (s[i + 1] == '\n')
                            line++;
                        i += 2;
                        continue;
                    }
                    if (s[i] == '\n')
                        break;
                    if (s[i] == c)
                    {
                        closed = true;
                        i++;
                        break;
                    }
                    i++;
                }
                if (!closed)
                    problems.Add(new(true, "lua.syntax", "строка в кавычках не закрыта", "a quoted string is not closed", $"строка {start}"));
                tokens.Add(new Token("\"", start, false));
                continue;
            }
            if (char.IsAsciiLetter(c) || c == '_')
            {
                int start = i;
                while (i < s.Length && (char.IsAsciiLetterOrDigit(s[i]) || s[i] == '_'))
                    i++;
                var word = s[start..i];
                tokens.Add(new Token(word, line, !Keywords.Contains(word)));
                continue;
            }
            if (char.IsAsciiDigit(c))
            {
                while (i < s.Length && (char.IsAsciiLetterOrDigit(s[i]) || s[i] == '.' || s[i] == '_'))
                    i++;
                tokens.Add(new Token("0", line, false));
                continue;
            }
            tokens.Add(new Token(c.ToString(), line, false));
            i++;
        }
        return tokens;
    }

    /// <summary>The level of a long bracket <c>[==[</c> at <paramref name="i"/>, or -1.</summary>
    private static int LongBracket(string s, int i)
    {
        if (i >= s.Length || s[i] != '[')
            return -1;
        int j = i + 1;
        while (j < s.Length && s[j] == '=')
            j++;
        return j < s.Length && s[j] == '[' ? j - i - 1 : -1;
    }

    private static bool SkipLong(string s, ref int i, int level, ref int line)
    {
        var close = "]" + new string('=', level) + "]";
        i += level + 2;
        int end = s.IndexOf(close, i, StringComparison.Ordinal);
        int stop = end < 0 ? s.Length : end + close.Length;
        for (int k = i; k < Math.Min(stop, s.Length); k++)
        {
            if (s[k] == '\n')
                line++;
        }
        i = stop;
        return end >= 0;
    }
}
