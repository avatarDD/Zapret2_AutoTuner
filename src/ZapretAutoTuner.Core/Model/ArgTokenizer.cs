using System.Text;

namespace ZapretAutoTuner.Core.Model;

/// <summary>
/// Splits an argument string the way a POSIX shell (or nfqws2's wordexp in @config) would for the
/// subset we produce and import: whitespace separates words, single and double quotes group,
/// backslash escapes the next character outside single quotes (unquoted, only a character a shell would treat
/// specially: elsewhere it is a Windows path separator and stays).
/// </summary>
public static class ArgTokenizer
{
    public static List<string> Split(string text)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        bool inWord = false;
        char quote = '\0';
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (quote == '\'')
            {
                if (c == '\'')
                    quote = '\0';
                else
                    sb.Append(c);
                continue;
            }
            if (quote == '"')
            {
                if (c == '"')
                    quote = '\0';
                else if (c == '\\' && i + 1 < text.Length && text[i + 1] is '"' or '\\' or '$' or '`')
                    sb.Append(text[++i]);
                else
                    sb.Append(c);
                continue;
            }
            if (char.IsWhiteSpace(c))
            {
                if (inWord)
                {
                    result.Add(sb.ToString());
                    sb.Clear();
                    inWord = false;
                }
                continue;
            }
            inWord = true;
            if (c is '\'' or '"')
                quote = c;
            // a shell escape only before what a shell would otherwise eat (a space, a quote, $, `, a backslash): a
            // Windows path from a .cmd (--hostlist=C:\zapret\lists\list.txt) keeps its backslashes
            else if (c == '\\' && i + 1 < text.Length && (char.IsWhiteSpace(text[i + 1]) || text[i + 1] is '"' or '\'' or '\\' or '$' or '`'))
                sb.Append(text[++i]);
            else
                sb.Append(c);
        }
        if (quote != '\0')
            throw new FormatException("unterminated quote");
        if (inWord)
            result.Add(sb.ToString());
        return result;
    }

    /// <summary>Quotes a word for a shell or @config file only when it needs it.</summary>
    public static string Quote(string word)
    {
        if (word.Length > 0 && word.All(c => char.IsAsciiLetterOrDigit(c) || "-_=.,:/@%+^".Contains(c, StringComparison.Ordinal)))
            return word;
        return "'" + word.Replace("'", "'\\''", StringComparison.Ordinal) + "'";
    }

    /// <summary>Splits <c>--name=value</c> into name and value (value null if no '=').</summary>
    public static (string Name, string? Value) SplitOption(string token)
    {
        int eq = token.IndexOf('=', StringComparison.Ordinal);
        return eq < 0 ? (token, null) : (token[..eq], token[(eq + 1)..]);
    }
}
