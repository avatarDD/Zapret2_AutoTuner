using System.Text;

namespace ZapretAutoTuner.Core.Programs;

/// <summary>
/// Splits a Windows argument string the way the C runtime (and <c>CommandLineToArgvW</c>) does, so a shortcut's
/// arguments survive: a backslash is literal unless a run of them precedes a quote (2n backslashes and a quote are n
/// backslashes and a delimiter; 2n+1 are n backslashes and a literal quote), <c>""</c> inside quotes is a quote.
/// </summary>
public static class WindowsCommandLine
{
    public static List<string> Split(string text)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        bool inWord = false, quoted = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '\\')
            {
                int n = 0;
                while (i < text.Length && text[i] == '\\')
                {
                    n++;
                    i++;
                }
                inWord = true;
                if (i < text.Length && text[i] == '"')
                {
                    sb.Append('\\', n / 2);
                    if (n % 2 == 1)
                        sb.Append('"');
                    else
                        quoted = !quoted;
                }
                else
                {
                    sb.Append('\\', n);
                    i--;
                }
                continue;
            }
            if (c == '"')
            {
                inWord = true;
                if (quoted && i + 1 < text.Length && text[i + 1] == '"')
                {
                    sb.Append('"');
                    i++;
                }
                else
                {
                    quoted = !quoted;
                }
                continue;
            }
            if (!quoted && c is ' ' or '\t')
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
            sb.Append(c);
        }
        if (inWord)
            result.Add(sb.ToString());
        return result;
    }
}
