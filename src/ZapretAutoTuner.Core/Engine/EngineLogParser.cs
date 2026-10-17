using System.Globalization;
using System.Text.RegularExpressions;

namespace ZapretAutoTuner.Core.Engine;

public enum EngineEventKind
{
    /// <summary>A profile was selected for a connection (<c>desync profile N (name) matches</c>).</summary>
    ProfileMatched,

    /// <summary>No profile matched (profile 0 is used, nothing happens).</summary>
    ProfileNotFound,

    /// <summary>The profile changed after the hostname or l7 protocol became known.</summary>
    ProfileChanged,

    /// <summary>A lua instance ran (<c>* lua 'name' : desync</c>).</summary>
    LuaDesync,

    /// <summary>Lua stopped being called for this flow.</summary>
    LuaCutoff,

    /// <summary>Waiting for a multi-packet ClientHello/QUIC Initial.</summary>
    ReasmDelay,

    /// <summary><c>rawpacket_queue failed !</c>: reassembly gave up, the payload became unknown (kyber CH too long).</summary>
    ReasmFailed,

    /// <summary>A blob referenced by a profile does not exist; the plan was aborted.</summary>
    BlobUnavailable,

    /// <summary>A blob or argument name is not a Lua identifier: the engine exits.</summary>
    BadIdentifier,

    /// <summary>lua and binary come from different releases.</summary>
    IncompatibleLua,

    /// <summary>Autohostlist decided a host fails or works.</summary>
    AutoHostlist,

    /// <summary>A lua error (the engine prints the traceback).</summary>
    LuaError,

    /// <summary>A fatal option parsing or startup error.</summary>
    StartupError,
}

public sealed record EngineEvent(EngineEventKind Kind, string Line, int? Profile = null, string? Name = null, string? Detail = null);

/// <summary>
/// Turns <c>--debug</c> output of nfqws2/winws2 into events (PLAN 1.2, nfqws2-engine §13). Formats come from
/// the DLOG calls in nfq2/desync.c, nfq2/lua.c and nfq2/nfqws.c of the bundled release.
/// </summary>
public static partial class EngineLogParser
{
    [GeneratedRegex(@"desync profile (\d+) \(([^)]*)\) matches")]
    private static partial Regex ProfileMatchRegex();

    [GeneratedRegex(@"using (?:cached )?desync profile (\d+) \(([^)]*)\)")]
    private static partial Regex ProfileUsingRegex();

    [GeneratedRegex(@"^\* lua '([^']+)' : desync")]
    private static partial Regex LuaDesyncRegex();

    [GeneratedRegex(@"lua cutoff from '([^']+)'|\* lua '([^']+)' : voluntary cutoff")]
    private static partial Regex CutoffRegex();

    [GeneratedRegex(@"DELAY desync until reasm is complete \(#(\d+)\)")]
    private static partial Regex DelayRegex();

    [GeneratedRegex(@"blob '([^']*)' unavailable")]
    private static partial Regex BlobRegex();

    [GeneratedRegex(@"bad identifier '([^']*)'")]
    private static partial Regex BadIdentRegex();

    [GeneratedRegex(@"auto hostlist \(profile (\d+)[^)]*\)\)? : (.*)")]
    private static partial Regex AutoHostlistRegex();

    public static EngineEvent? Parse(string line)
    {
        var l = line.TrimEnd();
        if (l.Length == 0)
            return null;
        Match m;
        if ((m = ProfileMatchRegex().Match(l)).Success || (m = ProfileUsingRegex().Match(l)).Success)
            return new EngineEvent(EngineEventKind.ProfileMatched, l, int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture), m.Groups[2].Value);
        if (l.Contains("desync profile not found", StringComparison.Ordinal) || l.Contains("matching desync profile not found", StringComparison.Ordinal))
            return new EngineEvent(EngineEventKind.ProfileNotFound, l);
        if (l.Contains("desync profile changed by revealed", StringComparison.Ordinal))
            return new EngineEvent(EngineEventKind.ProfileChanged, l);
        if ((m = LuaDesyncRegex().Match(l)).Success)
            return new EngineEvent(EngineEventKind.LuaDesync, l, Name: m.Groups[1].Value);
        if ((m = CutoffRegex().Match(l)).Success)
            return new EngineEvent(EngineEventKind.LuaCutoff, l, Name: m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value);
        if ((m = DelayRegex().Match(l)).Success)
            return new EngineEvent(EngineEventKind.ReasmDelay, l, Detail: m.Groups[1].Value);
        if (l.Contains("rawpacket_queue failed", StringComparison.Ordinal))
            return new EngineEvent(EngineEventKind.ReasmFailed, l);
        if ((m = BlobRegex().Match(l)).Success)
            return new EngineEvent(EngineEventKind.BlobUnavailable, l, Name: m.Groups[1].Value);
        if ((m = BadIdentRegex().Match(l)).Success)
            return new EngineEvent(EngineEventKind.BadIdentifier, l, Name: m.Groups[1].Value);
        if (l.Contains("Incompatible NFQWS2_COMPAT_VER", StringComparison.Ordinal))
            return new EngineEvent(EngineEventKind.IncompatibleLua, l);
        if ((m = AutoHostlistRegex().Match(l)).Success)
            return new EngineEvent(EngineEventKind.AutoHostlist, l, int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture), Detail: m.Groups[2].Value);
        if (l.Contains("stack traceback", StringComparison.Ordinal) || l.StartsWith("LUA ERROR", StringComparison.OrdinalIgnoreCase) || l.Contains(".lua:", StringComparison.Ordinal) && l.Contains("error", StringComparison.OrdinalIgnoreCase))
            return new EngineEvent(EngineEventKind.LuaError, l);
        if (l.StartsWith("invalid ", StringComparison.OrdinalIgnoreCase) || l.Contains("Invalid payload filter", StringComparison.Ordinal)
            || l.Contains("unrecognized option", StringComparison.Ordinal) || l.Contains("could not open", StringComparison.OrdinalIgnoreCase)
            || l.Contains("out of memory", StringComparison.Ordinal))
            return new EngineEvent(EngineEventKind.StartupError, l);
        return null;
    }

    /// <summary>Explains a fatal event to the user in Russian; null for informational events.</summary>
    public static string? Explain(EngineEvent e) => e.Kind switch
    {
        EngineEventKind.IncompatibleLua => "lua и движок из разных релизов zapret2. Переустановите zapret2 из программы.",
        EngineEventKind.BlobUnavailable => $"блоб «{e.Name}» не найден: профиль не будет работать. Нужен --blob={e.Name}:@файл.",
        EngineEventKind.BadIdentifier => $"«{e.Name}» — недопустимое имя (нужны латиница, цифры и _).",
        EngineEventKind.ReasmFailed => "ClientHello слишком длинный для сборки (обычно kyber): стратегия по маркерам не сработает.",
        EngineEventKind.LuaError => "ошибка в Lua-функции стратегии.",
        EngineEventKind.StartupError => "движок отказался запускаться: " + e.Line,
        _ => null,
    };

    public static bool IsFatal(EngineEvent e) => e.Kind is EngineEventKind.IncompatibleLua or EngineEventKind.BadIdentifier or EngineEventKind.StartupError;
}
