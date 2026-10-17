using ZapretAutoTuner.Core.Catalog;
using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Engine;

/// <summary>An engine command line split into global options, blobs, lua files and profiles.</summary>
public sealed class ParsedEngineArgs
{
    /// <summary>Global options other than --blob and --lua-init, in order.</summary>
    public List<string> Globals { get; } = [];

    /// <summary>Blob name → source after the colon (<c>@path</c>, <c>+ofs@path</c> or <c>0x…</c>).</summary>
    public Dictionary<string, string> Blobs { get; } = new(StringComparer.Ordinal);

    /// <summary><c>--lua-init</c> values in order (<c>@file</c> or inline code).</summary>
    public List<string> LuaInits { get; } = [];

    public List<Profile> Profiles { get; } = [];

    /// <summary>Tokens the parser could not place, with the reason (Russian).</summary>
    public List<(string Token, string Reason)> Problems { get; } = [];

    /// <summary>Index of the first token that belongs to a profile, -1 if none.</summary>
    public int FirstProfileToken { get; set; } = -1;

    /// <summary>Global options that appear after the first profile option (allowed by getopt, but confusing).</summary>
    public List<string> LateGlobals { get; } = [];
}

/// <summary>
/// Parses nfqws2/winws2 argv into the model. Used by the argv validator and by the importers (zapret2 config,
/// keenetic conf, winws2 .cmd, zapret-gui text).
/// </summary>
public static class EngineArgsParser
{
    public static ParsedEngineArgs Parse(IReadOnlyList<string> argv, LuaCatalog? catalog = null)
    {
        catalog ??= LuaCatalog.Default;
        var r = new ParsedEngineArgs();
        var cur = new Profile();
        var actions = new List<ProfileAction>();
        bool profileStarted = false;

        void Flush()
        {
            cur.Strategy = new Strategy(actions);
            r.Profiles.Add(cur);
            cur = new Profile();
            actions = [];
        }

        for (int i = 0; i < argv.Count; i++)
        {
            var tok = argv[i];
            if (!tok.StartsWith("--", StringComparison.Ordinal))
            {
                r.Problems.Add((tok, "не опция (возможно, значение через пробел вместо =)"));
                continue;
            }
            var (name, value) = ArgTokenizer.SplitOption(tok);
            var key = name[2..];
            if (key.StartsWith("dpi-desync", StringComparison.Ordinal))
            {
                r.Problems.Add((tok, "это синтаксис nfqws1 (zapret1); в nfqws2 используется --lua-desync"));
                continue;
            }
            if (!catalog.EngineOptions.TryGetValue(key, out var spec))
            {
                r.Problems.Add((tok, "неизвестная опция движка"));
                continue;
            }
            if (spec.Arg == "required" && value is null)
            {
                r.Problems.Add((tok, "у опции должно быть значение через ="));
                continue;
            }
            if (spec.Arg == "none" && value is not null)
                r.Problems.Add((tok, "опция без значения, значение будет отвергнуто"));

            switch (spec.Scope)
            {
                case "separator":
                    if (profileStarted || actions.Count > 0)
                        Flush();
                    else
                        r.Problems.Add((tok, "--new без предыдущего профиля"));
                    if (value is { Length: > 0 })
                        cur.Name = value;
                    profileStarted = true;
                    break;
                case "global":
                    if (key == "blob")
                    {
                        int colon = value!.IndexOf(':', StringComparison.Ordinal);
                        if (colon <= 0)
                            r.Problems.Add((tok, "ожидается --blob=имя:@файл или имя:0xHEX"));
                        else
                            r.Blobs[value[..colon]] = value[(colon + 1)..];
                    }
                    else if (key == "lua-init")
                    {
                        r.LuaInits.Add(value!);
                    }
                    else
                    {
                        r.Globals.Add(tok);
                    }
                    if (profileStarted)
                        r.LateGlobals.Add(tok);
                    break;
                case "action":
                    MarkStart(r, ref profileStarted, i);
                    try
                    {
                        actions.Add(key switch
                        {
                            "payload" => new PayloadFilter(value!.Split(',', StringSplitOptions.RemoveEmptyEntries)),
                            "in-range" => new InRange(value!),
                            "out-range" => new OutRange(value!),
                            _ => new LuaDesync(LuaCall.Parse(value!)),
                        });
                    }
                    catch (FormatException e)
                    {
                        r.Problems.Add((tok, e.Message));
                    }
                    break;
                default:
                    MarkStart(r, ref profileStarted, i);
                    ApplyProfileOption(cur, key, value, tok);
                    break;
            }
        }
        if (profileStarted || actions.Count > 0)
            Flush();
        return r;
    }

    private static void MarkStart(ParsedEngineArgs r, ref bool started, int i)
    {
        if (!started)
        {
            started = true;
            r.FirstProfileToken = i;
        }
    }

    private static void ApplyProfileOption(Profile p, string key, string? value, string tok)
    {
        switch (key)
        {
            case "name": p.Name = value!; break;
            case "filter-l3": p.L3 = value; break;
            case "filter-tcp": p.TcpPorts = value; break;
            case "filter-udp": p.UdpPorts = value; break;
            case "filter-l7": p.L7.AddRange(value!.Split(',', StringSplitOptions.RemoveEmptyEntries)); break;
            case "hostlist": p.Hostlists.Add(ListRefFromPath(value!)); break;
            case "hostlist-domains": p.HostlistDomains.AddRange(value!.Split(',', StringSplitOptions.RemoveEmptyEntries)); break;
            case "hostlist-exclude": p.HostlistExcludes.Add(ListRefFromPath(value!)); break;
            case "hostlist-auto": p.HostlistAuto = ListRefFromPath(value!); break;
            case "ipset": p.Ipsets.Add(ListRefFromPath(value!)); break;
            case "ipset-ip": p.IpsetIps.AddRange(value!.Split(',', StringSplitOptions.RemoveEmptyEntries)); break;
            case "ipset-exclude": p.IpsetExcludes.Add(ListRefFromPath(value!)); break;
            default: p.ExtraOptions.Add(tok); break;
        }
    }

    /// <summary>A list given by path: the name is the file name without extension, the path is kept.</summary>
    public static ListRef ListRefFromPath(string path)
    {
        var file = path.Replace('\\', '/').Split('/')[^1];
        int dot = file.IndexOf('.', StringComparison.Ordinal);
        var name = dot > 0 ? file[..dot] : file;
        return new ListRef(name, path);
    }
}
