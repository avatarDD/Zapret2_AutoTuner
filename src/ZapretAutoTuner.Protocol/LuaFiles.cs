using Google.Protobuf;
using Google.Protobuf.Collections;

namespace ZapretAutoTuner.Protocol;

/// <summary>
/// The UI half of the Lua hand-over (<c>lua_files</c> in agent.proto): the content of every <c>--lua-init=@file</c>
/// goes with the request, so the Agent runs the engine against its own protected copy and never reads a file the user
/// (or anything running as the user) can change between the check and the load.
/// </summary>
public static class LuaFiles
{
    /// <summary>The biggest Lua file that is sent (zapret-lib.lua is about 100 KB).</summary>
    public const int MaxFileBytes = 1024 * 1024;

    /// <summary>Adds the content of each existing <c>--lua-init=@path</c> file of <paramref name="argv"/> to <paramref name="into"/>.</summary>
    public static void Attach(IEnumerable<string> argv, MapField<string, ByteString> into)
    {
        foreach (var path in Paths(argv))
        {
            if (into.ContainsKey(path))
                continue;
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > MaxFileBytes)
                continue;
            into[path] = ByteString.CopyFrom(File.ReadAllBytes(path));
        }
    }

    /// <summary>The <c>@path</c> values of the <c>--lua-init</c> options, in order.</summary>
    public static IEnumerable<string> Paths(IEnumerable<string> argv)
    {
        const string prefix = "--lua-init=@";
        foreach (var t in argv)
        {
            if (t.StartsWith(prefix, StringComparison.Ordinal) && t.Length > prefix.Length)
                yield return t[prefix.Length..];
        }
    }

    public static StartEngineRequest WithLuaFiles(this StartEngineRequest r)
    {
        Attach(r.Argv, r.LuaFiles);
        return r;
    }

    public static CheckEngineArgsRequest WithLuaFiles(this CheckEngineArgsRequest r)
    {
        Attach(r.Argv, r.LuaFiles);
        return r;
    }
}
