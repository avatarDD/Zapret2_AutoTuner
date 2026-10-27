using Google.Protobuf;
using Google.Protobuf.Collections;

namespace ZapretAutoTuner.Protocol;

/// <summary>
/// The UI half of the file hand-over (<c>lua_files</c> in agent.proto): the content of every <c>--lua-init=@file</c>
/// and <c>--blob=name:[+ofs]@file</c> goes with the request, so the Agent runs the engine against its own protected
/// copy and never reads a file the user (or anything running as the user) can change or redirect by a symlink.
/// </summary>
public static class LuaFiles
{
    /// <summary>The biggest file that is sent (zapret-lib.lua is about 100 KB, a blob at most 16 KB).</summary>
    public const int MaxFileBytes = 1024 * 1024;

    /// <summary>
    /// Adds the content of each existing <c>--lua-init=@path</c> and <c>--blob=…@path</c> file of <paramref name="argv"/>
    /// to <paramref name="into"/>. A file that cannot be read is left out (the Agent then refuses it with the reason);
    /// throws nothing for it.
    /// </summary>
    public static void Attach(IEnumerable<string> argv, MapField<string, ByteString> into)
    {
        foreach (var path in Paths(argv))
        {
            if (into.ContainsKey(path))
                continue;
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists || info.Length > MaxFileBytes)
                    continue;
                into[path] = ByteString.CopyFrom(File.ReadAllBytes(path));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                // unreadable here: the Agent answers "file outside the engine directory without its content" for it
            }
        }
    }

    /// <summary>The <c>@path</c> values of the <c>--lua-init</c> and <c>--blob</c> options, in order.</summary>
    public static IEnumerable<string> Paths(IEnumerable<string> argv)
    {
        const string lua = "--lua-init=@";
        const string blob = "--blob=";
        foreach (var t in argv)
        {
            if (t.StartsWith(lua, StringComparison.Ordinal) && t.Length > lua.Length)
                yield return t[lua.Length..];
            else if (t.StartsWith(blob, StringComparison.Ordinal) && BlobPath(t[blob.Length..]) is { } path)
                yield return path;
        }
    }

    /// <summary>The file of a <c>--blob</c> value (<c>name:@file</c> or <c>name:+ofs@file</c>); null for <c>name:0xHEX</c>.</summary>
    public static string? BlobPath(string value)
    {
        int at = value.IndexOf('@', StringComparison.Ordinal);
        return at > 0 && at + 1 < value.Length ? value[(at + 1)..] : null;
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
