using ZapretAutoTuner.Core.Model;

namespace ZapretAutoTuner.Core.Resources;

/// <summary>
/// The kinds of strategy resources (PLAN 4a.5): named objects of the program, never files the caller points at. The
/// program builds every path itself (its data folder, <c>lists/</c>, <c>blobs/</c>, <c>lua/</c> on the router).
/// </summary>
public enum ResourceKind
{
    /// <summary>Domains for <c>--hostlist</c>.</summary>
    Hostlist,

    /// <summary>IP addresses and CIDRs for <c>--ipset</c>.</summary>
    Ipset,

    /// <summary>Bytes for <c>--blob</c> (≤ 16 KB, the engine's limit).</summary>
    Blob,

    /// <summary>Lua source for <c>--lua-init</c>; runs with the engine's rights, so it needs the user's approval.</summary>
    LuaScript,
}

/// <summary>A resource by kind and name.</summary>
public sealed record ResourceRef(ResourceKind Kind, string Name)
{
    public override string ToString() => $"{ResourceNames.KindNameEn(Kind)} {Name}";
}

/// <summary>One finding of the typed checks, in Russian and English. Errors refuse the save, warnings do not.</summary>
public sealed record ResourceProblem(bool IsError, string Code, string Ru, string En, string? Item = null)
{
    public string Message(bool russian = true) => (Item is null ? "" : Item + ": ") + (russian ? Ru : En);

    public override string ToString() => $"{(IsError ? "error" : "warning")} {Code}: {Message()}";
}

/// <summary>A refused resource operation: the message is shown to the user (or returned to the MCP client) as is.</summary>
public sealed class ResourceException : Exception
{
    public ResourceException(string ru, string en, IReadOnlyList<ResourceProblem>? problems = null)
        : base(ru)
    {
        Ru = ru;
        En = en;
        Problems = problems ?? [];
    }

    public ResourceException()
        : this("ошибка ресурса", "resource error")
    {
    }

    public ResourceException(string message)
        : this(message, message)
    {
    }

    public ResourceException(string message, Exception inner)
        : base(message, inner)
    {
        Ru = message;
        En = message;
        Problems = [];
    }

    public string Ru { get; }

    public string En { get; }

    public IReadOnlyList<ResourceProblem> Problems { get; }

    public string Text(bool russian = true) => russian ? Ru : En;

    public static ResourceException From(IReadOnlyList<ResourceProblem> problems)
    {
        var errors = problems.Where(p => p.IsError).ToList();
        return new ResourceException(
            string.Join("; ", errors.Take(10).Select(e => e.Message(true))) + (errors.Count > 10 ? $" (и ещё {errors.Count - 10})" : ""),
            string.Join("; ", errors.Take(10).Select(e => e.Message(false))) + (errors.Count > 10 ? $" (and {errors.Count - 10} more)" : ""),
            problems);
    }
}

/// <summary>
/// The content of one resource, already checked and normalised (<see cref="ResourceRules.Prepare"/>): list items for
/// hostlists and ipsets, bytes for a blob, the source for a Lua script.
/// </summary>
public sealed class ResourceData
{
    public required ResourceKind Kind { get; init; }

    public required string Name { get; init; }

    /// <summary>Domains (hostlist) or entries (ipset); empty for the other kinds.</summary>
    public IReadOnlyList<string> Items { get; init; } = [];

    /// <summary>Blob bytes; empty for the other kinds.</summary>
    public byte[] Bytes { get; init; } = [];

    /// <summary>Lua source; empty for the other kinds.</summary>
    public string Source { get; init; } = "";

    /// <summary>Desync functions the script defines (<c>function name(ctx, desync)</c>); empty for the other kinds.</summary>
    public IReadOnlyList<string> Functions { get; init; } = [];

    public ResourceRef Ref => new(Kind, Name);

    /// <summary>The canonical bytes stored for a version: lines for lists, raw bytes, UTF-8 source.</summary>
    public byte[] ToBytes() => Kind switch
    {
        ResourceKind.Blob => Bytes,
        ResourceKind.LuaScript => System.Text.Encoding.UTF8.GetBytes(Source),
        _ => System.Text.Encoding.UTF8.GetBytes(string.Join("\n", Items)),
    };

    /// <summary>Reads stored bytes back (no checks: they were checked when saved).</summary>
    public static ResourceData FromBytes(ResourceKind kind, string name, byte[] bytes)
    {
        switch (kind)
        {
            case ResourceKind.Blob:
                return new ResourceData { Kind = kind, Name = name, Bytes = bytes };
            case ResourceKind.LuaScript:
                var source = System.Text.Encoding.UTF8.GetString(bytes);
                return new ResourceData { Kind = kind, Name = name, Source = source, Functions = LuaScriptCheck.FindDesyncFunctions(source) };
            default:
                var text = System.Text.Encoding.UTF8.GetString(bytes);
                return new ResourceData { Kind = kind, Name = name, Items = text.Length == 0 ? [] : text.Split('\n') };
        }
    }

    /// <summary>
    /// Puts the resource into a <see cref="Solution"/> so every exporter carries it: <c>Hostlists</c>, <c>Ipsets</c>,
    /// <c>Blobs</c> by name, a Lua script as <c>LuaFiles["zt-&lt;name&gt;.lua"]</c>. Only an approved script version may
    /// go here; the store checks that before it hands one out.
    /// </summary>
    public void ApplyTo(Solution s)
    {
        switch (Kind)
        {
            case ResourceKind.Hostlist:
                s.Hostlists[Name] = [.. Items];
                break;
            case ResourceKind.Ipset:
                s.Ipsets[Name] = [.. Items];
                break;
            case ResourceKind.Blob:
                s.Blobs[Name] = Bytes;
                break;
            case ResourceKind.LuaScript:
                s.LuaFiles[ResourceNames.LuaFile(Name)] = Source;
                break;
        }
    }
}
