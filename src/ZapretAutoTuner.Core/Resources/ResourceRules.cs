using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core.Catalog;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Providers;
using ZapretAutoTuner.Core.Validation;

namespace ZapretAutoTuner.Core.Resources;

/// <summary>Names of resources and of the files the program makes from them, on the PC and on the router.</summary>
public static partial class ResourceNames
{
    public const int MaxLength = 48;

    [GeneratedRegex("^[a-z0-9_-]{1,48}\\z")]
    private static partial Regex NameRe();

    [GeneratedRegex("^zt-([a-z0-9_-]{1,48})\\.lua\\z")]
    private static partial Regex LuaFileRe();

    /// <summary>The Lua file of a script: <c>zt-&lt;name&gt;.lua</c> (the prefix keeps it apart from zapret2's own files).</summary>
    public static string LuaFile(string name) => $"zt-{name}.lua";

    /// <summary>The script name of a <c>zt-&lt;name&gt;.lua</c> file, or null for any other file.</summary>
    public static string? LuaNameOf(string file) => LuaFileRe().Match(file) is { Success: true } m ? m.Groups[1].Value : null;

    public static bool IsValid(string? name) => name is not null && NameRe().IsMatch(name);

    public static string KindNameRu(ResourceKind k) => k switch
    {
        ResourceKind.Hostlist => "хостлист",
        ResourceKind.Ipset => "ipset",
        ResourceKind.Blob => "блоб",
        _ => "Lua-скрипт",
    };

    public static string KindNameEn(ResourceKind k) => k switch
    {
        ResourceKind.Hostlist => "hostlist",
        ResourceKind.Ipset => "ipset",
        ResourceKind.Blob => "blob",
        _ => "Lua script",
    };

    /// <summary>Stable lower-case key of a kind (storage, MCP): hostlist, ipset, blob, lua.</summary>
    public static string Key(ResourceKind k) => k switch
    {
        ResourceKind.Hostlist => "hostlist",
        ResourceKind.Ipset => "ipset",
        ResourceKind.Blob => "blob",
        _ => "lua",
    };

    public static ResourceKind ParseKey(string key) => key switch
    {
        "hostlist" => ResourceKind.Hostlist,
        "ipset" => ResourceKind.Ipset,
        "blob" => ResourceKind.Blob,
        "lua" => ResourceKind.LuaScript,
        _ => throw new ArgumentException($"unknown resource kind '{key}'", nameof(key)),
    };
}

/// <summary>How the text of a blob is written.</summary>
public enum BlobEncoding
{
    /// <summary>Hex when the text is hex (optionally <c>0x</c>, spaces, <c>:</c>), base64 otherwise.</summary>
    Auto,
    Hex,
    Base64,
}

/// <summary>
/// The typed checks of PLAN 4a.5: names <c>[a-z0-9_-]{1,48}</c>; hostlist domains normalised the way nfqws2 reads a
/// hostlist (nfqws2-engine §11: one domain per line, subdomains match by themselves, <c>*</c> is not supported,
/// <c>^domain</c> means without subdomains); ipset entries through <see cref="Cidr"/>; blobs from hex or base64, at most
/// 16 KB (<see cref="StrategyValidator.MaxBlobSize"/>), named as a Lua identifier (§0.6); Lua scripts limited in size,
/// valid UTF-8, balanced blocks and no function names of the bundled library.
/// </summary>
public static partial class ResourceRules
{
    /// <summary>Lua source limit: generous for a script, far below zapret-gui's 1 MiB.</summary>
    public const int MaxLuaBytes = 256 * 1024;

    /// <summary>A sane ceiling for list sizes kept by the program.</summary>
    public const int MaxListItems = 100_000;

    /// <summary>Blobs a router package ships under these names (keenetic <c>blobs/</c>): a user blob must not shadow them.</summary>
    private static readonly string[] PackageBlobs = ["quic_initial", "tls_clienthello"];

    [GeneratedRegex("^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\\z")]
    private static partial Regex LabelRe();

    [GeneratedRegex("^(?:0x)?[0-9a-fA-F\\s:]+$")]
    private static partial Regex HexTextRe();

    /// <summary>Problems with a resource name; the blob name must also be a Lua identifier and not a built-in blob.</summary>
    public static List<ResourceProblem> CheckName(ResourceKind kind, string? name, LuaCatalog? catalog = null)
    {
        var p = new List<ResourceProblem>();
        if (!ResourceNames.IsValid(name))
        {
            p.Add(new(true, "name.bad", "имя: только латиница в нижнем регистре, цифры, _ и -, от 1 до 48 символов",
                "name: lower-case latin letters, digits, _ and - only, 1 to 48 characters", name ?? ""));
            return p;
        }
        if (kind == ResourceKind.Blob)
        {
            catalog ??= LuaCatalog.Default;
            if (!Identifiers.IsLuaIdentifier(name) || name!.Contains('-', StringComparison.Ordinal))
                p.Add(new(true, "name.blob", "имя блоба должно быть идентификатором Lua: буквы, цифры и _, не с цифры, не служебное слово (иначе движок выйдет с bad identifier)",
                    "a blob name must be a Lua identifier: letters, digits and _, not starting with a digit, not a keyword (or the engine exits with bad identifier)", name));
            else if (catalog.BuiltinBlobs.Contains(name) || PackageBlobs.Contains(name))
                p.Add(new(true, "name.builtin", "это имя встроенного блоба движка или пакета роутера", "this is the name of a blob built into the engine or the router package", name));
        }
        return p;
    }

    /// <summary>
    /// Normalises hostlist domains: lower case, IDN to punycode, scheme, port, path and a trailing dot removed, a
    /// leading <c>*.</c> or <c>.</c> dropped (subdomains match anyway), <c>^</c> kept; blank and comment lines skipped,
    /// duplicates dropped. Addresses are refused with a hint to use an ipset.
    /// </summary>
    public static (List<string> Domains, List<ResourceProblem> Problems) NormalizeDomains(IEnumerable<string> lines)
    {
        var result = new List<string>();
        var problems = new List<ResourceProblem>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var idn = new IdnMapping { AllowUnassigned = false, UseStd3AsciiRules = false };
        foreach (var raw in lines.SelectMany(l => (l ?? "").Split('\n')))
        {
            var item = raw.Trim().TrimEnd('\r');
            if (item.Length == 0 || item[0] is '#' or ';' or '/')
                continue;
            var original = item;
            bool exact = item.StartsWith('^');
            if (exact)
                item = item[1..];
            int scheme = item.IndexOf("://", StringComparison.Ordinal);
            if (scheme >= 0)
                item = item[(scheme + 3)..];
            int cut = item.IndexOfAny(['/', '?', '#']);
            if (cut >= 0)
                item = item[..cut];
            int at = item.LastIndexOf('@');
            if (at >= 0)
                item = item[(at + 1)..];
            if (item.StartsWith('[') || IPAddress.TryParse(item, out _) || (item.Count(c => c == ':') == 1 && IPAddress.TryParse(item.Split(':')[0], out _)))
            {
                problems.Add(new(true, "domain.ip", "это адрес, а не домен: адреса кладут в ipset", "this is an address, not a domain: addresses go into an ipset", original));
                continue;
            }
            int colon = item.IndexOf(':', StringComparison.Ordinal);
            if (colon >= 0)
                item = item[..colon];
            item = item.TrimEnd('.');
            if (item.StartsWith("*.", StringComparison.Ordinal))
            {
                item = item[2..];
                problems.Add(new(false, "domain.wildcard", "«*» движок не понимает: записан домен без «*.», поддомены совпадают сами",
                    "the engine does not understand '*': written without '*.', subdomains match by themselves", original));
            }
            else if (item.StartsWith('.'))
                item = item.TrimStart('.');
            if (item.Contains('*', StringComparison.Ordinal))
            {
                problems.Add(new(true, "domain.wildcard", "«*» в середине домена движок не поддерживает", "the engine does not support '*' inside a domain", original));
                continue;
            }
            string ascii;
            try
            {
                ascii = idn.GetAscii(item.ToLowerInvariant()).ToLowerInvariant();
            }
            catch (ArgumentException)
            {
                problems.Add(new(true, "domain.bad", "неверный домен", "invalid domain", original));
                continue;
            }
            var labels = ascii.Split('.');
            if (ascii.Length is 0 or > 253 || !labels.All(l => LabelRe().IsMatch(l)))
            {
                problems.Add(new(true, "domain.bad", "неверный домен (буквы, цифры, - и _; части через точку до 63 символов)",
                    "invalid domain (letters, digits, - and _; dot-separated parts up to 63 characters)", original));
                continue;
            }
            var entry = exact ? "^" + ascii : ascii;
            if (seen.Add(entry))
                result.Add(entry);
        }
        if (result.Count > MaxListItems)
            problems.Add(new(true, "list.size", $"больше {MaxListItems} записей", $"more than {MaxListItems} entries"));
        return (result, problems);
    }

    /// <summary>
    /// Normalises ipset entries: an address or a CIDR (host bits cleared, with a warning), IPv4-mapped IPv6 to IPv4,
    /// a full-length prefix written as the bare address; blank and comment lines skipped, duplicates dropped.
    /// </summary>
    public static (List<string> Entries, List<ResourceProblem> Problems) NormalizeIpset(IEnumerable<string> lines)
    {
        var result = new List<string>();
        var problems = new List<ResourceProblem>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in lines.SelectMany(l => (l ?? "").Split('\n')))
        {
            var item = raw.Trim().TrimEnd('\r');
            if (item.Length == 0 || item[0] is '#' or ';' or '/')
                continue;
            if (!Cidr.TryParse(item, out var c))
            {
                problems.Add(new(true, "ipset.bad", "ожидается IP-адрес или CIDR (1.2.3.0/24, 2001:db8::/32)", "an IP address or CIDR expected (1.2.3.0/24, 2001:db8::/32)", item));
                continue;
            }
            var text = c.Prefix == c.Bits ? c.At(0).ToString() : c.ToString();
            if (c.Prefix != c.Bits && Cidr.TryParse(item.Split('/')[0], out var host) && host.Start != c.Start)
                problems.Add(new(false, "ipset.hostbits", $"в сети были биты хоста, записано {text}", $"the network had host bits set, written as {text}", item));
            if (seen.Add(text))
                result.Add(text);
        }
        if (result.Count > MaxListItems)
            problems.Add(new(true, "list.size", $"больше {MaxListItems} записей", $"more than {MaxListItems} entries"));
        return (result, problems);
    }

    /// <summary>Blob bytes from hex (<c>0x</c>, spaces and <c>:</c> allowed) or base64; 1 to 16384 bytes.</summary>
    public static (byte[] Bytes, List<ResourceProblem> Problems) ParseBlob(string? text, BlobEncoding encoding = BlobEncoding.Auto)
    {
        var problems = new List<ResourceProblem>();
        var t = (text ?? "").Trim();
        if (t.StartsWith("base64:", StringComparison.OrdinalIgnoreCase))
        {
            t = t[7..].Trim();
            encoding = BlobEncoding.Base64;
        }
        bool hex = encoding == BlobEncoding.Hex || (encoding == BlobEncoding.Auto && HexTextRe().IsMatch(t)
            && Strip(t).Length % 2 == 0);
        byte[] bytes = [];
        try
        {
            bytes = hex ? Convert.FromHexString(Strip(t)) : Convert.FromBase64String(t);
        }
        catch (FormatException)
        {
            problems.Add(new(true, "blob.format", hex ? "неверный hex" : "ожидается hex (например 0x160301…) или base64", hex ? "invalid hex" : "hex (e.g. 0x160301…) or base64 expected"));
            return ([], problems);
        }
        if (bytes.Length == 0)
            problems.Add(new(true, "blob.empty", "блоб пустой", "the blob is empty"));
        else if (bytes.Length > StrategyValidator.MaxBlobSize)
            problems.Add(new(true, "blob.size", $"блоб {bytes.Length} байт: движок принимает не больше 16384 (MAX_BLOB_SIZE)",
                $"the blob is {bytes.Length} bytes: the engine accepts at most 16384 (MAX_BLOB_SIZE)"));
        return (bytes, problems);

        static string Strip(string s)
        {
            var x = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s;
            var sb = new StringBuilder(x.Length);
            foreach (var ch in x)
            {
                if (!char.IsWhiteSpace(ch) && ch != ':')
                    sb.Append(ch);
            }
            return sb.ToString();
        }
    }

    /// <summary>Checks a list of domains, entries, a blob text or a Lua source and gives the normalised content.</summary>
    /// <exception cref="ResourceException">Any error; the warnings come back with the data.</exception>
    public static (ResourceData Data, IReadOnlyList<ResourceProblem> Warnings) Prepare(ResourceInput input, LuaCatalog? catalog = null)
    {
        var problems = CheckName(input.Kind, input.Name, catalog);
        ResourceData? data = null;
        if (problems.Count == 0)
        {
            switch (input.Kind)
            {
                case ResourceKind.Hostlist:
                    var (domains, dp) = NormalizeDomains(input.Items);
                    problems.AddRange(dp);
                    if (domains.Count == 0 && !dp.Any(p => p.IsError))
                        problems.Add(new(true, "list.empty", "в списке нет ни одного домена", "the list has no domains"));
                    data = new ResourceData { Kind = input.Kind, Name = input.Name, Items = domains };
                    break;
                case ResourceKind.Ipset:
                    var (entries, ip) = NormalizeIpset(input.Items);
                    problems.AddRange(ip);
                    if (entries.Count == 0 && !ip.Any(p => p.IsError))
                        problems.Add(new(true, "list.empty", "в списке нет ни одного адреса", "the list has no addresses"));
                    data = new ResourceData { Kind = input.Kind, Name = input.Name, Items = entries };
                    break;
                case ResourceKind.Blob:
                    var (bytes, bp) = input.Bytes is { } given ? (given, SizeProblems(given)) : ParseBlob(input.Text, input.Encoding);
                    problems.AddRange(bp);
                    data = new ResourceData { Kind = input.Kind, Name = input.Name, Bytes = bytes };
                    break;
                case ResourceKind.LuaScript:
                    var check = LuaScriptCheck.Check(input.Text ?? "", catalog);
                    problems.AddRange(check.Problems);
                    data = new ResourceData { Kind = input.Kind, Name = input.Name, Source = (input.Text ?? "").ReplaceLineEndings("\n"), Functions = check.DesyncFunctions };
                    break;
            }
        }
        if (problems.Any(p => p.IsError) || data is null)
            throw ResourceException.From(problems);
        return (data, problems);
    }

    private static List<ResourceProblem> SizeProblems(byte[] b) =>
        b.Length == 0 ? [new(true, "blob.empty", "блоб пустой", "the blob is empty")]
        : b.Length > StrategyValidator.MaxBlobSize ? [new(true, "blob.size", $"блоб {b.Length} байт: движок принимает не больше 16384", $"the blob is {b.Length} bytes: the engine accepts at most 16384")]
        : [];
}

/// <summary>What the UI or an MCP client hands in: a kind, a name and the content as data (never a path).</summary>
public sealed class ResourceInput
{
    private ResourceInput()
    {
    }

    public ResourceKind Kind { get; private init; }

    public string Name { get; private init; } = "";

    public IReadOnlyList<string> Items { get; private init; } = [];

    public string? Text { get; private init; }

    public byte[]? Bytes { get; private init; }

    public BlobEncoding Encoding { get; private init; }

    public static ResourceInput Hostlist(string name, IEnumerable<string> domains) => new() { Kind = ResourceKind.Hostlist, Name = name, Items = [.. domains] };

    public static ResourceInput Ipset(string name, IEnumerable<string> entries) => new() { Kind = ResourceKind.Ipset, Name = name, Items = [.. entries] };

    /// <summary>A blob from text: hex or base64 (<see cref="BlobEncoding"/>).</summary>
    public static ResourceInput Blob(string name, string text, BlobEncoding encoding = BlobEncoding.Auto) => new() { Kind = ResourceKind.Blob, Name = name, Text = text, Encoding = encoding };

    public static ResourceInput Blob(string name, byte[] bytes) => new() { Kind = ResourceKind.Blob, Name = name, Bytes = bytes };

    public static ResourceInput Lua(string name, string source) => new() { Kind = ResourceKind.LuaScript, Name = name, Text = source };
}
