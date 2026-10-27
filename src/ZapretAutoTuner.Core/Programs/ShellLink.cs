using System.Buffers.Binary;
using System.Text;

namespace ZapretAutoTuner.Core.Programs;

/// <summary>A Windows shortcut's target, arguments and working directory.</summary>
public sealed record ShellLinkInfo(string? Target, string? Arguments, string? WorkingDirectory, string? IconLocation);

/// <summary>
/// The parts of a <c>.lnk</c> file (MS-SHLLINK) a program list needs: LinkInfo's local base path and the string data
/// that follows. Shortcuts that point at a shell item only (no LinkInfo: Control Panel, store apps) have no target.
/// Strings without the Unicode flag are in the system ANSI code page (cp1251 on a Russian Windows), not Latin-1;
/// Unicode variants are preferred when the file has them.
/// </summary>
public static class ShellLink
{
    /// <summary>The system ANSI code page on Windows (<c>CultureInfo.CurrentCulture.TextInfo.ANSICodePage</c>), else Latin-1.</summary>
    public static Encoding SystemAnsi { get; } = GetSystemAnsi();

    private static Encoding GetSystemAnsi()
    {
        if (!OperatingSystem.IsWindows())
            return Encoding.Latin1;
        try
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            return Encoding.GetEncoding(System.Globalization.CultureInfo.CurrentCulture.TextInfo.ANSICodePage);
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException)
        {
            return Encoding.Latin1;
        }
    }

    private const uint HasLinkTargetIdList = 0x1, HasLinkInfo = 0x2, HasName = 0x4, HasRelativePath = 0x8,
        HasWorkingDir = 0x10, HasArguments = 0x20, HasIconLocation = 0x40, IsUnicode = 0x80;

    /// <param name="linkPath">Where the .lnk lies: a RelativePath is relative to the shortcut's own folder.</param>
    /// <param name="ansi">The ANSI code page of non-Unicode strings; <see cref="SystemAnsi"/> by default.</param>
    public static ShellLinkInfo? Parse(ReadOnlySpan<byte> b, string? linkPath = null, Encoding? ansi = null)
    {
        ansi ??= SystemAnsi;
        try
        {
            if (b.Length < 0x4C || BinaryPrimitives.ReadUInt32LittleEndian(b) != 0x4C)
                return null;
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(b[0x14..]);
            int pos = 0x4C;
            if ((flags & HasLinkTargetIdList) != 0)
                pos += 2 + BinaryPrimitives.ReadUInt16LittleEndian(b[pos..]);
            string? target = null;
            if ((flags & HasLinkInfo) != 0)
            {
                var li = b[pos..];
                int size = (int)BinaryPrimitives.ReadUInt32LittleEndian(li);
                int headerSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(li[4..]);
                uint liFlags = BinaryPrimitives.ReadUInt32LittleEndian(li[8..]);
                if ((liFlags & 1) != 0)
                {
                    int baseOfs = (int)BinaryPrimitives.ReadUInt32LittleEndian(li[16..]);
                    int suffixOfs = (int)BinaryPrimitives.ReadUInt32LittleEndian(li[24..]);
                    if (headerSize >= 0x24)
                    {
                        int baseU = (int)BinaryPrimitives.ReadUInt32LittleEndian(li[28..]);
                        int suffixU = (int)BinaryPrimitives.ReadUInt32LittleEndian(li[32..]);
                        target = Utf16Z(li, baseU) + Utf16Z(li, suffixU);
                    }
                    else
                    {
                        target = AnsiZ(li, baseOfs, ansi) + AnsiZ(li, suffixOfs, ansi);
                    }
                }
                pos += size;
            }
            bool unicode = (flags & IsUnicode) != 0;
            var strings = new string?[5];
            uint[] order = [HasName, HasRelativePath, HasWorkingDir, HasArguments, HasIconLocation];
            for (int i = 0; i < order.Length; i++)
            {
                if ((flags & order[i]) == 0)
                    continue;
                int count = BinaryPrimitives.ReadUInt16LittleEndian(b[pos..]);
                int bytes = unicode ? count * 2 : count;
                strings[i] = unicode ? Encoding.Unicode.GetString(b.Slice(pos + 2, bytes)) : ansi.GetString(b.Slice(pos + 2, bytes));
                pos += 2 + bytes;
            }
            var (relative, workDir, args, icon) = (strings[1], strings[2], strings[3], strings[4]);
            // MS-SHLLINK 2.4: RELATIVE_PATH is relative to the link file, not to the working directory
            if (string.IsNullOrEmpty(target) && relative is not null && Path.GetDirectoryName(linkPath) is { Length: > 0 } linkDir)
                target = Path.GetFullPath(Path.Combine(linkDir, relative));
            return new ShellLinkInfo(string.IsNullOrEmpty(target) ? null : target, args, workDir, icon);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null; // a truncated or odd shortcut
        }
    }

    private static string Utf16Z(ReadOnlySpan<byte> b, int ofs)
    {
        if (ofs <= 0 || ofs >= b.Length)
            return "";
        var s = b[ofs..];
        int end = 0;
        while (end + 1 < s.Length && (s[end] != 0 || s[end + 1] != 0))
            end += 2;
        return Encoding.Unicode.GetString(s[..end]);
    }

    private static string AnsiZ(ReadOnlySpan<byte> b, int ofs, Encoding ansi)
    {
        if (ofs <= 0 || ofs >= b.Length)
            return "";
        var s = b[ofs..];
        int end = s.IndexOf((byte)0);
        return ansi.GetString(end < 0 ? s : s[..end]);
    }
}
