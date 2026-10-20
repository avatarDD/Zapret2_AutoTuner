using System.IO.Compression;

namespace ZapretAutoTuner.App.Services;

public static class Zip
{
    /// <summary>Every file of an archive by its path; big archives are refused (an export is a few KB).</summary>
    public static Dictionary<string, byte[]> Read(byte[] bytes, long maxTotal = 16L << 20)
    {
        using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        long total = 0;
        foreach (var e in zip.Entries.Where(e => e.Length > 0 && !e.FullName.EndsWith('/')))
        {
            total += e.Length;
            if (total > maxTotal)
                throw new InvalidDataException("архив слишком большой / the archive is too big");
            using var s = e.Open();
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            files[e.FullName] = ms.ToArray();
        }
        return files;
    }
}
