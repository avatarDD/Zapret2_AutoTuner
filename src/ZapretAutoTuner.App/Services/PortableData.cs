using ZapretAutoTuner.Storage;
using ZapretAutoTuner.Tuning.Geneva;

namespace ZapretAutoTuner.App.Services;

/// <summary>
/// The program's files in one folder: <c>&lt;program&gt;/data</c> (the knowledge base with the found strategies, settings,
/// solutions, exports, the Agent's socket and token). A read-only program folder (Program Files, a package in /opt)
/// keeps the user's folder. The first start of this version moves the user's folder of an earlier one into <c>data</c>.
/// </summary>
public static class PortableData
{
    public const string FolderName = "data";

    /// <summary>
    /// The data folder for a program in <paramref name="programDir"/>; <paramref name="legacy"/> is the old place. An
    /// elevated start (<paramref name="privileged"/>, "Run as administrator") does not move the data next to the
    /// program: it could write to Program Files, where the usual starts could not read back what moved there.
    /// </summary>
    public static string Resolve(string programDir, string legacy, bool? privileged = null)
    {
        // ZT_DATA_DIR: tests and users who want the data elsewhere
        if (Environment.GetEnvironmentVariable("ZT_DATA_DIR") is { Length: > 0 } explicitDir)
            return explicitDir;
        var portable = Path.Combine(programDir, FolderName);
        if ((privileged ?? Environment.IsPrivilegedProcess) && !File.Exists(Path.Combine(portable, "knowledge.db")))
            return legacy;
        if (!Writable(portable))
            return legacy;
        try
        {
            Migrate(legacy, portable);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
        {
            // what could not move stays where it was; the program starts with what it has
            Console.Error.WriteLine("data: " + e.Message);
        }
        return portable;
    }

    /// <summary>Whether the folder can be created and written by this user.</summary>
    internal static bool Writable(string dir)
    {
        try
        {
            Directory.CreateDirectory(dir);
            var probe = Path.Combine(dir, ".write-test-" + Environment.ProcessId);
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }

    private const string Db = "knowledge.db";

    /// <summary>
    /// Moves the old folder's data into the new one. With no knowledge base in the new folder yet, the old folder is
    /// copied and then removed (only once everything was copied). When the new folder already has one (an earlier
    /// start of this version, or the old version still running while it moved), a base with nothing of the user's in
    /// it is set aside for the old one; otherwise the old base's found strategies and settings are merged into it.
    /// The old base is renamed afterwards, so nothing is moved twice. Returns whether anything moved.
    /// </summary>
    internal static bool Migrate(string legacy, string portable)
    {
        var oldDb = Path.Combine(legacy, Db);
        var newDb = Path.Combine(portable, Db);
        if (!File.Exists(oldDb))
            return false;
        if (Path.GetFullPath(legacy).TrimEnd(Path.DirectorySeparatorChar) == Path.GetFullPath(portable).TrimEnd(Path.DirectorySeparatorChar))
            return false;
        // a file that is not an SQLite base is not opened at all: an open that fails can leave it locked on Windows
        if (File.Exists(newDb) && (!IsSqlite(newDb) || !IsSqlite(oldDb)))
            return false;
        if (File.Exists(newDb))
        {
            if (!Fresh(newDb))
            {
                Merge(oldDb, newDb);
                Copy(legacy, portable);
                SetAside(oldDb, "merged");
                return true;
            }
            SetAside(newDb, "unused");
        }
        bool complete = Copy(legacy, portable);
        if (complete)
        {
            try
            {
                Directory.Delete(legacy, recursive: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // a file still open or owned by root (the Agent's): the copy is in place, the rest stays
            }
        }
        if (File.Exists(oldDb) && File.Exists(newDb))
            SetAside(oldDb, "moved");
        return true;
    }

    /// <summary>Whether the file starts with SQLite's header; an empty file is a base SQLite has not written yet.</summary>
    internal static bool IsSqlite(string path)
    {
        try
        {
            using var f = File.OpenRead(path);
            if (f.Length == 0)
                return true;
            Span<byte> head = stackalloc byte[16];
            return f.ReadAtLeast(head, 16, throwOnEndOfStream: false) == 16 && head.SequenceEqual("SQLite format 3\0"u8);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>A base with nothing of the user's: no history, resources, found or imported strategies, services.</summary>
    internal static bool Fresh(string db)
    {
        KnowledgeBase kb;
        try
        {
            kb = KnowledgeBase.Open(db);
        }
        catch (Exception e) when (e is Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
        {
            // unreadable here: it is not set aside, what is in it stays the user's
            return false;
        }
        using var _ = kb;
        if (kb.HasUserData())
            return false;
        var g = GenevaState.Parse(kb.GetSetting(KbGenevaStore.Key));
        return g.Found.Count == 0 && g.Imported.Count == 0 && g.Auto.Services.Count == 0 && g.Searches.Count == 0;
    }

    /// <summary>The old base's settings the new one lacks, and its geneva state merged into the new one's.</summary>
    internal static void Merge(string oldDb, string newDb)
    {
        using var old = KnowledgeBase.Open(oldDb);
        using var kb = KnowledgeBase.Open(newDb);
        foreach (var (key, value) in old.AllSettings())
        {
            if (key == KbGenevaStore.Key)
                kb.SetSetting(key, GenevaState.Parse(kb.GetSetting(key)).MergedWith(GenevaState.Parse(value), DateTimeOffset.Now).Serialize());
            else if (kb.GetSetting(key) is null)
                kb.SetSetting(key, value);
        }
    }

    /// <summary>Renames a closed base with its journal files: kept for the user, never read again.</summary>
    private static void SetAside(string db, string why)
    {
        var suffix = "." + why + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);
        foreach (var ext in new[] { "", "-wal", "-shm" })
        {
            if (File.Exists(db + ext))
                File.Move(db + ext, db + suffix + ext);
        }
    }

    private static bool Copy(string from, string to)
    {
        bool complete = true;
        Directory.CreateDirectory(to);
        foreach (var dir in Directory.EnumerateDirectories(from))
        {
            // a link could point anywhere: not followed
            if (new DirectoryInfo(dir).LinkTarget is not null)
                continue;
            complete &= Copy(dir, Path.Combine(to, Path.GetFileName(dir)));
        }
        foreach (var file in Directory.EnumerateFiles(from))
        {
            var name = Path.GetFileName(file);
            // the Agent's socket and token of an old session are of no use
            if (name.EndsWith(".sock", StringComparison.Ordinal) || name.EndsWith(".token", StringComparison.Ordinal))
                continue;
            if (new FileInfo(file).LinkTarget is not null)
                continue;
            // what the new folder already has stays, and the old copy with it
            if (File.Exists(Path.Combine(to, name)))
            {
                complete = false;
                continue;
            }
            try
            {
                File.Copy(file, Path.Combine(to, name), overwrite: false);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                complete = false;
            }
        }
        return complete;
    }
}
