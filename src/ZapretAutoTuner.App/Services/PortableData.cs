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
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
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

    /// <summary>
    /// Copies the old folder into the new one when the new one has no knowledge base yet, then removes the old copy
    /// (only once everything was copied). Files the old folder holds that the user cannot read are left there.
    /// </summary>
    internal static bool Migrate(string legacy, string portable)
    {
        var oldDb = Path.Combine(legacy, "knowledge.db");
        if (!File.Exists(oldDb) || File.Exists(Path.Combine(portable, "knowledge.db")))
            return false;
        if (Path.GetFullPath(legacy).TrimEnd(Path.DirectorySeparatorChar) == Path.GetFullPath(portable).TrimEnd(Path.DirectorySeparatorChar))
            return false;
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
        return true;
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
