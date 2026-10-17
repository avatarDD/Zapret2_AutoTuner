using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ZapretAutoTuner.Agent;

/// <summary>Restricts the Agent socket to the UI user: owner uid, mode 0600 (the token is the second barrier).</summary>
[UnsupportedOSPlatform("windows")]
internal static partial class UnixSocket
{
    public static void Restrict(string path, int? ownerUid)
    {
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        if (ownerUid is { } uid && chown(path, uid, -1) != 0)
            Console.Error.WriteLine($"chown {path}: errno {Marshal.GetLastPInvokeError()}");
    }

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int chown(string path, int uid, int gid);
}
