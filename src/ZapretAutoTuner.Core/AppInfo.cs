using System.Reflection;

namespace ZapretAutoTuner.Core;

public static class AppInfo
{
    public const string Name = "Zapret2_AutoTuner";

    /// <summary>zapret2 release the application bundles and the catalog is checked against.</summary>
    public const string Zapret2Version = "1.0.5.2";

    /// <summary><c>NFQWS2_COMPAT_VER_REQUIRED</c> of the bundled lua (first line of zapret-lib.lua).</summary>
    public const int LuaCompatVersion = 6;

    public static string Version { get; } =
        typeof(AppInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? "0.0.0";
}
