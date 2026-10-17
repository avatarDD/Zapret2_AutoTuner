using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ZapretAutoTuner.Agent;

[SupportedOSPlatform("windows")]
internal static class PipeAcl
{
    /// <summary>Only the user who started the UI (same SID, elevated or not) and Administrators may connect.</summary>
    public static PipeSecurity CurrentUserOnly()
    {
        var ps = new PipeSecurity();
        var user = WindowsIdentity.GetCurrent().User!;
        ps.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        return ps;
    }
}
