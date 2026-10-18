using System.Globalization;

namespace ZapretAutoTuner.Agent;

/// <summary>
/// Agent command line. The UI starts the Agent elevated (UAC / pkexec) with these options; the token is passed in
/// a file readable only by the user, never on the command line, because other users can read argv.
/// </summary>
internal sealed class AgentOptions
{
    /// <summary>Linux: unix socket path. Created by the Agent, owned by <see cref="OwnerUid"/>, mode 0600.</summary>
    public string? Socket { get; set; }

    /// <summary>Windows: named pipe name (without <c>\\.\pipe\</c>).</summary>
    public string? Pipe { get; set; }

    /// <summary>File with the session token; deleted after reading.</summary>
    public string? TokenFile { get; set; }

    /// <summary>The token itself (tests only; visible to other users).</summary>
    public string? Token { get; set; }

    /// <summary>The UI process: when it exits, the Agent cleans up and exits.</summary>
    public int UiPid { get; set; }

    /// <summary>Linux: uid that may connect to the socket (pkexec sets <c>PKEXEC_UID</c>).</summary>
    public int? OwnerUid { get; set; }

    /// <summary>Engine binary; default — the bundled one.</summary>
    public string? Engine { get; set; }

    /// <summary>Directory for engine logs, captures and the Agent state file.</summary>
    public string? DataDir { get; set; }

    /// <summary>Clean up when no heartbeat arrives for this long.</summary>
    public TimeSpan HeartbeatTimeout { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>Clean up when the first heartbeat does not arrive for this long after the start.</summary>
    public TimeSpan StartupGrace { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Hosts file to edit; default — the system one (tests point it elsewhere).</summary>
    public string? HostsFile { get; set; }

    /// <summary>Only remove leftovers of a crashed Agent (firewall table, sysctls, engines) and exit.</summary>
    public bool CleanupOnly { get; set; }

    public static AgentOptions Parse(IReadOnlyList<string> args)
    {
        var o = new AgentOptions();
        foreach (var a in args)
        {
            var eq = a.IndexOf('=', StringComparison.Ordinal);
            var name = eq > 0 ? a[..eq] : a;
            var value = eq > 0 ? a[(eq + 1)..] : "";
            switch (name)
            {
                case "--socket": o.Socket = value; break;
                case "--pipe": o.Pipe = value; break;
                case "--token-file": o.TokenFile = value; break;
                case "--token": o.Token = value; break;
                case "--ui-pid": o.UiPid = int.Parse(value, CultureInfo.InvariantCulture); break;
                case "--owner-uid": o.OwnerUid = int.Parse(value, CultureInfo.InvariantCulture); break;
                case "--engine": o.Engine = value; break;
                case "--data-dir": o.DataDir = value; break;
                case "--heartbeat-timeout": o.HeartbeatTimeout = TimeSpan.FromMilliseconds(int.Parse(value, CultureInfo.InvariantCulture)); break;
                case "--cleanup": o.CleanupOnly = true; break;
                case "--hosts-file": o.HostsFile = value; break;
                default: throw new ArgumentException($"unknown option {a}");
            }
        }
        if (o.OwnerUid is null && int.TryParse(Environment.GetEnvironmentVariable("PKEXEC_UID"), NumberStyles.None, CultureInfo.InvariantCulture, out var uid))
            o.OwnerUid = uid;
        if (!o.CleanupOnly)
        {
            if (o.Socket is null == (o.Pipe is null))
                throw new ArgumentException("exactly one of --socket and --pipe is required");
            if (o.TokenFile is null && o.Token is null)
                throw new ArgumentException("--token-file is required");
            if (o.UiPid <= 0)
                throw new ArgumentException("--ui-pid is required");
        }
        if (o.DataDir is null)
            throw new ArgumentException("--data-dir is required");
        return o;
    }

    public string ReadToken()
    {
        if (Token is not null)
            return Token;
        var t = File.ReadAllText(TokenFile!).Trim();
        try
        {
            File.Delete(TokenFile!);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        if (t.Length < 32)
            throw new InvalidOperationException("session token is too short");
        return t;
    }
}
