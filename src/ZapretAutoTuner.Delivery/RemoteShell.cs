using System.Security.Cryptography;
using System.Text;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace ZapretAutoTuner.Delivery;

/// <summary>A shell on the router: run a command, read and write a file.</summary>
public interface IRemoteShell : IDisposable
{
    Task<(int Code, string Output)> RunAsync(string command, CancellationToken ct);

    Task<byte[]?> ReadAsync(string path, CancellationToken ct);

    Task WriteAsync(string path, byte[] data, CancellationToken ct);
}

/// <summary>How to reach the router over SSH.</summary>
public sealed record SshTarget
{
    public required string Host { get; init; }

    public int Port { get; init; } = 22;

    public string User { get; init; } = "root";

    public string? Password { get; init; }

    public string? PrivateKeyPath { get; init; }

    /// <summary>
    /// Decides on the server's host key, given as <c>SHA256:base64</c>: the UI shows it on the first connection and
    /// remembers it (trust on first use). Without a callback no key is accepted.
    /// </summary>
    public Func<string, bool>? TrustHostKey { get; init; }

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(15);
}

/// <summary>
/// <see cref="IRemoteShell"/> over SSH.NET. Files go through SFTP when the router has it; otherwise through
/// <c>printf</c> with octal escapes in chunks, which any POSIX shell (busybox on Entware) understands.
/// </summary>
public sealed class SshRemoteShell : IRemoteShell
{
    private const int ChunkBytes = 2048;
    private readonly SshClient _ssh;
    private readonly SftpClient? _sftp;

    private SshRemoteShell(SshClient ssh, SftpClient? sftp)
    {
        _ssh = ssh;
        _sftp = sftp;
    }

    public static async Task<SshRemoteShell> ConnectAsync(SshTarget t, CancellationToken ct)
    {
        var auth = new List<AuthenticationMethod>();
        if (t.PrivateKeyPath is not null)
            auth.Add(new PrivateKeyAuthenticationMethod(t.User, new PrivateKeyFile(t.PrivateKeyPath)));
        if (t.Password is not null)
            auth.Add(new PasswordAuthenticationMethod(t.User, t.Password));
        if (auth.Count == 0)
            throw new ArgumentException("нужен пароль или ключ / a password or a key is required");
        var info = new ConnectionInfo(t.Host, t.Port, t.User, [.. auth]) { Timeout = t.Timeout };

        void Check(object? sender, HostKeyEventArgs e) =>
            e.CanTrust = t.TrustHostKey?.Invoke("SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=')) == true;

        var ssh = new SshClient(info);
        ssh.HostKeyReceived += Check;
        try
        {
            await ssh.ConnectAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            ssh.Dispose();
            throw;
        }
        SftpClient? sftp = new(info);
        sftp.HostKeyReceived += Check;
        try
        {
            await sftp.ConnectAsync(ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is SshException or IOException)
        {
            sftp.Dispose();
            sftp = null; // no sftp-server on the router
        }
        return new SshRemoteShell(ssh, sftp);
    }

    public async Task<(int Code, string Output)> RunAsync(string command, CancellationToken ct)
    {
        using var cmd = _ssh.CreateCommand(command);
        await cmd.ExecuteAsync(ct).ConfigureAwait(false);
        return (cmd.ExitStatus ?? -1, cmd.Result + cmd.Error);
    }

    public async Task<byte[]?> ReadAsync(string path, CancellationToken ct)
    {
        if (_sftp is not null)
        {
            if (!await _sftp.ExistsAsync(path, ct).ConfigureAwait(false))
                return null;
            using var ms = new MemoryStream();
            await _sftp.DownloadFileAsync(path, ms, ct).ConfigureAwait(false);
            return ms.ToArray();
        }
        var (code, output) = await RunAsync($"test -f {Quote(path)} && od -An -v -tx1 {Quote(path)}", ct).ConfigureAwait(false);
        return code != 0 ? null : Convert.FromHexString(string.Concat(output.Where(Uri.IsHexDigit)));
    }

    public async Task WriteAsync(string path, byte[] data, CancellationToken ct)
    {
        if (_sftp is not null)
        {
            using var ms = new MemoryStream(data);
            await _sftp.UploadFileAsync(ms, path, ct).ConfigureAwait(false);
            return;
        }
        var tmp = path + ".zt-tmp";
        var (code, output) = await RunAsync($": > {Quote(tmp)}", ct).ConfigureAwait(false);
        for (int ofs = 0; code == 0 && ofs < data.Length; ofs += ChunkBytes)
            (code, output) = await RunAsync($"printf '{Octal(data.AsSpan(ofs, Math.Min(ChunkBytes, data.Length - ofs)))}' >> {Quote(tmp)}", ct).ConfigureAwait(false);
        if (code == 0)
            (code, output) = await RunAsync($"mv {Quote(tmp)} {Quote(path)}", ct).ConfigureAwait(false);
        if (code != 0)
            throw new IOException($"запись {path}: {output}");
    }

    internal static string Octal(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder(bytes.Length * 4);
        foreach (var b in bytes)
            sb.Append('\\').Append(Convert.ToString(b, 8).PadLeft(3, '0'));
        return sb.ToString();
    }

    /// <summary>Single-quoted for a POSIX shell.</summary>
    public static string Quote(string s) => "'" + s.Replace("'", "'\\''", StringComparison.Ordinal) + "'";

    public void Dispose()
    {
        _sftp?.Dispose();
        _ssh.Dispose();
    }
}
