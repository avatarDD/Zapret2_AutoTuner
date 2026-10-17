using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ZapretAutoTuner.Probes.Tests;

/// <summary>A self-signed CA and leaf certificates for loopback test servers.</summary>
internal static class TestCerts
{
    private static readonly Lazy<(X509Certificate2 Ca, RSA Key)> CaLazy = new(() =>
    {
        var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=ZT Test CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var ca = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return (ca, key);
    });

    public static X509Certificate2 Ca => CaLazy.Value.Ca;

    public static X509Certificate2Collection Roots => [Ca];

    public static X509Certificate2 Leaf(params string[] names)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest($"CN={names[0]}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        foreach (var n in names)
            san.AddDnsName(n);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var serial = RandomNumberGenerator.GetBytes(8);
        using var cert = req.Create(Ca.SubjectName, X509SignatureGenerator.CreateForRSA(CaLazy.Value.Key, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), serial);
        using var withKey = cert.CopyWithPrivateKey(key);
        // re-import: SslStream on Linux needs a key it can hand to OpenSSL
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx), null);
    }
}

public enum ServerMode
{
    /// <summary>Normal HTTPS (or HTTP) response.</summary>
    Ok,

    /// <summary>RST as soon as the ClientHello (first bytes) arrives.</summary>
    ResetOnHello,

    /// <summary>Reads the ClientHello and stays silent.</summary>
    SilentOnHello,

    /// <summary>FIN after the ClientHello.</summary>
    CloseOnHello,

    /// <summary>Sends the body up to <see cref="TestServer.CutAt"/> bytes, then goes silent (16 KB cut-off).</summary>
    StallAfter,

    /// <summary>Sends the body up to <see cref="TestServer.CutAt"/> bytes, then RST.</summary>
    ResetAfter,
}

/// <summary>A loopback HTTP(S) server with scripted failures, one connection at a time.</summary>
internal sealed class TestServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public TestServer(ServerMode mode, X509Certificate2? cert = null, int bodyBytes = 200_000, bool chunked = false, int status = 200, string? location = null,
        IPAddress? bind = null, int port = 0)
    {
        Mode = mode;
        Cert = cert;
        BodyBytes = bodyBytes;
        Chunked = chunked;
        Status = status;
        Location = location;
        _listener = new TcpListener(bind ?? IPAddress.Loopback, port);
        _listener.Start();
        _loop = Task.Run(LoopAsync);
    }

    public ServerMode Mode { get; }

    public X509Certificate2? Cert { get; }

    public int BodyBytes { get; }

    public bool Chunked { get; }

    public int Status { get; }

    public string? Location { get; }

    public int CutAt { get; init; } = 16 * 1024;

    /// <summary>When true the body is sent without Content-Length and the connection is closed after it.</summary>
    public bool CloseDelimited { get; init; }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public string? LastRequest { get; private set; }

    public string? LastSni { get; private set; }

    public int Connections { get; private set; }

    private async Task LoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            Socket s;
            try
            {
                s = await _listener.AcceptSocketAsync(_cts.Token);
            }
            catch (Exception)
            {
                return;
            }
            Connections++;
            _ = Task.Run(() => HandleAsync(s));
        }
    }

    private static void Rst(Socket s)
    {
        s.LingerState = new LingerOption(true, 0);
        s.Close();
    }

    private async Task HandleAsync(Socket s)
    {
        try
        {
            var ns = new NetworkStream(s, ownsSocket: false);
            if (Mode is ServerMode.ResetOnHello or ServerMode.SilentOnHello or ServerMode.CloseOnHello)
            {
                var b = new byte[4096];
                _ = await ns.ReadAsync(b, _cts.Token);
                if (Mode == ServerMode.ResetOnHello)
                    Rst(s);
                else if (Mode == ServerMode.CloseOnHello)
                    s.Close();
                else
                    await Task.Delay(Timeout.Infinite, _cts.Token);
                return;
            }

            Stream stream = ns;
            if (Cert is not null)
            {
                var ssl = new SslStream(ns, false);
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificateSelectionCallback = (_, name) =>
                    {
                        LastSni = name;
                        return Cert;
                    },
                    ApplicationProtocols = [SslApplicationProtocol.Http11],
                }, _cts.Token);
                stream = ssl;
            }

            var req = new MemoryStream();
            var buf = new byte[8192];
            while (!Encoding.ASCII.GetString(req.ToArray()).Contains("\r\n\r\n", StringComparison.Ordinal))
            {
                int n = await stream.ReadAsync(buf, _cts.Token);
                if (n == 0)
                    return;
                req.Write(buf, 0, n);
            }
            LastRequest = Encoding.ASCII.GetString(req.ToArray());
            bool head = LastRequest.StartsWith("HEAD ", StringComparison.Ordinal);

            var hdr = new StringBuilder($"HTTP/1.1 {Status} X\r\n");
            if (Location is not null)
                hdr.Append("Location: ").Append(Location).Append("\r\n");
            if (Chunked)
                hdr.Append("Transfer-Encoding: chunked\r\n");
            else if (!CloseDelimited)
                hdr.Append("Content-Length: ").Append(BodyBytes).Append("\r\n");
            hdr.Append("Connection: close\r\n\r\n");
            await stream.WriteAsync(Encoding.ASCII.GetBytes(hdr.ToString()), _cts.Token);
            if (head)
            {
                await stream.FlushAsync(_cts.Token);
                await Task.Delay(200);
                s.Close();
                return;
            }

            int sent = 0;
            var chunk = new byte[4000];
            Array.Fill(chunk, (byte)'z');
            while (sent < BodyBytes)
            {
                int n = Math.Min(chunk.Length, BodyBytes - sent);
                if (Mode is ServerMode.StallAfter or ServerMode.ResetAfter && sent + n > CutAt)
                {
                    await stream.FlushAsync(_cts.Token);
                    if (Mode == ServerMode.ResetAfter)
                    {
                        await Task.Delay(100);
                        Rst(s);
                        return;
                    }
                    await Task.Delay(Timeout.Infinite, _cts.Token);
                }
                if (Chunked)
                    await stream.WriteAsync(Encoding.ASCII.GetBytes($"{n:x}\r\n"), _cts.Token);
                await stream.WriteAsync(chunk.AsMemory(0, n), _cts.Token);
                if (Chunked)
                    await stream.WriteAsync("\r\n"u8.ToArray(), _cts.Token);
                sent += n;
            }
            if (Chunked)
                await stream.WriteAsync("0\r\n\r\n"u8.ToArray(), _cts.Token);
            await stream.FlushAsync(_cts.Token);
            if (stream is SslStream sslStream)
                await sslStream.ShutdownAsync();
            await Task.Delay(100);
            s.Close();
        }
        catch (Exception)
        {
            s.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _listener.Stop();
        try
        {
            await _loop;
        }
        catch (Exception)
        {
            // the loop ends with the listener
        }
        _cts.Dispose();
    }
}
