using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Probes.Net;

namespace ZapretAutoTuner.Probes.Http;

public enum TlsVersionLimit
{
    Any,
    Tls12,
    Tls13,
}

public sealed record HttpProbeOptions
{
    /// <summary>Host for the Host header and the certificate check.</summary>
    public required string Host { get; init; }

    /// <summary>The address to connect to (DNS is decided by the caller).</summary>
    public required IPAddress Address { get; init; }

    public int Port { get; init; } = 443;

    /// <summary>TLS on top of TCP; false for plain HTTP.</summary>
    public bool Tls { get; init; } = true;

    /// <summary>SNI to send; null means <see cref="Host"/>, empty means no SNI (cross-SNI and provider tests).</summary>
    public string? Sni { get; init; }

    public TlsVersionLimit TlsVersion { get; init; } = TlsVersionLimit.Any;

    public string Path { get; init; } = "/";

    public ProbeLevel Level { get; init; } = ProbeLevel.L2Body;

    /// <summary>L2 threshold: 64 KB normally, 128 KB for the 16 KB cut-off.</summary>
    public long MinBytes { get; init; } = 64 * 1024;

    /// <summary>
    /// Bytes of padding headers added to the request. A small site then still moves enough data for a volume-based
    /// cut-off to show (dpi-diagnostics §3).
    /// </summary>
    public int PadBytes { get; init; }

    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(5);

    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>No incoming bytes for this long after the request means a stall.</summary>
    public TimeSpan StallTimeout { get; init; } = TimeSpan.FromSeconds(3);

    public TimeSpan MaxTime { get; init; } = TimeSpan.FromSeconds(15);

    public string UserAgent { get; init; } = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

    /// <summary>Extra trust anchors (test servers). The system store is used when null.</summary>
    public X509Certificate2Collection? TrustedRoots { get; init; }
}

/// <summary>
/// A native HTTP/1.1 probe over TCP or TLS to a fixed address (the <c>curl --resolve</c> of blockcheck2), measuring
/// what <see cref="ProbeResult"/> needs: where the attempt broke, bytes received, stalls and resets. It never throws for
/// network failures; they become <see cref="ProbeResult.Error"/>.
/// </summary>
public static class HttpProbe
{
    private const int MaxHeaderBytes = 64 * 1024;

    public static async Task<ProbeResult> RunAsync(HttpProbeOptions o, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        string? sni = o.Tls ? o.Sni ?? o.Host : null;
        if (sni is { Length: 0 })
            sni = null;
        var r = new Builder { Host = o.Host, Address = o.Address.ToString(), Port = o.Port, Tls = o.Tls, Sni = sni, Head = o.Level == ProbeLevel.L1Handshake };
        using var total = CancellationTokenSource.CreateLinkedTokenSource(ct);
        total.CancelAfter(o.MaxTime);

        TcpConnectResult conn;
        try
        {
            conn = await TcpConnector.ConnectAsync(o.Address, o.Port, o.ConnectTimeout, total.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return r.Fail(ProbeError.ConnectTimeout, "истекло общее время", sw);
        }
        if (!conn.Ok)
        {
            ct.ThrowIfCancellationRequested();
            return r.Fail(conn.Error, conn.Detail ?? "", sw, rst: conn.Rst);
        }
        using var socket = conn.Socket!;
        r.ConnectOk = true;
        r.ConnectTime = sw.Elapsed;

        var raw = new CountingStream(new NetworkStream(socket, ownsSocket: false));
        Stream stream = raw;
        SslStream? ssl = null;
        try
        {
            if (o.Tls)
            {
                // The probe must see what the server (or a MITM) sends: the certificate is judged into CertValid,
                // and nothing secret goes over this connection.
#pragma warning disable CA5359
                ssl = new SslStream(raw, leaveInnerStreamOpen: true, (_, cert, _, errors) =>
                {
                    r.Certificate(o, cert, errors);
                    return true;
                });
#pragma warning restore CA5359
                var auth = new SslClientAuthenticationOptions
                {
                    TargetHost = sni ?? "",
                    EnabledSslProtocols = o.TlsVersion switch
                    {
                        TlsVersionLimit.Tls12 => SslProtocols.Tls12,
                        TlsVersionLimit.Tls13 => SslProtocols.Tls13,
                        _ => SslProtocols.Tls12 | SslProtocols.Tls13,
                    },
                    ApplicationProtocols = [SslApplicationProtocol.Http11],
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                };
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(total.Token);
                    cts.CancelAfter(o.HandshakeTimeout);
                    await ssl.AuthenticateAsClientAsync(auth, cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    return r.Fail(raw.Reset ? ProbeError.TlsReset : ProbeError.TlsTimeout, raw.Reset ? "RST во время handshake" : "нет ответа на ClientHello", sw, raw);
                }
                catch (Exception e) when (e is AuthenticationException or IOException or SocketException)
                {
                    if (raw.Reset)
                        return r.Fail(ProbeError.TlsReset, "RST во время handshake", sw, raw);
                    if (raw.Eof)
                        return r.Fail(ProbeError.TlsClosed, "соединение закрыто во время handshake", sw, raw);
                    return r.Fail(ProbeError.TlsFailed, Innermost(e).Message, sw, raw);
                }
                r.TlsOk = true;
                r.TlsTime = sw.Elapsed;
                r.TlsVersion = ssl.SslProtocol switch
                {
                    SslProtocols.Tls13 => "1.3",
                    SslProtocols.Tls12 => "1.2",
                    var p => p.ToString(),
                };
                r.Alpn = ssl.NegotiatedApplicationProtocol.Protocol.Length > 0 ? ssl.NegotiatedApplicationProtocol.ToString() : null;
                stream = ssl;
            }

            await ExchangeAsync(o, stream, raw, r, sw, total.Token, ct).ConfigureAwait(false);
            return r.Build(sw, raw);
        }
        finally
        {
            if (ssl is not null)
                await ssl.DisposeAsync().ConfigureAwait(false);
            await raw.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task ExchangeAsync(HttpProbeOptions o, Stream stream, CountingStream raw, Builder r, Stopwatch sw, CancellationToken total, CancellationToken user)
    {
        var request = BuildRequest(o);
        TimeSpan sent;
        try
        {
            await stream.WriteAsync(request, total).ConfigureAwait(false);
            await stream.FlushAsync(total).ConfigureAwait(false);
            sent = sw.Elapsed;
        }
        catch (OperationCanceledException) when (!user.IsCancellationRequested)
        {
            r.SetError(ProbeError.TimeLimit, "не удалось отправить запрос");
            return;
        }
        catch (Exception e) when (e is IOException or SocketException)
        {
            r.SetError(raw.Reset ? ProbeError.HttpReset : ProbeError.Truncated, Innermost(e).Message);
            return;
        }

        var buf = new byte[16 * 1024];
        var head = new MemoryStream();
        ResponseBody? body = null;
        while (true)
        {
            int n;
            try
            {
                using var stall = CancellationTokenSource.CreateLinkedTokenSource(total);
                stall.CancelAfter(o.StallTimeout);
                n = await stream.ReadAsync(buf, stall.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!user.IsCancellationRequested)
            {
                if (total.IsCancellationRequested)
                    r.SetError(r.BytesIn == 0 ? ProbeError.HttpTimeout : ProbeError.TimeLimit, "истекло общее время");
                else if (r.BytesIn == 0)
                    r.SetError(ProbeError.HttpTimeout, "нет ответа на запрос");
                else
                    r.Stall(raw.BytesIn);
                return;
            }
            catch (Exception e) when (e is IOException or SocketException)
            {
                r.SetError(raw.Reset ? ProbeError.HttpReset : ProbeError.Truncated, Innermost(e).Message, raw.Reset);
                return;
            }

            if (n == 0)
            {
                if (body is null)
                    r.SetError(r.BytesIn == 0 ? ProbeError.Truncated : ProbeError.BadResponse, "соединение закрыто до ответа");
                else if (body.CloseDelimited)
                    r.Complete = true;
                else if (!r.Complete)
                    r.SetError(ProbeError.Truncated, "соединение закрыто до конца ответа");
                return;
            }

            r.Ttfb ??= sw.Elapsed - sent;
            r.BytesIn += n;
            ReadOnlySpan<byte> chunk = buf.AsSpan(0, n);
            if (body is null)
            {
                head.Write(chunk);
                var h = head.GetBuffer().AsSpan(0, (int)head.Length);
                int end = h.IndexOf("\r\n\r\n"u8);
                if (end < 0)
                {
                    if (head.Length > MaxHeaderBytes)
                    {
                        r.SetError(ProbeError.BadResponse, "слишком длинные заголовки");
                        return;
                    }
                    continue;
                }
                if (!ParseHead(h[..end], r, out body))
                {
                    r.SetError(ProbeError.BadResponse, "ответ не похож на HTTP");
                    return;
                }
                chunk = h[(end + 4)..];
                if (o.Level == ProbeLevel.L1Handshake || body.Empty)
                {
                    r.Complete = body.Empty;
                    return;
                }
            }

            r.BodyBytes += body.Feed(chunk, out bool done);
            if (body.Malformed)
            {
                r.SetError(ProbeError.BadResponse, "испорченный chunked-ответ");
                return;
            }
            if (done)
            {
                r.Complete = true;
                return;
            }
            if (r.BodyBytes >= o.MinBytes)
                return;
        }
    }

    internal static byte[] BuildRequest(HttpProbeOptions o)
    {
        var sb = new StringBuilder();
        string host = o.Host.Contains(':', StringComparison.Ordinal) ? "[" + o.Host + "]" : o.Host;
        if (o.Port != (o.Tls ? 443 : 80))
            host += ":" + o.Port.ToString(CultureInfo.InvariantCulture);
        string method = o.Level == ProbeLevel.L1Handshake ? "HEAD" : "GET";
        sb.Append(method).Append(' ').Append(o.Path.Length == 0 ? "/" : o.Path).Append(" HTTP/1.1\r\n");
        sb.Append("Host: ").Append(host).Append("\r\n");
        sb.Append("User-Agent: ").Append(o.UserAgent).Append("\r\n");
        sb.Append("Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n");
        int left = o.PadBytes;
        for (int i = 1; left > 0; i++)
        {
            // header lines up to 4 KB each: servers usually allow 8 KB per line and 32-64 KB in total
            var name = $"X-Pad-{i:D2}: ";
            int len = Math.Max(1, Math.Min(4096, left - name.Length - 2));
            sb.Append(name).Append('a', len).Append("\r\n");
            left -= name.Length + len + 2;
        }
        sb.Append("\r\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    private static bool ParseHead(ReadOnlySpan<byte> head, Builder r, out ResponseBody body)
    {
        body = null!;
        var text = Encoding.Latin1.GetString(head);
        var lines = text.Split("\r\n");
        var status = lines[0].Split(' ', 3);
        if (status.Length < 2 || !status[0].StartsWith("HTTP/1.", StringComparison.Ordinal)
            || !int.TryParse(status[1], NumberStyles.None, CultureInfo.InvariantCulture, out int code) || code is < 100 or > 999)
            return false;
        long? length = null;
        bool chunked = false;
        foreach (var line in lines.Skip(1))
        {
            int colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
                continue;
            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) && long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var l))
                length = l;
            else if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) && value.Contains("chunked", StringComparison.OrdinalIgnoreCase))
                chunked = true;
            else if (name.Equals("Location", StringComparison.OrdinalIgnoreCase))
                r.Location = value;
        }
        r.HttpStatus = code;
        r.ContentLength = chunked ? null : length;
        bool empty = code is < 200 or 204 or 304 || r.Head || (!chunked && length == 0);
        body = new ResponseBody(chunked, chunked ? null : length, empty);
        return true;
    }

    private static Exception Innermost(Exception e)
    {
        while (e.InnerException is not null)
            e = e.InnerException;
        return e;
    }

    /// <summary>Counts the body of a response: Content-Length, chunked, or until close.</summary>
    internal sealed class ResponseBody(bool chunked, long? length, bool empty)
    {
        private long _chunkLeft = -1; // -1: reading a chunk-size line
        private int _state; // chunked: 0 size line, 1 data, 2 CRLF after data, 3 trailers
        private readonly StringBuilder _line = new();
        private long _received;

        public bool Empty { get; } = empty;

        public bool CloseDelimited => !chunked && length is null;

        public bool Malformed { get; private set; }

        /// <summary>Feeds response bytes; returns how many of them are body bytes.</summary>
        public long Feed(ReadOnlySpan<byte> data, out bool done)
        {
            done = false;
            if (!chunked)
            {
                long take = length is { } l ? Math.Min(data.Length, l - _received) : data.Length;
                _received += take;
                done = length is { } l2 && _received >= l2;
                return take;
            }

            long bodyBytes = 0;
            int p = 0;
            while (p < data.Length)
            {
                switch (_state)
                {
                    case 0 or 2 or 3:
                    {
                        byte b = data[p++];
                        if (b != '\n')
                        {
                            if (b != '\r')
                                _line.Append((char)b);
                            if (_line.Length > 1024)
                            {
                                Malformed = true;
                                return bodyBytes;
                            }
                            continue;
                        }
                        var line = _line.ToString();
                        _line.Clear();
                        if (_state == 2)
                        {
                            if (line.Length != 0)
                            {
                                Malformed = true;
                                return bodyBytes;
                            }
                            _state = 0;
                        }
                        else if (_state == 3)
                        {
                            if (line.Length == 0)
                            {
                                done = true;
                                return bodyBytes;
                            }
                        }
                        else
                        {
                            var hex = line.Split(';')[0].Trim();
                            if (!long.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out _chunkLeft) || _chunkLeft < 0)
                            {
                                Malformed = true;
                                return bodyBytes;
                            }
                            _state = _chunkLeft == 0 ? 3 : 1;
                        }
                        break;
                    }
                    case 1:
                    {
                        int take = (int)Math.Min(_chunkLeft, data.Length - p);
                        p += take;
                        _chunkLeft -= take;
                        bodyBytes += take;
                        if (_chunkLeft == 0)
                            _state = 2;
                        break;
                    }
                }
            }
            return bodyBytes;
        }
    }

    private sealed class Builder
    {
        public required string Host;
        public required string Address;
        public int Port;
        public bool Tls;
        public string? Sni;
        public bool ConnectOk, TlsOk, Complete, RstSeen, CertValid, Head;
        public int? HttpStatus;
        public long BytesIn, BodyBytes;
        public long? ContentLength, StalledAt;
        public TimeSpan? ConnectTime, TlsTime, Ttfb;
        public string? Alpn, TlsVersion, CertSubject, CertIssuer, CertError, Location, ErrorDetail;
        public IReadOnlyList<string> CertNames = [];
        public ProbeError Error;

        public void Certificate(HttpProbeOptions o, X509Certificate? cert, SslPolicyErrors errors)
        {
            if (cert is null)
            {
                CertError = "сервер не прислал сертификат";
                return;
            }
            var c = cert as X509Certificate2 ?? new X509Certificate2(cert);
            CertSubject = c.Subject;
            CertIssuer = c.Issuer;
            CertNames = DnsNames(c);
            bool chainOk;
            if (o.TrustedRoots is { Count: > 0 } roots)
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.AddRange(roots);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chainOk = chain.Build(c);
            }
            else
            {
                chainOk = (errors & ~SslPolicyErrors.RemoteCertificateNameMismatch) == SslPolicyErrors.None;
            }
            bool nameOk = c.MatchesHostname(o.Host, allowWildcards: true, allowCommonName: false);
            CertValid = chainOk && nameOk;
            if (!chainOk)
                CertError = "цепочка сертификата не доверенная";
            else if (!nameOk)
                CertError = $"сертификат не для {o.Host}";
        }

        private static List<string> DnsNames(X509Certificate2 c)
        {
            var list = new List<string>();
            foreach (var ext in c.Extensions)
            {
                if (ext is X509SubjectAlternativeNameExtension san)
                    list.AddRange(san.EnumerateDnsNames());
            }
            return list;
        }

        public void SetError(ProbeError e, string detail, bool rst = false)
        {
            Error = e;
            ErrorDetail = detail;
            RstSeen |= rst || e is ProbeError.HttpReset;
        }

        public void Stall(long rawBytes)
        {
            Error = ProbeError.Stalled;
            StalledAt = BytesIn;
            ErrorDetail = $"входящие данные остановились на {BytesIn} B ({rawBytes} B на проводе)";
        }

        public ProbeResult Fail(ProbeError e, string detail, Stopwatch sw, CountingStream? raw = null, bool rst = false)
        {
            SetError(e, detail, rst || raw?.Reset == true);
            return Build(sw, raw);
        }

        public ProbeResult Build(Stopwatch sw, CountingStream? raw) => new()
        {
            Host = Host,
            Address = Address,
            Port = Port,
            Tls = Tls,
            Sni = Sni,
            ConnectOk = ConnectOk,
            TlsOk = TlsOk,
            HttpStatus = HttpStatus,
            BytesIn = BytesIn,
            BodyBytes = BodyBytes,
            ContentLength = ContentLength,
            Complete = Complete,
            ConnectTime = ConnectTime,
            TlsTime = TlsTime,
            Ttfb = Ttfb,
            Duration = sw.Elapsed,
            StalledAt = StalledAt,
            RstSeen = RstSeen || raw?.Reset == true,
            Alpn = Alpn,
            TlsVersion = TlsVersion,
            CertValid = CertValid,
            CertSubject = CertSubject,
            CertIssuer = CertIssuer,
            CertNames = CertNames,
            CertError = CertError,
            Location = Location,
            Error = Error,
            ErrorDetail = ErrorDetail,
        };
    }
}
