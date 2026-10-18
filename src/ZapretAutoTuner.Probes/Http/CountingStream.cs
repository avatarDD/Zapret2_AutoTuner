using System.Net.Sockets;

namespace ZapretAutoTuner.Probes.Http;

/// <summary>Counts raw bytes under TLS and notes how the transport ended: reset (RST) or EOF (FIN).</summary>
internal sealed class CountingStream(Stream inner) : Stream
{
    public long BytesIn { get; private set; }

    public long BytesOut { get; private set; }

    public bool Reset { get; private set; }

    public bool Eof { get; private set; }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        try
        {
            int n = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            BytesIn += n;
            if (n == 0 && buffer.Length > 0)
                Eof = true;
            return n;
        }
        catch (Exception e) when (IsReset(e))
        {
            Reset = true;
            throw;
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        try
        {
            await inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            BytesOut += buffer.Length;
        }
        catch (Exception e) when (IsReset(e))
        {
            Reset = true;
            throw;
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count).GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count).GetAwaiter().GetResult();

    public override void Flush() => inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    private static bool IsReset(Exception e)
    {
        for (var x = e; x is not null; x = x.InnerException)
        {
            if (x is SocketException { SocketErrorCode: SocketError.ConnectionReset or SocketError.ConnectionAborted })
                return true;
        }
        return false;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            inner.Dispose();
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        await inner.DisposeAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }
}
