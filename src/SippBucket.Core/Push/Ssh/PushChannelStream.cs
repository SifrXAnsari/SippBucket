using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.DevTunnels.Ssh;
using Microsoft.DevTunnels.Ssh.Events;
using SippBucket.Core.Protocol;
using SshBuffer = Microsoft.DevTunnels.Ssh.Buffer;

namespace SippBucket.Core.Push.Ssh;

/// <summary>
/// A Direct Push channel as a stream: it holds the other side to the SSH flow-control window,
/// and gives up on it when it stalls.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why not the library's own stream.</b> <c>SshStream</c> queues whatever the channel
/// delivers and trusts the other side to keep to the window it was given, and the channel
/// itself does not check. A machine that ignored the window could make this one hold
/// everything it sent in memory. This stream holds at most the window: the other side may have
/// no more than that unacknowledged (RFC 4254 section 5.2), and this stream acknowledges only
/// what it has handed to a reader, so anything past the window is a violation. The data is
/// dropped, and every read from then on throws <see cref="PushFault.WindowExceeded"/>.
/// </para>
/// <para>
/// <b>Deadlines.</b> Every read and write carries the stall deadline sync uses: silence for
/// that long, while data is awaited or while the other side is not taking what is sent, throws
/// <see cref="PeerStalledException"/>. Writes go out in pieces of <see cref="SendPiece"/> bytes
/// and the deadline restarts on each, so a slow link is tolerated and a dead one is not.
/// </para>
/// <para>
/// <b>End of stream.</b> A read returns 0 once everything received has been read and the other
/// side has sent end-of-file or closed the channel. The push protocol is self-delimiting, so a
/// close part way through a message shows up there as a truncated message.
/// </para>
/// <para>
/// Asynchronous underneath. The synchronous forms exist so that a caller holding a
/// <see cref="Stream"/> never meets one that refuses: a synchronous read waits on the same
/// signal, and a synchronous write waits for the asynchronous one, which is safe because
/// nothing in SippBucket's daemon runs a synchronization context.
/// </para>
/// </remarks>
public sealed class PushChannelStream : Stream
{
    /// <summary>The most one write hands the channel at once; the stall deadline restarts on each.</summary>
    public const int SendPiece = 64 * 1024;

    private readonly SshChannel _channel;
    private readonly TimeSpan _stallTimeout;

    // Everything below is under _gate. The signal is released once for every change a reader
    // may be waiting for: data, the end, or a violation.
    private readonly Lock _gate = new();
    private readonly ReceiveWindow _received;
    private readonly SemaphoreSlim _signal = new(0);
    private bool _disposed;

    /// <summary>Starts reading a channel. Create it before the channel's first data can arrive.</summary>
    /// <param name="channel">The channel, with its window already set.</param>
    /// <param name="stallTimeout">How long a read or write may make no progress.</param>
    /// <exception cref="ArgumentNullException"><paramref name="channel"/> was null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="stallTimeout"/> is not positive.</exception>
    internal PushChannelStream(SshChannel channel, TimeSpan stallTimeout)
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(stallTimeout, TimeSpan.Zero);

        _channel = channel;
        _stallTimeout = stallTimeout;
        _received = new ReceiveWindow(channel.MaxWindowSize);

        channel.DataReceived += OnDataReceived;

        // Runs at once when the channel has already closed.
        channel.Closed += OnClosed;
    }

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanWrite => true;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <summary>Not supported: a channel has no length.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override long Length => throw new NotSupportedException("A Direct Push channel has no length.");

    /// <summary>Not supported: a channel has no position.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override long Position
    {
        get => throw new NotSupportedException("A Direct Push channel has no position.");
        set => throw new NotSupportedException("A Direct Push channel has no position.");
    }

    /// <summary>How many bytes have arrived and not yet been read: never more than the window.</summary>
    public long Buffered
    {
        get
        {
            lock (_gate)
            {
                return _received.Buffered;
            }
        }
    }

    /// <inheritdoc />
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (buffer.IsEmpty)
        {
            return 0;
        }

        while (true)
        {
            if (TryTake(buffer.Span, out var taken))
            {
                return taken;
            }

            if (!await _signal.WaitAsync(_stallTimeout, cancellationToken).ConfigureAwait(false))
            {
                throw Stalled("waiting for data");
            }
        }
    }

    /// <inheritdoc />
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ValidateBufferArguments(buffer, offset, count);
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <inheritdoc />
    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (buffer.IsEmpty)
        {
            return 0;
        }

        while (true)
        {
            if (TryTake(buffer, out var taken))
            {
                return taken;
            }

            if (!_signal.Wait(_stallTimeout))
            {
                throw Stalled("waiting for data");
            }
        }
    }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ValidateBufferArguments(buffer, offset, count);
        return Read(buffer.AsSpan(offset, count));
    }

    /// <inheritdoc />
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (buffer.IsEmpty)
        {
            return;
        }

        // One timer for the whole write, restarted for each piece, as Framing's stall deadline is.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        for (var offset = 0; offset < buffer.Length; offset += SendPiece)
        {
            var piece = AsSegment(buffer.Slice(offset, Math.Min(SendPiece, buffer.Length - offset)));
            deadline.CancelAfter(_stallTimeout);

            try
            {
                await _channel
                    .SendAsync(SshBuffer.From(piece.Array!, piece.Offset, piece.Count), deadline.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                throw Stalled("waiting for it to take what was sent", ex);
            }
            catch (Exception ex) when (ex is SshChannelException or SshConnectionException or ObjectDisposedException &&
                                       !cancellationToken.IsCancellationRequested)
            {
                // However the library reports a channel or session that ended, it is one thing here.
                throw new PushException(
                    PushFault.SessionFailed,
                    "The other machine closed the connection while this one was still sending.",
                    ex);
            }
        }
    }

    /// <inheritdoc />
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ValidateBufferArguments(buffer, offset, count);
        return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <inheritdoc />
    public override void Write(ReadOnlySpan<byte> buffer) =>
        WriteAsync(buffer.ToArray()).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ValidateBufferArguments(buffer, offset, count);
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    }

    /// <summary>Does nothing: a write is complete once the channel has taken it.</summary>
    public override void Flush()
    {
    }

    /// <summary>Does nothing: a write is complete once the channel has taken it.</summary>
    /// <param name="cancellationToken">Unused.</param>
    /// <returns>A completed task.</returns>
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>Not supported: a channel cannot seek.</summary>
    /// <param name="offset">Unused.</param>
    /// <param name="origin">Unused.</param>
    /// <returns>Never returns.</returns>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException("A Direct Push channel cannot seek.");

    /// <summary>Not supported: a channel has no length.</summary>
    /// <param name="value">Unused.</param>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override void SetLength(long value) =>
        throw new NotSupportedException("A Direct Push channel has no length.");

    /// <summary>Stops reading the channel. The channel and its session are their owner's to close.</summary>
    /// <param name="disposing">True when called from <see cref="Stream.Dispose()"/>.</param>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _channel.DataReceived -= OnDataReceived;
            _channel.Closed -= OnClosed;

            lock (_gate)
            {
                if (!_disposed)
                {
                    _disposed = true;
                    _received.Clear();
                    _signal.Dispose();
                }
            }
        }

        base.Dispose(disposing);
    }

    private static ArraySegment<byte> AsSegment(ReadOnlyMemory<byte> memory) =>
        MemoryMarshal.TryGetArray(memory, out var segment) ? segment : new ArraySegment<byte>(memory.ToArray());

    /// <summary>
    /// Answers a read from what has arrived: true with the bytes copied, or true with 0 at the
    /// end, or false when the reader must wait. Throws once the other side broke the window.
    /// </summary>
    private bool TryTake(Span<byte> destination, out int taken)
    {
        lock (_gate)
        {
            if (_received.Violation is { } violation)
            {
                throw new PushException(PushFault.WindowExceeded, violation);
            }

            taken = _received.Take(destination);
            if (taken == 0)
            {
                return _received.Ended;
            }
        }

        // Only now may the other side send this much more. The library sends the adjustment
        // itself once half the window has been read.
        _channel.AdjustWindow(checked((uint)taken));
        return true;
    }

    private void OnDataReceived(object? sender, SshBuffer data)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            // The library reports the other side's end-of-file as an empty delivery.
            var changed = data.Count == 0 ? _received.End() : _received.Receive(data.Span);

            // Inside the lock, so it can never meet a signal disposed under it.
            if (changed)
            {
                _signal.Release();
            }
        }
    }

    private void OnClosed(object? sender, SshChannelClosedEventArgs e)
    {
        lock (_gate)
        {
            if (!_disposed && _received.End())
            {
                _signal.Release();
            }
        }
    }

    private PeerStalledException Stalled(string what, Exception? cause = null)
    {
        var message = string.Create(
            CultureInfo.InvariantCulture,
            $"The other machine made no progress for {_stallTimeout.TotalSeconds:0.#}s while {what}.");

        return cause is null ? new PeerStalledException(message) : new PeerStalledException(message, cause);
    }
}
