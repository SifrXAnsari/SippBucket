using System.Globalization;

namespace SippBucket.Core.Push.Ssh;

/// <summary>
/// What has arrived on a channel and not yet been read, held to the SSH flow-control window.
/// </summary>
/// <remarks>
/// <para>
/// The other side may have at most the window unacknowledged (RFC 4254 section 5.2), and
/// <see cref="PushChannelStream"/> acknowledges only what a reader has taken, so what is held here
/// can never exceed the window unless the other side broke flow control. When it would, nothing
/// of that delivery is kept, the violation is recorded, and nothing that arrives afterwards is
/// kept either: the memory a channel can cost is the window, whatever the other side does.
/// </para>
/// <para>
/// The logic without the channel, so that a violation, which no well-behaved SSH client can
/// commit, can be tested. Not thread-safe: the stream holds its lock around every call.
/// </para>
/// </remarks>
internal sealed class ReceiveWindow
{
    private readonly Queue<byte[]> _received = new();
    private int _firstOffset;

    /// <summary>Creates an empty window.</summary>
    /// <param name="window">The most that may be held: the window the other side was given.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="window"/> is not positive.</exception>
    public ReceiveWindow(long window)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(window);
        Window = window;
    }

    /// <summary>The most that may be held.</summary>
    public long Window { get; }

    /// <summary>How many bytes have arrived and not been taken.</summary>
    public long Buffered { get; private set; }

    /// <summary>Whether the other side has finished: end-of-file, or the channel closed.</summary>
    public bool Ended { get; private set; }

    /// <summary>What the other side did wrong, once it broke the window; null until then.</summary>
    public string? Violation { get; private set; }

    /// <summary>Keeps what arrived, unless it breaks the window.</summary>
    /// <param name="data">The bytes, which are copied.</param>
    /// <returns>True when a reader waiting on this should look again.</returns>
    public bool Receive(ReadOnlySpan<byte> data)
    {
        if (Ended || Violation is not null || data.IsEmpty)
        {
            return false;
        }

        if (Buffered + data.Length > Window)
        {
            // One interpolated expression: concatenated pieces lose the handler conversion
            // string.Create's provider overload needs, and the call stops compiling.
            Violation = string.Create(
                CultureInfo.InvariantCulture,
                $"The other machine sent {Buffered + data.Length} bytes that had not been acknowledged, and the channel's window allows {Window}. It broke SSH flow control (RFC 4254 section 5.2), so nothing more it sends on this connection is read.");
            _received.Clear();
            _firstOffset = 0;
            Buffered = 0;
            return true;
        }

        _received.Enqueue(data.ToArray());
        Buffered += data.Length;
        return true;
    }

    /// <summary>Records that the other side has finished.</summary>
    /// <returns>True when this changed anything a reader is waiting on.</returns>
    public bool End()
    {
        if (Ended || Violation is not null)
        {
            return false;
        }

        Ended = true;
        return true;
    }

    /// <summary>Copies out as much of what has arrived as fits, oldest first.</summary>
    /// <param name="destination">Where to copy it.</param>
    /// <returns>How many bytes were copied; 0 when nothing is held.</returns>
    public int Take(Span<byte> destination)
    {
        var taken = 0;

        while (taken < destination.Length && _received.TryPeek(out var first))
        {
            var count = Math.Min(first.Length - _firstOffset, destination.Length - taken);

            first.AsSpan(_firstOffset, count).CopyTo(destination[taken..]);
            taken += count;
            _firstOffset += count;

            if (_firstOffset == first.Length)
            {
                _received.Dequeue();
                _firstOffset = 0;
            }
        }

        Buffered -= taken;
        return taken;
    }

    /// <summary>Lets go of everything held.</summary>
    public void Clear()
    {
        _received.Clear();
        _firstOffset = 0;
        Buffered = 0;
    }
}
