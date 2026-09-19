using System.Buffers.Binary;

namespace SippBucket.Core.Protocol;

/// <summary>
/// Length-prefixed framing over a stream: a 4-byte big-endian length followed by that many
/// bytes.
/// </summary>
/// <remarks>
/// <para>
/// A maximum frame size is enforced on read. Without one, a peer could announce a four
/// gigabyte frame and have the other side allocate for it before a single byte of payload
/// arrived.
/// </para>
/// <para>
/// Every read and every write carries a stall deadline. This is the single choke point for
/// the whole network path — the handshake, every request and every block goes through here
/// — so putting the deadline in this class rather than at each call site is what makes
/// "no read without a deadline" a property of the code instead of a habit.
/// </para>
/// </remarks>
public static class Framing
{
    /// <summary>Largest frame this build will send or accept, in bytes.</summary>
    /// <remarks>
    /// <para>
    /// Comfortably above the 16 MiB maximum block plus its authentication tag and envelope.
    /// This is the ceiling for an <em>authenticated</em> peer; see
    /// <see cref="HandshakeFrameSize"/> for what an unauthenticated one gets.
    /// </para>
    /// <para>
    /// Since protocol 2, <see cref="SecureChannel"/> no longer puts a whole message in one
    /// frame: it cuts each message into Noise messages of at most 65,535 bytes. This is then
    /// the ceiling on the reassembled message, checked against its authenticated length
    /// before anything is allocated for it.
    /// </para>
    /// </remarks>
    public const int MaximumFrameSize = 32 * 1024 * 1024;

    /// <summary>Largest frame accepted before the peer has proved who it is.</summary>
    /// <remarks>
    /// <para>
    /// Applying the 32 MiB ceiling from the first byte meant four attacker bytes bought
    /// 33.5 MB of daemon memory — roughly 8,000,000:1 amplification, with no credential, no
    /// valid device ID and no knowledge of the repository. The documents were never at risk;
    /// the daemon's memory was.
    /// </para>
    /// <para>
    /// What made it urgent is that it was hidden behind obscurity. Nobody knows the port is
    /// there — and local discovery exists precisely to announce it, every thirty seconds, on
    /// every network the laptop ever joins. Shipping discovery without this first would have
    /// removed the only protection the port had.
    /// </para>
    /// <para>
    /// 8 KiB against a handshake whose largest message is under a hundred bytes, and whose
    /// largest frame from an older build is its JSON hello of a few hundred: well over twenty
    /// times the headroom actually needed, which is the right trade when the cost of being
    /// wrong in the generous direction is a failed connection and the cost of being wrong in
    /// the tight direction is a protocol that cannot evolve.
    /// </para>
    /// </remarks>
    public const int HandshakeFrameSize = 8 * 1024;

    /// <summary>How long one read or write may make no progress before the peer is given up on.</summary>
    /// <remarks>
    /// This is a stall deadline, not a transfer deadline: the clock restarts on every byte
    /// that arrives, so a slow link is tolerated indefinitely while a dead one is not. A
    /// whole-transfer deadline would have to be sized for the worst plausible link, which
    /// puts it somewhere around ten minutes — long enough that a user would call it a hang.
    /// </remarks>
    public static TimeSpan DefaultStallTimeout { get; } = TimeSpan.FromSeconds(30);

    private const int LengthPrefixSize = 4;

    /// <summary>Writes one frame.</summary>
    /// <param name="stream">The stream to write to.</param>
    /// <param name="payload">The frame body.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>A task that completes when the frame has been written and flushed.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="stream"/> was null.</exception>
    /// <exception cref="SipProtocolException">The payload was too large to send.</exception>
    /// <exception cref="PeerStalledException">The peer stopped accepting data.</exception>
    public static Task WriteFrameAsync(
        Stream stream,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default) =>
        WriteFrameAsync(stream, payload, DefaultStallTimeout, cancellationToken);

    /// <summary>Writes one frame, giving up if the peer stops accepting data.</summary>
    /// <param name="stream">The stream to write to.</param>
    /// <param name="payload">The frame body.</param>
    /// <param name="stallTimeout">How long a single write may make no progress.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>A task that completes when the frame has been written and flushed.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="stream"/> was null.</exception>
    /// <exception cref="SipProtocolException">The payload was too large to send.</exception>
    /// <exception cref="PeerStalledException">The peer stopped accepting data.</exception>
    public static async Task WriteFrameAsync(
        Stream stream,
        ReadOnlyMemory<byte> payload,
        TimeSpan stallTimeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (payload.Length > MaximumFrameSize)
        {
            throw new SipProtocolException(
                $"Refusing to send a {payload.Length} byte frame; the limit is {MaximumFrameSize}.");
        }

        var prefix = new byte[LengthPrefixSize];
        BinaryPrimitives.WriteInt32BigEndian(prefix, payload.Length);

        // A write stalls just as readily as a read: once the peer stops draining its
        // receive window the send blocks, and a suspended laptop stops draining it.
        using var deadline = new StallDeadline(stallTimeout, cancellationToken);

        await deadline.RunAsync(
            token => stream.WriteAsync(prefix, token), "writing a frame header").ConfigureAwait(false);
        await deadline.RunAsync(
            token => stream.WriteAsync(payload, token), "writing a frame body").ConfigureAwait(false);
        await deadline.RunAsync(
            token => new ValueTask(stream.FlushAsync(token)), "flushing a frame").ConfigureAwait(false);
    }

    /// <summary>Reads one frame.</summary>
    /// <param name="stream">The stream to read from.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The frame body, or null when the peer closed the connection cleanly.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="stream"/> was null.</exception>
    /// <exception cref="SipProtocolException">The frame header was not valid.</exception>
    /// <exception cref="PeerStalledException">The peer stopped sending data.</exception>
    public static Task<byte[]?> ReadFrameAsync(
        Stream stream,
        CancellationToken cancellationToken = default) =>
        ReadFrameAsync(stream, MaximumFrameSize, DefaultStallTimeout, cancellationToken);

    /// <summary>Reads one frame, giving up if the peer stops sending or asks for too much.</summary>
    /// <param name="stream">The stream to read from.</param>
    /// <param name="maximumFrameSize">
    /// The largest frame to accept. Callers pass <see cref="HandshakeFrameSize"/> until the
    /// peer has authenticated and <see cref="MaximumFrameSize"/> afterwards — the limit is a
    /// parameter rather than a constant precisely because the answer differs before and
    /// after you know who you are talking to.
    /// </param>
    /// <param name="stallTimeout">How long a single read may make no progress.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The frame body, or null when the peer closed the connection cleanly.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="stream"/> was null.</exception>
    /// <exception cref="SipProtocolException">The frame header was not valid.</exception>
    /// <exception cref="PeerStalledException">The peer stopped sending data.</exception>
    public static async Task<byte[]?> ReadFrameAsync(
        Stream stream,
        int maximumFrameSize,
        TimeSpan stallTimeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumFrameSize);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumFrameSize, MaximumFrameSize);

        // One deadline for the whole frame, reset on every byte that arrives. A peer that
        // dribbles is fine; a peer that stops is not.
        using var deadline = new StallDeadline(stallTimeout, cancellationToken);

        var prefix = new byte[LengthPrefixSize];
        if (!await ReadExactlyOrEofAsync(stream, prefix, deadline).ConfigureAwait(false))
        {
            return null;
        }

        // Checked BEFORE the allocation, which is the entire point: the length prefix is
        // four bytes of attacker-controlled input and this is the line that decides what
        // they are allowed to cost.
        var length = BinaryPrimitives.ReadInt32BigEndian(prefix);
        if (length < 0 || length > maximumFrameSize)
        {
            throw new SipProtocolException(
                SipProtocolFault.FrameTooLarge,
                $"Peer announced a {length} byte frame; the limit here is {maximumFrameSize}.");
        }

        var payload = new byte[length];
        if (length == 0)
        {
            return payload;
        }

        if (!await ReadExactlyOrEofAsync(stream, payload, deadline).ConfigureAwait(false))
        {
            throw new SipProtocolException(
                SipProtocolFault.FrameTruncated,
                "The connection ended part way through a frame.");
        }

        return payload;
    }

    /// <summary>
    /// Fills <paramref name="buffer"/>. Returns false only when the stream ended before any
    /// byte arrived, which is a clean close rather than a truncation.
    /// </summary>
    private static async Task<bool> ReadExactlyOrEofAsync(
        Stream stream,
        Memory<byte> buffer,
        StallDeadline deadline)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var slice = buffer[total..];
            var read = await deadline
                .RunAsync(token => stream.ReadAsync(slice, token), "reading a frame")
                .ConfigureAwait(false);

            if (read == 0)
            {
                return total != 0
                    ? throw new SipProtocolException(
                        SipProtocolFault.FrameTruncated,
                        "The connection ended part way through a frame.")
                    : false;
            }

            total += read;
        }

        return true;
    }

    /// <summary>
    /// Runs stream operations under a deadline that restarts whenever one of them completes.
    /// </summary>
    /// <remarks>
    /// One linked source is created per frame rather than per read. A 16 MiB block arrives
    /// in a few thousand reads, and a cancellation source per read would be several thousand
    /// timer registrations for a single block — measurable cost for no extra safety, since
    /// resetting one timer expresses exactly the same thing.
    /// </remarks>
    private sealed class StallDeadline : IDisposable
    {
        private readonly CancellationTokenSource _linked;
        private readonly CancellationToken _caller;
        private readonly TimeSpan _timeout;

        public StallDeadline(TimeSpan timeout, CancellationToken caller)
        {
            if (timeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(timeout), timeout, "A stall timeout must be positive.");
            }

            _timeout = timeout;
            _caller = caller;
            _linked = CancellationTokenSource.CreateLinkedTokenSource(caller);
        }

        public async ValueTask<T> RunAsync<T>(
            Func<CancellationToken, ValueTask<T>> operation,
            string what)
        {
            _linked.CancelAfter(_timeout);

            try
            {
                return await operation(_linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException ex) when (!_caller.IsCancellationRequested)
            {
                throw Stalled(what, ex);
            }
        }

        public async ValueTask RunAsync(
            Func<CancellationToken, ValueTask> operation,
            string what)
        {
            _linked.CancelAfter(_timeout);

            try
            {
                await operation(_linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException ex) when (!_caller.IsCancellationRequested)
            {
                throw Stalled(what, ex);
            }
        }

        public void Dispose() => _linked.Dispose();

        private PeerStalledException Stalled(string what, Exception cause) =>
            new($"The peer made no progress for {_timeout.TotalSeconds:0.#}s while {what}.", cause);
    }
}

