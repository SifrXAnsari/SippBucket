using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using SippBucket.Core.Crypto;
using SippBucket.Core.Protocol.Noise;
using SippBucket.Core.Serialization;

namespace SippBucket.Core.Protocol;

/// <summary>
/// An authenticated, encrypted message channel between two peers.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this is.</b> The handshake is <c>Noise_XK_25519_ChaChaPoly_BLAKE2b</c> from the
/// Noise Protocol Framework, revision 34 (https://noiseprotocol.org/noise.html), and the
/// <see cref="Noise.HandshakeState"/> behind it reproduces the published cacophony, noise-c
/// and snow test vectors for that protocol byte for byte. It replaces a handshake that was
/// modelled on Noise XK but was not Noise.
/// </para>
/// <para>
/// <b>What has not been reviewed.</b> Noise is reviewed; the way SippBucket is mapped onto it
/// is not, by anyone outside this project. That covers the version preamble, the three
/// payload formats, the transport chunking below, and the reuse of the Ed25519 device key as
/// the X25519 static key (see <see cref="DeviceIdentity"/> for that argument and its limits).
/// </para>
/// <para>
/// <b>The exchange.</b> Every step is one <see cref="Framing"/> frame.
/// </para>
/// <list type="number">
/// <item>Initiator to responder, plaintext: <c>"SIPB"</c> and a 16-bit version.</item>
/// <item>Responder to initiator, plaintext: the same, naming the responder's version. Equal
/// versions carry on; otherwise the responder hangs up and the initiator raises
/// <see cref="SipProtocolFault.UnsupportedVersion"/>. Both preambles form the Noise prologue,
/// so altering either breaks the handshake. A protocol 1 build's JSON hello is answered in a
/// form that build reads as "version 2", and refused.</item>
/// <item>XK <c>-&gt; e, es</c>, carrying the repository ID, encrypted to the responder's
/// static key, which the initiator knows in advance from the device ID it dialled.</item>
/// <item>XK <c>&lt;- e, ee</c>, carrying accepted or unknown-repository. Only the holder of the
/// dialled device's key can produce this message, so the answer is authenticated.</item>
/// <item>XK <c>-&gt; s, se</c>, carrying the initiator's Ed25519 device ID. The responder
/// checks it converts to the static key just authenticated, and only then asks whether that
/// device is a known peer.</item>
/// </list>
/// <para>
/// <b>What travels in the clear.</b> The two preambles, the two ephemeral public keys, and
/// the size of every frame. Nothing that identifies a machine or a folder beyond the one
/// connection: no device ID, no repository ID, no static key (D-47). The preamble does mark
/// the traffic as SippBucket's. What Noise says about the limits of the rest, in section 7.8:
/// the initiator's identity is "Encrypted with forward secrecy to an authenticated party",
/// while for the responder "a passive attacker can check candidates for the responder's
/// private key", and an attacker could "replay a previously-recorded message to a new
/// responder and determine whether the two responders are the 'same'". Anyone who already
/// knows a device ID can test whether an address is that device; nobody can learn a device
/// ID by watching.
/// </para>
/// <para>
/// <b>Transport.</b> After <c>Split()</c> each direction has its own cipher state, so the two
/// directions count nonces independently. A Noise message is at most 65,535 bytes and an
/// application message reaches <see cref="Framing.MaximumFrameSize"/>, so each message is
/// sent as a big-endian 32-bit length, a type byte and the body, cut into Noise messages of at
/// most 65,535 bytes. The length is authenticated with the first chunk and checked against
/// <see cref="Framing.MaximumFrameSize"/> before anything is allocated for the rest. A
/// replayed, reordered or dropped chunk fails authentication, because the nonce is implicit
/// in the order of arrival. A connection that ends part way through a message is a
/// <see cref="SipProtocolFault.FrameTruncated"/> fault, never a shorter message; one that
/// ends between messages is a clean close.
/// </para>
/// <para>
/// A channel is not safe for concurrent sends or concurrent receives: chunks of two messages
/// would interleave. One sender and one receiver at a time is fine.
/// </para>
/// </remarks>
public sealed class SecureChannel : IDisposable
{
    // CA2213 does not apply: the stream belongs to whoever connected it. A SecureChannel
    // is layered over a caller-owned TcpClient stream and closing it here would tear down
    // a connection the caller may still be using.
#pragma warning disable CA2213
    private readonly Stream _stream;
#pragma warning restore CA2213
    private readonly CipherState _sender;
    private readonly CipherState _receiver;
    private readonly byte[] _handshakeHash;
    private readonly TimeSpan _stallTimeout;
    private bool _sendBroken;
    private bool _receiveBroken;
    private bool _disposed;

    private SecureChannel(
        Stream stream,
        CipherState sender,
        CipherState receiver,
        byte[] handshakeHash,
        string peerDeviceId,
        TimeSpan stallTimeout)
    {
        _stream = stream;
        _sender = sender;
        _receiver = receiver;
        _handshakeHash = handshakeHash;
        _stallTimeout = stallTimeout;
        PeerDeviceId = peerDeviceId;
    }

    /// <summary>The verified device ID of the peer on the other end, in lowercase hexadecimal.</summary>
    public string PeerDeviceId { get; }

    /// <summary>How long one read or write may make no progress on this channel.</summary>
    public TimeSpan StallTimeout => _stallTimeout;

    /// <summary>The Noise handshake hash <c>h</c>, identical on both ends of one channel.</summary>
    internal ReadOnlySpan<byte> HandshakeHash => _handshakeHash;

    /// <summary>Opens a channel as the side that dialled out.</summary>
    /// <param name="stream">The connected stream.</param>
    /// <param name="identity">This machine's identity.</param>
    /// <param name="repositoryId">The repository being synced.</param>
    /// <param name="expectedPeerDeviceId">
    /// The device ID of the machine being dialled. Required: Noise XK encrypts the very first
    /// message to that device's key, so there is no way to open a channel to "whoever
    /// answers". The parameter stays nullable only so its callers need no edit, and a null is
    /// refused with <see cref="ArgumentNullException"/> rather than accepted.
    /// </param>
    /// <param name="stallTimeout">
    /// How long one read or write may make no progress before the peer is given up on.
    /// Defaults to <see cref="Framing.DefaultStallTimeout"/>. The handshake needs this as
    /// much as the transfer does: a peer that completes the TCP connection and then says
    /// nothing is the cheapest way there is to pin a daemon thread.
    /// </param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <returns>The established channel.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="expectedPeerDeviceId"/> is not a usable device ID, or
    /// <paramref name="repositoryId"/> is empty or too long to send.
    /// </exception>
    /// <exception cref="SipProtocolException">The handshake failed.</exception>
    /// <exception cref="PeerStalledException">The peer stopped responding.</exception>
    public static async Task<SecureChannel> InitiateAsync(
        Stream stream,
        DeviceIdentity identity,
        string repositoryId,
        string? expectedPeerDeviceId,
        TimeSpan? stallTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(expectedPeerDeviceId);

        var responderStatic = ChannelWire.StaticKeyOf(expectedPeerDeviceId, out var responderDeviceId);
        var peerDeviceId = LowercaseHex(responderDeviceId);
        var request = ChannelWire.EncodeRequest(repositoryId);
        var stall = stallTimeout ?? Framing.DefaultStallTimeout;

        var ourPreamble = ChannelWire.Preamble(ChannelWire.ProtocolVersion);
        await WriteHandshakeFrameAsync(stream, ourPreamble, stall, cancellationToken).ConfigureAwait(false);

        var theirPreamble = await ReadHandshakeFrameAsync(stream, stall, cancellationToken).ConfigureAwait(false)
            ?? throw new SipProtocolException(
                SipProtocolFault.FrameTruncated,
                "The peer closed the connection without answering the protocol preamble. A SippBucket " +
                $"build that speaks protocol 1 does exactly that; this build speaks {ChannelWire.ProtocolVersion}, " +
                "and both machines need the same version.");

        if (!ChannelWire.TryReadPreamble(theirPreamble, out var theirVersion))
        {
            throw new SipProtocolException(
                SipProtocolFault.MalformedMessage,
                "The peer answered the protocol preamble with something that is not a preamble.");
        }

        if (theirVersion != ChannelWire.ProtocolVersion)
        {
            throw VersionMismatch(theirVersion);
        }

        using var handshake = new HandshakeState(
            HandshakePattern.XK,
            initiator: true,
            ChannelWire.Prologue(ourPreamble, theirPreamble),
            identity,
            responderStatic);

        await WriteHandshakeFrameAsync(stream, handshake.WriteMessage(request), stall, cancellationToken)
            .ConfigureAwait(false);

        var second = await ReadHandshakeFrameAsync(stream, stall, cancellationToken).ConfigureAwait(false)
            ?? throw new SipProtocolException(
                SipProtocolFault.FrameTruncated,
                $"The peer hung up after the first handshake message. Only device {Short(peerDeviceId)} " +
                "can read that message, so the machine at this address is most likely a different one.");

        byte[] answer;
        try
        {
            answer = handshake.ReadMessage(second);
        }
        catch (SipProtocolException ex) when (ex.Fault == SipProtocolFault.AuthenticationFailed)
        {
            throw new SipProtocolException(
                SipProtocolFault.WrongDevice,
                $"The peer did not prove it holds the key of device {Short(peerDeviceId)}: its handshake " +
                "reply could only have been made by that device, and it did not decrypt.",
                ex);
        }

        if (!ChannelWire.ReadAnswer(answer))
        {
            throw new SipProtocolException(
                SipProtocolFault.UnknownRepository,
                $"Device {Short(peerDeviceId)} does not serve this repository.");
        }

        await WriteHandshakeFrameAsync(
                stream,
                handshake.WriteMessage(ChannelWire.EncodeIdentity(Convert.FromHexString(identity.DeviceId))),
                stall,
                cancellationToken)
            .ConfigureAwait(false);

        var (initiatorCipher, responderCipher) = handshake.TakeCipherStates();
        return new SecureChannel(
            stream, initiatorCipher, responderCipher, handshake.GetHandshakeHash(), peerDeviceId, stall);
    }

    /// <summary>Opens a channel as the side that accepted the connection.</summary>
    /// <param name="stream">The accepted stream.</param>
    /// <param name="identity">This machine's identity.</param>
    /// <param name="repositoryId">The repository this daemon serves.</param>
    /// <param name="isPeerAllowed">
    /// Called with the caller's device ID once the handshake has proved the caller holds that
    /// device's key, which is after the third message. Return false to refuse an unknown
    /// machine.
    /// </param>
    /// <param name="stallTimeout">
    /// How long one read or write may make no progress before the caller is given up on.
    /// Defaults to <see cref="Framing.DefaultStallTimeout"/>. This side needs it more than
    /// the dialling side does, because anyone who can reach the port can open a connection
    /// and then go quiet.
    /// </param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <returns>The established channel.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="SipProtocolException">The handshake failed.</exception>
    /// <exception cref="PeerStalledException">The peer stopped responding.</exception>
    public static async Task<SecureChannel> AcceptAsync(
        Stream stream,
        DeviceIdentity identity,
        string repositoryId,
        Func<string, bool> isPeerAllowed,
        TimeSpan? stallTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(repositoryId);
        ArgumentNullException.ThrowIfNull(isPeerAllowed);

        var (channel, _) = await AcceptAsync(
            stream,
            identity,
            requested => string.Equals(requested, repositoryId, StringComparison.OrdinalIgnoreCase)
                ? isPeerAllowed
                : null,
            static (allowed, deviceId) => allowed(deviceId),
            stallTimeout,
            cancellationToken).ConfigureAwait(false);

        return channel;
    }

    /// <summary>
    /// Opens a channel as the side that accepted the connection, for whichever of several
    /// repositories the caller asks for.
    /// </summary>
    /// <typeparam name="TServed">What this side serves a repository as.</typeparam>
    /// <param name="stream">The accepted stream.</param>
    /// <param name="identity">This machine's identity.</param>
    /// <param name="resolveRepository">
    /// Called with the repository ID the caller asked for in the first message. Returns what
    /// serves it, or null when this side serves no such repository.
    /// </param>
    /// <param name="isPeerAllowed">
    /// Called, as in the single-repository overload, with what <paramref name="resolveRepository"/>
    /// returned and the caller's proven device ID, after the third message.
    /// </param>
    /// <param name="stallTimeout">How long one read or write may make no progress.</param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <returns>The established channel, and what serves the repository it was opened for.</returns>
    /// <exception cref="SipProtocolException">The handshake failed.</exception>
    /// <exception cref="PeerStalledException">The peer stopped responding.</exception>
    /// <remarks>
    /// This is how one listener serves every folder on a machine (D-40). The repository ID
    /// arrives inside the first message, encrypted to this device's key, so only a caller
    /// that already knows this device ID can ask at all. A repository this side does not serve
    /// is refused in the second message with the same answer whatever the reason: never
    /// served here, stopped being served, or anything else. A caller learns whether this
    /// machine serves a repository only by already knowing that repository's ID, exactly as
    /// it could with one listener per folder.
    /// </remarks>
    internal static async Task<(SecureChannel Channel, TServed Served)> AcceptAsync<TServed>(
        Stream stream,
        DeviceIdentity identity,
        Func<string, TServed?> resolveRepository,
        Func<TServed, string, bool> isPeerAllowed,
        TimeSpan? stallTimeout,
        CancellationToken cancellationToken)
        where TServed : class
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(resolveRepository);
        ArgumentNullException.ThrowIfNull(isPeerAllowed);

        var stall = stallTimeout ?? Framing.DefaultStallTimeout;

        var theirPreamble = await ReadHandshakeFrameAsync(stream, stall, cancellationToken).ConfigureAwait(false)
            ?? throw new SipProtocolException(
                SipProtocolFault.FrameTruncated, "The peer closed the connection during the handshake.");

        var ourPreamble = await AnswerPreambleAsync(stream, theirPreamble, stall, cancellationToken)
            .ConfigureAwait(false);

        using var handshake = new HandshakeState(
            HandshakePattern.XK,
            initiator: false,
            ChannelWire.Prologue(theirPreamble, ourPreamble),
            identity,
            ReadOnlySpan<byte>.Empty);

        var first = await ReadHandshakeFrameAsync(stream, stall, cancellationToken).ConfigureAwait(false)
            ?? throw new SipProtocolException(
                SipProtocolFault.FrameTruncated, "The peer closed the connection during the handshake.");

        byte[] request;
        try
        {
            request = handshake.ReadMessage(first);
        }
        catch (SipProtocolException ex) when (ex.Fault == SipProtocolFault.AuthenticationFailed)
        {
            throw new SipProtocolException(
                SipProtocolFault.AuthenticationFailed,
                "The caller's first handshake message did not decrypt. It was encrypted to a different " +
                "device's key, so the caller dialled the wrong machine, or it was altered in transit.",
                ex);
        }

        var served = resolveRepository(ChannelWire.ReadRequest(request));
        var accepted = served is not null;

        // The refusal goes back inside the second message, where only this device could have
        // written it, instead of as a hang-up the caller would have to guess the reason for.
        await WriteHandshakeFrameAsync(stream, handshake.WriteMessage(ChannelWire.EncodeAnswer(accepted)), stall, cancellationToken)
            .ConfigureAwait(false);

        if (served is null)
        {
            throw new SipProtocolException(
                SipProtocolFault.UnknownRepository,
                "The peer asked for a repository this daemon does not serve.");
        }

        var third = await ReadHandshakeFrameAsync(stream, stall, cancellationToken).ConfigureAwait(false)
            ?? throw new SipProtocolException(
                SipProtocolFault.FrameTruncated, "The peer closed the connection during the handshake.");

        byte[] claim;
        try
        {
            claim = handshake.ReadMessage(third);
        }
        catch (SipProtocolException ex) when (ex.Fault == SipProtocolFault.AuthenticationFailed)
        {
            throw new SipProtocolException(
                SipProtocolFault.AuthenticationFailed,
                "The caller's final handshake message did not decrypt: it did not prove it holds the " +
                "static key it sent, or the message was altered in transit.",
                ex);
        }

        var deviceId = VerifiedDeviceId(ChannelWire.ReadIdentity(claim), handshake.RemoteStaticPublicKey);

        if (!isPeerAllowed(served, deviceId))
        {
            throw new SipProtocolException(
                SipProtocolFault.UnknownDevice,
                $"Device {Short(deviceId)} is not a known peer of this repository.");
        }

        var (initiatorCipher, responderCipher) = handshake.TakeCipherStates();
        return (
            new SecureChannel(stream, responderCipher, initiatorCipher, handshake.GetHandshakeHash(), deviceId, stall),
            served);
    }

    /// <summary>Sends one encrypted message whose body is <paramref name="payload"/> as JSON.</summary>
    /// <typeparam name="T">The payload type.</typeparam>
    /// <param name="type">Which message this is.</param>
    /// <param name="payload">The payload to serialize.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <returns>A task that completes when the message is on the wire.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="payload"/> is a byte array or byte memory. Those bind to this overload
    /// rather than the binary one, and would be base64-encoded into JSON without complaint,
    /// which is the inflation D-45 exists to remove. Pass them as
    /// <see cref="ReadOnlyMemory{T}"/> instead.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The channel was disposed.</exception>
    public async Task SendAsync<T>(
        MessageType type,
        T payload,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (payload is byte[] or Memory<byte> or ArraySegment<byte>)
        {
            throw new ArgumentException(
                "Binary bodies go through SendAsync(MessageType, ReadOnlyMemory<byte>); this overload " +
                "would base64-encode them into JSON.",
                nameof(payload));
        }

        // Typed as ReadOnlyMemory on purpose: json.AsMemory() is a Memory<byte>, which binds
        // straight back to this overload and is refused by the check above.
        var json = new ReadOnlyMemory<byte>(JsonSerializer.SerializeToUtf8Bytes(payload, SipJson.Canonical));
        await SendAsync(type, json, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Sends one encrypted message whose body is <paramref name="body"/> exactly.</summary>
    /// <param name="type">Which message this is.</param>
    /// <param name="body">
    /// The body, sent as it is. The receiver reads it from <see cref="ReceivedMessage.Body"/>.
    /// Pass it typed as <see cref="ReadOnlyMemory{T}"/>: a <c>byte[]</c> or a
    /// <see cref="Memory{T}"/> binds to <see cref="SendAsync{T}"/> instead, which refuses it.
    /// </param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <returns>A task that completes when the message is on the wire.</returns>
    /// <exception cref="SipProtocolException">The message is larger than <see cref="Framing.MaximumFrameSize"/>.</exception>
    /// <exception cref="ObjectDisposedException">The channel was disposed.</exception>
    /// <exception cref="InvalidOperationException">An earlier send on this channel did not complete.</exception>
    public async Task SendAsync(
        MessageType type,
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ThrowIfBroken(_sendBroken, "send");

        // The type byte counts toward the limit, as it always did.
        var total = body.Length + 1L;
        if (total > Framing.MaximumFrameSize)
        {
            throw new SipProtocolException(
                SipProtocolFault.FrameTooLarge,
                $"Refusing to send a {total} byte message; the limit is {Framing.MaximumFrameSize}.");
        }

        // Until the last chunk is out, the peer is part way through a message and a retry on
        // this channel would put it out of step. Cleared only on success.
        _sendBroken = true;

        var plaintext = new byte[ChannelWire.TransportPlaintextCapacity];
        var sealedChunk = new byte[ChannelWire.TransportFrameSize];

        BinaryPrimitives.WriteUInt32BigEndian(plaintext, (uint)total);
        plaintext[ChannelWire.MessageLengthSize] = (byte)type;
        var used = ChannelWire.MessageLengthSize + 1;
        var sent = 0;

        do
        {
            var take = Math.Min(body.Length - sent, plaintext.Length - used);
            body.Span.Slice(sent, take).CopyTo(plaintext.AsSpan(used));
            used += take;
            sent += take;

            var sealedLength = used + CipherState.TagLength;
            _sender.EncryptWithAd(ReadOnlySpan<byte>.Empty, plaintext.AsSpan(0, used), sealedChunk.AsSpan(0, sealedLength));

            await Framing.WriteFrameAsync(_stream, sealedChunk.AsMemory(0, sealedLength), _stallTimeout, cancellationToken)
                .ConfigureAwait(false);

            used = 0;
        }
        while (sent < body.Length);

        _sendBroken = false;
    }

    /// <summary>Receives one encrypted message.</summary>
    /// <param name="stallTimeout">
    /// How long to allow with no progress, overriding this channel's default. Pass a longer
    /// value when waiting for a peer that is legitimately busy between messages rather than
    /// part way through one — see <see cref="SippBucket.Core.Sync.SyncTuning.IdleTimeout"/>.
    /// </param>
    /// <param name="cancellationToken">Cancels the receive.</param>
    /// <returns>
    /// The message type and its body, or null when the peer closed the connection between
    /// messages. A close part way through a message is a
    /// <see cref="SipProtocolFault.FrameTruncated"/> fault, not a clean close.
    /// </returns>
    /// <exception cref="ObjectDisposedException">The channel was disposed.</exception>
    /// <exception cref="SipProtocolException">The message failed authentication or was malformed.</exception>
    /// <exception cref="InvalidOperationException">An earlier receive on this channel did not complete.</exception>
    public async Task<ReceivedMessage?> ReceiveAsync(
        TimeSpan? stallTimeout = null,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ThrowIfBroken(_receiveBroken, "receive");

        var deadline = stallTimeout ?? _stallTimeout;

        // Set before the first read, not after it: a read that is cancelled or stalls part way
        // through a frame has consumed bytes nobody can put back, and Framing cannot say
        // whether it did. Cleared on a clean close and on a complete message.
        _receiveBroken = true;

        var first = await ReadTransportFrameAsync(deadline, cancellationToken).ConfigureAwait(false);
        if (first is null)
        {
            _receiveBroken = false;
            return null;
        }

        // A length, a type byte and a tag is the smallest legal first chunk.
        if (first.Length < ChannelWire.MessageLengthSize + 1 + CipherState.TagLength)
        {
            throw new SipProtocolException(SipProtocolFault.MalformedMessage, "The peer sent a frame too short to be a message.");
        }

        var head = new byte[first.Length - CipherState.TagLength];
        _receiver.DecryptWithAd(ReadOnlySpan<byte>.Empty, first, head);

        // Authenticated, and checked BEFORE the allocation below: this is the line that
        // decides what one message is allowed to cost, now that no single frame carries it.
        var total = BinaryPrimitives.ReadUInt32BigEndian(head);
        if (total == 0 || total > Framing.MaximumFrameSize)
        {
            throw new SipProtocolException(
                total == 0 ? SipProtocolFault.MalformedMessage : SipProtocolFault.FrameTooLarge,
                $"The peer announced a {total} byte message; the limit here is {Framing.MaximumFrameSize}.");
        }

        var inFirst = (int)Math.Min(total, ChannelWire.TransportPlaintextCapacity - ChannelWire.MessageLengthSize);
        if (head.Length != ChannelWire.MessageLengthSize + inFirst)
        {
            throw ChunkOutOfShape();
        }

        var message = new byte[total];
        head.AsSpan(ChannelWire.MessageLengthSize).CopyTo(message);
        var filled = inFirst;

        while (filled < message.Length)
        {
            var chunk = await ReadTransportFrameAsync(deadline, cancellationToken).ConfigureAwait(false)
                ?? throw new SipProtocolException(
                    SipProtocolFault.FrameTruncated, "The connection ended part way through a message.");

            var expected = Math.Min(message.Length - filled, ChannelWire.TransportPlaintextCapacity);
            if (chunk.Length != expected + CipherState.TagLength)
            {
                throw ChunkOutOfShape();
            }

            _receiver.DecryptWithAd(ReadOnlySpan<byte>.Empty, chunk, message.AsSpan(filled, expected));
            filled += expected;
        }

        _receiveBroken = false;

        // AsMemory slices without copying; the body can be large.
        return new ReceivedMessage((MessageType)message[0], message.AsMemory(1));
    }

    /// <summary>Deserializes a received body.</summary>
    /// <typeparam name="T">The expected payload type.</typeparam>
    /// <param name="message">The received message.</param>
    /// <returns>The payload.</returns>
    /// <exception cref="SipProtocolException">The body was not valid.</exception>
    public static T Decode<T>(ReceivedMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        try
        {
            return JsonSerializer.Deserialize<T>(message.Body.Span, SipJson.Canonical)
                ?? throw new SipProtocolException(
                    SipProtocolFault.MalformedMessage,
                    $"The peer sent an empty {typeof(T).Name}.");
        }
        catch (JsonException ex)
        {
            throw new SipProtocolException(
                SipProtocolFault.MalformedMessage,
                $"The peer sent a malformed {typeof(T).Name}.", ex);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _sender.Dispose();
        _receiver.Dispose();
        _disposed = true;
    }

    /// <summary>
    /// Answers a caller's first frame with this build's preamble, or refuses it.
    /// </summary>
    /// <returns>The preamble sent, which becomes half of the prologue.</returns>
    private static async Task<byte[]> AnswerPreambleAsync(
        Stream stream,
        byte[] theirs,
        TimeSpan stall,
        CancellationToken cancellationToken)
    {
        if (ChannelWire.TryReadPreamble(theirs, out var theirVersion))
        {
            // Sent whatever their version: to a peer on this version it is the go-ahead, and to
            // any other it is the refusal naming ours. Answering before hanging up is what lets
            // the other side say "version" instead of "connection closed".
            var ours = ChannelWire.Preamble(ChannelWire.ProtocolVersion);
            await WriteHandshakeFrameAsync(stream, ours, stall, cancellationToken).ConfigureAwait(false);

            return theirVersion == ChannelWire.ProtocolVersion ? ours : throw VersionMismatch(theirVersion);
        }

        if (ChannelWire.TryReadLegacyHello(theirs, out var legacyVersion))
        {
            await WriteHandshakeFrameAsync(stream, ChannelWire.LegacyRefusal.ToArray(), stall, cancellationToken)
                .ConfigureAwait(false);

            throw new SipProtocolException(
                SipProtocolFault.UnsupportedVersion,
                $"The peer speaks protocol version {legacyVersion}, which opened with a plaintext hello; " +
                $"this build speaks {ChannelWire.ProtocolVersion}. Both machines need the same SippBucket version.");
        }

        throw new SipProtocolException(
            SipProtocolFault.MalformedMessage,
            "The caller's first frame is neither a SippBucket protocol preamble nor an older build's hello.");
    }

    /// <summary>
    /// Checks that the device ID a caller named belongs to the static key it authenticated.
    /// </summary>
    private static string VerifiedDeviceId(byte[] claimedDeviceId, ReadOnlySpan<byte> authenticatedStatic)
    {
        // Until this comparison the device ID is only a claim. Noise proved the caller holds
        // the X25519 key it sent in message 3; the device ID is what the peer list is keyed
        // on, and it must convert to that same key or the caller is naming someone else.
        if (!RawX25519.TryConvertEd25519PublicKey(claimedDeviceId, out var implied)
            || !CryptographicOperations.FixedTimeEquals(implied, authenticatedStatic))
        {
            throw new SipProtocolException(
                SipProtocolFault.IdentityMismatch,
                "The caller authenticated with one key and named a device ID that does not belong to it.");
        }

        return LowercaseHex(claimedDeviceId);
    }

#pragma warning disable CA1308 // A device ID is an identifier, and lowercase hex is its wire form.
    private static string LowercaseHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
#pragma warning restore CA1308

    private static string Short(string deviceId) => deviceId[..Math.Min(12, deviceId.Length)];

    private static SipProtocolException VersionMismatch(int theirVersion) =>
        new(
            SipProtocolFault.UnsupportedVersion,
            $"The peer speaks protocol version {theirVersion}; this build speaks {ChannelWire.ProtocolVersion}. " +
            "Both machines need the same SippBucket version.");

    private static SipProtocolException ChunkOutOfShape() =>
        new(SipProtocolFault.MalformedMessage, "A message arrived cut into chunks of the wrong size.");

    private static void ThrowIfBroken(bool broken, string what)
    {
        if (broken)
        {
            throw new InvalidOperationException(
                $"An earlier {what} on this channel did not complete, so the two ends may be out of " +
                "step and the channel cannot be used again.");
        }
    }

    private static Task WriteHandshakeFrameAsync(
        Stream stream,
        byte[] frame,
        TimeSpan stallTimeout,
        CancellationToken cancellationToken) =>
        Framing.WriteFrameAsync(stream, frame, stallTimeout, cancellationToken);

    /// <summary>Reads one frame before the peer has been authenticated.</summary>
    private static Task<byte[]?> ReadHandshakeFrameAsync(
        Stream stream,
        TimeSpan stallTimeout,
        CancellationToken cancellationToken) =>
        // Framing.HandshakeFrameSize, not MaximumFrameSize. Nothing has been authenticated
        // yet, so this read is reachable by anyone who can open a TCP connection to the
        // port — and the only thing standing between four bytes of length prefix and an
        // arbitrary allocation is the number passed here. Every read until the third
        // handshake message has been processed comes through this method.
        Framing.ReadFrameAsync(stream, Framing.HandshakeFrameSize, stallTimeout, cancellationToken);

    private Task<byte[]?> ReadTransportFrameAsync(TimeSpan stallTimeout, CancellationToken cancellationToken) =>
        // One Noise message per frame, so no frame can be larger than one. The message-level
        // ceiling is applied to the authenticated length in ReceiveAsync.
        Framing.ReadFrameAsync(_stream, ChannelWire.TransportFrameSize, stallTimeout, cancellationToken);
}

/// <summary>One decrypted message: its type and its body.</summary>
/// <param name="Type">Which message this is.</param>
/// <param name="Body">
/// The body: JSON when it was sent with <see cref="SecureChannel.SendAsync{T}"/>, and the
/// sender's bytes exactly when it was sent with the binary overload. Exposed as a memory
/// rather than an array so that callers cannot mutate the decrypted buffer behind the
/// channel's back.
/// </param>
public sealed record ReceivedMessage(MessageType Type, ReadOnlyMemory<byte> Body);
