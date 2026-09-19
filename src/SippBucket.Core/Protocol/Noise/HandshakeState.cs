using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using SippBucket.Core.Crypto;

namespace SippBucket.Core.Protocol.Noise;

/// <summary>
/// The Noise <c>HandshakeState</c> for <c>Noise_*_25519_ChaChaPoly_BLAKE2b</c> (Noise revision
/// 34, section 5.3; https://noiseprotocol.org/noise.html).
/// </summary>
/// <remarks>
/// <para>
/// Written token by token from section 5.3 rather than specialised to XK, so that the same
/// code that carries SippBucket's handshake is the code checked against the published
/// cacophony, noise-c and snow vectors for both XK and NN.
/// </para>
/// <para>
/// <b>Failure.</b> Section 5.3: if an error is signalled "then the handshake has failed and
/// the HandshakeState is deleted". A failed instance refuses every further call, so a caller
/// cannot carry on from a state that has half-absorbed a bad message.
/// </para>
/// <para>
/// <b>The test seam.</b> Section 5.3's <c>"e"</c> token calls <c>GENERATE_KEYPAIR()</c>. A test
/// vector fixes the ephemeral keys, so the constructor takes the key generator as an optional
/// argument. It is internal, and production code never passes it: the default draws from the
/// operating system's CSPRNG through <see cref="X25519KeyPair.Generate"/>.
/// </para>
/// </remarks>
internal sealed class HandshakeState : IDisposable
{
    /// <summary>The DH, cipher and hash sections of the protocol name.</summary>
    public const string CipherSuite = "25519_ChaChaPoly_BLAKE2b";

    /// <summary>
    /// Section 3: "All Noise messages are less than or equal to 65535 bytes in length."
    /// </summary>
    public const int MaximumMessageLength = 65535;

    private readonly HandshakePattern _pattern;
    private readonly bool _initiator;
    private readonly SymmetricState _symmetric;
    private readonly IX25519KeyPair? _static;
    private readonly Func<X25519KeyPair> _generateKeyPair;
    private X25519KeyPair? _ephemeral;
    private byte[]? _remoteStatic;
    private byte[]? _remoteEphemeral;
    private CipherState? _initiatorCipher;
    private CipherState? _responderCipher;
    private int _next;
    private bool _failed;
    private bool _disposed;

    /// <summary>
    /// <c>Initialize(handshake_pattern, initiator, prologue, s, e, rs, re)</c>, with <c>e</c> and
    /// <c>re</c> always empty.
    /// </summary>
    /// <param name="pattern">The handshake pattern.</param>
    /// <param name="initiator">True for the side that sends the first message.</param>
    /// <param name="prologue">
    /// Context both sides must agree on (section 6). "If both parties do not provide identical
    /// prologue data, the handshake will fail due to a decryption error."
    /// </param>
    /// <param name="localStatic">This side's static key pair, or null if the pattern has none.</param>
    /// <param name="remoteStatic">The peer's static public key if a pre-message carries it, else empty.</param>
    /// <param name="generateKeyPair">
    /// <c>GENERATE_KEYPAIR()</c>. Null for the CSPRNG; only tests pass anything else.
    /// </param>
    public HandshakeState(
        HandshakePattern pattern,
        bool initiator,
        ReadOnlySpan<byte> prologue,
        IX25519KeyPair? localStatic,
        ReadOnlySpan<byte> remoteStatic,
        Func<X25519KeyPair>? generateKeyPair = null)
    {
        ArgumentNullException.ThrowIfNull(pattern);

        if (!remoteStatic.IsEmpty && remoteStatic.Length != RawX25519.KeySize)
        {
            throw new ArgumentException($"A static public key is {RawX25519.KeySize} bytes.", nameof(remoteStatic));
        }

        _pattern = pattern;
        _initiator = initiator;
        _static = localStatic;
        _remoteStatic = remoteStatic.IsEmpty ? null : remoteStatic.ToArray();
        _generateKeyPair = generateKeyPair ?? X25519KeyPair.Generate;

        // Section 8: "Noise_" then the pattern, DH, cipher and hash names, underscore-separated.
        _symmetric = new SymmetricState(Encoding.ASCII.GetBytes($"Noise_{pattern.Name}_{CipherSuite}"));
        _symmetric.MixHash(prologue);

        // "If both initiator and responder have pre-messages, the initiator's public keys are
        // hashed first."
        MixPreMessage(pattern.InitiatorPreMessage, fromInitiator: true);
        MixPreMessage(pattern.ResponderPreMessage, fromInitiator: false);
    }

    /// <summary>True once every message pattern has been processed.</summary>
    public bool IsComplete => _next == _pattern.Messages.Count;

    /// <summary>
    /// The peer's static public key: supplied up front, or learned from an <c>s</c> token.
    /// Empty until one of those has happened.
    /// </summary>
    public ReadOnlySpan<byte> RemoteStaticPublicKey => _remoteStatic;

    private bool IsMyTurn => (_next % 2 == 0) == _initiator;

    /// <summary><c>GetHandshakeHash()</c>, available once the handshake is complete.</summary>
    /// <returns>The 64-byte handshake hash <c>h</c>.</returns>
    public byte[] GetHandshakeHash()
    {
        ThrowIfUnusable();
        return IsComplete
            ? _symmetric.GetHandshakeHash()
            : throw new InvalidOperationException("The handshake hash is only defined once the handshake is complete.");
    }

    /// <summary>
    /// Hands over the two transport cipher states produced by <c>Split()</c>. The caller owns
    /// them from here on; this instance no longer disposes them.
    /// </summary>
    /// <returns><c>c1</c> for initiator-to-responder messages and <c>c2</c> for the reverse.</returns>
    public (CipherState Initiator, CipherState Responder) TakeCipherStates()
    {
        ThrowIfUnusable();

        if (_initiatorCipher is null || _responderCipher is null)
        {
            throw new InvalidOperationException("The handshake has not finished, or its cipher states were already taken.");
        }

        var result = (_initiatorCipher, _responderCipher);
        _initiatorCipher = null;
        _responderCipher = null;
        return result;
    }

    /// <summary><c>WriteMessage(payload, message_buffer)</c>.</summary>
    /// <param name="payload">The payload to carry.</param>
    /// <returns>The handshake message.</returns>
    public byte[] WriteMessage(ReadOnlySpan<byte> payload)
    {
        ThrowIfUnusable();
        if (IsComplete || !IsMyTurn)
        {
            throw new InvalidOperationException("It is not this side's turn to write a handshake message.");
        }

        var succeeded = false;
        try
        {
            var buffer = new ArrayBufferWriter<byte>();

            foreach (var token in _pattern.Messages[_next])
            {
                switch (token)
                {
                    case NoiseToken.E:
                        if (_ephemeral is not null)
                        {
                            throw new InvalidOperationException("The local ephemeral key is already set.");
                        }

                        _ephemeral = _generateKeyPair();
                        buffer.Write(_ephemeral.PublicKey);
                        _symmetric.MixHash(_ephemeral.PublicKey);
                        break;

                    case NoiseToken.S:
                        buffer.Write(_symmetric.EncryptAndHash(RequireStatic().PublicKey));
                        break;

                    default:
                        MixDh(token);
                        break;
                }
            }

            buffer.Write(_symmetric.EncryptAndHash(payload));

            if (buffer.WrittenCount > MaximumMessageLength)
            {
                throw new ArgumentException(
                    $"A Noise message is at most {MaximumMessageLength} bytes; this payload would make {buffer.WrittenCount}.",
                    nameof(payload));
            }

            Advance();
            succeeded = true;
            return buffer.WrittenSpan.ToArray();
        }
        finally
        {
            _failed |= !succeeded;
        }
    }

    /// <summary><c>ReadMessage(message, payload_buffer)</c>.</summary>
    /// <param name="message">The handshake message received.</param>
    /// <returns>The payload it carried.</returns>
    /// <exception cref="SipProtocolException">
    /// <see cref="SipProtocolFault.MalformedMessage"/> for a message that is too short, too long
    /// or carries a small-order public key; <see cref="SipProtocolFault.AuthenticationFailed"/>
    /// when an encrypted part does not decrypt.
    /// </exception>
    public byte[] ReadMessage(ReadOnlySpan<byte> message)
    {
        ThrowIfUnusable();
        if (IsComplete || IsMyTurn)
        {
            throw new InvalidOperationException("It is not this side's turn to read a handshake message.");
        }

        var succeeded = false;
        try
        {
            if (message.Length > MaximumMessageLength)
            {
                throw Malformed($"A Noise message is at most {MaximumMessageLength} bytes; this one is {message.Length}.");
            }

            var offset = 0;
            foreach (var token in _pattern.Messages[_next])
            {
                switch (token)
                {
                    case NoiseToken.E:
                        if (_remoteEphemeral is not null)
                        {
                            throw new InvalidOperationException("The remote ephemeral key is already set.");
                        }

                        _remoteEphemeral = Take(message, ref offset, RawX25519.KeySize).ToArray();
                        _symmetric.MixHash(_remoteEphemeral);
                        break;

                    case NoiseToken.S:
                        if (_remoteStatic is not null)
                        {
                            throw new InvalidOperationException("The remote static key is already set.");
                        }

                        var length = _symmetric.HasKey ? RawX25519.KeySize + CipherState.TagLength : RawX25519.KeySize;
                        _remoteStatic = _symmetric.DecryptAndHash(Take(message, ref offset, length));
                        break;

                    default:
                        MixDh(token);
                        break;
                }
            }

            var payload = _symmetric.DecryptAndHash(message[offset..]);

            Advance();
            succeeded = true;
            return payload;
        }
        finally
        {
            _failed |= !succeeded;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _symmetric.Dispose();
        _ephemeral?.Dispose();
        _initiatorCipher?.Dispose();
        _responderCipher?.Dispose();
        _disposed = true;
    }

    private static ReadOnlySpan<byte> Take(ReadOnlySpan<byte> message, ref int offset, int length)
    {
        if (message.Length - offset < length)
        {
            throw Malformed("A Noise handshake message ended before all of its keys had arrived.");
        }

        var slice = message.Slice(offset, length);
        offset += length;
        return slice;
    }

    private static SipProtocolException Malformed(string message) =>
        new(SipProtocolFault.MalformedMessage, message);

    private void MixPreMessage(IReadOnlyList<NoiseToken> tokens, bool fromInitiator)
    {
        foreach (var token in tokens)
        {
            if (token != NoiseToken.S)
            {
                throw new NotSupportedException($"Pre-message token {token} is not used by any pattern this build defines.");
            }

            // The pre-message's public key is ours when we are the side it describes.
            var ours = fromInitiator == _initiator;
            _symmetric.MixHash(ours
                ? RequireStatic().PublicKey
                : _remoteStatic ?? throw new ArgumentException("The pattern needs the peer's static public key in advance."));
        }
    }

    /// <summary>Section 5.3's rules for <c>ee</c>, <c>es</c>, <c>se</c> and <c>ss</c>.</summary>
    private void MixDh(NoiseToken token)
    {
        var (local, remote) = token switch
        {
            NoiseToken.Ee => ((IX25519KeyPair?)_ephemeral, _remoteEphemeral),
            NoiseToken.Es => _initiator ? (_ephemeral, _remoteStatic) : (_static, _remoteEphemeral),
            NoiseToken.Se => _initiator ? (_static, _remoteEphemeral) : (_ephemeral, _remoteStatic),
            NoiseToken.Ss => (_static, _remoteStatic),
            _ => throw new InvalidOperationException($"{token} is not a DH token."),
        };

        if (local is null || remote is null)
        {
            throw new InvalidOperationException($"The {token} token needs a key this side does not have.");
        }

        if (!local.TryAgree(remote, out var sharedSecret))
        {
            // See RawX25519.TryAgree for why an all-zero output is refused rather than mixed in.
            throw Malformed(
                "The peer sent a public key of small order, which would make an X25519 result " +
                "that does not depend on this side's private key.");
        }

        try
        {
            _symmetric.MixKey(sharedSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    private void Advance()
    {
        _next++;

        if (IsComplete)
        {
            (_initiatorCipher, _responderCipher) = _symmetric.Split();
        }
    }

    private IX25519KeyPair RequireStatic() =>
        _static ?? throw new InvalidOperationException("The pattern needs a local static key and none was given.");

    private void ThrowIfUnusable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_failed)
        {
            throw new InvalidOperationException(
                "This handshake has already failed. Noise requires a failed HandshakeState to be discarded.");
        }
    }
}
