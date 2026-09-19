using System.Buffers.Binary;
using Microsoft.DevTunnels.Ssh.Algorithms;
using NSec.Cryptography;
using SippBucket.Core.Crypto;
using SshBuffer = Microsoft.DevTunnels.Ssh.Buffer;

namespace SippBucket.Core.Push.Ssh;

/// <summary>
/// The <c>ssh-ed25519</c> public-key algorithm (RFC 8709) for Microsoft.DevTunnels.Ssh, over
/// NSec, so that the device key is the SSH key (docs/DIRECT-PUSH.md, rule 3).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why SippBucket supplies it.</b> The library does not implement <c>ssh-ed25519</c>, and
/// every device key is Ed25519. Its public-key algorithms are pluggable, so this is the
/// standard algorithm in the standard slot: the key format and the signature format are RFC
/// 8709's, the signature is RFC 8032's Ed25519, computed by libsodium through NSec as every
/// other signature in SippBucket is. Nothing here is a SippBucket construction, and the tests
/// hold it to RFC 8032's vectors and to OpenSSH's own test key and signature.
/// </para>
/// <para>
/// <b>What it signs with the device key</b>, and why that keeps D-52's standing rule, that
/// every signature made with the device key carries its own context label and a signature over
/// one label never verifies as another. SSH's formats are their own labels. The server signs
/// the exchange hash (RFC 4253 section 8), which is SHA-384 of the whole key exchange, 48
/// bytes; the client signs its authentication request (RFC 4252 section 7), which begins with
/// the session identifier's four-byte length, a zero byte first. Every SippBucket format signed
/// with the device key begins with its ASCII context label and is longer than 48 bytes, so
/// neither can pass for the other. The server signs before the caller has proved anything, as
/// every SSH server does; what a stranger obtains is a signature over an exchange hash, which
/// nothing in SippBucket accepts as anything else.
/// </para>
/// <para>
/// <b>It makes no keys.</b> <see cref="GenerateKeyPair"/> refuses: the only private key it
/// signs with is a <see cref="DeviceIdentity"/>, made where every device key is made.
/// </para>
/// </remarks>
public sealed class SshEd25519 : PublicKeyAlgorithm
{
    /// <summary>The algorithm's name, which RFC 8709 also gives its key format.</summary>
    public const string AlgorithmName = "ssh-ed25519";

    /// <summary>The length of a raw Ed25519 public key, in bytes (RFC 8032 section 5.1.5).</summary>
    public const int PublicKeyLength = 32;

    /// <summary>The length of an Ed25519 signature, in bytes (RFC 8032 section 5.1.6).</summary>
    public const int SignatureLength = 64;

    /// <summary>Creates the algorithm.</summary>
    /// <remarks>
    /// The hash name is informational: the library passes it only to algorithms that hash
    /// before they sign, and Ed25519 hashes internally with SHA-512 (RFC 8032 section 5.1).
    /// </remarks>
    public SshEd25519()
        : base(AlgorithmName, AlgorithmName, "SHA-512")
    {
    }

    /// <summary>Creates an empty key, which the library fills from a key blob it received.</summary>
    /// <returns>A key with no public or private half yet.</returns>
    public override IKeyPair CreateKeyPair() => new SshEd25519Key();

    /// <summary>Refuses: SippBucket makes no SSH keys, because the device key is the SSH key.</summary>
    /// <param name="keySizeInBits">Unused.</param>
    /// <returns>Never returns.</returns>
    /// <exception cref="NotSupportedException">Always.</exception>
    /// <remarks>
    /// The library calls this only when an application asks it to make a key, and SippBucket
    /// never does. A key made here would be one no pairing ever exchanged, so no machine would
    /// accept it; refusing keeps every private key SippBucket signs with a device key.
    /// </remarks>
    public override IKeyPair GenerateKeyPair(int? keySizeInBits = null) =>
        throw new NotSupportedException(
            "SippBucket makes no SSH keys: the device key is the SSH key (docs/DIRECT-PUSH.md, rule 3).");

    /// <summary>Creates a signer over a key's private half.</summary>
    /// <param name="keyPair">A device's key, from <see cref="SshEd25519Key.ForDevice"/>.</param>
    /// <returns>The signer.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="keyPair"/> was null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="keyPair"/> is not an <c>ssh-ed25519</c> key, or has no private half.
    /// </exception>
    public override ISigner CreateSigner(IKeyPair keyPair)
    {
        var key = Expect(keyPair);
        var device = key.Device ?? throw new ArgumentException(
            "This ssh-ed25519 key has no private half to sign with.", nameof(keyPair));

        return new Signer(device);
    }

    /// <summary>Creates a verifier over a key's public half.</summary>
    /// <param name="keyPair">The key, with its public half set.</param>
    /// <returns>The verifier.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="keyPair"/> was null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="keyPair"/> is not an <c>ssh-ed25519</c> key, or holds no key yet.
    /// </exception>
    public override IVerifier CreateVerifier(IKeyPair keyPair)
    {
        var key = Expect(keyPair);
        var publicKey = key.PublicHalf ?? throw new ArgumentException(
            "This ssh-ed25519 key holds no public key yet.", nameof(keyPair));

        return new Verifier(publicKey);
    }

    private static SshEd25519Key Expect(IKeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);

        return keyPair as SshEd25519Key ?? throw new ArgumentException(
            $"A {keyPair.KeyAlgorithmName} key cannot be used with {AlgorithmName}.", nameof(keyPair));
    }

    /// <summary>Signs with a device key: the raw 64-byte Ed25519 signature, as RFC 8709 section 6 wraps it.</summary>
    private sealed class Signer : ISigner
    {
        private readonly DeviceIdentity _device;

        public Signer(DeviceIdentity device)
        {
            _device = device;
        }

        public int DigestLength => SignatureLength;

        public void Sign(SshBuffer data, SshBuffer signature)
        {
            // The library sizes the buffer from DigestLength; anything else is a caller's bug.
            if (signature.Count != SignatureLength)
            {
                throw new ArgumentException(
                    $"An ssh-ed25519 signature is {SignatureLength} bytes, and the buffer holds {signature.Count}.",
                    nameof(signature));
            }

            _device.Sign(data.Span).AsSpan().CopyTo(signature.Span);
        }

        public void Dispose()
        {
            // Holds nothing of its own: the device key is its owner's to dispose.
        }
    }

    /// <summary>Verifies against a public key, as libsodium does: strictly (RFC 8032 section 5.1.7).</summary>
    private sealed class Verifier : IVerifier
    {
        private readonly PublicKey _publicKey;

        public Verifier(PublicKey publicKey)
        {
            _publicKey = publicKey;
        }

        public int DigestLength => SignatureLength;

        public bool Verify(SshBuffer data, SshBuffer signature) =>
            signature.Count == SignatureLength &&
            SignatureAlgorithm.Ed25519.Verify(_publicKey, data.Span, signature.Span);

        public void Dispose()
        {
            // A public key holds nothing to release.
        }
    }
}

/// <summary>
/// An <c>ssh-ed25519</c> key: a device's own key, which can sign, or another machine's public
/// key as it arrived in an SSH message.
/// </summary>
/// <remarks>
/// <para>
/// The key blob is RFC 8709 section 4's: <c>string "ssh-ed25519"</c> followed by
/// <c>string key</c>, where the key is the 32-byte public key, each string a four-byte
/// big-endian length and its bytes. That is exactly 51 bytes; anything else, trailing bytes
/// included, is refused, as OpenSSH refuses it.
/// </para>
/// <para>
/// A key made by <see cref="ForDevice"/> borrows the device key and never disposes it: the
/// daemon owns its <see cref="DeviceIdentity"/> for the life of the process, and one SSH key
/// over it serves every session.
/// </para>
/// </remarks>
public sealed class SshEd25519Key : IKeyPair
{
    /// <summary>The length of the name, <c>ssh-ed25519</c>, in the blob.</summary>
    private const int NameLength = 11;

    /// <summary>Where the key starts: after the name's length, the name, and the key's length.</summary>
    private const int KeyOffset = 4 + NameLength + 4;

    /// <summary>The length of an <c>ssh-ed25519</c> key blob, in bytes.</summary>
    public const int BlobLength = KeyOffset + SshEd25519.PublicKeyLength;

    private PublicKey? _publicKey;

    /// <summary>Creates an empty key, for <see cref="SetPublicKeyBytes"/> to fill.</summary>
    internal SshEd25519Key()
    {
    }

    private SshEd25519Key(DeviceIdentity device)
    {
        Device = device;
        _publicKey = device.PublicKey;
    }

    /// <summary>The key's algorithm name: <c>ssh-ed25519</c>.</summary>
    public string KeyAlgorithmName => SshEd25519.AlgorithmName;

    /// <summary>Whether this key can sign: true only for a device's own key.</summary>
    public bool HasPrivateKey => Device is not null;

    /// <summary>A comment, which SSH key files carry; SippBucket never sets or sends one.</summary>
    public string? Comment { get; set; }

    /// <summary>
    /// The device ID this key is, lowercase hexadecimal: the same string <c>peers.json</c> and
    /// pairing use for the machine that holds it.
    /// </summary>
    /// <exception cref="InvalidOperationException">The key holds no public key yet.</exception>
    public string DeviceId => Convert.ToHexStringLower(ExportPublicKey());

    /// <summary>The device key this key signs with, or null for a public key alone.</summary>
    internal DeviceIdentity? Device { get; }

    /// <summary>The public key, or null until one is set.</summary>
    internal PublicKey? PublicHalf => _publicKey;

    private static ReadOnlySpan<byte> Name => "ssh-ed25519"u8;

    /// <summary>The SSH key for this machine's own device key.</summary>
    /// <param name="device">The device identity. Borrowed, never disposed by the key.</param>
    /// <returns>A key that signs with the device key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="device"/> was null.</exception>
    public static SshEd25519Key ForDevice(DeviceIdentity device)
    {
        ArgumentNullException.ThrowIfNull(device);
        return new SshEd25519Key(device);
    }

    /// <summary>The raw 32-byte public key.</summary>
    /// <returns>A copy of the key.</returns>
    /// <exception cref="InvalidOperationException">The key holds no public key yet.</exception>
    public byte[] ExportPublicKey() =>
        (_publicKey ?? throw new InvalidOperationException("This ssh-ed25519 key holds no public key yet."))
            .Export(KeyBlobFormat.RawPublicKey);

    /// <summary>Sets the public key from a key blob the other side sent.</summary>
    /// <param name="keyBytes">The <c>ssh-ed25519</c> key blob.</param>
    /// <exception cref="InvalidOperationException">This is a device's own key, whose public half is fixed.</exception>
    /// <exception cref="ArgumentException">The blob is not a well-formed <c>ssh-ed25519</c> key.</exception>
    public void SetPublicKeyBytes(SshBuffer keyBytes)
    {
        if (Device is not null)
        {
            throw new InvalidOperationException("A device key's public half is the device's, and cannot be replaced.");
        }

        if (!TryDecodeBlob(keyBytes.Span, out var raw))
        {
            throw new ArgumentException(
                $"The key is not a well-formed {SshEd25519.AlgorithmName} key: it must be exactly {BlobLength} bytes, " +
                "its name and then its 32-byte public key.",
                nameof(keyBytes));
        }

        try
        {
            _publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, raw, KeyBlobFormat.RawPublicKey);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("The key is not an Ed25519 public key.", nameof(keyBytes), ex);
        }
    }

    /// <summary>The key blob, as SSH sends it.</summary>
    /// <param name="algorithmName">The algorithm it is sent for; must be <c>ssh-ed25519</c> when given.</param>
    /// <returns>The <see cref="BlobLength"/>-byte blob.</returns>
    /// <exception cref="ArgumentException"><paramref name="algorithmName"/> names another algorithm.</exception>
    /// <exception cref="InvalidOperationException">The key holds no public key yet.</exception>
    public SshBuffer GetPublicKeyBytes(string? algorithmName = null)
    {
        if (algorithmName is not null && !string.Equals(algorithmName, SshEd25519.AlgorithmName, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"An {SshEd25519.AlgorithmName} key cannot be sent as {algorithmName}.", nameof(algorithmName));
        }

        return SshBuffer.From(EncodeBlob(ExportPublicKey()));
    }

    /// <summary>Encodes a raw public key as an <c>ssh-ed25519</c> key blob.</summary>
    /// <param name="rawPublicKey">The 32-byte public key.</param>
    /// <returns>The <see cref="BlobLength"/>-byte blob.</returns>
    /// <exception cref="ArgumentException">The key is not 32 bytes.</exception>
    internal static byte[] EncodeBlob(ReadOnlySpan<byte> rawPublicKey)
    {
        if (rawPublicKey.Length != SshEd25519.PublicKeyLength)
        {
            throw new ArgumentException(
                $"An Ed25519 public key is {SshEd25519.PublicKeyLength} bytes, and this one is {rawPublicKey.Length}.",
                nameof(rawPublicKey));
        }

        var blob = new byte[BlobLength];
        var span = blob.AsSpan();

        BinaryPrimitives.WriteUInt32BigEndian(span, NameLength);
        Name.CopyTo(span[4..]);
        BinaryPrimitives.WriteUInt32BigEndian(span[(4 + NameLength)..], SshEd25519.PublicKeyLength);
        rawPublicKey.CopyTo(span[KeyOffset..]);
        return blob;
    }

    /// <summary>Reads the raw public key from an <c>ssh-ed25519</c> key blob.</summary>
    /// <param name="blob">The blob, as an SSH message carries it.</param>
    /// <param name="rawPublicKey">The 32-byte key when this returns true.</param>
    /// <returns>True when the blob is exactly a well-formed <c>ssh-ed25519</c> key.</returns>
    internal static bool TryDecodeBlob(ReadOnlySpan<byte> blob, out byte[] rawPublicKey)
    {
        rawPublicKey = [];

        if (blob.Length != BlobLength ||
            BinaryPrimitives.ReadUInt32BigEndian(blob) != NameLength ||
            !blob.Slice(4, NameLength).SequenceEqual(Name) ||
            BinaryPrimitives.ReadUInt32BigEndian(blob[(4 + NameLength)..]) != SshEd25519.PublicKeyLength)
        {
            return false;
        }

        rawPublicKey = blob[KeyOffset..].ToArray();
        return true;
    }

    /// <summary>Releases nothing: a device key is its owner's, and a public key holds nothing.</summary>
    public void Dispose()
    {
    }
}
