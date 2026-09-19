using System.Security.Cryptography;
using NSec.Cryptography;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Crypto;

/// <summary>
/// This machine's permanent identity on the network: an Ed25519 key pair whose public half
/// is the device ID other peers know it by.
/// </summary>
/// <remarks>
/// <para>
/// Creating an identity needs no central server and no coordination: the key pair can be
/// made offline, which is what keeps SippBucket peer-to-peer rather than merely self-hosted.
/// The same approach Radicle takes for node identity.
/// </para>
/// <para>
/// <b>One key, two jobs.</b> The sync handshake is Noise XK, which needs an X25519 static key,
/// and a device ID is an Ed25519 public key. Rather than invent a second identity and a way to
/// bind it to the first, the X25519 key is derived from the Ed25519 one with libsodium's
/// <c>crypto_sign_ed25519_sk_to_curve25519</c>, and a peer derives the matching public key
/// from the device ID with <c>crypto_sign_ed25519_pk_to_curve25519</c>. libsodium documents
/// the conversion for exactly this: "Ed25519 keys can be converted to X25519 keys, so that
/// the same key pair can be used both for authenticated encryption (crypto_box) and for
/// signatures (crypto_sign)" (https://doc.libsodium.org/advanced/ed25519-curve25519).
/// </para>
/// <para>
/// The security argument for sharing the key is published: Degabriele, Lehmann, Paterson,
/// Smart and Strefler proved joint security of an elliptic-curve Schnorr signature and an
/// ECDH-based KEM sharing one key pair ("On the Joint Security of Encryption and Signature in
/// EMV", CT-RSA 2012; IACR ePrint 2011/615), and Thormarker extended that to
/// Ed25519 with an X25519-based KEM using an HKDF-Extract-like KDF, in the random oracle
/// model, without assuming domain separation between the two ("On using the same key pair for
/// Ed25519 and an X25519 based KEM", IACR ePrint 2021/509).
/// </para>
/// <para>
/// <b>What that argument does not cover, stated because the alternative is implying it
/// does.</b> Thormarker's result is for a KEM, not for Noise XK; it is supporting evidence
/// about the key reuse, not a proof about this handshake. libsodium itself still advises
/// "If you can afford it, using distinct keys for signing and for encryption is still highly
/// recommended", and Noise section 14 says a static key pair "should not be used outside of
/// Noise". Finally, the two roles fall together: whoever reads <c>device.key</c> can both sign
/// as this machine and complete handshakes as it.
/// </para>
/// <para>
/// <b>What signs with it.</b> Sync's Noise handshake signs nothing. Three things sign, and no
/// two of their messages can be mistaken for each other (D-52's standing rule: every signature
/// SippBucket defines over this key begins with its own ASCII context label):
/// </para>
/// <list type="bullet">
/// <item><description>SSH, because the owner's design makes the device key the SSH key
/// (docs/DIRECT-PUSH.md, rule 3): the exchange hash, 48 bytes of SHA-384, and the
/// authentication request, which begins with a four-byte length whose first byte is
/// zero (RFC 8709, through <c>Push.Ssh.SshEd25519</c>);</description></item>
/// <item><description>snapshot signatures (D-21): a fixed-length message beginning with the
/// ASCII label <c>sippbucket-snapshot-sig-v1</c> (<c>SnapshotSigner</c>);</description></item>
/// <item><description>direct messages: a body beginning with the length-prefixed label
/// <c>sippbucket-dm-v1</c>, whose first byte is zero and whose length field can never be an
/// SSH session identifier's (docs/DIRECT-MESSAGES.md).</description></item>
/// </list>
/// <para>
/// Noise section 14's advice against using a Noise static key outside Noise is answered by the
/// same separation: Noise itself signs nothing here, and none of the three signed forms can be
/// a Noise message or one of the other two.
/// </para>
/// <para>
/// The X25519 private key is derived once, when the identity is created or loaded, and held
/// on the pinned object heap for the identity's lifetime, so the garbage collector never
/// moves it and leaves a copy behind. It is zeroed on dispose and never leaves this class:
/// the handshake asks the identity to perform the exchange (<see cref="IX25519KeyPair"/>)
/// rather than asking it for the key.
/// </para>
/// </remarks>
public sealed class DeviceIdentity : IDisposable, IX25519KeyPair
{
    private static readonly SignatureAlgorithm Algorithm = SignatureAlgorithm.Ed25519;

    private const int SeedSize = 32;

    private readonly Key _key;
    private readonly byte[] _agreementPrivateKey;
    private readonly byte[] _agreementPublicKey;
    private bool _disposed;

    /// <summary>Builds the identity from its 32-byte Ed25519 seed.</summary>
    /// <param name="seed">The seed. Not kept; the caller zeroes it.</param>
    /// <param name="exportPolicy">
    /// Whether the Ed25519 key may be exported once, which only a newly created identity
    /// needs so that <see cref="LoadOrCreate"/> can save it.
    /// </param>
    private DeviceIdentity(ReadOnlySpan<byte> seed, KeyExportPolicies exportPolicy)
    {
        _key = Key.Import(
            Algorithm,
            seed,
            KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = exportPolicy });

        PublicKey = _key.PublicKey;
        var publicKeyBytes = PublicKey.Export(KeyBlobFormat.RawPublicKey);
#pragma warning disable CA1308 // A device ID is an identifier, and lowercase hex is its wire form.
        DeviceId = Convert.ToHexString(publicKeyBytes).ToLowerInvariant();
#pragma warning restore CA1308

        // libsodium's form of an Ed25519 secret key is the seed followed by the public key.
        var secretKey = GC.AllocateArray<byte>(RawX25519.Ed25519SecretKeySize, pinned: true);
        byte[]? agreementPrivateKey = null;
        try
        {
            seed.CopyTo(secretKey);
            publicKeyBytes.CopyTo(secretKey, SeedSize);
            agreementPrivateKey = RawX25519.ConvertEd25519SecretKey(secretKey);
            _agreementPublicKey = RawX25519.PublicKeyOf(agreementPrivateKey);
            _agreementPrivateKey = agreementPrivateKey;
        }
        catch
        {
            if (agreementPrivateKey is not null)
            {
                CryptographicOperations.ZeroMemory(agreementPrivateKey);
            }

            _key.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretKey);
        }
    }

    /// <summary>The public key other peers verify signatures against.</summary>
    public PublicKey PublicKey { get; }

    /// <summary>
    /// The lowercase hexadecimal public key. This is the string a user copies when adding
    /// this machine as a peer.
    /// </summary>
    public string DeviceId { get; }

    /// <summary>A shortened device ID for display.</summary>
    public string ShortId => DeviceId[..12];

    /// <inheritdoc />
    ReadOnlySpan<byte> IX25519KeyPair.PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _agreementPublicKey;
        }
    }

    /// <summary>Creates a brand new identity.</summary>
    /// <returns>A new device identity, not yet saved anywhere.</returns>
    /// <remarks>
    /// The seed is drawn here rather than by NSec's <c>Key.Create</c> because the X25519 key
    /// has to be derived from it, and a key NSec generated could then only be exported once,
    /// which <see cref="LoadOrCreate"/> needs for saving it. Any 32 bytes are a valid Ed25519
    /// seed (RFC 8032 section 5.1.5), so this is the same key NSec would have made.
    /// </remarks>
    public static DeviceIdentity Create()
    {
        var seed = GC.AllocateArray<byte>(SeedSize, pinned: true);
        try
        {
            RandomNumberGenerator.Fill(seed);
            return new DeviceIdentity(seed, KeyExportPolicies.AllowPlaintextArchiving);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <summary>
    /// Loads the identity at <paramref name="path"/>, creating and saving a new one if no
    /// file is there yet.
    /// </summary>
    /// <param name="path">Full path to the private key file.</param>
    /// <returns>The device identity for this machine.</returns>
    /// <exception cref="ArgumentException"><paramref name="path"/> was null or blank.</exception>
    /// <remarks>
    /// A key file in the raw form an older build wrote is rewritten protected here, the first
    /// time it loads (D-51). <see cref="DeviceKeyFile"/> always said the caller did this, and
    /// no caller did, so a key written before the protection existed stayed plaintext for
    /// ever. It is rewritten only after the identity has been built from it, so a file that
    /// is not a key is never dressed up as a protected one. A rewrite that fails leaves the
    /// file readable and plain, which the window and <c>sip doctor</c> then report, and the
    /// next load tries again.
    /// </remarks>
    public static DeviceIdentity LoadOrCreate(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (File.Exists(path))
        {
            // A scanner reading the key file for a moment must not stop the daemon starting
            // (D-69).
            var stored = SharingRetry.Run(() => File.ReadAllBytes(path));

            try
            {
                var raw = DeviceKeyFile.Unprotect(stored);

                try
                {
                    // Both on-disk forms, the DPAPI-wrapped one and the raw 32 bytes older
                    // builds wrote, unwrap to the same seed NSec always imported.
                    var loaded = new DeviceIdentity(raw, KeyExportPolicies.None);

                    if (!DeviceKeyFile.IsProtected(stored))
                    {
                        _ = DeviceKeyFile.UpgradeInPlace(path);
                    }

                    return loaded;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(raw);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(stored);
            }
        }

        var identity = Create();
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var exported = identity._key.Export(KeyBlobFormat.RawPrivateKey);

        try
        {
            var protectedKey = DeviceKeyFile.Protect(exported);
            SharingRetry.Run(() => File.WriteAllBytes(path, protectedKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exported);
        }

        return identity;
    }

    /// <summary>Signs data with this device's private key.</summary>
    /// <param name="data">The bytes to sign.</param>
    /// <returns>The Ed25519 signature.</returns>
    /// <exception cref="ObjectDisposedException">The identity was disposed.</exception>
    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return Algorithm.Sign(_key, data);
    }

    /// <summary>Verifies a signature made by another device.</summary>
    /// <param name="deviceId">The signing device's hexadecimal public key.</param>
    /// <param name="data">The signed bytes.</param>
    /// <param name="signature">The signature to check.</param>
    /// <returns>True when the signature is valid for that device.</returns>
    public static bool Verify(string deviceId, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        if (!TryImportPublicKey(deviceId, out var publicKey))
        {
            return false;
        }

        return Algorithm.Verify(publicKey, data, signature);
    }

    /// <summary>Whether a device ID names the same device as this machine's own.</summary>
    /// <param name="deviceId">The other device's ID, as received or typed.</param>
    /// <param name="ownDeviceId">This machine's own device ID.</param>
    /// <returns>True when they are the same key, in either case.</returns>
    /// <remarks>
    /// A machine is never its own peer. Two machines that present one device ID hold one
    /// copied <c>device.key</c>: a cloned disk, or a restored <c>%APPDATA%</c>. Pairing them
    /// used to succeed silently, each recording a peer under its own ID; the two-machine test
    /// kit found it by giving two sandboxes one key. Pairing checks at both ends, so an older
    /// or altered build at one end is still refused at the other, and <c>sip peer add</c>
    /// checks too.
    /// </remarks>
    public static bool IsSameDevice(string? deviceId, string ownDeviceId) =>
        string.Equals(deviceId, ownDeviceId, StringComparison.OrdinalIgnoreCase);

    /// <summary>Parses a hexadecimal device ID into a public key.</summary>
    /// <param name="deviceId">The hexadecimal public key.</param>
    /// <param name="publicKey">The parsed key when this returns true.</param>
    /// <returns>True when the device ID was well formed.</returns>
    public static bool TryImportPublicKey(string deviceId, out PublicKey publicKey)
    {
        publicKey = null!;
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return false;
        }

        byte[] raw;
        try
        {
            raw = Convert.FromHexString(deviceId);
        }
        catch (FormatException)
        {
            return false;
        }

        if (raw.Length != Algorithm.PublicKeySize)
        {
            return false;
        }

        try
        {
            publicKey = PublicKey.Import(Algorithm, raw, KeyBlobFormat.RawPublicKey);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <inheritdoc />
    bool IX25519KeyPair.TryAgree(ReadOnlySpan<byte> publicKey, out byte[] sharedSecret)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return RawX25519.TryAgree(_agreementPrivateKey, publicKey, out sharedSecret);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _key.Dispose();
        CryptographicOperations.ZeroMemory(_agreementPrivateKey);
        _disposed = true;
    }
}
