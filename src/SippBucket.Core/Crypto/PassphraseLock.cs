using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace SippBucket.Core.Crypto;

/// <summary>
/// Wraps a repository key with a passphrase, using Argon2id.
/// </summary>
/// <remarks>
/// <para>
/// Every parameter here was measured on this stack rather than copied from a
/// recommendation, and the measurement mattered: <strong>both of RFC 9106's recommended
/// parameter sets specify p=4, and both are rejected outright.</strong> libsodium's
/// <c>argon2id13</c> implements parallelism 1 only, and NSec surfaces that as an
/// <see cref="ArgumentException"/>. A design that had quoted the RFC verbatim would have
/// thrown on first run. See <c>RESEARCH-argon2-measured.md</c>.
/// </para>
/// <para>
/// What this protects, stated narrowly because the marketing version of it is false:
/// another account on the same machine reading <c>.sip/config.json</c>, and that folder
/// being copied to a backup, a USB stick or a cloud drive. What it does not protect: a
/// machine that is running and logged in, because the key is deliberately held in memory so
/// the daemon can keep syncing. BitLocker is already on for every volume on this hardware
/// and already covers the stolen-powered-off-machine case that people actually picture, so
/// this is a narrower addition than its name suggests.
/// </para>
/// <para>
/// No separate verifier is stored. A wrong passphrase is caught by the AEAD tag failing,
/// which was verified rather than assumed — and a stored hash of the passphrase would only
/// be one more thing to attack offline.
/// </para>
/// </remarks>
public static class PassphraseLock
{
    private static readonly AeadAlgorithm Aead = AeadAlgorithm.XChaCha20Poly1305;

    /// <summary>Salt length. Not a choice: libsodium fixes it at exactly this.</summary>
    /// <remarks><c>MinSaltSize == MaxSaltSize == 16</c>, measured.</remarks>
    public const int SaltSize = 16;

    /// <summary>The only degree of parallelism this stack accepts.</summary>
    public const int RequiredParallelism = 1;

    /// <summary>Associated data binding a wrapped key to its purpose.</summary>
    private static ReadOnlySpan<byte> WrapDomain => "sippbucket-keywrap-v1"u8;

    /// <summary>
    /// Argon2id cost to use for a new lock on this machine.
    /// </summary>
    /// <returns>Parameters that will not exhaust this machine's memory.</returns>
    /// <remarks>
    /// <para>
    /// 256 MiB with four passes measures 603 ms on the slower of the two target machines.
    /// That is the intended cost: this is an interactive unlock typed once per session, not
    /// server-side password storage, and the threat is an attacker with the config file
    /// guessing offline. OWASP's 19 MiB floor runs in 23 ms, which is an order of magnitude
    /// too cheap for a key that opens every document in the store.
    /// </para>
    /// <para>
    /// It steps down rather than insisting, because this desktop has been observed with as
    /// little as 1.07 GB free and a hard 256 MiB would turn "unlock my documents" into an
    /// out-of-memory crash on a bad day. The chosen values are stored with the wrapped key,
    /// so stepping down on a constrained machine does not stop the repository opening later
    /// on a roomier one.
    /// </para>
    /// </remarks>
    public static Argon2Parameters RecommendedParameters()
    {
        // Never take more than an eighth of what the runtime believes exists. The memory is
        // touched for the whole derivation, so this is a real working set, not a reservation.
        var available = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        var ceilingKib = available > 0 ? available / 8 / 1024 : long.MaxValue;

        long[] preference = [256 * 1024, 128 * 1024, 64 * 1024, 19 * 1024];

        foreach (var memoryKib in preference)
        {
            if (memoryKib <= ceilingKib)
            {
                return new Argon2Parameters
                {
                    DegreeOfParallelism = RequiredParallelism,
                    MemorySize = memoryKib,
                    NumberOfPasses = memoryKib >= 256 * 1024 ? 4 : 3,
                };
            }
        }

        // OWASP's documented minimum. Below this the derivation is not worth doing, so it is
        // the floor rather than another step down.
        return new Argon2Parameters
        {
            DegreeOfParallelism = RequiredParallelism,
            MemorySize = 19 * 1024,
            NumberOfPasses = 2,
        };
    }

    /// <summary>Wraps a repository key so only the passphrase recovers it.</summary>
    /// <param name="repositoryKey">The raw repository key.</param>
    /// <param name="passphrase">The passphrase to lock it with.</param>
    /// <param name="parameters">Argon2id cost, or null for <see cref="RecommendedParameters"/>.</param>
    /// <returns>Everything needed to unwrap it again, except the passphrase.</returns>
    /// <exception cref="ArgumentException">The passphrase was empty.</exception>
    public static WrappedKey Wrap(
        ReadOnlySpan<byte> repositoryKey,
        string passphrase,
        Argon2Parameters? parameters = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);

        var cost = parameters ?? RecommendedParameters();
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var nonce = RandomNumberGenerator.GetBytes(Aead.NonceSize);

        using var wrappingKey = Derive(passphrase, salt, cost);
        var ciphertext = Aead.Encrypt(wrappingKey, nonce, WrapDomain, repositoryKey);

        return new WrappedKey
        {
            Salt = Convert.ToBase64String(salt),
            Nonce = Convert.ToBase64String(nonce),
            Ciphertext = Convert.ToBase64String(ciphertext),
            MemoryKib = cost.MemorySize,
            Passes = cost.NumberOfPasses,
            Parallelism = cost.DegreeOfParallelism,
        };
    }

    /// <summary>Recovers a repository key from its wrapped form.</summary>
    /// <param name="wrapped">The stored wrapping.</param>
    /// <param name="passphrase">The passphrase to try.</param>
    /// <returns>The raw repository key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="wrapped"/> was null.</exception>
    /// <exception cref="ArgumentException">The passphrase was empty.</exception>
    /// <exception cref="WrongPassphraseException">The passphrase did not open it.</exception>
    /// <exception cref="InvalidKeyWrapException">The stored wrapping was not usable.</exception>
    public static byte[] Unwrap(WrappedKey wrapped, string passphrase)
    {
        ArgumentNullException.ThrowIfNull(wrapped);
        ArgumentException.ThrowIfNullOrEmpty(passphrase);

        var salt = DecodeOrThrow(wrapped.Salt, nameof(wrapped.Salt));
        var nonce = DecodeOrThrow(wrapped.Nonce, nameof(wrapped.Nonce));
        var ciphertext = DecodeOrThrow(wrapped.Ciphertext, nameof(wrapped.Ciphertext));

        if (salt.Length != SaltSize)
        {
            throw new InvalidKeyWrapException(
                $"The stored salt is {salt.Length} bytes; this algorithm requires exactly " +
                $"{SaltSize}.");
        }

        if (nonce.Length != Aead.NonceSize)
        {
            throw new InvalidKeyWrapException(
                $"The stored nonce is {nonce.Length} bytes; {Aead.NonceSize} were expected.");
        }

        if (ciphertext.Length <= Aead.TagSize)
        {
            throw new InvalidKeyWrapException("The stored wrapped key is too short to be valid.");
        }

        var cost = ParametersOrThrow(wrapped);

        using var wrappingKey = Derive(passphrase, salt, cost);

        var plaintext = new byte[ciphertext.Length - Aead.TagSize];
        if (!Aead.Decrypt(wrappingKey, nonce, WrapDomain, ciphertext, plaintext))
        {
            // The tag failing IS the wrong-passphrase signal. Verified, not assumed.
            throw new WrongPassphraseException();
        }

        return plaintext;
    }

    /// <summary>Checks whether a passphrase opens a wrapping, without throwing.</summary>
    /// <param name="wrapped">The stored wrapping.</param>
    /// <param name="passphrase">The passphrase to try.</param>
    /// <returns>True when the passphrase is correct.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="wrapped"/> was null.</exception>
    public static bool Verify(WrappedKey wrapped, string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase))
        {
            return false;
        }

        try
        {
            CryptographicOperations.ZeroMemory(Unwrap(wrapped, passphrase));
            return true;
        }
        catch (WrongPassphraseException)
        {
            return false;
        }
    }

    private static Key Derive(string passphrase, byte[] salt, Argon2Parameters cost)
    {
        var algorithm = PasswordBasedKeyDerivationAlgorithm.Argon2id(in cost);

        return algorithm.DeriveKey(
            Encoding.UTF8.GetBytes(passphrase),
            salt,
            Aead,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
    }

    private static Argon2Parameters ParametersOrThrow(WrappedKey wrapped)
    {
        if (wrapped.Parallelism != RequiredParallelism)
        {
            // Worth its own message rather than a generic failure: this is exactly the trap
            // that a recommendation copied from RFC 9106 walks into, and a repository
            // carrying p=4 was written by something that never tried to open it.
            throw new InvalidKeyWrapException(
                $"The stored wrapping asks for parallelism {wrapped.Parallelism}; this " +
                $"implementation supports {RequiredParallelism} only.");
        }

        if (wrapped.MemoryKib <= 0 || wrapped.Passes <= 0)
        {
            throw new InvalidKeyWrapException("The stored Argon2id cost is not valid.");
        }

        return new Argon2Parameters
        {
            DegreeOfParallelism = wrapped.Parallelism,
            MemorySize = wrapped.MemoryKib,
            NumberOfPasses = wrapped.Passes,
        };
    }

    private static byte[] DecodeOrThrow(string value, string what)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new InvalidKeyWrapException($"The stored {what} is missing.");
        }

        var decoded = new byte[(value.Length / 4 * 3) + 3];
        if (!Convert.TryFromBase64String(value, decoded, out var written))
        {
            throw new InvalidKeyWrapException($"The stored {what} is not valid base64.");
        }

        return decoded[..written];
    }
}
