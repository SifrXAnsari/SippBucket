using System.Runtime.InteropServices;

namespace SippBucket.Core.Crypto;

/// <summary>
/// X25519 as Noise needs it: the raw Diffie-Hellman output, and the conversions that let an
/// Ed25519 device key serve as a Noise static key.
/// </summary>
/// <remarks>
/// <para>
/// This calls libsodium directly rather than going through NSec, which supplies everything
/// else. NSec's key agreement returns a <c>SharedSecret</c> that can only be handed to a key
/// derivation function and never exposes its bytes. That is a sound default and exactly what
/// Noise cannot work with: <c>MixKey</c> feeds the raw DH output into its own chaining key
/// (Noise revision 34, section 5.2), so the bytes are the input. The library is the one NSec
/// already loads, libsodium 1.0.22 from the <c>libsodium</c> package under
/// <c>runtimes/&lt;rid&gt;/native</c>, resolved through deps.json, so nothing new ships.
/// </para>
/// <para>
/// DllImport rather than LibraryImport, for the reason <see cref="Platform.SleepBlocker"/>
/// gives: the generator needs AllowUnsafeBlocks across the whole library. Every parameter is
/// a blittable <c>byte[]</c>, which the marshaller pins rather than copies, so libsodium
/// reads and writes the managed array in place and a secret is never duplicated into a
/// marshalling buffer.
/// </para>
/// </remarks>
internal static class RawX25519
{
    /// <summary>The size of a public key, a private key and a DH output (DHLEN).</summary>
    public const int KeySize = 32;

    /// <summary>The size of the Ed25519 secret key libsodium's conversion reads: seed then public key.</summary>
    public const int Ed25519SecretKeySize = 64;

    // "sodium_init() initializes the library and should be called before any other function
    // provided by Sodium" (https://doc.libsodium.org/usage). NSec calls it too; calling it
    // again is documented as safe and without effect, and relying on NSec having happened to
    // run first would be relying on an accident of ordering.
    private static readonly int InitializeResult = NativeMethods.Initialize();

    /// <summary>Computes the X25519 public key for a private key.</summary>
    /// <param name="privateKey">A 32-byte private key. libsodium clamps it, as RFC 7748 specifies.</param>
    /// <returns>The public key.</returns>
    public static byte[] PublicKeyOf(byte[] privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        RequireSize(privateKey.Length, nameof(privateKey));
        EnsureInitialized();

        var publicKey = new byte[KeySize];
        if (NativeMethods.ScalarMultBase(publicKey, privateKey) != 0)
        {
            throw new InvalidOperationException("libsodium refused to derive an X25519 public key.");
        }

        return publicKey;
    }

    /// <summary>
    /// The Noise <c>DH()</c> function for 25519 (Noise revision 34, section 12.1).
    /// </summary>
    /// <param name="privateKey">This side's 32-byte private key.</param>
    /// <param name="publicKey">The other side's 32-byte public key.</param>
    /// <param name="sharedSecret">
    /// Receives the 32-byte output. The caller owns it and should zero it once it has been
    /// mixed in. It is allocated on the pinned object heap so the garbage collector never
    /// leaves a moved copy of it behind.
    /// </param>
    /// <returns>
    /// False when the output is all zeros, which happens exactly when the public key has small
    /// order. The caller must treat that as a refused key, not as a secret.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>Why an all-zero output is refused.</b> RFC 7748 section 6.1 allows it: "Both MAY
    /// check, without leaking extra information about the value of K, whether K is the
    /// all-zero value and abort if so." Noise section 12.1 allows it too ("implementations are
    /// allowed to detect inputs that produce an all-zeros output and signal an error instead"),
    /// while saying plainly that it discourages the check because it "does not improve
    /// security": in every Noise pattern the other DH results still protect the session.
    /// </para>
    /// <para>
    /// It is refused here for a narrower reason than security. libsodium's
    /// <c>crypto_scalarmult_curve25519</c> performs the check itself and returns -1 on an
    /// all-zero result (src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c,
    /// read at the 1.0.20 release; <c>NoiseVectorTests</c> asserts the shipped 1.0.22 does the
    /// same). Carrying on regardless would mean discarding a return code, which the build
    /// standards count as a swallowed error. RFC 7748 section 7 also warns that designers
    /// "must not assume contributory behaviour", because a small-order point removes this
    /// side's private key from the result entirely, and a peer that sends one is either broken
    /// or probing. Refusing it costs nothing an honest peer will ever send.
    /// </para>
    /// </remarks>
    public static bool TryAgree(byte[] privateKey, ReadOnlySpan<byte> publicKey, out byte[] sharedSecret)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        RequireSize(privateKey.Length, nameof(privateKey));
        RequireSize(publicKey.Length, nameof(publicKey));
        EnsureInitialized();

        var remote = publicKey.ToArray();
        sharedSecret = GC.AllocateArray<byte>(KeySize, pinned: true);

        if (NativeMethods.ScalarMult(sharedSecret, privateKey, remote) == 0)
        {
            return true;
        }

        System.Security.Cryptography.CryptographicOperations.ZeroMemory(sharedSecret);
        return false;
    }

    /// <summary>Converts an Ed25519 public key (a device ID) to the X25519 public key it implies.</summary>
    /// <param name="ed25519PublicKey">The 32-byte Ed25519 public key.</param>
    /// <param name="x25519PublicKey">The converted key when this returns true.</param>
    /// <returns>
    /// False when libsodium rejects the key: not a point on the curve, of small order, or
    /// outside the main subgroup (<c>crypto_sign_ed25519_pk_to_curve25519</c> in
    /// src/libsodium/crypto_sign/ed25519/ref10/keypair.c).
    /// </returns>
    public static bool TryConvertEd25519PublicKey(
        ReadOnlySpan<byte> ed25519PublicKey,
        out byte[] x25519PublicKey)
    {
        x25519PublicKey = [];
        if (ed25519PublicKey.Length != KeySize)
        {
            return false;
        }

        EnsureInitialized();

        var converted = new byte[KeySize];
        if (NativeMethods.Ed25519PublicKeyToCurve25519(converted, ed25519PublicKey.ToArray()) != 0)
        {
            return false;
        }

        x25519PublicKey = converted;
        return true;
    }

    /// <summary>Converts an Ed25519 secret key to the X25519 private key with the same scalar.</summary>
    /// <param name="ed25519SecretKey">
    /// The 64-byte libsodium form: the 32-byte seed followed by the 32-byte public key. The
    /// libsodium documentation says the function "only reads the first 32 bytes (the 32 byte
    /// seed ...) and ignores the 32 remaining bytes", but the documented argument is the
    /// 64-byte key, so that is what is passed.
    /// </param>
    /// <returns>
    /// The X25519 private key on the pinned object heap. The caller owns it and must zero it.
    /// </returns>
    public static byte[] ConvertEd25519SecretKey(byte[] ed25519SecretKey)
    {
        ArgumentNullException.ThrowIfNull(ed25519SecretKey);
        if (ed25519SecretKey.Length != Ed25519SecretKeySize)
        {
            throw new ArgumentException(
                $"An Ed25519 secret key is {Ed25519SecretKeySize} bytes.", nameof(ed25519SecretKey));
        }

        EnsureInitialized();

        var converted = GC.AllocateArray<byte>(KeySize, pinned: true);
        if (NativeMethods.Ed25519SecretKeyToCurve25519(converted, ed25519SecretKey) != 0)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(converted);
            throw new InvalidOperationException("libsodium refused to convert an Ed25519 secret key.");
        }

        return converted;
    }

    private static void RequireSize(int length, string parameterName)
    {
        if (length != KeySize)
        {
            throw new ArgumentException($"An X25519 key is {KeySize} bytes, not {length}.", parameterName);
        }
    }

    private static void EnsureInitialized()
    {
        // 0 is a fresh initialisation and 1 means it had already been done; only -1 is a
        // failure (https://doc.libsodium.org/usage).
        if (InitializeResult < 0)
        {
            throw new InvalidOperationException("libsodium failed to initialise.");
        }
    }

    /// <summary>The five libsodium entry points, and nothing else.</summary>
    /// <remarks>
    /// The search path is the application's own directory and the system's safe directories,
    /// never the current directory. libsodium is resolved first through deps.json, which is
    /// where the host actually finds it; the attribute governs the fallback, and a daemon that
    /// syncs folders is a good delivery vehicle for a planted DLL in whatever directory it
    /// happens to be running from.
    /// </remarks>
    // CA5393 flags AssemblyDirectory because a writable application directory lets someone
    // plant a DLL there. It does not apply here in the way it would to a plug-in host: the
    // directory it names is the one holding SippBucket.Core.dll and the libsodium.dll NSec
    // already loads, so anyone able to plant a library in it can replace those binaries
    // outright, and the installed copy lives under Program Files where only an administrator
    // can write. It is kept because the brief for this change specifies it, so that this
    // import resolves libsodium from the same place NSec's does. What would remove the need:
    // dropping AssemblyDirectory once SafeDirectories alone is known to find libsodium in
    // every layout that ships. Measured 2026-09-18 with SafeDirectories alone: the test host
    // passed every Noise and channel test, and the self-extracting single-file publish that
    // Install.ps1 builds completed a real sync between two device identities. Not run: the
    // framework-dependent SippBucket.exe straight from bin, which resolves native libraries
    // through deps.json exactly as the test host does.
#pragma warning disable CA5393
    private static class NativeMethods
    {
        private const string Library = "libsodium";

        private const DllImportSearchPath SearchPath =
            DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories;

        [DllImport(Library, EntryPoint = "sodium_init", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(SearchPath)]
        public static extern int Initialize();

        [DllImport(Library, EntryPoint = "crypto_scalarmult_curve25519_base", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(SearchPath)]
        public static extern int ScalarMultBase([Out] byte[] q, byte[] n);

        [DllImport(Library, EntryPoint = "crypto_scalarmult_curve25519", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(SearchPath)]
        public static extern int ScalarMult([Out] byte[] q, byte[] n, byte[] p);

        [DllImport(Library, EntryPoint = "crypto_sign_ed25519_pk_to_curve25519", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(SearchPath)]
        public static extern int Ed25519PublicKeyToCurve25519([Out] byte[] x25519PublicKey, byte[] ed25519PublicKey);

        [DllImport(Library, EntryPoint = "crypto_sign_ed25519_sk_to_curve25519", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(SearchPath)]
        public static extern int Ed25519SecretKeyToCurve25519([Out] byte[] x25519SecretKey, byte[] ed25519SecretKey);
    }
#pragma warning restore CA5393
}
