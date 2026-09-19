using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SippBucket.Core.Crypto;

/// <summary>
/// The ristretto255 prime-order group (RFC 9496), from the libsodium NSec already ships.
/// </summary>
/// <remarks>
/// <para>
/// NSec exposes Ed25519 and X25519 but not ristretto255, and CPace needs the group itself:
/// an element-derivation map from 64 bytes, scalar multiplication that rejects bad
/// encodings, and a uniform scalar. libsodium has had all three since 1.0.18, and the
/// <c>libsodium.dll</c> NSec depends on is 1.0.22, resolved by the host through deps.json.
/// Nothing new is shipped: these are extra entry points into a library already loaded.
/// </para>
/// <para>
/// <c>DllImport</c>, not the source-generated <c>LibraryImport</c>, for the reason
/// <see cref="Platform.SleepBlocker"/> gives: <c>LibraryImport</c> needs
/// <c>AllowUnsafeBlocks</c> on the whole library. Every parameter here is a blittable
/// <c>byte[]</c>, which the marshaller pins for the length of the call and copies nothing.
/// The search path is the assembly directory and the safe directories, never the current
/// directory, for the planted-DLL reason that pins <c>kernel32</c> to System32 there. The
/// assembly directory is the one place libsodium actually sits — beside the assembly, or
/// under the <c>runtimes</c> folder deps.json names — and CA5393's objection to it is
/// answered on the class's suppression below.
/// </para>
/// <para>
/// Semantics, from the libsodium documentation
/// (https://doc.libsodium.org/advanced/point-arithmetic/ristretto): <c>from_hash</c>
/// "maps a 64 bytes vector r (usually the output of a hash function) to a group element";
/// <c>crypto_scalarmult_ristretto255</c> "returns 0 on success, or -1 if q is the identity
/// element"; <c>scalar_random</c> returns a scalar "in the ]0..L[ interval". The
/// documentation does not say what the multiplication does with an encoding that is not a
/// valid element, so <see cref="TryScalarMultiply"/> checks validity itself first.
/// </para>
/// <para>
/// <strong>That check is insurance, not the protection, and was measured to be.</strong>
/// With it removed, the draft's invalid-encoding vector (B.3.11) is still refused: the
/// 1.0.22 multiplication rejects the encoding on its own. It stays because that refusal is
/// behaviour the documentation does not promise, and costs one decode.
/// </para>
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Security",
    "CA5393:Do not use unsafe DllImportSearchPath value",
    Justification =
        "Why it does not apply: CA5393 objects that the assembly directory could hold a " +
        "planted DLL. This library is libsodium, which on every path of this program that " +
        "reaches these entry points NSec has already loaded from that same directory's " +
        "deps.json native path - NSec's own imports carry no search-path attribute, so they " +
        "search it too - and anyone who can write to that directory can replace the " +
        "program's own assemblies, which is a larger problem than this. Measured with the " +
        "flag removed: the test suite and a single-file self-contained publish both still " +
        "resolved libsodium, but in both NSec had loaded it first, so that shows the flag is " +
        "not needed in this program, not that probing alone would find it; the brief requires " +
        "it, and it stays as insurance. What would remove the need: resolving libsodium once, " +
        "by absolute path, through NativeLibrary.SetDllImportResolver, or NSec wrapping " +
        "ristretto255 so these imports are not needed at all.")]
internal static class Ristretto255
{
    /// <summary>Bytes in an encoded group element.</summary>
    public const int ElementSize = 32;

    /// <summary>Bytes in a scalar.</summary>
    public const int ScalarSize = 32;

    /// <summary>Bytes the element-derivation map consumes.</summary>
    public const int HashSize = 64;

    private const string Library = "libsodium";

    private static readonly Lazy<bool> Initialised = new(
        static () => sodium_init() >= 0,
        LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>Maps 64 uniformly random bytes to a group element (RFC 9496 section 4.3.4).</summary>
    /// <param name="uniformBytes">Exactly <see cref="HashSize"/> bytes, normally a hash output.</param>
    /// <returns>The encoded element.</returns>
    /// <exception cref="ArgumentException">The input was the wrong length.</exception>
    /// <exception cref="CryptographicException">libsodium could not be initialised.</exception>
    public static byte[] FromHash(byte[] uniformBytes)
    {
        ArgumentNullException.ThrowIfNull(uniformBytes);
        if (uniformBytes.Length != HashSize)
        {
            throw new ArgumentException(
                $"The element-derivation map takes {HashSize} bytes; got {uniformBytes.Length}.",
                nameof(uniformBytes));
        }

        EnsureInitialised();

        var element = new byte[ElementSize];
        if (crypto_core_ristretto255_from_hash(element, uniformBytes) != 0)
        {
            throw new CryptographicException("libsodium refused to derive a ristretto255 element.");
        }

        return element;
    }

    /// <summary>Whether an encoding is a canonical encoding of a group element.</summary>
    /// <param name="element">The candidate encoding.</param>
    /// <returns>True when it decodes.</returns>
    public static bool IsValidElement(byte[] element)
    {
        ArgumentNullException.ThrowIfNull(element);
        if (element.Length != ElementSize)
        {
            return false;
        }

        EnsureInitialised();
        return crypto_core_ristretto255_is_valid_point(element) == 1;
    }

    /// <summary>Multiplies an encoded element by a scalar.</summary>
    /// <param name="scalar">A little-endian scalar below the group order.</param>
    /// <param name="element">The encoded element.</param>
    /// <param name="product">The encoded product, when this returns true.</param>
    /// <returns>
    /// False when the element does not decode or the product is the identity; the caller
    /// decides what those mean. Both are reported the same way on purpose, because CPace's
    /// <c>scalar_mult_vfy</c> maps both to the neutral element.
    /// </returns>
    /// <exception cref="ArgumentException">The scalar was the wrong length.</exception>
    public static bool TryScalarMultiply(byte[] scalar, byte[] element, out byte[] product)
    {
        ArgumentNullException.ThrowIfNull(scalar);
        ArgumentNullException.ThrowIfNull(element);

        if (scalar.Length != ScalarSize)
        {
            throw new ArgumentException(
                $"A ristretto255 scalar is {ScalarSize} bytes; got {scalar.Length}.",
                nameof(scalar));
        }

        product = new byte[ElementSize];

        if (!IsValidElement(element))
        {
            return false;
        }

        if (crypto_scalarmult_ristretto255(product, scalar, element) != 0)
        {
            CryptographicOperations.ZeroMemory(product);
            return false;
        }

        return true;
    }

    /// <summary>A uniformly random scalar in [1, L-1].</summary>
    /// <returns>The scalar, little-endian.</returns>
    public static byte[] RandomScalar()
    {
        EnsureInitialised();

        var scalar = new byte[ScalarSize];
        crypto_core_ristretto255_scalar_random(scalar);
        return scalar;
    }

    /// <summary>
    /// libsodium's own initialisation, which NSec also performs. Called here as well rather
    /// than trusting that NSec happened to run first: <c>sodium_init</c> is idempotent and
    /// thread-safe, and the random scalar depends on it.
    /// </summary>
    private static void EnsureInitialised()
    {
        if (!Initialised.Value)
        {
            throw new CryptographicException("libsodium could not be initialised.");
        }
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int sodium_init();

    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int crypto_core_ristretto255_from_hash(byte[] p, byte[] r);

    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int crypto_core_ristretto255_is_valid_point(byte[] p);

    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int crypto_scalarmult_ristretto255(byte[] q, byte[] n, byte[] p);

    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void crypto_core_ristretto255_scalar_random(byte[] r);
}
