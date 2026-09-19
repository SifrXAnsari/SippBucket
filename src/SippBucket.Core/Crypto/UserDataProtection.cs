using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace SippBucket.Core.Crypto;

/// <summary>
/// Windows' per-user data protection (DPAPI), called directly: what ties a secret at rest to
/// this Windows account's logon credential.
/// </summary>
/// <remarks>
/// <para>
/// One caller's honest limits are every caller's, so they are stated once, here, and each
/// caller's own remarks say what they mean for its file. DPAPI protects against other
/// non-administrator accounts on the machine and against a copy of the file taken without the
/// user's Windows password. It does not protect against anything running as this user, an
/// administrator while the user is signed in, or anyone holding the user's password and
/// profile — the same limits <see cref="DeviceKeyFile"/> documents in full, with Microsoft's
/// own words cited.
/// </para>
/// <para>
/// Direct P/Invoke rather than <c>System.Security.Cryptography.ProtectedData</c>, which is a
/// separate NuGet package for a <c>net10.0</c> target, and this project has already lost an
/// hour to a broken package source. Two P/Invokes with no dependency is the smaller risk, and
/// the surface is small enough to read in one sitting.
/// </para>
/// <para>
/// Every use passes its own entropy, a fixed per-purpose label. The entropy separates
/// nothing from software running as the user — it is written in this program — it exists so
/// one purpose's file handed to another purpose's reader fails cleanly rather than being
/// misread.
/// </para>
/// </remarks>
internal static class UserDataProtection
{
    /// <summary>Whether this platform can protect data at rest this way.</summary>
    /// <remarks>
    /// <see cref="OperatingSystem.IsWindows"/>, the one form the platform-compatibility
    /// analyser recognises as a guard.
    /// </remarks>
    public static bool IsAvailable => OperatingSystem.IsWindows();

    /// <summary>Wraps bytes for storage under this user's credential.</summary>
    /// <param name="plaintext">The bytes to protect. The caller zeroes them when they are secret.</param>
    /// <param name="entropy">The purpose's own label.</param>
    /// <returns>The wrapped bytes.</returns>
    /// <exception cref="CryptographicException">Windows could not protect them.</exception>
    [SupportedOSPlatform("windows")]
    public static byte[] Protect(byte[] plaintext, ReadOnlySpan<byte> entropy) =>
        Call(plaintext, entropy, protect: true);

    /// <summary>Unwraps stored bytes.</summary>
    /// <param name="wrapped">The wrapped bytes.</param>
    /// <param name="entropy">The purpose's own label, as it was wrapped with.</param>
    /// <returns>The plaintext. The caller zeroes it when it is secret.</returns>
    /// <exception cref="CryptographicException">
    /// They belong to a different user account or machine, were wrapped for another purpose,
    /// or are damaged.
    /// </exception>
    [SupportedOSPlatform("windows")]
    public static byte[] Unprotect(byte[] wrapped, ReadOnlySpan<byte> entropy) =>
        Call(wrapped, entropy, protect: false);

    [SupportedOSPlatform("windows")]
    private static byte[] Call(byte[] input, ReadOnlySpan<byte> entropySpan, bool protect)
    {
        ArgumentNullException.ThrowIfNull(input);

        // Unmanaged buffers rather than `fixed`, because AllowUnsafeBlocks is off for this
        // library and enabling it project-wide to write two P/Invokes would be a much
        // bigger change than the one being made.
        var entropy = entropySpan.ToArray();

        var inputPtr = IntPtr.Zero;
        var entropyPtr = IntPtr.Zero;
        NativeMethods.DataBlob dataOut = default;

        try
        {
            inputPtr = Marshal.AllocHGlobal(input.Length);
            Marshal.Copy(input, 0, inputPtr, input.Length);

            entropyPtr = Marshal.AllocHGlobal(entropy.Length);
            Marshal.Copy(entropy, 0, entropyPtr, entropy.Length);

            var dataIn = new NativeMethods.DataBlob { Length = input.Length, Data = inputPtr };
            var entropyBlob = new NativeMethods.DataBlob
            {
                Length = entropy.Length,
                Data = entropyPtr,
            };

            var ok = protect
                ? NativeMethods.CryptProtectData(
                    ref dataIn, null, ref entropyBlob, IntPtr.Zero, IntPtr.Zero,
                    NativeMethods.UiForbidden, ref dataOut)
                : NativeMethods.CryptUnprotectData(
                    ref dataIn, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero,
                    NativeMethods.UiForbidden, ref dataOut);

            if (!ok)
            {
                // The Win32 code is carried as an inner exception rather than folded into
                // the message, so a caller can branch on it and a log still reads plainly.
                throw new CryptographicException(
                    protect
                        ? "Windows could not protect this data."
                        : "Windows could not read this protected data. It belongs to a " +
                          "different user account or machine, or to another purpose.",
                    new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
            }

            var result = new byte[dataOut.Length];
            Marshal.Copy(dataOut.Data, result, 0, dataOut.Length);
            return result;
        }
        finally
        {
            Release(ref inputPtr, input.Length);
            Release(ref entropyPtr, entropy.Length);

            if (dataOut.Data != IntPtr.Zero)
            {
                // Zeroed before release. On the unprotect path these bytes ARE the secret,
                // and LocalFree does not clear what it frees.
                Zero(dataOut.Data, dataOut.Length);
                _ = NativeMethods.LocalFree(dataOut.Data);
            }
        }
    }

    private static void Release(ref IntPtr buffer, int length)
    {
        if (buffer == IntPtr.Zero)
        {
            return;
        }

        Zero(buffer, length);
        Marshal.FreeHGlobal(buffer);
        buffer = IntPtr.Zero;
    }

    private static void Zero(IntPtr buffer, int length)
    {
        for (var i = 0; i < length; i++)
        {
            Marshal.WriteByte(buffer, i, 0);
        }
    }

    private static class NativeMethods
    {
        /// <summary>Never show a UI prompt; fail instead. This runs in a background daemon.</summary>
        public const uint UiForbidden = 0x1;

        [StructLayout(LayoutKind.Sequential)]
        internal struct DataBlob
        {
            public int Length;
            public IntPtr Data;
        }

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptProtectData(
            ref DataBlob dataIn,
            string? description,
            ref DataBlob optionalEntropy,
            IntPtr reserved,
            IntPtr promptStruct,
            uint flags,
            ref DataBlob dataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptUnprotectData(
            ref DataBlob dataIn,
            IntPtr description,
            ref DataBlob optionalEntropy,
            IntPtr reserved,
            IntPtr promptStruct,
            uint flags,
            ref DataBlob dataOut);

        [DllImport("kernel32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern IntPtr LocalFree(IntPtr handle);
    }
}
