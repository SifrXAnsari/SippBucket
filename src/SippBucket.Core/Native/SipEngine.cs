using System.Runtime.InteropServices;
using System.Text;

namespace SippBucket.Core.Native;

/// <summary>
/// SippBucket's native engine, <c>sipengine.dll</c>: self-contained computation written in
/// C++ (<c>sample/src/sipengine</c>), behind a small C ABI.
/// </summary>
/// <remarks>
/// <para>
/// The engine does pure computation over buffers the caller owns: it allocates nothing,
/// keeps no state, never calls back, and reads no file, registry key or network. Its C ABI
/// is <c>sipengine.h</c>, and these imports mirror it: every parameter blittable, errors as
/// return codes, no <c>SetLastError</c>, the same rules <c>sipnative</c> measured.
/// </para>
/// <para>
/// <c>DllImport</c>, not the source-generated <c>LibraryImport</c>, for the reason
/// <see cref="Platform.SleepBlocker"/> gives: <c>LibraryImport</c> needs
/// <c>AllowUnsafeBlocks</c> on the whole library. Every array is blittable, which the
/// marshaller pins for the length of the call and copies nothing of.
/// </para>
/// <para>
/// <c>DllImport</c> binds lazily, so a missing DLL would otherwise surface in the middle of a
/// transfer. <see cref="Problem"/> is the start-up probe that turns it into an immediate,
/// legible failure; SippBucket.exe runs it before anything else, as it does for libsodium.
/// </para>
/// </remarks>
public static class SipEngine
{
    /// <summary>The library's name, as the imports use it.</summary>
    public const string LibraryName = "sipengine";

    /// <summary>The ABI version this build was written against: <c>SIPE_ABI_VERSION</c> in sipengine.h.</summary>
    public const uint AbiVersion = 2;

    /// <summary>The engine's success code, <c>SIPE_OK</c>.</summary>
    internal const int Ok = 0;

    /// <summary><c>SIPE_ERR_CAPACITY</c>: the buffer was too small, and the length it needs came back.</summary>
    internal const int ErrorCapacity = -2;

    /// <summary><c>SIPE_ERR_UNKNOWN</c>: a number that names nothing.</summary>
    internal const int ErrorUnknown = -3;

    /// <summary><c>SIPE_ERR_UNAVAILABLE</c>: Windows would not give what was asked for.</summary>
    internal const int ErrorUnavailable = -4;

    /// <summary><c>SIPE_ERR_MALFORMED</c>: the input is not in the format the export reads.</summary>
    internal const int ErrorMalformed = -5;

    /// <summary><c>SIPE_SMBIOS_FIELDS</c>: the version, the ending, and three places for each of seven values.</summary>
    internal const int SmbiosFieldCount = 23;

    /// <summary><c>SIPE_RANDOMNESS_SAMPLE_BYTES</c>: the most of a file the randomness test reads.</summary>
    internal const int RandomnessSampleBytes = 65536;

    /// <summary><c>SIPE_RANDOMNESS_FIELDS</c>: the verdict, the entropy, the statistic and the bytes judged.</summary>
    private const int RandomnessFieldCount = 4;

    /// <summary>Judges whether a sample of a file's content looks random, as encrypted data does.</summary>
    /// <param name="sample">The file's first bytes.</param>
    /// <param name="length">How many of them to read.</param>
    /// <returns>
    /// The verdict (<c>SIPE_RANDOMNESS_*</c>), the entropy in thousandths of a bit per byte, the
    /// chi-square statistic in hundredths, and how many bytes were judged.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="sample"/> was null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="length"/> was negative or longer than the sample.</exception>
    /// <exception cref="InvalidOperationException">The engine refused its arguments, which would be a defect here.</exception>
    internal static (uint Verdict, uint EntropyMilli, uint ChiCenti, uint Judged) Randomness(byte[] sample, int length)
    {
        ArgumentNullException.ThrowIfNull(sample);
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, sample.Length);

        var fields = new uint[RandomnessFieldCount];
        var code = NativeMethods.Randomness(length == 0 ? null : sample, checked((nuint)length), fields, checked((nuint)fields.Length));
        if (code != Ok)
        {
            throw new InvalidOperationException($"The engine refused a randomness test with code {code}.");
        }

        return (fields[0], fields[1], fields[2], fields[3]);
    }

    /// <summary>Whether the engine loads and speaks this build's ABI, and if not, what to do.</summary>
    /// <returns>Null when it does; otherwise a message naming the file and the folder.</returns>
    /// <remarks>
    /// Asked through the imports themselves, so the resolution tested is the one every later
    /// call will make: beside SippBucket.exe for a published copy, and beside the assemblies
    /// in a build's output, where the project copies it.
    /// </remarks>
    public static string? Problem()
    {
        uint version;
        try
        {
            version = NativeMethods.AbiVersion();
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return
                $"SippBucket cannot start: sipengine.dll could not be loaded ({ex.GetType().Name}).{Environment.NewLine}" +
                $"It ships beside SippBucket.exe and has to stay beside it, in {AppContext.BaseDirectory}" +
                $"{Environment.NewLine}Copy the files together, or reinstall SippBucket.";
        }

        return version == AbiVersion
            ? null
            : $"SippBucket cannot start: the sipengine.dll beside it speaks engine ABI {version}, and this " +
              $"SippBucket.exe was built for ABI {AbiVersion}. They come from different builds; reinstall " +
              "SippBucket so both are from the same one.";
    }

    /// <summary>A content type's name for a person, from the engine.</summary>
    /// <param name="type">The type's number.</param>
    /// <returns>Its name, or null for a number that is not a type.</returns>
    internal static string? TypeName(uint type) => Text(type, NativeMethods.ContentTypeName);

    /// <summary>The extension a file of the type usually has, from the engine, without the dot.</summary>
    /// <param name="type">The type's number.</param>
    /// <returns>The extension, empty when the type has none, or null for a number that is not a type.</returns>
    internal static string? TypeExtension(uint type) => Text(type, NativeMethods.ContentTypeExtension);

    /// <summary>Runs the content check.</summary>
    /// <param name="head">The file's first bytes.</param>
    /// <param name="headLength">How many of them to read.</param>
    /// <param name="totalLength">The file's whole length.</param>
    /// <param name="name">The file's name, UTF-8.</param>
    /// <returns>The verdict, the reason, the detected type and the type the name claims.</returns>
    /// <exception cref="ArgumentNullException">An array was null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A length was negative, or longer than its array.</exception>
    /// <exception cref="InvalidOperationException">The engine refused its arguments, which would be a defect here.</exception>
    internal static (uint Verdict, uint Reason, uint Detected, uint Claimed) CheckContent(
        byte[] head, int headLength, long totalLength, byte[] name)
    {
        ArgumentNullException.ThrowIfNull(head);
        ArgumentNullException.ThrowIfNull(name);
        ArgumentOutOfRangeException.ThrowIfNegative(headLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(headLength, head.Length);
        ArgumentOutOfRangeException.ThrowIfNegative(totalLength);

        var fields = new uint[FieldCount];
        var code = NativeMethods.ContentCheck(
            headLength == 0 ? null : head,
            checked((nuint)headLength),
            checked((ulong)totalLength),
            name.Length == 0 ? null : name,
            checked((nuint)name.Length),
            fields,
            checked((nuint)fields.Length));

        if (code != Ok)
        {
            throw new InvalidOperationException($"The engine refused a content check with code {code}.");
        }

        return (fields[0], fields[1], fields[2], fields[3]);
    }

    /// <summary>Asks Windows, through the engine, for the firmware's SMBIOS tables.</summary>
    /// <param name="largest">The most bytes to accept; a table claiming more is not read.</param>
    /// <returns>
    /// The tables as Windows gives them (<c>RawSMBIOSData</c>), or null and why there are none.
    /// </returns>
    /// <exception cref="InvalidOperationException">The engine refused its arguments, which would be a defect here.</exception>
    /// <remarks>
    /// Asked once for the size and once for the tables. Once more, should they have grown in
    /// between, which firmware tables do not do while Windows runs; after that the answer is a
    /// problem, not another attempt.
    /// </remarks>
    internal static (byte[]? Table, string? Problem) ReadSmbios(int largest)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(largest);

        var code = NativeMethods.SmbiosRead(null, 0, out var needed, out var windowsError);

        for (var attempt = 0; attempt < 2 && code == ErrorCapacity; attempt++)
        {
            if (needed > (nuint)largest)
            {
                return (null, $"Windows reported SMBIOS tables of {needed} bytes, more than the {largest} any real table needs, so they were not read.");
            }

            var buffer = new byte[(int)needed];
            code = NativeMethods.SmbiosRead(buffer, (nuint)buffer.Length, out var written, out windowsError);
            if (code == Ok)
            {
                return (written == (nuint)buffer.Length ? buffer : buffer[..(int)written], null);
            }

            needed = written;
        }

        return code switch
        {
            ErrorUnavailable => (null, $"Windows gave no SMBIOS tables (error {windowsError})."),
            ErrorCapacity => (null, "The SMBIOS tables changed size while they were being read."),
            _ => throw new InvalidOperationException($"The engine refused to read the SMBIOS tables with code {code}."),
        };
    }

    /// <summary>Reads the values that identify a machine from its SMBIOS tables.</summary>
    /// <param name="table">The tables, as <see cref="ReadSmbios"/> returns them.</param>
    /// <returns>
    /// The engine's <c>SIPE_SMBIOS_FIELDS</c> values, whose offsets count into
    /// <paramref name="table"/>; or null when it is not a <c>RawSMBIOSData</c>.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="table"/> was null.</exception>
    /// <exception cref="InvalidOperationException">The engine refused its arguments, which would be a defect here.</exception>
    internal static uint[]? IdentifySmbios(byte[] table)
    {
        ArgumentNullException.ThrowIfNull(table);

        var fields = new uint[SmbiosFieldCount];
        var code = NativeMethods.SmbiosIdentity(
            table.Length == 0 ? null : table,
            checked((nuint)table.Length),
            fields,
            checked((nuint)fields.Length));

        return code switch
        {
            Ok => fields,
            ErrorMalformed => null,
            _ => throw new InvalidOperationException($"The engine refused to read an SMBIOS table with code {code}."),
        };
    }

    /// <summary><c>SIPE_CONTENT_FIELDS</c>: the verdict, the reason, the detected type and the claimed type.</summary>
    private const int FieldCount = 4;

    private delegate int TextExport(uint type, byte[]? buffer, nuint capacity, out nuint length);

    private static string? Text(uint type, TextExport export)
    {
        var code = export(type, null, 0, out var length);
        if (code == ErrorUnknown)
        {
            return null;
        }

        if (length == 0)
        {
            return string.Empty;
        }

        var buffer = new byte[checked((int)length)];
        code = export(type, buffer, checked((nuint)buffer.Length), out length);
        if (code != Ok || length != checked((nuint)buffer.Length))
        {
            throw new InvalidOperationException($"The engine could not name content type {type} (code {code}).");
        }

        return Encoding.UTF8.GetString(buffer);
    }

    // CA5393 flags AssemblyDirectory because a writable application directory lets someone
    // plant a DLL there. It is the directory sipengine.dll ships in, beside SippBucket.exe and
    // SippBucket.Core.dll, so anyone able to plant a library in it can replace those binaries
    // outright; the installed copy lives under Program Files, where only an administrator can
    // write. What would remove the need: loading the engine once by absolute path through
    // NativeLibrary.SetDllImportResolver, which would answer the same question with more code.
#pragma warning disable CA5393
    private static class NativeMethods
    {
        private const DllImportSearchPath SearchPath =
            DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories;

        [DllImport(LibraryName, EntryPoint = "sipe_abi_version", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(SearchPath)]
        public static extern uint AbiVersion();

        [DllImport(LibraryName, EntryPoint = "sipe_content_check", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(SearchPath)]
        public static extern int ContentCheck(
            byte[]? head,
            nuint headLength,
            ulong totalLength,
            byte[]? name,
            nuint nameLength,
            [Out] uint[] fields,
            nuint capacity);

        [DllImport(LibraryName, EntryPoint = "sipe_content_type_name", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(SearchPath)]
        public static extern int ContentTypeName(uint type, [Out] byte[]? buffer, nuint capacity, out nuint length);

        [DllImport(LibraryName, EntryPoint = "sipe_content_type_extension", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(SearchPath)]
        public static extern int ContentTypeExtension(uint type, [Out] byte[]? buffer, nuint capacity, out nuint length);

        [DllImport(LibraryName, EntryPoint = "sipe_smbios_read", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(SearchPath)]
        public static extern int SmbiosRead([Out] byte[]? buffer, nuint capacity, out nuint length, out uint windowsError);

        [DllImport(LibraryName, EntryPoint = "sipe_smbios_identity", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(SearchPath)]
        public static extern int SmbiosIdentity(byte[]? table, nuint length, [Out] uint[] fields, nuint capacity);

        [DllImport(LibraryName, EntryPoint = "sipe_randomness", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(SearchPath)]
        public static extern int Randomness(byte[]? sample, nuint length, [Out] uint[] fields, nuint capacity);
    }
#pragma warning restore CA5393
}
