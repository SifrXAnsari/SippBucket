using System.Runtime.InteropServices;

namespace SippBucket.Tray;

/// <summary>
/// Checks, before anything else runs, that libsodium can be loaded.
/// </summary>
/// <remarks>
/// <para>
/// SippBucket.exe used to carry libsodium.dll inside itself and unpack it into
/// <c>%TEMP%\.net</c> at every first start (D-46). It now ships beside the executable
/// instead, which makes the program two files. The price of that is a new way to break it:
/// copy SippBucket.exe somewhere on its own and it cannot find its cryptography.
/// </para>
/// <para>
/// Measured, not supposed: an executable copied without libsodium.dll crashed on
/// <c>SippBucket id</c> with an unhandled <c>TypeInitializationException</c> from deep
/// inside NSec, and the tray, which reaches the same code before it has a window, died with
/// nothing on screen at all - an APPCRASH in the Application event log and no window. So the
/// check is made first, and the failure names the missing file and where it has to be.
/// </para>
/// </remarks>
internal static class NativeDependencies
{
    /// <summary>The native library NSec binds to, by the name its imports use.</summary>
    internal const string Sodium = "libsodium";

    /// <summary>Whether libsodium loads, and if not, what a person should do about it.</summary>
    /// <returns>Null when it loads; otherwise a message naming the file and the folder.</returns>
    /// <remarks>
    /// Loaded the way NSec's own imports will load it - by the same name, on behalf of NSec's
    /// assembly, so the runtime's probing (the application directory for a published copy,
    /// the paths in <c>SippBucket.deps.json</c> for a build) is the probing tested. Both were
    /// checked: the published executable finds it beside itself, and the test build finds it
    /// under <c>runtimes\win-x64\native</c>. The search path is the one the project's rules
    /// give for libsodium imports, and the handle is released at once: this is a question,
    /// not the load NSec will make.
    /// </remarks>
    public static string? SodiumProblem()
    {
        if (NativeLibrary.TryLoad(
                Sodium,
                typeof(NSec.Cryptography.Key).Assembly,
                DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories,
                out var handle))
        {
            NativeLibrary.Free(handle);
            return null;
        }

        return
            $"SippBucket cannot start: libsodium.dll could not be loaded.{Environment.NewLine}" +
            $"It ships beside SippBucket.exe and has to stay beside it, in {AppContext.BaseDirectory}" +
            $"{Environment.NewLine}Copy the files together, or reinstall SippBucket.";
    }

    /// <summary>
    /// Whether SippBucket's own native engine, <c>sipengine.dll</c>, loads and is from the same
    /// build, and if not, what a person should do about it.
    /// </summary>
    /// <returns>Null when it does; otherwise a message naming the file and the folder.</returns>
    /// <remarks>
    /// The engine checks every file Direct Push receives. A copy without it could not tell a
    /// disguised program from a photo, so it is a broken install in the same way a copy without
    /// libsodium is, and it is refused the same way, before anything runs.
    /// </remarks>
    public static string? EngineProblem() => Core.Native.SipEngine.Problem();
}
