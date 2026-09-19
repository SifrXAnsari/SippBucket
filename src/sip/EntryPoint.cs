using SippBucket.Cli;

namespace SippBucket.CliShim;

/// <summary>
/// The standalone <c>sip</c> executable: a shim over the shared command surface.
/// </summary>
/// <remarks>
/// It exists so a power user has <c>sip</c> on PATH with no console-attachment tricks. The
/// combined SippBucket application runs the same <see cref="CommandLine.RunAsync"/>.
/// </remarks>
internal static class EntryPoint
{
    private static Task<int> Main(string[] args) => CommandLine.RunAsync(args);
}