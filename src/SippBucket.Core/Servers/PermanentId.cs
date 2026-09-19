using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SippBucket.Core.Configuration;
using SippBucket.Core.Hashing;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Servers;

/// <summary>Where a permanent ID came from.</summary>
public enum PermanentIdSource
{
    /// <summary>The baseboard's serial number and the system UUID, both real.</summary>
    Smbios,

    /// <summary>The system UUID alone: the serial number is missing or a placeholder.</summary>
    SmbiosUuidOnly,

    /// <summary>The serial number alone: the UUID is missing or a placeholder.</summary>
    SmbiosSerialOnly,

    /// <summary>A random value made once, at install, that every account on the machine reads.</summary>
    GeneratedMachine,

    /// <summary>A random value kept for this account: a copy run without the installer.</summary>
    GeneratedAccount,
}

/// <summary>
/// A server's permanent ID: which physical machine it is, from the firmware, so it is the same
/// after a restart, a Windows reinstall and an account change.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it is (docs/SERVER-ID.md).</b> BLAKE2b-256 under a SippBucket domain string, of the
/// SMBIOS baseboard serial number and system UUID. The raw serial number never leaves the
/// machine; peers receive this one-way hash. It is guidance, never authority: a serial number
/// is not a secret, and only the device key proves which machine is which.
/// </para>
/// <para>
/// <b>The fallbacks, in order.</b> The serial number and the UUID when both are real. The UUID
/// alone when the serial number is missing or a placeholder. The serial number alone when the
/// UUID is (a case the design page did not list; it is recorded there as decided here, because
/// a real serial number survives a reinstall and a random value does not). A random value the
/// installer made once, with administrator rights, in the machine-wide folder every account
/// reads (<see cref="MachineIdFileName"/>). And last, a random value kept for this account, for
/// a copy run without the installer, which <c>sip id</c> says.
/// </para>
/// <para>
/// <b>The bytes hashed</b> are <see cref="Domain"/> in ASCII, then three fields, each a 4-byte
/// big-endian length and its bytes: the source's wire name, the first value and the second.
/// For the firmware sources the first value is the serial number as stored (without the spaces
/// firmware pads it with, which the engine drops) and the second the UUID's 16 bytes as stored;
/// a value not used is empty. For the generated sources the first value is the random value's
/// 32 bytes and the second is empty. The source is hashed too, so a generated value can never
/// produce the same ID as a firmware one.
/// </para>
/// </remarks>
public sealed class PermanentId
{
    /// <summary>The domain string every permanent ID is hashed under.</summary>
    public const string Domain = "SippBucket Server.ID permanent v1";

    /// <summary>The machine-wide random value's file, in the folder beside <c>master.json</c>.</summary>
    public const string MachineIdFileName = "machine-id";

    /// <summary>The per-account random value's file, in the data directory beside the device key.</summary>
    public const string AccountIdFileName = "server-id";

    /// <summary>How many random bytes a generated value holds.</summary>
    public const int GeneratedBytes = 32;

    private PermanentId(PermanentIdSource source, byte[] hash, string explanation)
    {
        Source = source;
        Hex = Convert.ToHexStringLower(hash);
        Fingerprint = ServerId.FromPermanent(hash);
        Explanation = explanation;
    }

    /// <summary>Where it came from.</summary>
    public PermanentIdSource Source { get; }

    /// <summary>The full 256-bit hash, in lower-case hexadecimal: what exact comparisons use.</summary>
    public string Hex { get; }

    /// <summary>The <c>Server.ID#XXX-XXX-XXX</c> fingerprint.</summary>
    public ServerId Fingerprint { get; }

    /// <summary>Where it came from, and why, in words for <c>sip id</c>.</summary>
    public string Explanation { get; }

    /// <summary>The wire name of a source, as the <c>sippbucket.server/1</c> record carries it.</summary>
    /// <param name="source">The source.</param>
    /// <returns><c>smbios</c>, <c>smbios-uuid-only</c>, <c>smbios-serial-only</c>, <c>generated-machine</c> or <c>generated-account</c>.</returns>
    public static string WireName(PermanentIdSource source) => source switch
    {
        PermanentIdSource.Smbios => "smbios",
        PermanentIdSource.SmbiosUuidOnly => "smbios-uuid-only",
        PermanentIdSource.SmbiosSerialOnly => "smbios-serial-only",
        PermanentIdSource.GeneratedMachine => "generated-machine",
        PermanentIdSource.GeneratedAccount => "generated-account",
        _ => throw new ArgumentOutOfRangeException(nameof(source), source, "Not a permanent ID source."),
    };

    /// <summary>Reads a source's wire name.</summary>
    /// <param name="name">The name, exactly as <see cref="WireName"/> writes it.</param>
    /// <param name="source">The source, when this returns true.</param>
    /// <returns>False for anything else.</returns>
    public static bool TryParseWireName(string? name, out PermanentIdSource source)
    {
        foreach (var candidate in Enum.GetValues<PermanentIdSource>())
        {
            if (string.Equals(WireName(candidate), name, StringComparison.Ordinal))
            {
                source = candidate;
                return true;
            }
        }

        source = default;
        return false;
    }

    /// <summary>Works out this machine's permanent ID.</summary>
    /// <param name="firmware">What the firmware's tables said, or why they could not be read.</param>
    /// <param name="machineIdPath">The machine-wide random value's file.</param>
    /// <param name="accountIdPath">The per-account random value's file, made here when it is the one needed.</param>
    /// <returns>The permanent ID, with where it came from.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="IOException">The per-account value was needed and could not be read or made.</exception>
    public static PermanentId Derive(FirmwareReading firmware, string machineIdPath, string accountIdPath)
    {
        ArgumentNullException.ThrowIfNull(firmware);
        ArgumentException.ThrowIfNullOrWhiteSpace(machineIdPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(accountIdPath);

        string whyNotFirmware;
        if (firmware.Tables is { } tables)
        {
            var serial = tables.BoardSerial;
            var uuid = tables.Uuid;

            if (serial.IsReal && uuid.IsReal)
            {
                return Make(
                    PermanentIdSource.Smbios,
                    serial.Bytes,
                    uuid.Bytes,
                    "from this board's serial number and the system UUID, as the firmware reports them");
            }

            if (uuid.IsReal)
            {
                return Make(
                    PermanentIdSource.SmbiosUuidOnly,
                    [],
                    uuid.Bytes,
                    $"from the system UUID alone: the board's serial number is {Describe(serial)}");
            }

            if (serial.IsReal)
            {
                return Make(
                    PermanentIdSource.SmbiosSerialOnly,
                    serial.Bytes,
                    [],
                    $"from the board's serial number alone: the system UUID is {Describe(uuid)}");
            }

            whyNotFirmware =
                $"the firmware's serial number is {Describe(serial)} and its UUID is {Describe(uuid)}";
        }
        else
        {
            whyNotFirmware = $"the firmware's tables could not be read: {firmware.Problem}";
        }

        var machineWide = ReadGenerated(machineIdPath, out var machineProblem);
        if (machineWide is not null)
        {
            return Make(
                PermanentIdSource.GeneratedMachine,
                machineWide,
                [],
                $"from the random value made when SippBucket was installed ({machineIdPath}), because {whyNotFirmware}");
        }

        var account = ReadOrMakeAccountValue(accountIdPath);
        return Make(
            PermanentIdSource.GeneratedAccount,
            account,
            [],
            $"from a random value kept for this account only ({accountIdPath}), because {whyNotFirmware}, and " +
            $"no machine-wide value was made at install: {machineProblem}. Another account on this machine " +
            "has its own, and a copy installed with the MSI would use one value for every account.");
    }

    /// <summary>
    /// Where the machine-wide random value is: beside <c>master.json</c>, in
    /// <c>C:\ProgramData\SippBucket</c>, or in the data-directory override when one is set.
    /// </summary>
    /// <returns>A fully qualified path.</returns>
    public static string MachineIdPath() =>
        Path.Combine(
            Path.GetDirectoryName(MasterConfig.ResolvePath())
                ?? throw new InvalidOperationException("master.json's path has no folder."),
            MachineIdFileName);

    /// <summary>The exact bytes a permanent ID hashes. Internal, for the golden test.</summary>
    /// <param name="source">The source.</param>
    /// <param name="first">The first value.</param>
    /// <param name="second">The second value.</param>
    /// <returns>The domain string, then the three length-prefixed fields.</returns>
    internal static byte[] Input(PermanentIdSource source, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        var domain = Encoding.ASCII.GetBytes(Domain);
        var name = Encoding.ASCII.GetBytes(WireName(source));

        var input = new byte[domain.Length + (3 * sizeof(uint)) + name.Length + first.Length + second.Length];
        var at = 0;

        domain.CopyTo(input, at);
        at += domain.Length;
        at = Append(input, at, name);
        at = Append(input, at, first);
        _ = Append(input, at, second);
        return input;
    }

    /// <summary>Reads a generated value's file.</summary>
    /// <param name="path">The file.</param>
    /// <param name="problem">Why there is no usable value, when this returns null.</param>
    /// <returns>The value's bytes, or null when the file is missing, unreadable or not one.</returns>
    /// <remarks>
    /// The file holds the value as 64 hexadecimal characters, and nothing but whitespace
    /// around them. Anything else is not guessed at: a damaged machine-wide file falls through
    /// to the per-account value, and says why.
    /// </remarks>
    internal static byte[]? ReadGenerated(string path, out string problem)
    {
        string text;
        try
        {
            text = SharingRetry.Run(() => File.ReadAllText(path));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            problem = $"{path} does not exist";
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            problem = $"{path} could not be read ({ex.Message})";
            return null;
        }

        var hex = text.Trim();
        if (hex.Length != 2 * GeneratedBytes || !hex.All(char.IsAsciiHexDigit))
        {
            problem = $"{path} does not hold a value SippBucket made";
            return null;
        }

        problem = string.Empty;
        return Convert.FromHexString(hex);
    }

    private static PermanentId Make(PermanentIdSource source, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, string explanation) =>
        new(source, Blake2.Hash(Input(source, first, second)).ToByteArray(), explanation);

    private static int Append(byte[] input, int at, ReadOnlySpan<byte> field)
    {
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(at), (uint)field.Length);
        at += sizeof(uint);
        field.CopyTo(input.AsSpan(at));
        return at + field.Length;
    }

    private static string Describe(FirmwareValue value) => value.State switch
    {
        FirmwareValueState.Placeholder => "a placeholder the firmware reports when it has none",
        _ => "not in its tables",
    };

    /// <summary>Reads this account's random value, making it the first time it is needed.</summary>
    /// <remarks>
    /// Made with <see cref="FileMode.CreateNew"/>, so when the tray and a command make it at the
    /// same moment one of them wins and the other reads the winner's value: one account, one
    /// value.
    /// </remarks>
    private static byte[] ReadOrMakeAccountValue(string path)
    {
        var existing = ReadGenerated(path, out var problem);
        if (existing is not null)
        {
            return existing;
        }

        if (File.Exists(path))
        {
            throw new IOException(
                $"{problem}. It is this account's server identity when the firmware gives none; delete it and " +
                "SippBucket makes a new one, which the other machines will see as a different server.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? throw new IOException($"{path} has no folder."));

        var value = RandomNumberGenerator.GetBytes(GeneratedBytes);
        try
        {
            using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            file.Write(Encoding.ASCII.GetBytes(Convert.ToHexStringLower(value) + Environment.NewLine));
            file.Flush(flushToDisk: true);
            return value;
        }
        catch (IOException) when (File.Exists(path))
        {
            // Another process made it first. Its value is this account's.
            return ReadGenerated(path, out var raced)
                ?? throw new IOException($"{raced}. Another SippBucket process was making it at the same moment.");
        }
    }
}
