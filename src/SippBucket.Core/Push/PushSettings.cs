namespace SippBucket.Core.Push;

/// <summary>
/// Direct Push's limits on this machine, from the <c>push</c> section of <c>master.json</c>.
/// </summary>
/// <remarks>
/// <para>
/// Built to docs/DIRECT-PUSH.md and docs/MASTER-CONFIG.md. The file can tune these within the
/// hard limits in <see cref="Configuration.MasterSettings"/>; it can never switch off the key
/// check, the encryption or the content check, because none of those is a setting.
/// </para>
/// <para>
/// Byte sizes are held as bytes. The file states them in KiB and MiB, binary units, labelled as
/// such (standard F3).
/// </para>
/// </remarks>
public sealed record PushSettings
{
    /// <summary>The SSH port when the file does not set one: two above the sync port's default.</summary>
    /// <remarks>
    /// The sync port's default is 8471 and pairing listens one above it, on 8472, so 8473 is
    /// the first port neither uses.
    /// </remarks>
    public const int DefaultPort = 8473;

    /// <summary>
    /// The least free space the inbox's disk must keep after a file is written there, or the file
    /// is refused before any of it is written.
    /// </summary>
    /// <remarks>
    /// A floor in code, not a setting, for the same reason as the hard limits: a push from a
    /// paired machine must never be able to fill the disk Windows and this machine's own work
    /// live on. One gibibyte is room for Windows to keep running and for the person to act.
    /// </remarks>
    public const long DiskReserveBytes = 1024L * 1024 * 1024;

    /// <summary>The TCP port the SSH server listens on.</summary>
    public required int Port { get; init; }

    /// <summary>How many bytes a sender may have unacknowledged on one transfer.</summary>
    public required long WindowBytes { get; init; }

    /// <summary>The most the quarantine may hold, in bytes.</summary>
    public required long QuarantineCapBytes { get; init; }

    /// <summary>The most one other person's files may take in the inbox and quarantine together.</summary>
    public required long PersonInboxCapBytes { get; init; }

    /// <summary>The largest single file accepted, in bytes.</summary>
    public required long LargestFileBytes { get; init; }

    /// <summary>The largest direct message accepted, not counting attachments, in bytes.</summary>
    public required long LargestMessageBytes { get; init; }

    /// <summary>How many direct messages one sender may deliver in a minute.</summary>
    public required int MessagesPerMinute { get; init; }

    /// <summary>
    /// Whether the SSH port is the sync port or the pairing port beside it, where it cannot
    /// listen.
    /// </summary>
    /// <param name="listenPort">This machine's <c>server.listenPort</c>.</param>
    /// <returns>True when Direct Push must not start on this port.</returns>
    public bool ClashesWith(int listenPort) => Port == listenPort || Port == listenPort + 1;
}
