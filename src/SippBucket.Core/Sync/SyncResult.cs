namespace SippBucket.Core.Sync;

/// <summary>What one sync with one peer did.</summary>
public sealed record SyncResult
{
    /// <summary>
    /// The peer that was synced with, as screens name it: "Server 2 (Dell Inspiron 15 3511)" for
    /// one of the person's own numbered servers, the name in the peer list otherwise.
    /// </summary>
    public required string PeerName { get; init; }

    /// <summary>The peer's device ID: what a status is kept by, because a name can change.</summary>
    public required string DeviceId { get; init; }

    /// <summary>What the sync concluded.</summary>
    public required SyncOutcome Outcome { get; init; }

    /// <summary>How many blocks were fetched from the peer.</summary>
    public int BlocksFetched { get; init; }

    /// <summary>How many files were written into the working folder.</summary>
    public int FilesWritten { get; init; }

    /// <summary>
    /// How many files were deleted from the working folder because the peer deleted them
    /// and nobody had changed them here.
    /// </summary>
    public int FilesDeleted { get; init; }

    /// <summary>
    /// Files renamed because both sides changed them independently. Empty in every other
    /// case.
    /// </summary>
    public IReadOnlyList<string> ConflictsRenamed { get; init; } = [];

    /// <summary>
    /// How many snapshots the peer had that this replica did not, when the pull that would
    /// have fetched them failed or was deferred. Zero after any successful sync.
    /// </summary>
    /// <remarks>
    /// Counted from the peer's ancestry: the entries between its head and the first
    /// snapshot this replica already knows. It is only ever non-zero on a
    /// <see cref="SyncOutcome.Failed"/> or <see cref="SyncOutcome.Deferred"/> result where the
    /// peer was reached and its head was learned, which is exactly the case "Behind desktop
    /// by 3 snapshots" describes — a peer that could not be reached at all tells us nothing
    /// about how far ahead it is.
    /// </remarks>
    public int SnapshotsBehind { get; init; }

    /// <summary>
    /// Why the sync failed, was deferred, was not tried or was held, when <see cref="Outcome"/> is
    /// <see cref="SyncOutcome.Failed"/>, <see cref="SyncOutcome.Deferred"/>,
    /// <see cref="SyncOutcome.NotTried"/> or <see cref="SyncOutcome.Held"/>. Null otherwise.
    /// </summary>
    public string? FailureReason { get; init; }

    /// <summary>
    /// True when the peer answered: the connection was made and this machine's side of the
    /// handshake completed, so the machine at the other end proved it is the peer that was
    /// dialled and serves this repository. True for every result that came back from the peer,
    /// a deferred one included, and for a failure that happened after that point.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A separate fact from <see cref="Succeeded"/>, and conflating the two was D-58: a peer
    /// that answered and then served a snapshot that did not match its ID, or could not
    /// produce a block, was reported as unreachable, and the machines view sent the person
    /// to check cables for a fault that was in the data. A deferred sync is the same: the peer
    /// did everything asked of it, and calling it unreachable would blame it for this machine's
    /// own state.
    /// </para>
    /// <para>
    /// The handshake is where the line is drawn, not the TCP connection, because before it
    /// nothing has shown that the program that accepted is SippBucket on the right machine.
    /// Another device at the address fails the handshake's second message, which only the
    /// dialled device can make, and one that does not serve this repository says so in that
    /// message; both read as not reached.
    /// </para>
    /// <para>
    /// A peer that does not list this machine reads as reached, with the sync failed. In
    /// Noise XK the dialling side sends the last handshake message, and the answering side
    /// checks its peer list only after reading it (<c>SecureChannel.AcceptAsync</c>), then
    /// closes the connection without a word. So this side's handshake has completed, against
    /// the right machine, before the refusal can arrive: that machine is on the network and
    /// answered, and what failed is that it would not sync with this one.
    /// </para>
    /// <para>
    /// False for a peer not tried, and for one held because the person said a change from it
    /// was not them: neither was asked anything.
    /// </para>
    /// </remarks>
    public bool PeerReached { get; init; }

    /// <summary>True when this peer was contacted and this replica is now level with what it offered.</summary>
    /// <remarks>
    /// False for a deferred sync as well as a failed one: a deferred sync reached the peer
    /// and changed nothing here, so this copy is exactly as out of date as it was (A1). False
    /// for a peer not tried at all, and for a change held, for the same reason.
    /// </remarks>
    public bool Succeeded => Outcome is not (SyncOutcome.Failed or SyncOutcome.Deferred or SyncOutcome.NotTried or SyncOutcome.Held);

    /// <summary>True when this cycle contacted the peer, or tried to.</summary>
    /// <remarks>
    /// A result that was not tried says nothing about the peer, good or bad: whatever was last
    /// known about it still stands, and a caller keeping a peer's status must leave it as it was
    /// rather than record an answer, a last-seen time or a failure it never had (A1). A change
    /// held because the peer answered with one is tried; a peer held because the person said an
    /// earlier change of its was not them is not asked at all, so it is not tried either.
    /// </remarks>
    public bool Tried => Outcome switch
    {
        SyncOutcome.NotTried => false,
        SyncOutcome.Held => PeerReached,
        _ => true,
    };

    /// <summary>A one-line description of the result, ready to print.</summary>
    public string Summary => Outcome switch
    {
        SyncOutcome.AlreadyUpToDate => $"{PeerName}: already up to date",
        SyncOutcome.PeerIsEmpty => $"{PeerName}: peer has nothing saved yet",
        SyncOutcome.FastForwarded =>
            $"{PeerName}: fast-forwarded, {FilesWritten} file(s), {BlocksFetched} block(s)" +
            Extras(),
        SyncOutcome.Merged =>
            $"{PeerName}: merged, {FilesWritten} file(s), {BlocksFetched} block(s), " +
            $"{ConflictsRenamed.Count} conflict(s) kept" +
            (FilesDeleted > 0 ? $", {FilesDeleted} deleted" : string.Empty),
        SyncOutcome.PushedNothing => $"{PeerName}: peer is behind; it will pull on its next sync",
        SyncOutcome.Failed => $"{PeerName}: NOT synced - {FailureReason}",
        SyncOutcome.Deferred or SyncOutcome.NotTried => $"{PeerName}: NOT synced yet - {FailureReason}",
        SyncOutcome.Held => $"{PeerName}: its change is HELD - {FailureReason}",
        _ => $"{PeerName}: {Outcome}",
    };

    /// <summary>
    /// The parts of a fast-forward worth mentioning only when they happened. A fast-forward
    /// keeps both versions of a file edited here while the sync was running, and saying
    /// "fast-forwarded" with no mention of that would hide the one thing to look at.
    /// </summary>
    private string Extras() =>
        (FilesDeleted > 0 ? $", {FilesDeleted} deleted" : string.Empty) +
        (ConflictsRenamed.Count > 0 ? $", {ConflictsRenamed.Count} conflict(s) kept" : string.Empty);
}

/// <summary>How a sync ended.</summary>
public enum SyncOutcome
{
    /// <summary>Both sides were already at the same snapshot.</summary>
    AlreadyUpToDate = 0,

    /// <summary>The peer had never saved anything.</summary>
    PeerIsEmpty = 1,

    /// <summary>
    /// The peer's head descended from this replica's, and the working folder moved forward
    /// onto it.
    /// </summary>
    FastForwarded = 2,

    /// <summary>Both sides had diverged and the result keeps both sets of changes.</summary>
    Merged = 3,

    /// <summary>The peer was behind this replica, so there was nothing to pull.</summary>
    PushedNothing = 4,

    /// <summary>
    /// The peer could not be synced with. Unreachable, stalled, refused, or speaking
    /// nonsense — from the user's point of view these are one thing: that copy is not
    /// current, and saying so is the entire point of this value existing.
    /// </summary>
    Failed = 5,

    /// <summary>
    /// The peer answered and had something to apply, and this machine did not apply it: the
    /// folder was busy with another operation (D-38), its head moved while the pull was on
    /// the network, or a file to be changed was in use. Nothing was changed here, and the
    /// next sync tries again.
    /// </summary>
    /// <remarks>
    /// Not <see cref="Failed"/>, because that blames the peer: the daemon would call a machine
    /// that answered perfectly well unreachable, and count a failure against it. Not a
    /// success either, because this copy is exactly as out of date as it was.
    /// </remarks>
    Deferred = 6,

    /// <summary>
    /// This cycle did not contact the peer at all. An earlier peer's apply found the folder
    /// held by another operation, and this peer's apply would have waited out the same lock.
    /// </summary>
    /// <remarks>
    /// Not <see cref="Deferred"/>, which means the peer answered: recording a peer that was
    /// never asked as reached gave it a last-seen time it never had, and forgave the failures
    /// of a machine that may still be switched off (A1). Not <see cref="Failed"/> either,
    /// because nothing is known against it. This cycle says nothing about the peer, and
    /// whatever was last known about it stands.
    /// </remarks>
    NotTried = 7,

    /// <summary>
    /// The peer's change looked like damage and was held for the person to answer, or the
    /// person said an earlier change from it was not them and it is not taken from at all
    /// (docs/PEER-HEALTH.md). Nothing was changed here.
    /// </summary>
    /// <remarks>
    /// Not <see cref="Failed"/>: the peer answered, and whether its change is wanted is the
    /// person's question, not a fault. Not a success: this copy is not level with it.
    /// </remarks>
    Held = 8,
}
