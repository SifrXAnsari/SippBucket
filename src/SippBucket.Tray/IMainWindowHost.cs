using SippBucket.Core.Discovery;
using SippBucket.Core.Health;
using SippBucket.Core.Machines;
using SippBucket.Core.Pairing;
using SippBucket.Core.Storage;
using SippBucket.Core.Sync;

namespace SippBucket.Tray;

/// <summary>
/// What the main window may read from, and ask of, the tray that owns the folders.
/// </summary>
/// <remarks>
/// <para>
/// The window owns no state. The running services, the watch list and the activity log all
/// belong to the tray, which outlives the window — closing the window hides it, and the
/// daemon carries on. So the window asks for a fresh picture each time it draws and hands
/// every action back, which means there is exactly one place a folder's truth can come
/// from and the window cannot drift from the tray icon.
/// </para>
/// <para>
/// Every member is called on the UI thread.
/// </para>
/// </remarks>
internal interface IMainWindowHost
{
    /// <summary>This machine's device ID: 64 hex characters.</summary>
    string DeviceId { get; }

    /// <summary>What happens at the next sign-in, in one line.</summary>
    string AutostartDescription { get; }

    /// <summary>The path of this machine's device key file, which the window reads to describe it.</summary>
    /// <remarks>
    /// A path rather than a yes or no, so the window's line about the key comes from the file.
    /// It was a boolean, and the tray answered it from the platform, so the window said the key
    /// was protected by Windows while it sat on disk in the clear (D-51).
    /// </remarks>
    string DeviceKeyFile { get; }

    /// <summary>How often each folder polls its peers.</summary>
    TimeSpan PollInterval { get; }

    /// <summary>The watched folders, in the order they were added, each with its status now.</summary>
    /// <returns>A snapshot. It does not change after it is returned.</returns>
    IReadOnlyList<WatchedFolderView> Folders();

    /// <summary>The most recent activity lines, newest first.</summary>
    /// <param name="count">How many lines at most.</param>
    /// <returns>A copy of the lines.</returns>
    IReadOnlyList<string> RecentActivity(int count);

    /// <summary>Lets the user pick a folder and starts watching it.</summary>
    /// <param name="owner">The window any dialog should belong to.</param>
    void AddFolder(IWin32Window owner);

    /// <summary>Runs a sync cycle for every watched folder now.</summary>
    /// <returns>A task that completes when every cycle has finished or given up.</returns>
    Task SyncAllNowAsync();

    /// <summary>Runs a sync cycle for one folder now.</summary>
    /// <param name="folder">The folder's path.</param>
    /// <returns>A task that completes when the cycle has finished or given up.</returns>
    Task SyncNowAsync(string folder);

    /// <summary>Opens the folder in Explorer.</summary>
    /// <param name="folder">The folder's path.</param>
    void OpenFolder(string folder);

    /// <summary>Stops watching a folder. The folder and its history are left untouched.</summary>
    /// <param name="folder">The folder's path.</param>
    /// <returns>A task that completes when the folder's service has stopped.</returns>
    Task StopWatchingAsync(string folder);

    /// <summary>Opens the command line in a window of its own.</summary>
    /// <param name="owner">The window any error message should belong to.</param>
    void OpenCommandLine(IWin32Window owner);

    /// <summary>Copies this machine's device ID to the clipboard.</summary>
    void CopyDeviceId();

    /// <summary>Tells the user, once per session, that closing the window did not quit.</summary>
    void AnnounceStillRunning();

    /// <summary>Quits SippBucket: stops every folder's service cleanly and exits.</summary>
    void Quit();

    /// <summary>The per-network discovery consent the daemon announces under.</summary>
    NetworkConsent Consent { get; }

    /// <summary>This machine's sync port, which pairing offers beside and enter defaults to.</summary>
    int ListenPort { get; }

    /// <summary>The folders a pairing can be offered for: the running ones.</summary>
    IReadOnlyList<(string Path, string Name)> PairableFolders();

    /// <summary>Measures one folder's bucket. Walks the store, so it runs on demand only.</summary>
    /// <param name="folder">The folder's path.</param>
    /// <returns>The usage, or why it could not be measured.</returns>
    Task<(BucketUsage? Usage, string? Problem)> MeasureFolderBucketAsync(string folder);

    /// <summary>Applies one folder's retention policy and sweeps unreferenced blocks.</summary>
    /// <param name="folder">The folder's path.</param>
    /// <returns>What happened, in a sentence, and whether it failed.</returns>
    Task<(string Summary, bool Failed)> CollectFolderAsync(string folder);

    /// <summary>One folder's recent history, newest first.</summary>
    /// <param name="folder">The folder's path.</param>
    /// <param name="limit">The most entries.</param>
    /// <returns>The entries, or empty when the folder is not running here.</returns>
    Task<IReadOnlyList<HistoryLine>> FolderHistoryAsync(string folder, int limit);

    /// <summary>What the detail view says about one folder, or null when it is not running.</summary>
    /// <param name="folder">The folder's path.</param>
    FolderFacts? FolderFacts(string folder);

    /// <summary>
    /// Answers one alert the way <c>sip alerts answer</c> does: the answer is recorded in
    /// the permanent log, and for a held change the folder's record is answered too — from
    /// the running folder, with no second open. "Not me" marks the install suspect;
    /// "that was me" kicks a sync cycle so the held change applies now.
    /// </summary>
    /// <param name="id">The alert's number.</param>
    /// <param name="choice">The answer.</param>
    /// <returns>What happened, in sentences ready to show.</returns>
    Task<string> AnswerAlertAsync(int id, AlertChoice choice);

    /// <summary>Starts offering a pairing code for one folder (D-90).</summary>
    /// <param name="folder">The folder's path.</param>
    /// <returns>The live offer, or null with why not.</returns>
    (PairOfferSession? Session, string? Problem) BeginPairOffer(string folder);

    /// <summary>
    /// Joins a folder offered by another machine, with the one question answered (D-90):
    /// the new replica starts syncing here at once.
    /// </summary>
    /// <param name="host">The other machine's address.</param>
    /// <param name="port">Its sync port.</param>
    /// <param name="code">The spoken code.</param>
    /// <param name="directory">The empty folder to become the replica.</param>
    /// <param name="owner">Whose machine the offering one is.</param>
    /// <returns>What happened.</returns>
    Task<PairEnterResult> PairEnterAsync(string host, int port, string code, string directory, MachineOwner owner);

    /// <summary>
    /// Records whose machine a newly paired device is: the one question, answered in the
    /// window.
    /// </summary>
    /// <param name="deviceId">The device.</param>
    /// <param name="name">The name this machine calls it.</param>
    /// <param name="owner">The answer.</param>
    /// <returns>What the answer means, in a sentence, or the failure.</returns>
    string RecordPairedOwner(string deviceId, string name, MachineOwner owner);
}

/// <summary>One history entry, as the folder detail draws it.</summary>
/// <param name="ShortId">The snapshot's short ID.</param>
/// <param name="WhenLocal">When it was taken, local time, ready to print.</param>
/// <param name="Who">Who took it: "you", a peer's name, or the device's first characters.</param>
/// <param name="Message">Its message, or "(no message)".</param>
/// <param name="Files">How many files it records.</param>
/// <param name="Size">Their total size, ready to print.</param>
internal sealed record HistoryLine(
    string ShortId,
    string WhenLocal,
    string Who,
    string Message,
    int Files,
    string Size);

/// <summary>What the folder detail says beside the history.</summary>
/// <param name="Name">The folder's display name.</param>
/// <param name="Mode">Power or Simple, with what that means.</param>
/// <param name="HasPassphrase">Whether this machine's copy is behind a passphrase.</param>
/// <param name="UnlockedForSession">Whether it is open right now.</param>
/// <param name="RepositoryId">The repository's ID, which every replica shares.</param>
/// <param name="Conflicts">Files kept under both versions recently.</param>
/// <param name="PeerCount">How many machines this folder syncs with.</param>
internal sealed record FolderFacts(
    string Name,
    string Mode,
    bool HasPassphrase,
    bool UnlockedForSession,
    string RepositoryId,
    IReadOnlyList<string> Conflicts,
    int PeerCount);

/// <summary>A live pairing offer: the code on screen, and the exchange's end.</summary>
internal sealed class PairOfferSession : IAsyncDisposable
{
    private readonly PairingServer _server;

    /// <summary>Wraps a started server.</summary>
    /// <param name="server">The server, owned by this session.</param>
    /// <param name="addresses">This machine's usable addresses, for the screen.</param>
    /// <param name="port">The sync port the other machine dials.</param>
    public PairOfferSession(PairingServer server, IReadOnlyList<string> addresses, int port)
    {
        ArgumentNullException.ThrowIfNull(server);
        _server = server;
        Addresses = addresses;
        Port = port;
    }

    /// <summary>The spoken code.</summary>
    public string Code => _server.Code;

    /// <summary>This machine's usable IPv4 addresses, gateway ones first.</summary>
    public IReadOnlyList<string> Addresses { get; }

    /// <summary>The sync port the other machine dials.</summary>
    public int Port { get; }

    /// <summary>Waits for the exchange to finish.</summary>
    /// <returns>How it ended, and the peer when one paired.</returns>
    public async Task<(PairingClosure Outcome, string? PeerDeviceId, string? PeerName)> WaitAsync()
    {
        var outcome = await _server.WaitForOutcomeAsync().ConfigureAwait(false);
        return (outcome, _server.PairedPeer?.DeviceId, _server.PairedPeer?.Name);
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync() => _server.DisposeAsync();
}

/// <summary>What entering a code did.</summary>
/// <param name="Succeeded">True when this machine now holds the folder and syncs it.</param>
/// <param name="Message">What happened, ready to show.</param>
/// <param name="PeerDeviceId">The offering machine's device ID, for the one question.</param>
/// <param name="PeerName">What this machine calls it.</param>
internal sealed record PairEnterResult(
    bool Succeeded,
    string Message,
    string? PeerDeviceId,
    string? PeerName);

/// <summary>One watched folder, as the window draws it.</summary>
/// <param name="Path">The folder's path, which identifies it.</param>
/// <param name="Name">The repository's display name.</param>
/// <param name="Status">Its status now, or null when its service is not running.</param>
internal sealed record WatchedFolderView(string Path, string Name, FolderStatus? Status);
