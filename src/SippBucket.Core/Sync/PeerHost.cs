using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using SippBucket.Core.Configuration;
using SippBucket.Core.Crypto;
using SippBucket.Core.Hashing;
using SippBucket.Core.Health;
using SippBucket.Core.Protocol;
using SippBucket.Core.Repository;
using SippBucket.Core.Servers;

namespace SippBucket.Core.Sync;

/// <summary>
/// This machine's server: one listener, on one port, serving every folder this machine holds
/// to the peers each of them trusts.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why one (D-40).</b> Each folder used to run a listener of its own on the port in its
/// config, and every folder the tray created had the same one, 8471. The second folder's
/// listener could not bind, so that folder was served to nobody: "more folders, more
/// workspaces" is the design, and the second workspace was unreachable from every other
/// machine. Discovery's announcement was always shaped for one server per machine, one
/// sync port and a list of repository IDs; the server never was. (That JSON announcement
/// is gone since D-32 — the shape argument stands as history.)
/// </para>
/// <para>
/// <b>How a connection finds its folder.</b> The caller names the repository inside the
/// first handshake message, encrypted to this device's key, and the host looks it up among
/// the folders registered with it (<see cref="SecureChannel"/>). A repository that is not
/// registered is refused with exactly the answer it always got, whether it was never served
/// here or has just stopped being served, so a caller learns nothing by asking about
/// repositories whose IDs it does not already know. The caller's device is then checked
/// against that one folder's peer list, so a machine trusted by one folder gains nothing in
/// another.
/// </para>
/// <para>
/// <b>What each connection keeps from before.</b> A fault boundary of its own, so one bad
/// peer never stops this machine serving the others; the stall deadline on every read and
/// write, and the longer idle deadline between requests; the pre-authentication frame
/// ceiling, which is <see cref="SecureChannel"/>'s; Keep Alive only while blocks move; and
/// no write to any folder on a peer's instruction.
/// </para>
/// <para>
/// <b>What a caller with no credential can cost (SEC-3).</b> Anyone who can reach the port
/// can open a connection, and until it has proved which device it is, it is owed nothing.
/// Before this the listener accepted without limit, and the only deadline before
/// authentication was the stall deadline, which restarts on every byte: one byte just inside
/// each stall interval held a connection, its socket and its task, for as long as the caller
/// liked. Three bounds now apply until the handshake is done, and none after it, because an
/// authenticated peer is a machine the person paired. Each connection has
/// <see cref="SyncTuning.HandshakeDeadline"/> from accept to a proven device ID, however its
/// bytes are spaced. Each source address may hold
/// <see cref="SyncTuning.MaximumPendingHandshakesPerAddress"/> unfinished handshakes, and the
/// machine <see cref="SyncTuning.MaximumPendingHandshakes"/>. At either limit the newcomer is
/// let in and an old unfinished handshake is closed instead: the arriving address's own
/// oldest, or, machine-wide, the oldest from whichever address holds the most, and when
/// several addresses tie for the most, the oldest connection held by any of them. Refusing
/// newcomers would let a flood that arrived first keep every real peer out; shedding the
/// oldest from the heaviest address means a flood costs its own connections. What that
/// guarantees, and no more: while one address holds more unfinished handshakes than a real
/// peer's address does, the real peer's handshake is never the one closed. A flood spread
/// thinly, one connection from each of as many addresses as the limit allows, ties every
/// address, and then the oldest handshake goes, whoever it belongs to; the peer's next attempt
/// is let in the same way. The counting and choosing are <see cref="HandshakeAdmission"/>'s,
/// shared with Direct Push's listener so the two apply one rule.
/// </para>
/// <para>
/// <b>Where the port comes from.</b> The machine's <c>server.listenPort</c> in
/// <c>master.json</c>, which whoever creates the host passes in, usually through
/// <see cref="ForMachine"/>. Nothing reads the port a folder's own config records.
/// </para>
/// </remarks>
public sealed class PeerHost : IAsyncDisposable, IDisposable
{
    private readonly DeviceIdentity _identity;
    private readonly int _requestedPort;
    private readonly Action<string>? _log;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, ServedRepository> _served = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<Task> _connections = [];
    private readonly CancellationTokenSource _stopping = new();

    // Connections accepted and not yet authenticated. See the remarks on SEC-3.
    private readonly HandshakeAdmission _admission;

    private TcpListener? _listener;
    private Task? _accepting;
    private string? _fault;
    private bool _listening;
    private bool _disposed;

    /// <summary>Creates a host. Call <see cref="Start"/> or <see cref="RunAsync"/> to listen.</summary>
    /// <param name="identity">This machine's identity, which every folder is served as.</param>
    /// <param name="port">The port to listen on: the machine's <c>server.listenPort</c>, or 0 for any free one.</param>
    /// <param name="log">Optional sink for log lines.</param>
    /// <param name="tuning">The deadlines and limits to serve under, or null for the defaults.</param>
    /// <exception cref="ArgumentNullException"><paramref name="identity"/> was null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="port"/> is not a TCP port, or <paramref name="tuning"/> sets a handshake
    /// deadline or limit that is not positive.
    /// </exception>
    public PeerHost(
        DeviceIdentity identity,
        int port,
        Action<string>? log = null,
        SyncTuning? tuning = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentOutOfRangeException.ThrowIfNegative(port);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, IPEndPoint.MaxPort);

        var chosen = tuning ?? SyncTuning.Default;
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(chosen.HandshakeDeadline, TimeSpan.Zero, nameof(tuning));
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(chosen.MaximumPendingHandshakes, nameof(tuning));
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(chosen.MaximumPendingHandshakesPerAddress, nameof(tuning));

        _identity = identity;
        _requestedPort = port;
        _log = log;
        Tuning = chosen;
        _admission = new HandshakeAdmission(chosen.MaximumPendingHandshakes, chosen.MaximumPendingHandshakesPerAddress);
        _fault = "not serving peers: the server has not started";
    }

    /// <summary>
    /// Creates the host this machine's settings describe: on its <c>server.listenPort</c>, with
    /// its <c>sync</c> deadlines.
    /// </summary>
    /// <param name="identity">This machine's identity.</param>
    /// <param name="machine">This machine's settings, from <c>master.json</c>.</param>
    /// <param name="log">Optional sink for log lines.</param>
    /// <returns>The host, not yet started.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <remarks>
    /// The one place the tray and <c>sip serve</c> turn <c>master.json</c> into a server, so
    /// that the two cannot come to disagree about which of its values a server honours. The
    /// limits on unauthenticated callers are not among them: those are hard limits in code
    /// (docs/MASTER-CONFIG.md) and keep their built-in values whatever the file says.
    /// </remarks>
    public static PeerHost ForMachine(DeviceIdentity identity, MasterConfig machine, Action<string>? log = null)
    {
        ArgumentNullException.ThrowIfNull(machine);
        return new PeerHost(identity, machine.ListenPort, log, machine.Sync)
        {
            Upload = machine.UploadLimit,
        };
    }

    /// <summary>The port the host is actually listening on, or 0 before it has bound one.</summary>
    public int Port { get; private set; }

    /// <summary>The deadlines connections are served under.</summary>
    public SyncTuning Tuning { get; }

    /// <summary>
    /// Server.ID's exchange, the names it gives the person's servers, and the health records it
    /// keeps; or null when this host takes no part in them.
    /// </summary>
    /// <remarks>
    /// With it, a caller that asks for this machine's Server.ID record is answered when the
    /// person said the caller is theirs, log lines name callers "Server 2 (…)", and what a
    /// served connection shows against its caller, once the handshake has proved which machine
    /// that is, goes to the caller's health record. Without it, record requests get an empty
    /// answer and everything else is served as before.
    /// </remarks>
    public ServerExchange? Servers { get; set; }

    /// <summary>
    /// The ceiling on what this machine sends peers, as blocks (D-29): the machine's
    /// <c>network.uploadKiBps</c>, or <see cref="RateLimiter.Unlimited"/>, the default.
    /// </summary>
    /// <remarks>
    /// One limiter for the whole machine, not one per connection, because the link being
    /// protected is the machine's: two transfers at half the ceiling each are exactly as
    /// polite as one at the ceiling.
    /// </remarks>
    public RateLimiter Upload { get; set; } = RateLimiter.Unlimited;

    /// <summary>
    /// The discovery key this machine minted for a caller (docs/DISCOVERY.md), or null for a
    /// caller it does not announce to; null while discovery does not run here at all.
    /// </summary>
    /// <remarks>
    /// Set by the daemon, which owns the key store and the policy: a key goes only to a
    /// machine the person answered is their own, or to a person they allowed. Serving a key
    /// mints one when none exists, so the announcer's half of a lost store repairs itself.
    /// </remarks>
    public Func<string, string?>? DiscoveryKeyForCaller { get; set; }

    /// <summary>
    /// Why this machine is not serving peers, or null while it is listening.
    /// </summary>
    /// <remarks>
    /// A property of the machine, not of any one folder, and every folder's status reports it
    /// (<see cref="AutoSyncService.ServerFault"/>): a port that cannot be opened makes every
    /// folder on this machine invisible to every other machine, which is exactly as true of
    /// each of them. Null only while the listener is actually open, so a host that has not
    /// started, has failed or has stopped never reads as serving.
    /// </remarks>
    public string? Fault
    {
        get
        {
            lock (_gate)
            {
                return _listening ? null : _fault;
            }
        }
    }

    /// <summary>
    /// Test seam: runs when a peer has asked for a snapshot, before it is read.
    /// </summary>
    /// <remarks>
    /// Internal and for tests only. The race D-57 describes is a Simple-mode trim landing
    /// between a peer's request and the read that answers it, and the only way to show the
    /// answer is a clean "not found" is to delete the file in exactly that window. Production
    /// code never sets it.
    /// </remarks>
    internal Func<ContentHash, CancellationToken, Task>? BeforeSnapshotRead { get; set; }

    /// <summary>
    /// Test seam: runs when a peer has asked for a block, before it is read.
    /// </summary>
    /// <remarks>
    /// Internal and for tests only, for the same race as <see cref="BeforeSnapshotRead"/> on
    /// blocks: a collection deleting a block between a peer's request and the read that
    /// answers it. Production code never sets it.
    /// </remarks>
    internal Func<ContentHash, CancellationToken, Task>? BeforeBlockRead { get; set; }

    /// <summary>Creates a host that serves one repository, for <c>sip serve</c>.</summary>
    /// <param name="repository">The repository to serve.</param>
    /// <param name="identity">This machine's identity.</param>
    /// <param name="port">The port to listen on.</param>
    /// <param name="log">Optional sink for log lines.</param>
    /// <param name="tuning">The deadlines to serve under, or null for the defaults.</param>
    /// <returns>The host, with the repository registered. Disposing the host stops serving it.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public static PeerHost ForRepository(
        SipRepository repository,
        DeviceIdentity identity,
        int port,
        Action<string>? log = null,
        SyncTuning? tuning = null)
    {
        ArgumentNullException.ThrowIfNull(repository);

        var host = new PeerHost(identity, port, log, tuning);
        try
        {
            // Owned by the host from here: DisposeAsync stops every folder still registered.
            _ = host.Register(repository);
            return host;
        }
        catch
        {
            host.Dispose();
            throw;
        }
    }

    /// <summary>Starts serving a repository through this host.</summary>
    /// <param name="repository">The repository. Its peer list decides who may connect to it.</param>
    /// <returns>The registration. Dispose it to stop serving the repository.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="repository"/> was null.</exception>
    /// <exception cref="ObjectDisposedException">The host was disposed.</exception>
    /// <exception cref="RepositoryAlreadyServedException">
    /// Another folder on this machine already serves a repository with the same ID.
    /// </exception>
    /// <remarks>
    /// Folders register and unregister while the host runs, because the tray adds and removes
    /// them live. Two folders that are replicas of one repository cannot both be served from
    /// one port: a caller names the repository, not the folder, so there would be no way to
    /// say which one it meant. The second is refused, and says so.
    /// </remarks>
    public IAsyncDisposable Register(SipRepository repository)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var served = new ServedRepository(this, repository);

        lock (_gate)
        {
            if (_served.TryGetValue(served.RepositoryId, out var existing))
            {
                throw new RepositoryAlreadyServedException(
                    served.Name, existing.Repository.Layout.WorkingRoot);
            }

            _served.Add(served.RepositoryId, served);
        }

        Log($"serving '{served.Name}'");
        return served;
    }

    /// <summary>Whether a repository is registered with this host right now.</summary>
    /// <param name="repositoryId">The repository ID.</param>
    /// <returns>True when a connection asking for it would be routed to a folder.</returns>
    public bool IsServing(string repositoryId)
    {
        ArgumentNullException.ThrowIfNull(repositoryId);

        lock (_gate)
        {
            return _served.ContainsKey(repositoryId);
        }
    }

    /// <summary>
    /// Opens the listener and accepts connections in the background until disposed. A port
    /// that cannot be opened is recorded in <see cref="Fault"/>, not thrown.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The host was disposed.</exception>
    /// <remarks>
    /// For the daemon, which must go on saving every folder locally, and saying why nothing
    /// is served, when the port is taken. The listener is opened before this returns, so
    /// <see cref="Fault"/> and <see cref="Port"/> are settled by then.
    /// </remarks>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_listener is not null || _accepting is not null)
        {
            return;
        }

        TcpListener listener;
        try
        {
            listener = Bind();
        }
        catch (SocketException)
        {
            // Bind recorded and logged it. Nothing is served; every folder says so.
            return;
        }

        _accepting = AcceptInBackgroundAsync(listener, _stopping.Token);
    }

    /// <summary>Opens the listener and accepts connections until cancelled.</summary>
    /// <param name="cancellationToken">Stops the host.</param>
    /// <returns>A task that completes when the host has stopped and its connections have closed.</returns>
    /// <exception cref="ObjectDisposedException">The host was disposed.</exception>
    /// <exception cref="SocketException">The port could not be opened, or the listener failed.</exception>
    /// <remarks>
    /// For <c>sip serve</c> and for tests. The listener is opened before the returned task
    /// first waits, so <see cref="Port"/> is settled when this returns.
    /// </remarks>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var listener = Bind();

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stopping.Token);
        try
        {
            await AcceptAsync(listener, linked.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            RecordFault($"not serving peers: the listener failed: {ex.Message}");
            throw;
        }
        finally
        {
            await linked.CancelAsync().ConfigureAwait(false);
            await DrainAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Stops listening, stops serving every folder, and waits for connections to close.</summary>
    /// <returns>A task that completes when nothing is being served.</returns>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        StopListening();

        if (_accepting is not null)
        {
            await _accepting.ConfigureAwait(false);
        }

        List<ServedRepository> remaining;
        lock (_gate)
        {
            remaining = [.. _served.Values];
        }

        foreach (var served in remaining)
        {
            await served.DisposeAsync().ConfigureAwait(false);
        }

        await DrainAsync().ConfigureAwait(false);

        _disposed = true;
        _stopping.Dispose();
    }

    /// <summary>
    /// Stops listening and tells every connection to stop, without waiting for them.
    /// </summary>
    /// <remarks>
    /// Prefer <see cref="DisposeAsync"/>, which waits, whenever the repositories are about
    /// to be disposed too.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        StopListening();
        _disposed = true;
        _stopping.Dispose();
    }

    /// <summary>Writes a line to the host's log, if it has one.</summary>
    /// <param name="line">The line.</param>
    internal void Log(string line) => _log?.Invoke(line);

    /// <summary>Forgets a repository, so new connections asking for it are refused.</summary>
    /// <param name="served">The registration to remove.</param>
    internal void Remove(ServedRepository served)
    {
        lock (_gate)
        {
            if (_served.TryGetValue(served.RepositoryId, out var current) && ReferenceEquals(current, served))
            {
                _served.Remove(served.RepositoryId);
            }
        }
    }

    private ServedRepository? Resolve(string repositoryId)
    {
        lock (_gate)
        {
            return _served.GetValueOrDefault(repositoryId);
        }
    }

    private TcpListener Bind()
    {
        var listener = new TcpListener(IPAddress.Any, _requestedPort);
        try
        {
            listener.Start();
        }
        catch (SocketException ex)
        {
            listener.Dispose();

            var fault = $"not serving peers: port {_requestedPort} could not be opened ({ex.SocketErrorCode}): {ex.Message}";
            RecordFault(fault);

            // Logged outside the lock. The sink is someone else's code, and a callback run
            // while holding the lock is a deadlock waiting for the day it reads the status.
            Log(fault);
            throw;
        }

        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        lock (_gate)
        {
            _listener = listener;
            _listening = true;
            _fault = null;
        }

        Log($"serving on port {Port} as {_identity.ShortId}");
        return listener;
    }

    private void RecordFault(string fault)
    {
        lock (_gate)
        {
            _listening = false;
            _fault = fault;
        }
    }

    private void StopListening()
    {
        _stopping.Cancel();

        TcpListener? listener;
        lock (_gate)
        {
            listener = _listener;
            if (_listening)
            {
                _listening = false;
                _fault = "not serving peers: the server has stopped";
            }
        }

        listener?.Dispose();
    }

    /// <summary>
    /// Accepts in the background for <see cref="Start"/>, and records why it stopped if it
    /// ever stops on its own.
    /// </summary>
    /// <remarks>
    /// Nobody awaits this until shutdown, so an escaping exception would be unobserved: the
    /// machine would stop serving every folder while every status still said it was.
    /// </remarks>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Fault boundary for the daemon's accept loop, a background task whose exception would " +
                        "otherwise be unobserved until shutdown. The fault is recorded so every folder reports it.")]
    private async Task AcceptInBackgroundAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        try
        {
            // Returns by itself when the host is stopped; anything it throws is a failure.
            await AcceptAsync(listener, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            var fault = $"not serving peers: the listener failed: {ex.Message}";
            RecordFault(fault);
            Log(fault);
        }
    }

    private async Task AcceptAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);

                // Counted before it is handled, so the limits on unauthenticated connections
                // hold however fast they arrive.
                var pending = _admission.Admit(client.Client);

                // Each peer is handled independently: one bad connection must not stop the
                // daemon serving everyone else.
                Track(HandleClientSafelyAsync(client, pending, cancellationToken));
            }
        }
        catch (Exception ex) when (cancellationToken.IsCancellationRequested &&
                                   ex is OperationCanceledException or SocketException or ObjectDisposedException)
        {
            // Stopping cancels and then closes the listener, and a pending accept can report
            // either one first. Both are the host being asked to stop, not a failure.
            Log("server stopped");
        }
        finally
        {
            listener.Stop();
            lock (_gate)
            {
                if (_listening && ReferenceEquals(_listener, listener))
                {
                    _listening = false;
                    _fault = "not serving peers: the server has stopped";
                }
            }
        }
    }

    private void Track(Task connection)
    {
        lock (_gate)
        {
            _connections.Add(connection);
        }

        _ = connection.ContinueWith(
            finished =>
            {
                lock (_gate)
                {
                    _connections.Remove(finished);
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private async Task DrainAsync()
    {
        Task[] pending;
        lock (_gate)
        {
            pending = [.. _connections];
        }

        // Every connection runs inside its own fault boundary and never throws, so this only
        // waits; nothing it could raise is being ignored.
        await Task.WhenAll(pending).ConfigureAwait(false);
    }

    /// <summary>
    /// Handles one peer connection and never lets it take down the server.
    /// </summary>
    /// <remarks>
    /// This task is started without being awaited, so anything escaping it becomes an
    /// unobserved exception: invisible in a log, and torn down at a garbage collection
    /// rather than where it happened. Everything a connection can do wrong belongs here.
    /// </remarks>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Per-connection fault boundary on a task nobody awaits. One bad " +
                        "peer must not stop this machine serving the others.")]
    private async Task HandleClientSafelyAsync(
        TcpClient client,
        HandshakeAdmission.Admitted pending,
        CancellationToken cancellationToken)
    {
        using (client)
        {
            try
            {
                await HandleClientAsync(client, pending, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // The daemon is shutting down. Nothing to report.
            }
            catch (Exception ex)
            {
                // The bracketed fault is machine-readable and stable; the sentence after it
                // is prose and is expected to be reworded. They have different consumers —
                // the sentence is for whoever is reading a log, the code is for whatever is
                // matching on it — and different rates of change, so coupling the slower
                // guarantee to the faster text is how a test quietly stops testing.
                var fault = ex switch
                {
                    SipProtocolException protocol => protocol.Fault,
                    PeerStalledException => SipProtocolFault.PeerStalled,
                    _ => SipProtocolFault.Unspecified,
                };

                Log(ex switch
                {
                    SipProtocolException => $"refused a connection [{fault}]: {ex.Message}",
                    CorruptBlockException => $"dropped a connection [{fault}]: {ex.Message}",
                    PeerStalledException => $"dropped a stalled peer [{fault}]: {ex.Message}",
                    SocketException socket => $"socket error [{fault}]: {socket.SocketErrorCode}",
                    IOException => $"connection lost [{fault}]: {ex.Message}",
                    _ => $"dropped a connection [{fault}]: {ex.GetType().Name}: {ex.Message}",
                });
            }
        }
    }

    private async Task HandleClientAsync(
        TcpClient client,
        HandshakeAdmission.Admitted pending,
        CancellationToken cancellationToken)
    {
        var network = client.GetStream();
        await using var _ = network.ConfigureAwait(false);

        var (channel, served) = await HandshakeAsync(network, pending, cancellationToken).ConfigureAwait(false);

        using (channel)
        {
            try
            {
                await served.ServeConnectionAsync(channel, cancellationToken).ConfigureAwait(false);
            }
            catch (SipProtocolException ex)
            {
                // The handshake proved which machine this is, so what it sent wrong is its own.
                // Recorded, then handled as every connection's failure is.
                if (HealthFaults.FromProtocol(ex.Fault) is { } fault)
                {
                    Servers?.RecordFault(channel.PeerDeviceId, fault, ex.Message, served.Name);
                }

                throw;
            }
        }
    }

    /// <summary>
    /// Runs the responder's handshake under the deadline trickling cannot extend, and stops
    /// counting the connection as unauthenticated however the handshake ends.
    /// </summary>
    /// <exception cref="SipProtocolException">
    /// The handshake failed, ran past <see cref="SyncTuning.HandshakeDeadline"/>
    /// (<see cref="SipProtocolFault.HandshakeTimedOut"/>), or was shed to make room
    /// (<see cref="SipProtocolFault.HandshakeShed"/>).
    /// </exception>
    private async Task<(SecureChannel Channel, ServedRepository Served)> HandshakeAsync(
        NetworkStream network,
        HandshakeAdmission.Admitted pending,
        CancellationToken hostStopping)
    {
        (SecureChannel Channel, ServedRepository Served) accepted;
        bool stillCounted;

        // One deadline for the whole exchange, set once at accept and never restarted. The
        // stall deadline inside still applies to each frame; this is the one that bounds the
        // total (SEC-3).
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(hostStopping))
        {
            deadline.CancelAfter(Tuning.HandshakeDeadline);

            try
            {
                accepted = await SecureChannel.AcceptAsync(
                    network,
                    _identity,
                    Resolve,
                    static (repository, deviceId) => repository.IsKnownPeer(deviceId),
                    Tuning.StallTimeout,
                    deadline.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (pending.WasShed && !hostStopping.IsCancellationRequested)
            {
                // Its socket was closed under it, so what it threw is whatever a closed socket
                // throws. The reason is known, and is the fault.
                throw Shed(ex);
            }
            catch (OperationCanceledException ex) when (deadline.IsCancellationRequested && !hostStopping.IsCancellationRequested)
            {
                throw new SipProtocolException(
                    SipProtocolFault.HandshakeTimedOut,
                    $"The caller did not finish the handshake within {Tuning.HandshakeDeadline.TotalSeconds:0.#}s of connecting.",
                    ex);
            }
            finally
            {
                stillCounted = pending.Release();
            }
        }

        if (!stillCounted)
        {
            // Shed in the instant between finishing and being released. It was closed, so it
            // is not served.
            accepted.Channel.Dispose();
            throw Shed(null);
        }

        return accepted;
    }

    private SipProtocolException Shed(Exception? cause)
    {
        var message =
            $"The caller had not finished the handshake when the limit of {Tuning.MaximumPendingHandshakes} " +
            $"unauthenticated connections, or {Tuning.MaximumPendingHandshakesPerAddress} from one address, " +
            "was reached, and it was the oldest from the busiest address.";

        return cause is null
            ? new SipProtocolException(SipProtocolFault.HandshakeShed, message)
            : new SipProtocolException(SipProtocolFault.HandshakeShed, message, cause);
    }

}

/// <summary>
/// Thrown when a folder is registered with a <see cref="PeerHost"/> that already serves
/// another folder holding the same repository.
/// </summary>
public sealed class RepositoryAlreadyServedException : InvalidOperationException
{
    /// <summary>Creates the exception for one repository.</summary>
    /// <param name="repositoryName">The repository's name.</param>
    /// <param name="servingFolder">The folder that already serves it.</param>
    public RepositoryAlreadyServedException(string repositoryName, string servingFolder)
        : base(
            $"another folder on this machine, {servingFolder}, already serves '{repositoryName}', " +
            "and one machine can serve each repository from one folder only")
    {
        ServingFolder = servingFolder;
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">The message.</param>
    public RepositoryAlreadyServedException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying failure.</param>
    public RepositoryAlreadyServedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no detail.</summary>
    public RepositoryAlreadyServedException()
        : base("Another folder on this machine already serves this repository.")
    {
    }

    /// <summary>The folder that already serves the repository, when known.</summary>
    public string? ServingFolder { get; }
}
