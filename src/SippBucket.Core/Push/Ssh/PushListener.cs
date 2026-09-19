using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using Microsoft.DevTunnels.Ssh;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using SippBucket.Core.Crypto;
using SippBucket.Core.Protocol;

namespace SippBucket.Core.Push.Ssh;

/// <summary>
/// Direct Push's SSH server: SippBucket's own, on its own port, accepting deliveries from paired
/// machines and nothing else (docs/DIRECT-PUSH.md, rules 1 to 3).
/// </summary>
/// <remarks>
/// <para>
/// <b>What a connection must do, in order, within <see cref="PushTuning.HandshakeDeadline"/>
/// of being accepted:</b> the SSH version lines and key exchange, with only the algorithms
/// <see cref="PushSsh"/> lists; the server proves this machine's device key; the caller proves
/// its own with a <c>publickey</c> login as <see cref="PushSsh.UserName"/>; the key must be one
/// the caller lookup accepts; and the caller opens one channel of type
/// <see cref="PushSsh.PushChannelType"/>. Only then is anything handed to the delivery handler.
/// </para>
/// <para>
/// <b>Refused, whatever else happens:</b> every other authentication method, which the library
/// refuses before any SippBucket code runs; a key the lookup does not accept; a key query, which
/// would tell a stranger whether a key is paired here; every other channel type, the standard
/// <c>session</c> channel included, so no shell, command or subsystem can be asked for; a
/// second channel on one connection; every request on the channel and every global request,
/// port forwarding included. Nothing of any of these reaches a file.
/// </para>
/// <para>
/// <b>Bounded before authentication</b> (SEC-3, as sync is): a deadline on the whole handshake
/// that a trickle of bytes cannot extend, and <see cref="HandshakeAdmission"/>'s limits on
/// unfinished handshakes, machine-wide and per address. After authentication:
/// <see cref="PushTuning.MaximumSessions"/> deliveries at once, each held to its flow-control
/// window by <see cref="PushChannelStream"/> and to the stall deadline on every read and write.
/// </para>
/// <para>
/// <b>When it runs</b> is its owner's decision: only while Direct Push or team features are on
/// (approval condition 5). Each connection has its own fault boundary, so one bad caller never
/// stops the others.
/// </para>
/// </remarks>
public sealed class PushListener : IAsyncDisposable, IDisposable
{
    /// <summary>
    /// The smallest window SSH can work with: one packet of the library's default size, 32 KiB,
    /// which the channel refuses to go below. The master config's own minimum is far above it.
    /// </summary>
    private const long SmallestWindow = 32 * 1024;

    private readonly SshEd25519Key _hostKey;
    private readonly int _requestedPort;
    private readonly uint _window;
    private readonly Func<string, PushCaller?> _callers;
    private readonly Func<PushCaller, Stream, CancellationToken, Task> _deliver;
    private readonly Action<string>? _log;
    private readonly HandshakeAdmission _admission;
    private readonly Lock _gate = new();
    private readonly HashSet<Task> _connections = [];
    private readonly CancellationTokenSource _stopping = new();

    private TcpListener? _listener;
    private Task? _accepting;
    private int _sessions;
    private string? _fault;
    private bool _listening;
    private bool _disposed;

    /// <summary>Creates a listener. Call <see cref="Start"/> to listen.</summary>
    /// <param name="identity">This machine's identity: its device key is the SSH host key. Borrowed.</param>
    /// <param name="settings">The <c>push</c> settings: the port, and the flow-control window.</param>
    /// <param name="callers">
    /// Decides whether a key that has proved itself may push here: the caller for its device ID,
    /// or null to refuse it. Called once per connection, off the network thread, and may read
    /// files.
    /// </param>
    /// <param name="deliver">
    /// Receives each delivery once the caller is authenticated and its channel is open. The
    /// stream is the channel; the connection closes when the task completes.
    /// </param>
    /// <param name="log">Optional sink for log lines.</param>
    /// <param name="tuning">The deadlines and limits, or null for the defaults.</param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The port is not a TCP port, the window is outside what SSH can carry, or a deadline or
    /// limit is not positive.
    /// </exception>
    public PushListener(
        DeviceIdentity identity,
        PushSettings settings,
        Func<string, PushCaller?> callers,
        Func<PushCaller, Stream, CancellationToken, Task> deliver,
        Action<string>? log = null,
        PushTuning? tuning = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(callers);
        ArgumentNullException.ThrowIfNull(deliver);
        ArgumentOutOfRangeException.ThrowIfNegative(settings.Port, nameof(settings));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(settings.Port, IPEndPoint.MaxPort, nameof(settings));

        // SSH's window is a 32-bit count, and must hold at least one packet (RFC 4254 section 5.2).
        ArgumentOutOfRangeException.ThrowIfLessThan(settings.WindowBytes, SmallestWindow, nameof(settings));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(settings.WindowBytes, uint.MaxValue, nameof(settings));

        var chosen = tuning ?? PushTuning.Default;
        chosen.Validate(nameof(tuning));

        _hostKey = SshEd25519Key.ForDevice(identity);
        _requestedPort = settings.Port;
        _window = checked((uint)settings.WindowBytes);
        _callers = callers;
        _deliver = deliver;
        _log = log;
        Tuning = chosen;
        _admission = new HandshakeAdmission(chosen.MaximumPendingHandshakes, chosen.MaximumPendingHandshakesPerAddress);
        _fault = "Direct Push is not listening: it has not started";
    }

    /// <summary>The port the listener is actually on, or 0 before it has bound one.</summary>
    public int Port { get; private set; }

    /// <summary>The deadlines and limits connections run under.</summary>
    public PushTuning Tuning { get; }

    /// <summary>Why Direct Push is not listening, or null while it is.</summary>
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

    /// <summary>How many connections are still in the handshake.</summary>
    public int PendingHandshakes => _admission.Count;

    /// <summary>How many deliveries are arriving now.</summary>
    public int ActiveSessions => Volatile.Read(ref _sessions);

    /// <summary>
    /// Opens the port and accepts connections in the background until disposed. A port that
    /// cannot be opened is recorded in <see cref="Fault"/>, not thrown.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The listener was disposed.</exception>
    /// <remarks>The port is opened before this returns, so <see cref="Fault"/> and <see cref="Port"/> are settled.</remarks>
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
            // Bind recorded and logged it.
            return;
        }

        _accepting = AcceptInBackgroundAsync(listener, _stopping.Token);
    }

    /// <summary>Stops listening and waits for every connection to end.</summary>
    /// <returns>A task that completes when nothing is being received.</returns>
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

        await DrainAsync().ConfigureAwait(false);

        _disposed = true;
        _stopping.Dispose();
        _hostKey.Dispose();
    }

    /// <summary>Stops listening and tells every connection to stop, without waiting for them.</summary>
    /// <remarks>Prefer <see cref="DisposeAsync"/>, which waits.</remarks>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        StopListening();
        _disposed = true;
        _stopping.Dispose();
        _hostKey.Dispose();
    }

    private void Log(string line) => _log?.Invoke(line);

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

            var fault = $"Direct Push is not listening: port {_requestedPort} could not be opened ({ex.SocketErrorCode}): {ex.Message}";
            RecordFault(fault);
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

        Log(string.Create(CultureInfo.InvariantCulture, $"Direct Push listening on port {Port}"));
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
                _fault = "Direct Push is not listening: it has stopped";
            }
        }

        listener?.Dispose();
    }

    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Fault boundary for the accept loop, a background task whose exception would otherwise " +
                        "be unobserved until shutdown. The fault is recorded so status reports it.")]
    private async Task AcceptInBackgroundAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        try
        {
            await AcceptAsync(listener, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            var fault = $"Direct Push is not listening: the listener failed: {ex.Message}";
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

                // Counted before it is handled, so the limits hold however fast connections arrive.
                var admitted = _admission.Admit(client.Client);
                Track(HandleConnectionSafelyAsync(client, admitted, cancellationToken));
            }
        }
        catch (Exception ex) when (cancellationToken.IsCancellationRequested &&
                                   ex is OperationCanceledException or SocketException or ObjectDisposedException)
        {
            Log("Direct Push stopped listening");
        }
        finally
        {
            listener.Stop();
            lock (_gate)
            {
                if (_listening && ReferenceEquals(_listener, listener))
                {
                    _listening = false;
                    _fault = "Direct Push is not listening: it has stopped";
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
        Task[] running;
        lock (_gate)
        {
            running = [.. _connections];
        }

        // Every connection runs inside its own fault boundary and never throws.
        await Task.WhenAll(running).ConfigureAwait(false);
    }

    /// <summary>Handles one connection and never lets it take down the listener.</summary>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Per-connection fault boundary on a task nobody awaits. One bad caller must not stop " +
                        "this machine receiving from the others.")]
    private async Task HandleConnectionSafelyAsync(
        TcpClient client,
        HandshakeAdmission.Admitted admitted,
        CancellationToken stopping)
    {
        using (client)
        {
            var connection = new Connection(this, admitted.Address);

            try
            {
                await HandleConnectionAsync(client, admitted, connection, stopping).ConfigureAwait(false);
            }
            catch (Exception) when (stopping.IsCancellationRequested)
            {
                // Shutting down: the socket was closed or the token cancelled under whatever it
                // was doing, and that is not a fault to report.
            }
            catch (Exception ex)
            {
                Log(connection.Describe(ex));
            }
            finally
            {
                connection.End();
            }
        }
    }

    private async Task HandleConnectionAsync(
        TcpClient client,
        HandshakeAdmission.Admitted admitted,
        Connection connection,
        CancellationToken stopping)
    {
        var network = client.GetStream();
        await using var networkOwned = network.ConfigureAwait(false);

        using var session = new SshServerSession(PushSsh.CreateConfiguration(), PushSsh.CreateTrace());
        session.Credentials = new SshServerCredentials(_hostKey);
        session.Authenticating += connection.OnAuthenticating;
        session.ChannelOpening += connection.OnChannelOpening;
        session.Request += RefuseSessionRequest;

        bool stillCounted;

        // One deadline for the whole handshake, set once at accept and never restarted (SEC-3).
        // When it passes, the socket is closed as well as the token cancelled, so the handshake
        // ends even where the library is waiting on something the token does not reach.
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(stopping))
        using (deadline.Token.Register(static socket => ((Socket)socket!).Dispose(), client.Client))
        {
            deadline.CancelAfter(Tuning.HandshakeDeadline);

            try
            {
                await session.ConnectAsync(network, deadline.Token).ConfigureAwait(false);
                _ = await session.AcceptChannelAsync(PushSsh.PushChannelType, deadline.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (admitted.WasShed && !stopping.IsCancellationRequested)
            {
                // Its socket was closed under it, so what it threw is whatever a closed socket
                // throws. The reason is known, and is the fault.
                throw Shed(ex);
            }
            catch (Exception ex) when (deadline.IsCancellationRequested && !stopping.IsCancellationRequested)
            {
                // Whatever the closed socket or the cancelled token made it throw, the deadline is
                // the reason.
                throw new PushException(
                    PushFault.HandshakeTimedOut,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"The caller did not finish the handshake within {Tuning.HandshakeDeadline.TotalSeconds:0.#}s of connecting."),
                    ex);
            }
            finally
            {
                stillCounted = admitted.Release();
            }
        }

        if (!stillCounted)
        {
            // Shed in the instant between finishing and being released. It was closed, so it is
            // not served.
            throw Shed(null);
        }

        var (caller, channel) = connection.Delivery
            ?? throw new PushException(PushFault.ChannelRefused, "The delivery channel opened without being accepted.");

        await using (channel.ConfigureAwait(false))
        {
            Log($"receiving from {caller.Name} ({ShortId(caller.DeviceId)})");
            await _deliver(caller, channel, stopping).ConfigureAwait(false);
        }

        if (session.IsClosed)
        {
            // The sender closed first, as it may once it has what it waited for.
            return;
        }

        try
        {
            // The goodbye is a courtesy: a sender that will not take even that is not waited on
            // past the stall deadline, and disposing the session closes the socket regardless.
            await session
                .CloseAsync(SshDisconnectReason.ByApplication, "done")
                .WaitAsync(Tuning.StallTimeout, stopping)
                .ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            Log($"{caller.Name} did not take the end of the delivery; closing the connection anyway");
        }
        catch (Exception ex) when (ex is SshConnectionException or ObjectDisposedException or IOException or SocketException)
        {
            // The sender closed in the same moment. The delivery was already complete.
        }
    }

    private PushException Shed(Exception? cause)
    {
        // One interpolated expression: concatenating pieces inside string.Create loses the
        // interpolation-handler conversion, and the call stops compiling.
        var message = string.Create(
            CultureInfo.InvariantCulture,
            $"The caller had not finished the handshake when the limit of {_admission.Maximum} unauthenticated connections, or {_admission.MaximumPerAddress} from one address, was reached, and it was the oldest from the busiest address.");

        return cause is null
            ? new PushException(PushFault.HandshakeShed, message)
            : new PushException(PushFault.HandshakeShed, message, cause);
    }

    private bool TryTakeSession()
    {
        while (true)
        {
            var current = Volatile.Read(ref _sessions);
            if (current >= Tuning.MaximumSessions)
            {
                return false;
            }

            if (Interlocked.CompareExchange(ref _sessions, current + 1, current) == current)
            {
                return true;
            }
        }
    }

    private void ReturnSession() => Interlocked.Decrement(ref _sessions);

    private static string ShortId(string deviceId) => deviceId.Length > 12 ? deviceId[..12] : deviceId;

    /// <summary>Refuses every global request: port forwarding, keep-alives, anything.</summary>
    private static void RefuseSessionRequest(object? sender, SshRequestEventArgs<SessionRequestMessage> e) =>
        e.IsAuthorized = false;

    /// <summary>Refuses every request on the delivery channel: shells, commands, environment, anything.</summary>
    private static void RefuseChannelRequest(object? sender, SshRequestEventArgs<ChannelRequestMessage> e) =>
        e.IsAuthorized = false;

    /// <summary>One connection's state, which the session's handlers fill in as the handshake goes.</summary>
    /// <remarks>
    /// The handlers run on the session's own task and the connection's handler reads the result
    /// on another, so everything here is under <see cref="_gate"/>.
    /// </remarks>
    private sealed class Connection
    {
        private readonly PushListener _listener;
        private readonly IPAddress _address;
        private readonly Lock _gate = new();
        private PushCaller? _caller;
        private string? _refusedDeviceId;
        private (PushCaller Caller, PushChannelStream Channel)? _delivery;
        private bool _channelAsked;
        private bool _holdsSession;

        public Connection(PushListener listener, IPAddress address)
        {
            _listener = listener;
            _address = address;
        }

        /// <summary>The accepted caller and its channel, once the channel has opened.</summary>
        public (PushCaller Caller, PushChannelStream Channel)? Delivery
        {
            get
            {
                lock (_gate)
                {
                    return _delivery;
                }
            }
        }

        /// <summary>
        /// Decides a <c>publickey</c> login. The library has already refused every other method
        /// and verified the signature; this decides whether the key is welcome.
        /// </summary>
        public void OnAuthenticating(object? sender, SshAuthenticatingEventArgs e)
        {
            // A query (no signature) is never answered: it would tell a stranger whether a key is
            // paired here. A SippBucket client always signs.
            if (e.AuthenticationType != SshAuthenticationType.ClientPublicKey ||
                !string.Equals(e.Username, PushSsh.UserName, StringComparison.Ordinal) ||
                e.PublicKey is not SshEd25519Key key)
            {
                return;
            }

            var deviceId = key.DeviceId;
            e.AuthenticationTask = Task.Run(() => Decide(deviceId));
        }

        /// <summary>Opens the one delivery channel, and refuses every other.</summary>
        public void OnChannelOpening(object? sender, SshChannelOpeningEventArgs e)
        {
            if (!e.IsRemoteRequest)
            {
                return;
            }

            if (!string.Equals(e.Request.ChannelType, PushSsh.PushChannelType, StringComparison.Ordinal))
            {
                e.FailureReason = SshChannelOpenFailureReason.UnknownChannelType;
                e.FailureDescription = "This server accepts Direct Push deliveries and nothing else.";
                return;
            }

            lock (_gate)
            {
                // The library refuses channels before authentication; this holds even if it did not.
                if (_caller is null)
                {
                    e.FailureReason = SshChannelOpenFailureReason.AdministrativelyProhibited;
                    e.FailureDescription = "Authenticate first.";
                    return;
                }

                if (_channelAsked)
                {
                    e.FailureReason = SshChannelOpenFailureReason.AdministrativelyProhibited;
                    e.FailureDescription = "One delivery per connection.";
                    return;
                }

                _channelAsked = true;

                if (!_listener.TryTakeSession())
                {
                    e.FailureReason = SshChannelOpenFailureReason.ResourceShortage;
                    e.FailureDescription =
                        "This machine is receiving as many deliveries as it takes at once. Try again shortly.";
                    return;
                }

                _holdsSession = true;

                // Before the channel is confirmed, so the window the caller is given is this one,
                // and so the stream is reading before the first byte can arrive.
                e.Channel.MaxWindowSize = _listener._window;

                // The pinned 3.12.42 keeps its receive-credit counter at the construction
                // default when MaxWindowSize is lowered here, in the one place lowering it
                // is valid - so it believes this side still holds a megabyte of credit, and
                // the first window adjustment would only go out after more data than the
                // sender's shrunken window can ever have in flight: every delivery larger
                // than one window deadlocked at exactly the window. Spending the phantom
                // credit re-syncs the counter to what the confirmation actually advertises,
                // and stays under the send threshold, so nothing goes on the wire. Verified
                // against the decompiled 3.12.42 (AdjustWindow: subtract, then send only at
                // half-window); the version pin the library was approved under is what makes
                // relying on that shape sound.
                if (SshChannel.DefaultMaxWindowSize > _listener._window)
                {
                    e.Channel.AdjustWindow(SshChannel.DefaultMaxWindowSize - _listener._window);
                }

                e.Channel.Request += RefuseChannelRequest;
                _delivery = (_caller, new PushChannelStream(e.Channel, _listener.Tuning.StallTimeout));
            }
        }

        /// <summary>
        /// Ends the connection's claim on the listener: gives back its delivery slot, and stops
        /// reading its channel. Safe to call more than once.
        /// </summary>
        public void End()
        {
            PushChannelStream? channel;
            bool heldSession;

            lock (_gate)
            {
                channel = _delivery?.Channel;
                heldSession = _holdsSession;
                _holdsSession = false;
            }

            channel?.Dispose();

            if (heldSession)
            {
                _listener.ReturnSession();
            }
        }

        /// <summary>The log line for a connection that ended in a fault.</summary>
        public string Describe(Exception ex)
        {
            string? refused;
            lock (_gate)
            {
                refused = _refusedDeviceId;
            }

            // A key that was turned away ends the session from the library's side, so what the
            // handler sees is a closed session; the refusal is the reason.
            var fault = refused is not null
                ? PushFault.NotAccepted
                : ex switch
                {
                    PushException push => push.Fault,
                    PeerStalledException => PushFault.PeerStalled,
                    _ => PushFault.SessionFailed,
                };

            var who = refused is not null
                ? $"{_address}, key {ShortId(refused)} not accepted"
                : _address.ToString();

            return ex switch
            {
                _ when refused is not null => $"refused a Direct Push connection from {who} [{fault}]",
                PushException => $"refused a Direct Push connection from {who} [{fault}]: {ex.Message}",
                PeerStalledException => $"dropped a stalled Direct Push connection from {who} [{fault}]: {ex.Message}",
                SocketException socket => $"Direct Push socket error from {who} [{fault}]: {socket.SocketErrorCode}",
                _ => $"dropped a Direct Push connection from {who} [{fault}]: {ex.GetType().Name}: {ex.Message}",
            };
        }

        [SuppressMessage(
            "Design",
            "CA1031:Do not catch general exception types",
            Justification = "The lookup reads the peer lists, which a person edits by hand; whatever it throws, " +
                            "the key is refused and the reason logged, rather than failing the session some other way.")]
        private ClaimsPrincipal? Decide(string deviceId)
        {
            PushCaller? caller;
            try
            {
                caller = _listener._callers(deviceId);
            }
            catch (Exception ex)
            {
                _listener.Log($"Direct Push could not check key {ShortId(deviceId)}, so refused it: {ex.Message}");
                caller = null;
            }

            lock (_gate)
            {
                if (caller is null || !DeviceIdentity.IsSameDevice(caller.DeviceId, deviceId))
                {
                    _refusedDeviceId = deviceId;
                    return null;
                }

                _caller = caller;
            }

            return new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim(ClaimTypes.NameIdentifier, deviceId)],
                SshEd25519.AlgorithmName));
        }
    }
}
