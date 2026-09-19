using System.Globalization;
using System.Net.Sockets;
using System.Security.Claims;
using Microsoft.DevTunnels.Ssh;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using SippBucket.Core.Crypto;
using SippBucket.Core.Repository;

namespace SippBucket.Core.Push.Ssh;

/// <summary>
/// The sending side of one Direct Push delivery: an SSH connection to a paired machine, proved
/// both ways, with the delivery channel open.
/// </summary>
/// <remarks>
/// <para>
/// <b>The receiving machine's key is checked against the pairing record</b>, never trusted on
/// first use (docs/DIRECT-PUSH.md, rule 3): the host key must be the device key of the machine
/// that was dialled, or the connection ends before this machine proves anything about itself.
/// There is no "trust this machine?" question to click through. Then this machine logs in with
/// its own device key, and opens the one delivery channel.
/// </para>
/// <para>
/// The whole of that runs under <see cref="PushTuning.HandshakeDeadline"/>, after the connect
/// deadline. The channel is a <see cref="PushChannelStream"/>, so the receiving machine is held
/// to its window and to the stall deadline as the listener holds the sender.
/// </para>
/// </remarks>
public sealed class PushLink : IAsyncDisposable, IDisposable
{
    private readonly TcpClient _client;
    private readonly SshClientSession _session;
    private readonly PushChannelStream _channel;
    private readonly TimeSpan _stallTimeout;
    private bool _disposed;

    private PushLink(TcpClient client, SshClientSession session, PushChannelStream channel, string deviceId, TimeSpan stallTimeout)
    {
        _client = client;
        _session = session;
        _channel = channel;
        _stallTimeout = stallTimeout;
        DeviceId = deviceId;
    }

    /// <summary>The receiving machine's device ID, as its key proved.</summary>
    public string DeviceId { get; }

    /// <summary>The delivery channel.</summary>
    public Stream Channel => _channel;

    /// <summary>Connects to a paired machine and opens the delivery channel.</summary>
    /// <param name="identity">This machine's identity: its device key logs in. Borrowed.</param>
    /// <param name="host">The receiving machine's address or name.</param>
    /// <param name="port">Its Direct Push port.</param>
    /// <param name="deviceId">The device ID it was paired as: the only host key accepted.</param>
    /// <param name="tuning">The deadlines, or null for the defaults.</param>
    /// <param name="cancellationToken">Cancels the connection.</param>
    /// <returns>The open link. Dispose it to close the connection.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="ArgumentException">
    /// The host is blank, the device ID is not a well-formed device ID, or it is this machine's own.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">The port is not a TCP port, or a deadline is not positive.</exception>
    /// <exception cref="PushException">
    /// The machine could not be reached (<see cref="PushFault.Unreachable"/>), answered with
    /// another key (<see cref="PushFault.WrongDevice"/>), did not accept this machine's key
    /// (<see cref="PushFault.NotAccepted"/>), is busy (<see cref="PushFault.Busy"/>), refused the
    /// channel (<see cref="PushFault.ChannelRefused"/>), took too long
    /// (<see cref="PushFault.HandshakeTimedOut"/>), or the session failed
    /// (<see cref="PushFault.SessionFailed"/>).
    /// </exception>
    public static async Task<PushLink> ConnectAsync(
        DeviceIdentity identity,
        string host,
        int port,
        string deviceId,
        PushTuning? tuning = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(port);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, System.Net.IPEndPoint.MaxPort);

        if (!PeerRegistry.IsWellFormedDeviceId(deviceId))
        {
            throw new ArgumentException("The machine to push to must be named by its 64-character device ID.", nameof(deviceId));
        }

        if (DeviceIdentity.IsSameDevice(deviceId, identity.DeviceId))
        {
            throw new ArgumentException("A machine does not push to itself.", nameof(deviceId));
        }

        var chosen = tuning ?? PushTuning.Default;
        chosen.Validate(nameof(tuning));

        var client = await ConnectTcpAsync(host, port, chosen, cancellationToken).ConfigureAwait(false);
        SshClientSession? session = null;

        try
        {
            session = new SshClientSession(PushSsh.CreateConfiguration(), PushSsh.CreateTrace());

            var check = new HostKeyCheck(deviceId);
            session.Authenticating += check.OnAuthenticating;
            session.ChannelOpening += RefuseChannel;
            session.Request += RefuseSessionRequest;

            var channel = await HandshakeAsync(client, session, identity, check, chosen, cancellationToken).ConfigureAwait(false);
            return new PushLink(client, session, channel, check.ProvedDeviceId ?? deviceId, chosen.StallTimeout);
        }
        catch
        {
            session?.Dispose();
            client.Dispose();
            throw;
        }
    }

    /// <summary>Closes the connection, telling the other side it was deliberate.</summary>
    /// <returns>A task that completes when the connection is closed.</returns>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        try
        {
            if (!_session.IsClosed)
            {
                // The goodbye is a courtesy: a machine that will not take even that is not waited
                // on past the stall deadline.
                await _session
                    .CloseAsync(SshDisconnectReason.ByApplication, "done")
                    .WaitAsync(_stallTimeout)
                    .ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or SshConnectionException or SocketException or
                                       TimeoutException)
        {
            // The other side may already have gone; the connection is being closed either way.
        }
        finally
        {
            await _channel.DisposeAsync().ConfigureAwait(false);
            _session.Dispose();
            _client.Dispose();
        }
    }

    /// <summary>Closes the connection at once.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _channel.Dispose();
        _session.Dispose();
        _client.Dispose();
    }

    /// <summary>Connects the socket under the connect deadline, which the operating system's own does not respect.</summary>
    private static async Task<TcpClient> ConnectTcpAsync(
        string host,
        int port,
        PushTuning tuning,
        CancellationToken cancellationToken)
    {
        var client = new TcpClient();

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(tuning.ConnectTimeout);

        try
        {
            await client.ConnectAsync(host, port, deadline.Token).ConfigureAwait(false);
            return client;
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            client.Dispose();
            throw new PushException(
                PushFault.Unreachable,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{host}:{port} did not accept a connection within {tuning.ConnectTimeout.TotalSeconds:0.#}s."),
                ex);
        }
        catch (SocketException ex)
        {
            client.Dispose();
            throw new PushException(
                PushFault.Unreachable,
                $"{host}:{port} could not be reached ({ex.SocketErrorCode}): {ex.Message}",
                ex);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    /// <summary>
    /// The SSH handshake, both logins and the channel, under one deadline that also closes the
    /// socket when it passes.
    /// </summary>
    private static async Task<PushChannelStream> HandshakeAsync(
        TcpClient client,
        SshClientSession session,
        DeviceIdentity identity,
        HostKeyCheck check,
        PushTuning tuning,
        CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var closeOnDeadline = deadline.Token.Register(static socket => ((Socket)socket!).Dispose(), client.Client);
        deadline.CancelAfter(tuning.HandshakeDeadline);

        // Used only to log in, which is over before this returns.
        using var userKey = SshEd25519Key.ForDevice(identity);

        SshChannel channel;
        try
        {
            await session.ConnectAsync(client.GetStream(), deadline.Token).ConfigureAwait(false);

            var credentials = new SshClientCredentials(PushSsh.UserName, userKey);
            if (!await session.AuthenticateAsync(credentials, deadline.Token).ConfigureAwait(false))
            {
                throw check.ProvedDeviceId is null ? WrongDevice(check, null) : NotAccepted(check, null);
            }

            channel = await session.OpenChannelAsync(PushSsh.PushChannelType, deadline.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not PushException &&
                                   deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            // The deadline closed the socket, so whatever this is, the deadline is the reason.
            throw new PushException(
                PushFault.HandshakeTimedOut,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{Short(check.ExpectedDeviceId)} did not finish the handshake within {tuning.HandshakeDeadline.TotalSeconds:0.#}s."),
                ex);
        }
        catch (SshChannelException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw ex.OpenFailureReason == SshChannelOpenFailureReason.ResourceShortage
                ? new PushException(PushFault.Busy, $"{Short(check.ExpectedDeviceId)} is busy receiving: {ex.Message}", ex)
                : new PushException(PushFault.ChannelRefused, $"{Short(check.ExpectedDeviceId)} refused the delivery: {ex.Message}", ex);
        }
        catch (SshConnectionException ex) when (!cancellationToken.IsCancellationRequested &&
                                                ex.DisconnectReason == SshDisconnectReason.HostKeyNotVerifiable)
        {
            throw WrongDevice(check, ex);
        }
        catch (SshConnectionException ex) when (!cancellationToken.IsCancellationRequested &&
                                                ex.DisconnectReason == SshDisconnectReason.NoMoreAuthMethodsAvailable)
        {
            // The receiving machine ends the session on the first key it refuses.
            throw NotAccepted(check, ex);
        }
        catch (Exception ex) when (ex is not PushException && !cancellationToken.IsCancellationRequested)
        {
            throw new PushException(
                PushFault.SessionFailed,
                $"The connection to {Short(check.ExpectedDeviceId)} failed during the handshake: {ex.Message}",
                ex);
        }

        channel.Request += RefuseChannelRequest;
        return new PushChannelStream(channel, tuning.StallTimeout);
    }

    private static PushException WrongDevice(HostKeyCheck check, Exception? cause)
    {
        var offered = check.OfferedDeviceId is { } key ? $" (it offered {Short(key)})" : string.Empty;
        var message =
            $"The machine that answered is not {Short(check.ExpectedDeviceId)}: its key is not the one it was paired " +
            $"with{offered}. Nothing was sent.";

        return cause is null
            ? new PushException(PushFault.WrongDevice, message)
            : new PushException(PushFault.WrongDevice, message, cause);
    }

    private static PushException NotAccepted(HostKeyCheck check, Exception? cause)
    {
        var message =
            $"{Short(check.ExpectedDeviceId)} did not accept this machine's key. It may no longer be paired with this " +
            "machine, or it takes pushes only from its owner's own machines while team features are off there. " +
            "Nothing was sent.";

        return cause is null
            ? new PushException(PushFault.NotAccepted, message)
            : new PushException(PushFault.NotAccepted, message, cause);
    }

    private static string Short(string deviceId) => deviceId.Length > 12 ? deviceId[..12] : deviceId;

    /// <summary>The receiving machine never opens a channel to the sender.</summary>
    private static void RefuseChannel(object? sender, SshChannelOpeningEventArgs e)
    {
        if (e.IsRemoteRequest)
        {
            e.FailureReason = SshChannelOpenFailureReason.AdministrativelyProhibited;
            e.FailureDescription = "A Direct Push sender accepts no channels.";
        }
    }

    /// <summary>Refuses every global request from the receiving machine.</summary>
    private static void RefuseSessionRequest(object? sender, SshRequestEventArgs<SessionRequestMessage> e) =>
        e.IsAuthorized = false;

    /// <summary>Refuses every request on the delivery channel.</summary>
    private static void RefuseChannelRequest(object? sender, SshRequestEventArgs<ChannelRequestMessage> e) =>
        e.IsAuthorized = false;

    /// <summary>Accepts the receiving machine's host key only when it is the paired device key.</summary>
    private sealed class HostKeyCheck
    {
        private readonly Lock _gate = new();
        private string? _offered;
        private string? _proved;

        public HostKeyCheck(string expectedDeviceId)
        {
            ExpectedDeviceId = expectedDeviceId;
        }

        public string ExpectedDeviceId { get; }

        /// <summary>The key the machine that answered presented, whether or not it was accepted.</summary>
        public string? OfferedDeviceId
        {
            get
            {
                lock (_gate)
                {
                    return _offered;
                }
            }
        }

        /// <summary>The paired device ID, once the host key has proved to be it.</summary>
        public string? ProvedDeviceId
        {
            get
            {
                lock (_gate)
                {
                    return _proved;
                }
            }
        }

        public void OnAuthenticating(object? sender, SshAuthenticatingEventArgs e)
        {
            // The library has already verified that the server holds the key's private half: the
            // key exchange's signature checked out before this is asked.
            if (e.AuthenticationType != SshAuthenticationType.ServerPublicKey || e.PublicKey is not SshEd25519Key key)
            {
                return;
            }

            var offered = key.DeviceId;
            lock (_gate)
            {
                _offered = offered;

                if (!DeviceIdentity.IsSameDevice(offered, ExpectedDeviceId))
                {
                    return;
                }

                _proved = offered;
            }

            e.AuthenticationTask = Task.FromResult<ClaimsPrincipal?>(new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim(ClaimTypes.NameIdentifier, offered)],
                SshEd25519.AlgorithmName)));
        }
    }
}
