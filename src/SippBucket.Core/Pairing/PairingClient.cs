using System.Net.Sockets;
using System.Security.Cryptography;
using SippBucket.Core.Crypto;
using SippBucket.Core.Model;
using SippBucket.Core.Protocol;
using SippBucket.Core.Repository;

namespace SippBucket.Core.Pairing;

/// <summary>Where and how a joining machine should become a replica.</summary>
public sealed record PairingJoinOptions
{
    /// <summary>The folder to become the replica. It must not already be a repository.</summary>
    public required string Directory { get; init; }

    /// <summary>Whether the replica keeps history.</summary>
    public RepositoryMode Mode { get; init; } = RepositoryMode.Power;

    /// <summary>What to call the offering machine in this replica's peer list.</summary>
    public string PeerName { get; init; } = "origin";

    /// <summary>The port this replica's daemon will serve on, told to the offering machine.</summary>
    public int ListenPort { get; init; } = RepositoryConfig.DefaultListenPort;

    /// <summary>
    /// Whether this end refuses an offering machine with its own device ID. Always true in
    /// the product.
    /// </summary>
    /// <remarks>
    /// Internal, and false only in the test that plays an older or altered joiner, which is
    /// how that test proves the offering machine refuses on its own.
    /// </remarks>
    internal bool RefuseOwnDevice { get; init; } = true;

    /// <summary>
    /// Told what the new replica recorded for the offering machine, and the record that
    /// replaced when the folder's peer list already named that device.
    /// </summary>
    /// <remarks>
    /// So the caller can say what it replaced, as <c>sip peer add</c> does (D-64). The replaced
    /// record is normally null: a new replica's peer list is new. It is not null when the
    /// folder held a <c>.sip</c> left over from an earlier repository, with its
    /// <c>peers.json</c> but no <c>config.json</c>.
    /// </remarks>
    public Action<PeerRecord, PeerRecord?>? Recorded { get; init; }
}

/// <summary>
/// Joins a repository by running the pairing exchange against a machine that has a window
/// open, with a spoken code or a pasted invitation.
/// </summary>
/// <remarks>
/// <para>
/// Nothing is written until the exchange has finished: both key confirmations verified, the
/// offering machine's identity checked, the repository received and authenticated. A
/// refusal of any kind leaves the folder exactly as it was, with no <c>.sip</c> in it.
/// </para>
/// <para>
/// The offering machine is recorded at the host this machine dialled — the string the user
/// typed or the invitation listed and the connection actually reached — never at an address
/// taken from a message. That was D-43: the old invite carried a host, the offering side
/// filled it with <c>127.0.0.1</c> by default, and two real machines paired and then could
/// not find each other.
/// </para>
/// </remarks>
public static class PairingClient
{
    /// <summary>How long to wait for a connection to one address.</summary>
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Joins with a code read out from the offering machine.</summary>
    /// <param name="host">The host to dial, as typed.</param>
    /// <param name="port">Its sync port; pairing is one above.</param>
    /// <param name="typedCode">Whatever the user typed.</param>
    /// <param name="identity">This machine's identity.</param>
    /// <param name="options">Where the replica goes and how it behaves.</param>
    /// <param name="cancellationToken">Cancels the attempt.</param>
    /// <returns>The new replica, with the offering machine recorded as a peer.</returns>
    /// <exception cref="ArgumentException">The code was not well formed.</exception>
    /// <exception cref="RepositoryAlreadyExistsException">The folder is already a repository.</exception>
    /// <exception cref="SipProtocolException">
    /// The code was not accepted (<see cref="SipProtocolFault.AuthenticationFailed"/>), the
    /// other machine speaks another pairing version
    /// (<see cref="SipProtocolFault.UnsupportedVersion"/>), or it sent something malformed.
    /// </exception>
    /// <exception cref="SocketException">The other machine could not be reached.</exception>
    public static async Task<SipRepository> JoinWithCodeAsync(
        string host,
        int port,
        string typedCode,
        DeviceIdentity identity,
        PairingJoinOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(options);

        // Before the network, so a mistyped code costs neither a connection nor one of the
        // five attempts on the other machine.
        if (!PairingCode.TryNormalise(typedCode, out var code))
        {
            throw new ArgumentException(
                $"A pairing code is {PairingCode.Length} characters from the printed " +
                "alphabet. Check it and try again.",
                nameof(typedCode));
        }

        EnsureNoRepository(options.Directory);

        var password = PairingSession.PasswordForCode(code);
        try
        {
            using var client = await ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
            return await RunAsync(
                client, host, password, identity, options, expectedOffererDeviceId: null, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
        }
    }

    /// <summary>Joins with a pasted <c>sip2_</c> invitation.</summary>
    /// <param name="invitation">The decoded invitation.</param>
    /// <param name="identity">This machine's identity.</param>
    /// <param name="options">Where the replica goes and how it behaves.</param>
    /// <param name="cancellationToken">Cancels the attempt.</param>
    /// <returns>The new replica, with the offering machine recorded as a peer.</returns>
    /// <exception cref="RepositoryAlreadyExistsException">The folder is already a repository.</exception>
    /// <exception cref="SipProtocolException">
    /// Not accepted, another pairing version, or <see cref="SipProtocolFault.WrongDevice"/>
    /// when the machine that answered is not the one that made the invitation.
    /// </exception>
    /// <exception cref="SocketException">None of the invitation's addresses could be reached.</exception>
    /// <remarks>
    /// Tries the invitation's addresses in order and runs the exchange on the first one that
    /// connects. Only a connection failure moves on to the next address; a refusal does not,
    /// because each exchange spends one of the other machine's five attempts.
    /// </remarks>
    public static async Task<SipRepository> JoinWithInvitationAsync(
        PairingInvitation invitation,
        DeviceIdentity identity,
        PairingJoinOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(invitation);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(options);

        if (invitation.Hosts.Count == 0)
        {
            throw new ArgumentException("The invitation lists no address to reach.", nameof(invitation));
        }

        EnsureNoRepository(options.Directory);

        var password = invitation.Password();
        try
        {
            var failures = new List<SocketException>();

            foreach (var host in invitation.Hosts)
            {
                using var client = await TryConnectAsync(host, invitation.Port, failures, cancellationToken)
                    .ConfigureAwait(false);

                if (client is null)
                {
                    continue;
                }

                return await RunAsync(
                    client, host, password, identity, options, invitation.DeviceId, cancellationToken)
                    .ConfigureAwait(false);
            }

            // Every address failed to connect. The last failure is the one reported; the
            // caller knows the list it tried.
            throw failures[^1];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
        }
    }

    private static void EnsureNoRepository(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        // Checked before dialling as well as by Join afterwards: finding out only after the
        // other machine has spent its code on us would waste the code.
        var layout = new RepositoryLayout(directory);
        if (layout.Exists)
        {
            throw new RepositoryAlreadyExistsException(layout.WorkingRoot);
        }
    }

    /// <summary>Connects, or records why not and returns null so the next address can be tried.</summary>
    private static async Task<TcpClient?> TryConnectAsync(
        string host,
        int port,
        List<SocketException> failures,
        CancellationToken cancellationToken)
    {
        try
        {
            return await ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            failures.Add(ex);
            return null;
        }
    }

    private static async Task<TcpClient> ConnectAsync(
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        var client = new TcpClient();

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(ConnectTimeout);

        try
        {
            await client.ConnectAsync(host, port + PairingServer.PortOffset, deadline.Token)
                .ConfigureAwait(false);
            return client;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            client.Dispose();
            throw new SocketException((int)SocketError.TimedOut);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static async Task<SipRepository> RunAsync(
        TcpClient client,
        string dialledHost,
        byte[] password,
        DeviceIdentity identity,
        PairingJoinOptions options,
        string? expectedOffererDeviceId,
        CancellationToken cancellationToken)
    {
        var stream = client.GetStream();
        await using var _ = stream.ConfigureAwait(false);

        // 1 and 2: versions, and the session identifier from both nonces.
        var nonce = RandomNumberGenerator.GetBytes(PairingProtocol.NonceSize);
        await PairingProtocol.WriteAsync(
            stream,
            new PairingHello { Protocol = PairingProtocol.Version, Nonce = nonce },
            cancellationToken).ConfigureAwait(false);

        var reply = await PairingProtocol.ReadAsync<PairingHelloReply>(stream, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new SipProtocolException(
                "The other machine closed the connection without answering. An older " +
                "SippBucket pairs differently and does exactly this; if that is the case, " +
                "update both machines to the same version. Otherwise check the address and port.");

        if (reply.Protocol != PairingProtocol.Version)
        {
            throw new SipProtocolException(
                SipProtocolFault.UnsupportedVersion,
                $"The other machine pairs with protocol {reply.Protocol}; this one speaks " +
                $"{PairingProtocol.Version}. Update SippBucket so both run the same version, " +
                "then pair again. Nothing was sent and nothing was written.");
        }

        if (reply.Nonce is not { Length: PairingProtocol.NonceSize })
        {
            throw Malformed();
        }

        var sessionId = PairingProtocol.SessionId(nonce, reply.Nonce);

        // 3: this machine's CPace message.
        using var party = CPaceParty.Start(
            CPaceRole.Initiator,
            password,
            PairingProtocol.ChannelIdentifier,
            sessionId,
            PairingProtocol.JoinerAssociatedData);

        await PairingProtocol.WriteAsync(
            stream,
            new PairingShareMessage { Share = party.Share, AssociatedData = party.AssociatedData },
            cancellationToken).ConfigureAwait(false);

        // 4: the answer, and the offering machine's proof that it holds the same code. Every
        // refusal — wrong, expired, used up, closed — fails here and looks the same.
        var answer = await PairingProtocol.ReadAsync<PairingAnswer>(stream, cancellationToken)
            .ConfigureAwait(false);

        if (answer?.Share is null ||
            answer.Confirmation is null ||
            answer.AssociatedData is null ||
            !answer.AssociatedData.AsSpan().SequenceEqual(PairingProtocol.OffererAssociatedData))
        {
            throw NotAccepted();
        }

        using var keys = party.Complete(answer.Share, answer.AssociatedData) ?? throw NotAccepted();

        if (!keys.IsRemoteTagValid(answer.Confirmation))
        {
            throw NotAccepted();
        }

        if (!PairingProtocol.TryOpen<OffererIdentity>(
                answer.Sealed, keys.Isk, sessionId, PairingProtocol.Purpose.OffererIdentity, out var offerer) ||
            !PairingProtocol.IsDeviceId(offerer.DeviceId))
        {
            throw new SipProtocolException(
                SipProtocolFault.AuthenticationFailed,
                "The other machine proved the code but its identity did not verify, which " +
                "means something between the two machines altered it. Nothing was written.");
        }

        // The invitation named a machine; this is the one that answered, under a key only
        // the holder of the secret could produce. Checked before this machine says anything
        // about itself, so a stranger who somehow has the secret learns nothing more.
        if (expectedOffererDeviceId is not null &&
            !string.Equals(expectedOffererDeviceId, offerer.DeviceId, StringComparison.OrdinalIgnoreCase))
        {
            throw new SipProtocolException(
                SipProtocolFault.WrongDevice,
                $"The machine that answered ({offerer.DeviceId![..12]}) is not the one that " +
                $"made this invite ({expectedOffererDeviceId[..Math.Min(12, expectedOffererDeviceId.Length)]}). " +
                "Nothing was written. Someone else may be answering at that address.");
        }

        // Never with itself, and said before this machine says anything about itself.
        if (options.RefuseOwnDevice && DeviceIdentity.IsSameDevice(offerer.DeviceId, identity.DeviceId))
        {
            throw new SipProtocolException(
                SipProtocolFault.WrongDevice,
                $"The machine that answered has this machine's own device ID ({identity.DeviceId[..12]}). " +
                "A machine cannot pair with itself: two machines with one device ID means device.key " +
                "was copied, for example by cloning a disk or restoring another machine's settings. " +
                "Nothing was written.");
        }

        // 5: this machine's confirmation and identity.
        await PairingProtocol.WriteAsync(
            stream,
            new PairingConfirmation
            {
                Confirmation = keys.OwnTag,
                Sealed = PairingProtocol.Seal(
                    new JoinerIdentity
                    {
                        DeviceId = identity.DeviceId,
                        MachineName = Environment.MachineName,
                        ListenPort = options.ListenPort,
                    },
                    keys.Isk,
                    sessionId,
                    PairingProtocol.Purpose.JoinerIdentity),
            },
            cancellationToken).ConfigureAwait(false);

        // 6: the repository, or a refusal with nothing in it.
        var result = await PairingProtocol.ReadAsync<PairingResultMessage>(stream, cancellationToken)
            .ConfigureAwait(false);

        if (result is null || !result.Accepted)
        {
            throw NotAccepted();
        }

        if (!PairingProtocol.TryOpen<RepositoryInvite>(
                result.Sealed, keys.Isk, sessionId, PairingProtocol.Purpose.Repository, out var invite) ||
            !IsUsable(invite, offerer.DeviceId!))
        {
            throw new SipProtocolException(
                SipProtocolFault.AuthenticationFailed,
                "The folder's details did not verify under the pairing key. Nothing was written.");
        }

        return SipRepository.Join(
            options.Directory,
            invite,
            dialledHost,
            options.Mode,
            options.PeerName,
            options.ListenPort,
            options.Recorded);
    }

    private static bool IsUsable(RepositoryInvite invite, string offererDeviceId)
    {
        if (string.IsNullOrWhiteSpace(invite.RepositoryId) ||
            string.IsNullOrWhiteSpace(invite.Name) ||
            !PairingProtocol.IsPort(invite.Port) ||
            !string.Equals(invite.DeviceId, offererDeviceId, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // The ring travels whole (D-70): the current key and every older one must each be a
        // repository key, and the list is bounded like the wire's own.
        if (invite.PreviousKeys is null || invite.RevokedDevices is null ||
            invite.PreviousKeys.Count >= Protocol.KeyUpdateMessage.MaximumKeys ||
            invite.RevokedDevices.Count > Protocol.KeyUpdateMessage.MaximumRevoked)
        {
            return false;
        }

        return IsRepositoryKey(invite.EncryptionKey) && invite.PreviousKeys.All(IsRepositoryKey);
    }

    private static bool IsRepositoryKey(string? stored)
    {
        var key = new byte[RepositoryCipher.KeySize + 3];
        try
        {
            return stored is not null &&
                   Convert.TryFromBase64String(stored, key, out var written) &&
                   written == RepositoryCipher.KeySize;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static SipProtocolException NotAccepted() =>
        new(SipProtocolFault.AuthenticationFailed, PairingProtocol.NotAcceptedMessage);

    private static SipProtocolException Malformed() =>
        new(SipProtocolFault.MalformedMessage, "The other machine's pairing answer was malformed.");
}
