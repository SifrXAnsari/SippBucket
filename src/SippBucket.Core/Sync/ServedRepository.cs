using SippBucket.Core.Hashing;
using SippBucket.Core.Platform;
using SippBucket.Core.Protocol;
using SippBucket.Core.Repository;
using SippBucket.Core.Servers;

namespace SippBucket.Core.Sync;

/// <summary>
/// One repository as a <see cref="PeerHost"/> serves it: the requests a peer may make of it,
/// answered on a connection the host has already authenticated for it.
/// </summary>
/// <remarks>
/// <para>
/// The server only ever answers questions: what is your head, where did it come from, give
/// me this snapshot, give me these blocks. It never writes to the local repository on a
/// peer's instruction, so a compromised or buggy peer cannot change anything here — it can
/// only be refused. For the same reason it never takes the folder's
/// <see cref="OperationLock"/>: it reads the store while a save, a sync or a collection
/// changes it. That is safe because blocks and snapshots are write-once under
/// content-addressed names and reach those names only by a rename once they are whole, so a
/// read finds all of one or none of it; and each is read once, with "not here" decided by
/// that read, so one trimmed or collected away after the request arrived is answered as not
/// found (D-57) rather than dropping the connection.
/// </para>
/// <para>
/// This was <c>PeerServer</c>, which also owned a listener of its own on the repository's
/// port. Every folder the tray created had the same port, so only the first could be served
/// (D-40). The listener is the host's now, one per machine; what is left here is what was
/// always per repository.
/// </para>
/// <para>
/// Disposing it is how a folder stops being served: the host forgets it, so a new connection
/// asking for it is refused as if it had never been served here, and every connection already
/// open for it is closed and waited for, so the repository can be disposed straight after.
/// </para>
/// </remarks>
internal sealed class ServedRepository : IAsyncDisposable
{
    private readonly PeerHost _host;
    private readonly Lock _gate = new();
    private readonly CancellationTokenSource _stopping = new();
    private TaskCompletionSource? _drained;
    private int _connections;
    private bool _stopped;

    /// <summary>Wraps a repository for serving. The host registers it.</summary>
    /// <param name="host">The host that serves it.</param>
    /// <param name="repository">The repository.</param>
    public ServedRepository(PeerHost host, SipRepository repository)
    {
        _host = host;
        Repository = repository;
        RepositoryId = repository.Config.RepositoryId;
        Name = repository.Config.Name;
    }

    /// <summary>The repository being served.</summary>
    public SipRepository Repository { get; }

    /// <summary>The ID a caller asks for this repository by.</summary>
    public string RepositoryId { get; }

    /// <summary>The repository's display name, for log lines.</summary>
    public string Name { get; }

    /// <summary>Whether a device may use this repository.</summary>
    /// <param name="deviceId">A device ID the handshake has proved.</param>
    /// <returns>
    /// True when it is in the peer list, its membership has not expired, and no rotation has
    /// revoked it (D-70). A revoked device is refused even if a hand edit put it back in the
    /// list, because revocation is what a removal promised.
    /// </returns>
    public bool IsKnownPeer(string deviceId) =>
        !Repository.IsRevoked(deviceId) &&
        Repository.Peers.Load().Any(p =>
            string.Equals(p.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
            !p.IsExpired(DateTimeOffset.UtcNow));

    /// <summary>Answers one peer's requests until it says goodbye, goes idle, or this stops.</summary>
    /// <param name="channel">The channel the host opened for this repository.</param>
    /// <param name="hostStopping">Stops the whole host.</param>
    /// <returns>A task that completes when the connection is finished with.</returns>
    public async Task ServeConnectionAsync(SecureChannel channel, CancellationToken hostStopping)
    {
        var peer = _host.Servers?.NameOf(channel.PeerDeviceId) ?? channel.PeerDeviceId[..12];

        if (!TryEnter())
        {
            // Resolved during the handshake, and stopped being served before it finished.
            _host.Log($"peer {peer} connected as '{Name}' stopped being served; closed the connection");
            return;
        }

        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(hostStopping, _stopping.Token);

            _host.Log($"peer {peer} connected to '{Name}'");

            try
            {
                await AnswerAsync(channel, linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_stopping.IsCancellationRequested && !hostStopping.IsCancellationRequested)
            {
                _host.Log($"peer {peer} disconnected: '{Name}' is no longer served here");
                return;
            }

            _host.Log($"peer {peer} disconnected from '{Name}'");
        }
        finally
        {
            Exit();
        }
    }

    /// <summary>Stops serving this repository and waits for its open connections to close.</summary>
    /// <returns>A task that completes when nothing is serving it any more.</returns>
    public async ValueTask DisposeAsync()
    {
        _host.Remove(this);

        Task drained;
        lock (_gate)
        {
            if (_stopped)
            {
                return;
            }

            _stopped = true;
            if (_connections == 0)
            {
                drained = Task.CompletedTask;
            }
            else
            {
                _drained = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                drained = _drained.Task;
            }
        }

        await _stopping.CancelAsync().ConfigureAwait(false);
        await drained.ConfigureAwait(false);
        _stopping.Dispose();

        _host.Log($"stopped serving '{Name}'");
    }

    private bool TryEnter()
    {
        lock (_gate)
        {
            if (_stopped)
            {
                return false;
            }

            _connections++;
            return true;
        }
    }

    private void Exit()
    {
        lock (_gate)
        {
            _connections--;
            if (_connections == 0)
            {
                _drained?.TrySetResult();
            }
        }
    }

    private async Task AnswerAsync(SecureChannel channel, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            // The idle timeout, not the stall timeout: between requests the peer is usually
            // busy writing the last batch to disk, and hanging up on it for that would be a
            // failure that only shows on large transfers.
            var message = await channel
                .ReceiveAsync(_host.Tuning.IdleTimeout, cancellationToken)
                .ConfigureAwait(false);

            if (message is null || message.Type == MessageType.Goodbye)
            {
                return;
            }

            await ServeAsync(channel, message, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ServeAsync(
        SecureChannel channel,
        ReceivedMessage message,
        CancellationToken cancellationToken)
    {
        switch (message.Type)
        {
            case MessageType.HeadRequest:
                await channel.SendAsync(
                    MessageType.HeadResponse,
                    new HeadResponseMessage
                    {
                        SnapshotId = Repository.GetHead(),
                        RepositoryName = Repository.Config.Name,
                    },
                    cancellationToken).ConfigureAwait(false);
                break;

            case MessageType.SnapshotRequest:
                await ServeSnapshotAsync(channel, message, cancellationToken).ConfigureAwait(false);
                break;

            case MessageType.AncestryRequest:
                await ServeAncestryAsync(channel, message, cancellationToken).ConfigureAwait(false);
                break;

            case MessageType.BlockRequest:
                await ServeBlocksAsync(channel, message, cancellationToken).ConfigureAwait(false);
                break;

            case MessageType.HaveRequest:
                await ServeHaveAsync(channel, message, cancellationToken).ConfigureAwait(false);
                break;

            case MessageType.ServerRecordRequest:
                await ServeServerRecordAsync(channel, message, cancellationToken).ConfigureAwait(false);
                break;

            case MessageType.KeyStatusRequest:
                await ServeKeyStatusAsync(channel, message, cancellationToken).ConfigureAwait(false);
                break;

            case MessageType.KeyUpdatePush:
                await TakeKeyUpdateAsync(channel, message, cancellationToken).ConfigureAwait(false);
                break;

            case MessageType.DiscoveryKeyRequest:
                // The key this machine minted for this caller (docs/DISCOVERY.md), or nothing
                // for a caller it does not announce to. The daemon's policy decides; with no
                // policy set, discovery does not run here and the answer is empty.
                await channel.SendAsync(
                    MessageType.DiscoveryKeyResponse,
                    new DiscoveryKeyResponseMessage
                    {
                        KeyBase64 = _host.DiscoveryKeyForCaller?.Invoke(channel.PeerDeviceId),
                    },
                    cancellationToken).ConfigureAwait(false);
                break;

            default:
                await channel.SendAsync(
                    MessageType.Error,
                    new ErrorMessage { Reason = $"{message.Type} is not a request this side serves." },
                    cancellationToken).ConfigureAwait(false);
                break;
        }
    }

    /// <summary>Answers a snapshot request with the snapshot, or with "not found".</summary>
    /// <remarks>
    /// One read, and its absence is the answer (D-57). This used to ask whether the file
    /// existed and then read it; a Simple-mode save trims every snapshot but the newest, and
    /// one that landed between the two turned "I do not have that", an answer the peer knows
    /// what to do with, into a dropped connection.
    /// </remarks>
    private async Task ServeSnapshotAsync(
        SecureChannel channel,
        ReceivedMessage message,
        CancellationToken cancellationToken)
    {
        var request = SecureChannel.Decode<SnapshotRequestMessage>(message);

        if (_host.BeforeSnapshotRead is { } beforeRead)
        {
            await beforeRead(request.SnapshotId, cancellationToken).ConfigureAwait(false);
        }

        // As stored: a canonical snapshot goes as its header, and the peer fetches the trees it
        // lacks as blocks, so an unchanged folder is never sent again (D-23).
        var snapshot = await Repository.TryGetStoredSnapshotAsync(request.SnapshotId, cancellationToken)
            .ConfigureAwait(false);

        await channel.SendAsync(
            MessageType.SnapshotResponse,
            new SnapshotResponseMessage { SnapshotId = request.SnapshotId, Snapshot = snapshot },
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Answers one page of a peer's walk back through this replica's history.
    /// </summary>
    /// <remarks>
    /// Served from the ancestry index, not the snapshot files, so a Simple replica can say
    /// where its head came from after the snapshots on the way have been trimmed. The
    /// request is a peer's input and bounded like one: too many starting points is refused
    /// outright, and the page size is clamped rather than trusted, so one request costs at
    /// most <see cref="AncestryRequestMessage.MaximumLimit"/> entries of work however it is
    /// worded.
    /// </remarks>
    private async Task ServeAncestryAsync(
        SecureChannel channel,
        ReceivedMessage message,
        CancellationToken cancellationToken)
    {
        var request = SecureChannel.Decode<AncestryRequestMessage>(message);

        if (request.From is null || request.From.Count > AncestryRequestMessage.MaximumRoots)
        {
            throw new SipProtocolException(
                SipProtocolFault.MalformedMessage,
                $"The peer asked for ancestry from {request.From?.Count ?? 0} snapshots; " +
                $"at most {AncestryRequestMessage.MaximumRoots} are served per request.");
        }

        var limit = Math.Clamp(request.Limit, 1, AncestryRequestMessage.MaximumLimit);

        await channel.SendAsync(
            MessageType.AncestryResponse,
            new AncestryResponseMessage { Entries = Repository.Ancestry.Walk(request.From, limit) },
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Takes a caller's Server.ID record and answers with this machine's, when each is the
    /// other's person's own machine.
    /// </summary>
    /// <remarks>
    /// The one request that writes anything on a peer's say-so, and it writes only this
    /// machine's directory of the person's servers, never the folder. What is written is
    /// guidance: nothing in it grants trust or changes what is synced. A host with no exchange
    /// set, and a caller the person has not said is theirs, get an empty answer, so a Server.ID
    /// never reaches another person's machine.
    /// </remarks>
    private async Task ServeServerRecordAsync(
        SecureChannel channel,
        ReceivedMessage message,
        CancellationToken cancellationToken)
    {
        var request = SecureChannel.Decode<ServerExchangeMessage>(message);
        var answer = ServerExchangeMessage.Nothing;

        if (_host.Servers is { } servers)
        {
            servers.Take(channel.PeerDeviceId, request, Name);
            answer = servers.For(channel.PeerDeviceId);
        }

        await channel.SendAsync(MessageType.ServerRecordResponse, answer, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Answers where this folder's key ring stands, carrying the whole ring only to a caller
    /// that is behind (D-70).
    /// </summary>
    private async Task ServeKeyStatusAsync(
        SecureChannel channel,
        ReceivedMessage message,
        CancellationToken cancellationToken)
    {
        var request = SecureChannel.Decode<KeyStatusRequestMessage>(message);
        var generation = Repository.KeyGeneration;

        var answer = new KeyStatusResponseMessage
        {
            Generation = generation,
            Update = request.Generation < generation
                ? new KeyUpdateMessage { Keys = Repository.KeyRing, Revoked = Repository.RevokedDevices }
                : null,
        };

        await channel.SendAsync(MessageType.KeyStatusResponse, answer, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Takes a rotation a caller learned before this machine did, and answers with the ring's
    /// state afterwards (D-70). The second request that writes anything on a peer's say-so,
    /// and like the first it writes guidance and configuration, never the folder's files.
    /// </summary>
    private async Task TakeKeyUpdateAsync(
        SecureChannel channel,
        ReceivedMessage message,
        CancellationToken cancellationToken)
    {
        var update = SecureChannel.Decode<KeyUpdateMessage>(message);

        if (update.Keys is null || update.Revoked is null)
        {
            throw new SipProtocolException(
                SipProtocolFault.MalformedMessage, "A key update named no ring or no revoked list.");
        }

        _ = Repository.ApplyKeyUpdate(update.Keys, update.Revoked, _host.Log);

        await channel.SendAsync(
            MessageType.KeyStatusResponse,
            new KeyStatusResponseMessage { Generation = Repository.KeyGeneration },
            cancellationToken).ConfigureAwait(false);
    }

    private async Task ServeBlocksAsync(
        SecureChannel channel,
        ReceivedMessage message,
        CancellationToken cancellationToken)
    {
        var request = SecureChannel.Decode<BlockRequestMessage>(message);

        // The serving side needs Keep Alive too. A peer pulling a large folder from this
        // machine is relying on it staying awake, and nothing about being the source
        // counts as local activity that Windows would notice. Held only for the duration
        // of an actual block batch, never for the head or snapshot requests that a mere
        // poll consists of.
        using var keepAwake = SleepBlocker.Hold($"serving {request.Hashes.Count} block(s)");

        // One response per requested hash, in order, so the caller can match them up
        // without needing correlation IDs.
        foreach (var hash in request.Hashes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_host.BeforeBlockRead is { } beforeRead)
            {
                await beforeRead(hash, cancellationToken).ConfigureAwait(false);
            }

            // One read, and its absence is the answer, as for snapshots (D-57): a block the
            // collector removed after the request arrived is "not found", not a dropped
            // connection.
            var raw = await Repository.Blobs.TryGetRawAsync(hash, cancellationToken).ConfigureAwait(false);

            // Politeness before speed (D-29): the ceiling is the machine's, in master.json,
            // and the default is no ceiling at all.
            await _host.Upload.WaitAsync(ContentHash.SizeInBytes + (raw?.Length ?? 0), cancellationToken)
                .ConfigureAwait(false);

            // As raw bytes (D-45): base64 in JSON inflated every transfer by about 44%.
            await channel.SendAsync(
                MessageType.BlockData,
                new ReadOnlyMemory<byte>(BlockWire.Encode(hash, raw)),
                cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Answers which of the asked-about blocks this store holds (D-28): the question a
    /// caller asks before fetching, so a block this machine lacks routes the fetch to a
    /// machine that has it instead of failing it a round trip later.
    /// </summary>
    private async Task ServeHaveAsync(
        SecureChannel channel,
        ReceivedMessage message,
        CancellationToken cancellationToken)
    {
        var request = SecureChannel.Decode<HaveRequestMessage>(message);

        if (request.Hashes is null || request.Hashes.Count > HaveRequestMessage.MaximumHashes)
        {
            throw new SipProtocolException(
                SipProtocolFault.MalformedMessage,
                $"The peer asked whether {request.Hashes?.Count ?? 0} blocks are held; " +
                $"at most {HaveRequestMessage.MaximumHashes} are answered per request.");
        }

        var present = new bool[request.Hashes.Count];
        for (var i = 0; i < present.Length; i++)
        {
            present[i] = Repository.Blobs.Contains(request.Hashes[i]);
        }

        await channel.SendAsync(
            MessageType.HaveResponse,
            new HaveResponseMessage { Present = present },
            cancellationToken).ConfigureAwait(false);
    }
}
