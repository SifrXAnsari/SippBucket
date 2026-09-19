using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using SippBucket.Core.Crypto;
using SippBucket.Core.Machines;
using SippBucket.Core.Push;
using SippBucket.Core.Push.Ssh;

namespace SippBucket.Core.Messages;

/// <summary>Where one target machine of a message can be reached now.</summary>
/// <param name="DeviceId">The machine.</param>
/// <param name="Name">The name this machine knows it by.</param>
/// <param name="Host">Its address, from the pairing record that synced most recently.</param>
/// <param name="Port">Its Direct Push port.</param>
public sealed record MessageRoute(string DeviceId, string Name, string Host, int Port);

/// <summary>
/// The sending side of Direct Messages: store-and-forward, at the sender
/// (docs/DIRECT-MESSAGES.md, "No central server holds anything").
/// </summary>
/// <remarks>
/// <para>
/// A queued message waits in the store until each of the person's machines can be reached.
/// Each machine gets its own signed copy under the same message ID — the recipient device is
/// inside the signed bytes, so one machine's copy can never be replayed to another — and the
/// message ID is what makes a retry harmless at the far end. The status never claims more
/// than a receipt proved: <em>Delivered</em> from the first machine that confirmed, checked,
/// saved and flushed; <em>Not accepted</em> only for a refusal the receiving machine stated;
/// <em>Sending</em> for everything else, unreachable and blocked alike, which the sender
/// cannot tell apart and so must not pretend to.
/// </para>
/// <para>
/// One connection per target and cycle carries every message owed to it, oldest first. A
/// failure records why on the target and moves on: the next cycle tries again, and a message
/// is never dropped by not arriving.
/// </para>
/// </remarks>
public sealed class MessageDelivery
{
    private readonly MessageStore _store;
    private readonly DeviceIdentity _identity;
    private readonly Func<bool> _teamOn;
    private readonly Func<string, MessageRoute?> _routeTo;
    private readonly PushTuning _tuning;
    private readonly Action<string>? _log;
    private readonly TimeProvider _time;

    /// <summary>Creates the sending side.</summary>
    /// <param name="store">Where messages wait and their statuses live.</param>
    /// <param name="identity">This machine's identity: what signs each copy. Borrowed.</param>
    /// <param name="teamOn">Whether team features are on here, read per attempt: both ends must have them on.</param>
    /// <param name="routeTo">Where a target machine can be reached now, or null while it cannot.</param>
    /// <param name="tuning">The deadlines, or null for the defaults.</param>
    /// <param name="log">Optional sink for log lines.</param>
    /// <param name="time">The clock, or null for the system's.</param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public MessageDelivery(
        MessageStore store,
        DeviceIdentity identity,
        Func<bool> teamOn,
        Func<string, MessageRoute?> routeTo,
        PushTuning? tuning = null,
        Action<string>? log = null,
        TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(teamOn);
        ArgumentNullException.ThrowIfNull(routeTo);

        var chosen = tuning ?? PushTuning.Default;
        chosen.Validate(nameof(tuning));

        _store = store;
        _identity = identity;
        _teamOn = teamOn;
        _routeTo = routeTo;
        _tuning = chosen;
        _log = log;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Writes a message into the queue, to a person, for every machine of theirs named.</summary>
    /// <param name="personKey">The conversation: the recipient's person scope key.</param>
    /// <param name="targetDevices">Their machines.</param>
    /// <param name="text">The text.</param>
    /// <param name="attachments">The Direct Push files it names, already read for their hashes.</param>
    /// <returns>The queued message, status <see cref="MessageStatus.Sending"/>.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="ArgumentException">No target was named, or a field is over the format's ceiling.</exception>
    /// <exception cref="InvalidOperationException">Team features are off here: both ends must have them on.</exception>
    /// <exception cref="IOException">The store could not be written. Nothing was queued.</exception>
    public StoredMessage Queue(
        string personKey,
        IReadOnlyList<string> targetDevices,
        string text,
        IReadOnlyList<DmAttachment> attachments)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(personKey);
        ArgumentNullException.ThrowIfNull(targetDevices);
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(attachments);

        if (!_teamOn())
        {
            throw new InvalidOperationException(
                "Direct messages are a team feature, and team features are off on this machine. 'sip team' says why.");
        }

        if (targetDevices.Count == 0)
        {
            throw new ArgumentException("A message goes to a person's machines; none were named.", nameof(targetDevices));
        }

        var message = new DirectMessage
        {
            MessageId = DirectMessage.NewMessageId(),
            SenderDeviceId = _identity.DeviceId,
            RecipientDeviceId = targetDevices[0],
            CreatedUtc = _time.GetUtcNow(),
            Text = text,
            Attachments = attachments,
        };

        // Encoding now surfaces a text or attachment over the format's ceiling here, at the
        // keyboard, rather than at the first delivery attempt.
        _ = DmWire.EncodeBody(message);

        return _store.QueueSent(message, personKey, targetDevices, _time.GetUtcNow());
    }

    /// <summary>
    /// Tries to deliver everything still owed: each target machine gets one connection
    /// carrying its messages, oldest first. What the daemon runs on its timer, and
    /// <c>sip dm</c> runs once after queueing.
    /// </summary>
    /// <param name="cancellationToken">Stops between messages; the message in flight finishes or fails.</param>
    /// <returns>How many copies were confirmed delivered in this pass.</returns>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Per-target fault boundary on a background pass: one unreachable or misbehaving machine " +
                        "must not stop the messages owed to the others, and the failure is recorded on the target " +
                        "and shown by 'sip messages', never swallowed.")]
    public async Task<int> DeliverPendingAsync(CancellationToken cancellationToken = default)
    {
        if (!_teamOn())
        {
            return 0;
        }

        var pending = _store.Load(out _)
            .Where(message => message.Direction == MessageDirection.Sent && message.Status != MessageStatus.Delivered)
            .SelectMany(message => message.Targets
                .Where(target => !target.Delivered)
                .Select(target => (Message: message, target.DeviceId)))
            .GroupBy(owed => owed.DeviceId, StringComparer.OrdinalIgnoreCase);

        var delivered = 0;
        foreach (var target in pending)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var owed = target
                .Select(pair => pair.Message)
                .OrderBy(message => message.Message.CreatedUtc)
                .ToList();

            if (_routeTo(target.Key) is not { } route)
            {
                continue;
            }

            try
            {
                delivered += await DeliverToAsync(route, owed, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                RecordAttemptFailure(owed, route, ex.Message);
            }
        }

        return delivered;
    }

    private async Task<int> DeliverToAsync(MessageRoute route, IReadOnlyList<StoredMessage> owed, CancellationToken cancellationToken)
    {
        var link = await PushLink.ConnectAsync(_identity, route.Host, route.Port, route.DeviceId, _tuning, cancellationToken)
            .ConfigureAwait(false);

        var delivered = 0;
        await using (link.ConfigureAwait(false))
        {
            foreach (var stored in owed)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // This machine's copy for this machine of theirs: the recipient is inside the
                // signed bytes, so each target's copy is addressed and signed for it alone.
                var copy = stored.Message with { RecipientDeviceId = route.DeviceId };
                var body = DmWire.EncodeBody(copy);
                var signature = DmWire.Sign(_identity, body);

                await PushWire.WriteAsync(
                    link.Channel,
                    new MessageOffer(copy.MessageId, body.Length, signature),
                    _tuning.StallTimeout,
                    cancellationToken).ConfigureAwait(false);

                var answer = await PushWire.ReadAsync(link.Channel, _tuning.StallTimeout, cancellationToken).ConfigureAwait(false)
                    as MessageAnswer
                    ?? throw new PushException(PushFault.UnexpectedMessage, $"{route.Name} did not answer the message offer.");

                if (answer.Refusal != MessageRefusal.None)
                {
                    RecordRefusal(stored, route, answer.Refusal, answer.Detail);
                    continue;
                }

                await link.Channel.WriteAsync(body, cancellationToken).ConfigureAwait(false);

                var receipt = await PushWire.ReadAsync(link.Channel, _tuning.StallTimeout, cancellationToken).ConfigureAwait(false)
                    as MessageReceipt
                    ?? throw new PushException(PushFault.UnexpectedMessage, $"{route.Name} did not answer with a receipt.");

                if (!string.Equals(receipt.MessageId, copy.MessageId, StringComparison.OrdinalIgnoreCase))
                {
                    throw new PushException(
                        PushFault.UnexpectedMessage, $"{route.Name} answered with a receipt for another message.");
                }

                if (receipt.Delivered)
                {
                    delivered++;
                    RecordDelivered(stored, route);
                    Log($"a message to {route.Name} was delivered");
                }
                else
                {
                    RecordRefusal(stored, route, receipt.Refusal, receipt.Detail);
                }
            }
        }

        return delivered;
    }

    private void RecordDelivered(StoredMessage stored, MessageRoute route) =>
        _store.UpdateSent(stored.Message.MessageId, current =>
        {
            var targets = current.Targets
                .Select(target => DeviceIdentity.IsSameDevice(target.DeviceId, route.DeviceId)
                    ? target with { Delivered = true, LastError = null }
                    : target)
                .ToList();

            // Delivered from the first machine that confirmed: the person has it. The other
            // machines' copies keep going in the background (docs/DIRECT-MESSAGES.md; the
            // one-of-their-machines default is recorded there).
            return current with
            {
                Targets = targets,
                Status = MessageStatus.Delivered,
                StatusDetail = string.Empty,
                StatusUtc = _time.GetUtcNow(),
            };
        });

    private void RecordRefusal(StoredMessage stored, MessageRoute route, MessageRefusal refusal, string detail) =>
        _store.UpdateSent(stored.Message.MessageId, current =>
        {
            var why = refusal switch
            {
                MessageRefusal.TooLarge => "too large",
                MessageRefusal.TooManyTooFast => "too many too fast",
                MessageRefusal.SignatureRejected => "signature rejected",
                _ => "not accepted",
            };
            var line = detail.Length == 0 ? why : $"{why}: {DisplayTextSafe(detail)}";

            var targets = current.Targets
                .Select(target => DeviceIdentity.IsSameDevice(target.DeviceId, route.DeviceId)
                    ? target with { LastError = line }
                    : target)
                .ToList();

            // Delivered anywhere outranks refused somewhere; a refusal only speaks while no
            // machine has confirmed.
            return current.Status == MessageStatus.Delivered
                ? current with { Targets = targets }
                : current with
                {
                    Targets = targets,
                    Status = MessageStatus.NotAccepted,
                    StatusDetail = line,
                    StatusUtc = _time.GetUtcNow(),
                };
        });

    private void RecordAttemptFailure(IReadOnlyList<StoredMessage> owed, MessageRoute route, string reason)
    {
        var line = DisplayTextSafe(reason);
        Log($"messages to {route.Name} wait: {line}");

        foreach (var stored in owed)
        {
            _ = _store.UpdateSent(stored.Message.MessageId, current => current with
            {
                Targets = current.Targets
                    .Select(target => DeviceIdentity.IsSameDevice(target.DeviceId, route.DeviceId) && !target.Delivered
                        ? target with { LastError = line }
                        : target)
                    .ToList(),
            });
        }
    }

    private static string DisplayTextSafe(string text) => Platform.DisplayText.Printable(text, 200);

    private void Log(string line) => _log?.Invoke(line);
}

/// <summary>
/// Finds where a paired machine can be reached for a message: its pairing record's address,
/// and the Direct Push port.
/// </summary>
public static class MessageRoutes
{
    /// <summary>The route to one device, from the folders' pairing records.</summary>
    /// <param name="folders">Every folder this person syncs.</param>
    /// <param name="deviceId">The machine.</param>
    /// <param name="pushPort">
    /// The Direct Push port to dial: this machine's own configured port, which pairing keeps
    /// the same on every machine unless the person moves it, exactly as <c>sip push</c>
    /// assumes; a moved port is the <c>--port</c> option's job there and a setting's here.
    /// </param>
    /// <returns>The route, or null while no folder here is paired with it.</returns>
    public static MessageRoute? To(IEnumerable<string> folders, string deviceId, int pushPort)
    {
        ArgumentNullException.ThrowIfNull(folders);
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        var found = PairedMachines.Find(folders, deviceId, out _);
        return found.Peer is { } peer
            ? new MessageRoute(peer.DeviceId, peer.Name, peer.Host, pushPort)
            : null;
    }
}
