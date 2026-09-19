using System.Globalization;
using SippBucket.Core.Crypto;
using SippBucket.Core.Health;
using SippBucket.Core.Machines;
using SippBucket.Core.Push;

namespace SippBucket.Core.Messages;

/// <summary>
/// The receiving side of Direct Messages: answers each offer before any body moves, checks
/// the signature against the machine that authenticated the session, saves, flushes, and only
/// then confirms (docs/DIRECT-MESSAGES.md).
/// </summary>
/// <remarks>
/// <para>
/// <b>The exchange.</b> On the same authenticated channel Direct Push files use, the sender
/// sends a <see cref="MessageOffer"/>; this side answers once
/// (<see cref="MessageAnswer"/>), so a message that is too large or too frequent costs
/// nothing to transfer; an accepted body streams raw, exactly its offered length; and a
/// <see cref="MessageReceipt"/> says what became of it, sent only after the saved copy is
/// flushed to disk. Several messages may follow each other on one channel.
/// </para>
/// <para>
/// <b>Blocking is silence.</b> A blocked person's offer is never answered: the connection
/// just ends, which a sender cannot tell from unreachable, and their message never becomes
/// <em>Delivered</em>. No refusal is ever used for blocking, because every refusal reason is
/// a statement to the sender (docs/DIRECT-MESSAGES.md, "Blocking").
/// </para>
/// <para>
/// <b>What counts against whom.</b> The rate and the conversation are per person: all of one
/// person's machines are one sender (<see cref="PersonScope"/>). A signature that does not
/// verify, or a body that is not the format, is a fault against the machine
/// (docs/PEER-HEALTH.md); message volume over the rate is recorded and never alerted.
/// </para>
/// </remarks>
public sealed class MessageReceiver
{
    private readonly MessageStore _store;
    private readonly PushSettings _settings;
    private readonly TimeSpan _stallTimeout;
    private readonly string _ownDeviceId;
    private readonly Func<bool> _teamOn;
    private readonly Func<string, PersonScope> _scopeOf;
    private readonly Action<string, HealthFault, string>? _onFault;
    private readonly Action<PersonScope, string>? _onMessage;
    private readonly Action<string>? _log;
    private readonly TimeProvider _time;

    // When each sender's recent messages arrived, newest last, for the per-minute rate.
    // Keyed by person scope, under the lock.
    private readonly Lock _rateGate = new();
    private readonly Dictionary<string, Queue<DateTimeOffset>> _recent = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Creates the receiving side.</summary>
    /// <param name="store">Where messages are kept.</param>
    /// <param name="settings">The <c>push</c> limits: the message size cap and the rate.</param>
    /// <param name="ownDeviceId">This machine's device ID: the only recipient a body may name.</param>
    /// <param name="teamOn">Whether team features are on, read per message.</param>
    /// <param name="scopeOf">The person scope of a sender's device, read per message.</param>
    /// <param name="tuning">The deadlines, or null for the defaults.</param>
    /// <param name="onFault">
    /// Told of each fault against the sending machine — a bad signature, a malformed body,
    /// volume over the rate — for its health record; or null to record nothing.
    /// </param>
    /// <param name="onMessage">
    /// Told of each message stored, with the sender's scope and name, unless the person is
    /// muted: what the tray's notification hangs off. Or null.
    /// </param>
    /// <param name="log">Optional sink for log lines.</param>
    /// <param name="time">The clock, or null for the system's.</param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public MessageReceiver(
        MessageStore store,
        PushSettings settings,
        string ownDeviceId,
        Func<bool> teamOn,
        Func<string, PersonScope> scopeOf,
        PushTuning? tuning = null,
        Action<string, HealthFault, string>? onFault = null,
        Action<PersonScope, string>? onMessage = null,
        Action<string>? log = null,
        TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentException.ThrowIfNullOrWhiteSpace(ownDeviceId);
        ArgumentNullException.ThrowIfNull(teamOn);
        ArgumentNullException.ThrowIfNull(scopeOf);

        var chosen = tuning ?? PushTuning.Default;
        chosen.Validate(nameof(tuning));

        _store = store;
        _settings = settings;
        _stallTimeout = chosen.StallTimeout;
        _ownDeviceId = ownDeviceId;
        _teamOn = teamOn;
        _scopeOf = scopeOf;
        _onFault = onFault;
        _onMessage = onMessage;
        _log = log;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>
    /// Receives messages over an authenticated channel, starting from the offer the dispatcher
    /// already read, until the sender says goodbye or the channel ends.
    /// </summary>
    /// <param name="caller">Who is sending, as the listener's key check found it.</param>
    /// <param name="channel">The delivery channel.</param>
    /// <param name="first">The first message the dispatcher read: the offer that chose this path.</param>
    /// <param name="cancellationToken">Stops receiving.</param>
    /// <returns>A task that completes when the exchange ends.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="PushException">The sender broke the format.</exception>
    /// <exception cref="Protocol.PeerStalledException">The sender stopped making progress.</exception>
    public async Task ReceiveAsync(PushCaller caller, Stream channel, PushMessage first, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(first);

        var message = first;
        while (true)
        {
            if (message is not MessageOffer offer)
            {
                throw new PushException(
                    PushFault.UnexpectedMessage,
                    $"The sender sent {message.GetType().Name} where a message offer was due.");
            }

            if (!await HandleOneAsync(caller, channel, offer, cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            var next = await PushWire.ReadAsync(channel, _stallTimeout, cancellationToken).ConfigureAwait(false);
            if (next is null)
            {
                return;
            }

            message = next;
        }
    }

    /// <summary>Handles one offer. False ends the exchange without another read: the blocked case.</summary>
    private async Task<bool> HandleOneAsync(
        PushCaller caller,
        Stream channel,
        MessageOffer offer,
        CancellationToken cancellationToken)
    {
        var scope = ScopeOf(caller);

        // Blocked is silence: no answer, no receipt, and the connection ends here. The log
        // line is this machine's own; the sender is never told (docs/DIRECT-MESSAGES.md).
        var preferences = _store.LoadPreferences(out var damagedPreferences);
        if (damagedPreferences is not null)
        {
            Log($"the message preferences could not be read, so nobody is blocked or muted: {damagedPreferences}");
        }

        if (preferences.Blocked.Contains(scope.Key, StringComparer.OrdinalIgnoreCase))
        {
            Log($"dropped a message from {caller.Name}, who is blocked; they were not told");
            return false;
        }

        if (!_teamOn())
        {
            await AnswerAsync(channel, MessageRefusal.NotAvailable, string.Empty, cancellationToken).ConfigureAwait(false);
            Log($"{caller.Name}: refused a message: team features are off on this machine");
            return true;
        }

        if (MachineOwnership.IsOwn(caller.Owner))
        {
            await AnswerAsync(
                channel,
                MessageRefusal.NotAvailable,
                "Direct messages travel between people, and this is your own machine.",
                cancellationToken).ConfigureAwait(false);
            return true;
        }

        if (OverRate(scope.Key))
        {
            await AnswerAsync(
                channel,
                MessageRefusal.TooManyTooFast,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"This machine takes {_settings.MessagesPerMinute} messages a minute from one person."),
                cancellationToken).ConfigureAwait(false);
            _onFault?.Invoke(caller.DeviceId, HealthFault.MessageVolume, "messages over the configured rate");
            Log($"{caller.Name}: refused a message over the rate");
            return true;
        }

        var allowed = TextCap() + DmWire.MaximumEnvelopeBytes;
        if (offer.BodyLength > allowed)
        {
            await AnswerAsync(
                channel,
                MessageRefusal.TooLarge,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"This machine takes messages up to {_settings.LargestMessageBytes / 1024} KiB."),
                cancellationToken).ConfigureAwait(false);
            Log($"{caller.Name}: refused a message of {offer.BodyLength} bytes before it was sent");
            return true;
        }

        await AnswerAsync(channel, MessageRefusal.None, string.Empty, cancellationToken).ConfigureAwait(false);

        var body = await ReadBodyAsync(channel, offer.BodyLength, cancellationToken).ConfigureAwait(false);

        // The signature first, against the machine that authenticated the session: a body is
        // accepted only from its own signer (docs/DIRECT-MESSAGES.md).
        if (!DmWire.Verify(caller.DeviceId, body, offer.Signature))
        {
            _onFault?.Invoke(caller.DeviceId, HealthFault.BadSignature, "a direct message whose signature did not verify");
            await ReceiptAsync(
                channel, offer.MessageId, MessageRefusal.SignatureRejected, "The signature did not verify.", cancellationToken)
                .ConfigureAwait(false);
            Log($"{caller.Name}: refused a message whose signature did not verify");
            return true;
        }

        DirectMessage decoded;
        try
        {
            decoded = DmWire.DecodeBody(body, TextCap());
        }
        catch (FormatException ex)
        {
            _onFault?.Invoke(caller.DeviceId, HealthFault.MalformedMessage, $"a malformed direct message: {ex.Message}");
            throw new PushException(PushFault.MalformedMessage, $"A message's body is not the signed format: {ex.Message}", ex);
        }

        if (!DeviceIdentity.IsSameDevice(decoded.SenderDeviceId, caller.DeviceId) ||
            !string.Equals(decoded.MessageId, offer.MessageId, StringComparison.OrdinalIgnoreCase))
        {
            _onFault?.Invoke(caller.DeviceId, HealthFault.BadSignature, "a direct message signed as another machine or offer");
            await ReceiptAsync(
                channel, offer.MessageId, MessageRefusal.SignatureRejected,
                "The body names another sender or message.", cancellationToken).ConfigureAwait(false);
            return true;
        }

        if (!DeviceIdentity.IsSameDevice(decoded.RecipientDeviceId, _ownDeviceId))
        {
            // Signed for another machine: a replay, or a copy delivered to the wrong door.
            // Refused, so a message can never appear on a machine it was not written for.
            await ReceiptAsync(
                channel, offer.MessageId, MessageRefusal.NotAvailable,
                "This copy was written for another machine.", cancellationToken).ConfigureAwait(false);
            Log($"{caller.Name}: refused a message written for another machine");
            return true;
        }

        RecordArrival(scope.Key);

        var stored = _store.SaveReceived(decoded, offer.Signature, scope.Key, _time.GetUtcNow());
        await ReceiptAsync(channel, offer.MessageId, MessageRefusal.None, string.Empty, cancellationToken).ConfigureAwait(false);

        var who = scope.Name ?? caller.Name;
        if (stored)
        {
            Log($"a message from {who} arrived");
            if (!preferences.Muted.Contains(scope.Key, StringComparer.OrdinalIgnoreCase))
            {
                _onMessage?.Invoke(scope, who);
            }
        }

        return true;
    }

    private PersonScope ScopeOf(PushCaller caller)
    {
        try
        {
            return _scopeOf(caller.DeviceId);
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException)
        {
            // An unreadable grouping counts the machine alone, which caps it tightest.
            Log($"the people list could not be read, so {caller.Name} counts alone: {ex.Message}");
            return PeopleStore.SoleScope(caller.DeviceId);
        }
    }

    private int TextCap() => (int)Math.Clamp(_settings.LargestMessageBytes, 0, DmWire.MaximumTextBytes);

    private bool OverRate(string scopeKey)
    {
        var now = _time.GetUtcNow();
        lock (_rateGate)
        {
            var queue = _recent.TryGetValue(scopeKey, out var known) ? known : null;
            if (queue is null)
            {
                return false;
            }

            while (queue.Count > 0 && now - queue.Peek() > TimeSpan.FromMinutes(1))
            {
                _ = queue.Dequeue();
            }

            return queue.Count >= _settings.MessagesPerMinute;
        }
    }

    private void RecordArrival(string scopeKey)
    {
        var now = _time.GetUtcNow();
        lock (_rateGate)
        {
            if (!_recent.TryGetValue(scopeKey, out var queue))
            {
                queue = new Queue<DateTimeOffset>();
                _recent[scopeKey] = queue;
            }

            queue.Enqueue(now);

            // Bounded however fast messages come: the window plus one is all the rate needs.
            while (queue.Count > _settings.MessagesPerMinute + 1)
            {
                _ = queue.Dequeue();
            }
        }
    }

    private static async Task<byte[]> ReadBodyAsync(Stream channel, int length, CancellationToken cancellationToken)
    {
        var body = new byte[length];
        var received = 0;
        while (received < length)
        {
            var read = await channel.ReadAsync(body.AsMemory(received), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new PushException(
                    PushFault.SessionFailed,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"The sender ended the delivery {received} bytes into a message body of {length}."));
            }

            received += read;
        }

        return body;
    }

    private Task AnswerAsync(Stream channel, MessageRefusal refusal, string detail, CancellationToken cancellationToken) =>
        PushWire.WriteAsync(channel, new MessageAnswer(refusal, detail), _stallTimeout, cancellationToken);

    private Task ReceiptAsync(
        Stream channel,
        string messageId,
        MessageRefusal refusal,
        string detail,
        CancellationToken cancellationToken) =>
        PushWire.WriteAsync(
            channel,
            new MessageReceipt(messageId, refusal == MessageRefusal.None, refusal, detail),
            _stallTimeout,
            cancellationToken);

    private void Log(string line) => _log?.Invoke(line);
}
