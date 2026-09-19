using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// A port the home router is forwarding to this machine: renewed in the background before it
/// expires, and deleted from the router when removed or disposed.
/// </summary>
/// <remarks>
/// <para>
/// Obtained from <see cref="PortMapper.MapAsync"/>. From then on it renews itself on the
/// schedule in RFC 6887 section 11.2.1, which suits NAT-PMP and UPnP IGD as well (see
/// <see cref="MappingTimers.RenewalOffsets"/>). It never asks for a new mapping on its own:
/// once a renewal is refused, or none is answered before the mapping expires, it is
/// <see cref="PortMappingState.Lost"/> and stays that way, and it is the owner's decision
/// whether to call <see cref="PortMapper.MapAsync"/> again.
/// </para>
/// <para>
/// <strong>Read the state on a clock, not on an event.</strong> <see cref="IsActiveAt"/>
/// checks the expiry time as well as the state, so a status line built from it degrades on
/// its own if renewal ever stops without saying so (standard A2).
/// </para>
/// <para>
/// <strong>Removing it is best effort, and says so.</strong> <see cref="RemoveAsync"/> stops
/// renewing and asks the router to delete the mapping, and returns whether the router
/// confirmed. An unconfirmed removal is not retried: the mapping still ends when its lifetime
/// runs out, at <see cref="ExpiresUtc"/>, which is why a mapping is never asked for without
/// one.
/// </para>
/// </remarks>
public sealed class ActivePortMapping : IAsyncDisposable
{
    private readonly MappingSession _session;
    private readonly PortMapperOptions _options;
    private readonly Action<string>? _log;
    private readonly uint _requestedSeconds;
    private readonly CancellationTokenSource _stopping = new();
    private readonly object _lock = new();

    private MappingGrant _grant;
    private long _grantedAt;
    private DateTimeOffset _grantedUtc;
    private PortMappingState _state = PortMappingState.Active;
    private PortMappingFailure _lostBecause;
    private string? _lostDetail;
    private int _renewals;
    private Task? _renewing;
    private Task<bool>? _removal;
    private bool _disposed;

    internal ActivePortMapping(
        MappingSession session,
        MappingGrant grant,
        uint requestedSeconds,
        PortMapperOptions options,
        Action<string>? log)
    {
        _session = session;
        _grant = grant;
        _requestedSeconds = requestedSeconds;
        _options = options;
        _log = log;
        _grantedAt = Stopwatch.GetTimestamp();
        _grantedUtc = DateTimeOffset.UtcNow;
    }

    /// <summary>The protocol the mapping was made with.</summary>
    public PortMappingProtocol Protocol => _session.Protocol;

    /// <summary>The gateway that holds the mapping.</summary>
    public IPAddress Gateway => _session.Gateway;

    /// <summary>This machine's address, which the mapping forwards to.</summary>
    public IPAddress InternalAddress => _session.InternalAddress;

    /// <summary>The port on this machine the mapping forwards to.</summary>
    public int InternalPort => _session.InternalPort;

    /// <summary>The external port the gateway forwards. Can change if the gateway restarts.</summary>
    public int ExternalPort
    {
        get
        {
            lock (_lock)
            {
                return _grant.ExternalPort;
            }
        }
    }

    /// <summary>The gateway's external address, or null when it did not say.</summary>
    /// <remarks>
    /// This is the address the router has on its outside. Behind a second NAT, such as a
    /// carrier's, it is not an address the internet can reach, and nothing here can tell.
    /// </remarks>
    public IPAddress? ExternalAddress
    {
        get
        {
            lock (_lock)
            {
                return _grant.ExternalAddress;
            }
        }
    }

    /// <summary>When the gateway last granted or renewed the mapping.</summary>
    public DateTimeOffset GrantedUtc
    {
        get
        {
            lock (_lock)
            {
                return _grantedUtc;
            }
        }
    }

    /// <summary>When the mapping ends unless it is renewed first.</summary>
    public DateTimeOffset ExpiresUtc
    {
        get
        {
            lock (_lock)
            {
                return _grantedUtc + _grant.Lifetime;
            }
        }
    }

    /// <summary>How many renewals the gateway has answered.</summary>
    public int Renewals
    {
        get
        {
            lock (_lock)
            {
                return _renewals;
            }
        }
    }

    /// <summary>How many times an answer showed the gateway had restarted and lost its mappings.</summary>
    public int GatewayRestartsDetected => _session.GatewayRestarts;

    /// <summary>
    /// How many datagrams were thrown away for not being the gateway's answer: another source,
    /// another nonce, or the wrong size.
    /// </summary>
    public int IgnoredReplies => _session.Ignored;

    /// <summary>Where the mapping stands.</summary>
    public PortMappingState State
    {
        get
        {
            lock (_lock)
            {
                return _state;
            }
        }
    }

    /// <summary>Why the mapping was lost, or <see cref="PortMappingFailure.None"/> when it was not.</summary>
    public PortMappingFailure LostBecause
    {
        get
        {
            lock (_lock)
            {
                return _lostBecause;
            }
        }
    }

    /// <summary>One line saying why the mapping was lost, or null.</summary>
    public string? LostDetail
    {
        get
        {
            lock (_lock)
            {
                return _lostDetail;
            }
        }
    }

    /// <summary>Whether the mapping can be relied on at a given moment.</summary>
    /// <param name="nowUtc">The moment.</param>
    /// <returns>True when it is being held and has not yet expired.</returns>
    public bool IsActiveAt(DateTimeOffset nowUtc)
    {
        lock (_lock)
        {
            return _state == PortMappingState.Active && nowUtc < _grantedUtc + _grant.Lifetime;
        }
    }

    /// <summary>Stops renewing and asks the gateway to delete the mapping.</summary>
    /// <param name="cancellationToken">
    /// Stops this caller waiting. The removal itself carries on regardless, bounded by the
    /// removal budget, ten seconds by default: a removal abandoned half way would leave the
    /// mapping renewed by nobody and deleted by nobody, which is the one outcome worse than
    /// either.
    /// </param>
    /// <returns>True when the gateway confirmed the deletion.</returns>
    /// <remarks>
    /// Safe to call more than once and from more than one place: every call waits on the same
    /// removal.
    /// </remarks>
    public Task<bool> RemoveAsync(CancellationToken cancellationToken = default)
    {
        Task<bool> removal;
        lock (_lock)
        {
            removal = _removal ??= RemoveCoreAsync();
        }

        return removal.WaitAsync(cancellationToken);
    }

    /// <summary>Removes the mapping, as <see cref="RemoveAsync"/>.</summary>
    /// <returns>A task that completes when the gateway has answered or the removal budget is spent.</returns>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await RemoveAsync(CancellationToken.None).ConfigureAwait(false);
        _disposed = true;
        _stopping.Dispose();
    }

    /// <summary>Records the external address found after the grant, before renewal starts.</summary>
    internal void SetExternalAddress(IPAddress? address)
    {
        lock (_lock)
        {
            _grant = _grant with { ExternalAddress = address ?? _grant.ExternalAddress };
        }
    }

    /// <summary>Starts renewing.</summary>
    internal void Start() => _renewing = RenewSafelyAsync(_stopping.Token);

    private async Task<bool> RemoveCoreAsync()
    {
        // Off the caller's thread at once: RemoveAsync starts this while holding the state
        // lock, and none of the removal should run under it.
        await Task.Yield();

        await _stopping.CancelAsync().ConfigureAwait(false);
        if (_renewing is not null)
        {
            await _renewing.ConfigureAwait(false);
        }

        bool confirmed;
        try
        {
            confirmed = await _session.DeleteAsync(_options.RemovalBudget, CancellationToken.None).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            _log?.Invoke(Say($"could not ask {Gateway} to delete the mapping: {ex.SocketErrorCode}"));
            confirmed = false;
        }
        finally
        {
            lock (_lock)
            {
                _state = PortMappingState.Removed;
            }

            await _session.DisposeAsync().ConfigureAwait(false);
        }

        _log?.Invoke(confirmed
            ? Say($"{Gateway} deleted the mapping of TCP {InternalPort}")
            : Say($"{Gateway} did not confirm deleting the mapping of TCP {InternalPort}; it ends by itself at {ExpiresUtc:u}"));

        return confirmed;
    }

    /// <summary>The renewal loop's fault boundary.</summary>
    /// <remarks>
    /// This task is started and not awaited until removal, so anything escaping it would be
    /// invisible until then, with the state still reading Active while nothing renews. Every
    /// way the loop can end is written to the state instead.
    /// </remarks>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Fault boundary for a background task nobody awaits until removal. " +
                        "An escaping exception would leave the state reading Active while " +
                        "nothing renews; cancellation is removal and ends it quietly.")]
    private async Task RenewSafelyAsync(CancellationToken cancellationToken)
    {
        try
        {
            await RenewAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _log?.Invoke(Say($"stopped renewing TCP {InternalPort}"));
        }
        catch (Exception ex)
        {
            MarkLost(PortMappingFailure.Fault, Say($"renewal failed: {ex.GetType().Name}: {ex.Message}"));
        }
    }

    private async Task RenewAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            MappingGrant grant;
            long grantedAt;
            lock (_lock)
            {
                grant = _grant;
                grantedAt = _grantedAt;
            }

            var offsets = MappingTimers.RenewalOffsets(grant.Lifetime, _options.MinimumRenewalSpacing);
            SessionOutcome? outcome = null;

            for (var i = 0; i < offsets.Count; i++)
            {
                await DelayUntilAsync(grantedAt + TicksOf(offsets[i]), cancellationToken).ConfigureAwait(false);

                var windowEnds = grantedAt + TicksOf(i + 1 < offsets.Count ? offsets[i + 1] : grant.Lifetime);
                var budget = Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), windowEnds);

                try
                {
                    outcome = await _session
                        .RequestAsync(_requestedSeconds, renewal: true, budget, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (SocketException ex)
                {
                    // The network went away under the request: a laptop between networks. The
                    // next renewal in the schedule tries again.
                    outcome = SessionOutcome.Failed(
                        PortMappingFailure.NoAnswer,
                        Say($"could not reach {Gateway} to renew: {ex.SocketErrorCode}"));
                }

                if (outcome.Grant is not null || outcome.Failure != PortMappingFailure.NoAnswer)
                {
                    break;
                }
            }

            if (outcome?.Grant is { } renewed)
            {
                Renewed(renewed);
                continue;
            }

            if (outcome is not null && outcome.Failure != PortMappingFailure.NoAnswer)
            {
                MarkLost(outcome.Failure, outcome.Detail);
                return;
            }

            await DelayUntilAsync(grantedAt + TicksOf(grant.Lifetime), cancellationToken).ConfigureAwait(false);
            MarkLost(
                PortMappingFailure.NoAnswer,
                Say($"no renewal was answered before the mapping expired at {ExpiresUtc:u}"));
            return;
        }
    }

    private void Renewed(MappingGrant renewed)
    {
        int previousPort;
        lock (_lock)
        {
            previousPort = _grant.ExternalPort;
            _grant = renewed with { ExternalAddress = renewed.ExternalAddress ?? _grant.ExternalAddress };
            _grantedAt = Stopwatch.GetTimestamp();
            _grantedUtc = DateTimeOffset.UtcNow;
            _renewals++;
        }

        if (previousPort != renewed.ExternalPort)
        {
            _log?.Invoke(Say($"{Gateway} moved the mapping of TCP {InternalPort} from external port {previousPort} to {renewed.ExternalPort}"));
        }
    }

    private void MarkLost(PortMappingFailure failure, string detail)
    {
        lock (_lock)
        {
            if (_state != PortMappingState.Active)
            {
                return;
            }

            _state = PortMappingState.Lost;
            _lostBecause = failure;
            _lostDetail = detail;
        }

        // Outside the lock: the sink is someone else's code.
        _log?.Invoke(detail);
    }

    private static async Task DelayUntilAsync(long timestamp, CancellationToken cancellationToken)
    {
        var remaining = Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), timestamp);
        if (remaining > TimeSpan.Zero)
        {
            await Task.Delay(remaining, cancellationToken).ConfigureAwait(false);
        }
    }

    private static long TicksOf(TimeSpan span) => (long)(span.TotalSeconds * Stopwatch.Frequency);

    private string Say(FormattableString text) =>
        Protocol.Name() + ": " + text.ToString(CultureInfo.InvariantCulture);
}
