using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>What the port mapping is doing on this machine, for status lines and the window.</summary>
/// <param name="Enabled">Whether <c>network.portMapping</c> is on.</param>
/// <param name="Active">Whether a mapping is active now.</param>
/// <param name="Line">
/// One sentence, honest to standard A1: what the router forwards, or why nothing is
/// forwarded. Never "reachable from the internet", which no mapping can promise.
/// </param>
public sealed record PortMappingServiceState(bool Enabled, bool Active, string Line);

/// <summary>
/// Port mapping in the daemon: holds one mapping for the sync port while the setting is on,
/// and never otherwise (D-05, the portmap wiring proposal).
/// </summary>
/// <remarks>
/// <para>
/// Off by default (<c>network.portMapping</c>), because a forwarded port is the whole
/// internet at the listener. What protects the listener is the handshake, its fixed
/// deadlines and the peer list; what a mapping adds is only reachability, and the state line
/// says exactly that.
/// </para>
/// <para>
/// The daemon calls <see cref="RefreshAsync"/> on its timer. Mapping can take about 18
/// seconds against a silent gateway, so a refresh never blocks the timer: it starts the
/// attempt in the background and later refreshes read its outcome. A lost mapping is retried
/// after what the gateway asked (<see cref="PortMappingResult.RetryAfter"/>) or half an hour;
/// an active one renews itself (<see cref="ActivePortMapping"/>), and this only reads its
/// state. Switching the setting off, and disposing, deletes the mapping from the router,
/// bounded at ten seconds.
/// </para>
/// </remarks>
public sealed class PortMappingService : IAsyncDisposable
{
    private static readonly TimeSpan DefaultRetry = TimeSpan.FromMinutes(30);

    private readonly PortMapper _mapper;
    private readonly int _port;
    private readonly TimeSpan _lifetime;
    private readonly Action<string>? _log;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private Task<PortMappingResult>? _attempt;
    private ActivePortMapping? _mapping;
    private DateTimeOffset _nextAttemptUtc = DateTimeOffset.MinValue;
    private string _line = "Port mapping is off: the router is not asked to forward anything.";
    private bool _wasLost;
    private bool _disposed;

    /// <summary>Creates the service. Nothing is sent until a refresh finds the setting on.</summary>
    /// <param name="port">The sync listen port: the only port ever mapped.</param>
    /// <param name="lifetime">The lifetime each mapping asks for, from <c>network.portMappingLifetimeMinutes</c>.</param>
    /// <param name="log">Optional sink for log lines.</param>
    /// <param name="mapper">The mapper, or null for one against this machine's gateway.</param>
    /// <param name="time">The clock, or null for the system's.</param>
    /// <exception cref="ArgumentOutOfRangeException">The port is not a TCP port.</exception>
    public PortMappingService(
        int port,
        TimeSpan lifetime,
        Action<string>? log = null,
        PortMapper? mapper = null,
        TimeProvider? time = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, ushort.MaxValue);

        _port = port;
        _lifetime = lifetime;
        _log = log;
        _mapper = mapper ?? new PortMapper(log);
        _time = time ?? TimeProvider.System;
    }

    /// <summary>What the mapping is doing now.</summary>
    public PortMappingServiceState State
    {
        get
        {
            var mapping = Volatile.Read(ref _mapping);
            var active = mapping is not null && mapping.IsActiveAt(_time.GetUtcNow());
            return new PortMappingServiceState(Enabled, active, _line);
        }
    }

    /// <summary>Whether the last refresh found the setting on.</summary>
    public bool Enabled { get; private set; }

    /// <summary>
    /// Brings the mapping into line with the setting: asks the router while it is on and
    /// nothing is held, and deletes the mapping when it is off.
    /// </summary>
    /// <param name="enabled">The setting, read by the caller from <c>master.json</c>.</param>
    /// <param name="cancellationToken">Cancels waiting for another refresh to finish.</param>
    /// <returns>A task that completes when the state is settled; a mapping attempt keeps running behind it.</returns>
    /// <exception cref="ObjectDisposedException">The service was disposed.</exception>
    public async Task RefreshAsync(bool enabled, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Enabled = enabled;

            if (!enabled)
            {
                if (_mapping is not null || _attempt is not null)
                {
                    await StopAsync().ConfigureAwait(false);
                    _log?.Invoke("port mapping switched off; the router's forwarding was deleted");
                }

                _line = "Port mapping is off: the router is not asked to forward anything.";
                return;
            }

            TakeFinishedAttempt();

            var now = _time.GetUtcNow();
            if (_mapping is { } held)
            {
                if (held.IsActiveAt(now))
                {
                    _line = Describe(held);
                    _wasLost = false;
                    return;
                }

                // Lost: the router restarted, refused a renewal, or the machine slept past
                // expiry. Says so once, and retries on the schedule below.
                if (!_wasLost)
                {
                    _wasLost = true;
                    _log?.Invoke($"the router's forwarding was lost ({held.LostBecause}): {held.LostDetail ?? "no detail"}");
                }

                _line = $"The router's forwarding was lost ({held.LostBecause}); it is asked again on a timer.";
                await ReplaceMappingAsync(null).ConfigureAwait(false);
                _nextAttemptUtc = now + DefaultRetry;
            }

            if (_attempt is null && now >= _nextAttemptUtc)
            {
                // Off the timer's thread: a silent gateway costs about 18 seconds.
                _attempt = Task.Run(() => _mapper.MapAsync(_port, _lifetime, CancellationToken.None));
                if (_line.StartsWith("Port mapping is off", StringComparison.Ordinal))
                {
                    _line = "Port mapping is on: asking the router to forward the sync port.";
                }
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Reads a finished attempt's outcome into the held state. The caller holds the gate.</summary>
    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Fault boundary over the background attempt: MapAsync documents that it does not throw " +
                        "for anything the network does, so anything here is a defect, recorded as the state line " +
                        "rather than lost with an unobserved task.")]
    private void TakeFinishedAttempt()
    {
        if (_attempt is not { IsCompleted: true } finished)
        {
            return;
        }

        _attempt = null;
        var now = _time.GetUtcNow();

        try
        {
            var result = finished.GetAwaiter().GetResult();
            foreach (var tried in result.Attempts)
            {
                _log?.Invoke($"port mapping: {tried.Protocol}: {tried.Detail}");
            }

            if (result.Mapping is { } mapping)
            {
                _mapping = mapping;
                _wasLost = false;
                _line = Describe(mapping);
                _log?.Invoke(result.Summary);
            }
            else
            {
                _nextAttemptUtc = now + (result.RetryAfter ?? DefaultRetry);
                _line = $"The router forwards nothing: {result.Summary} It is asked again on a timer.";
                _log?.Invoke($"port mapping: {result.Summary}");
            }
        }
        catch (Exception ex)
        {
            _nextAttemptUtc = now + DefaultRetry;
            _line = $"The router forwards nothing: the attempt failed ({ex.Message}). It is asked again on a timer.";
            _log?.Invoke($"port mapping: the attempt failed: {ex.Message}");
        }
    }

    /// <summary>Deletes the mapping from the router and stops. Safe to call more than once.</summary>
    /// <returns>A task that completes when nothing is held.</returns>
    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            await StopAsync().ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }

        _gate.Dispose();
    }

    /// <summary>The state line, standard A1: what is forwarded, never what is "reachable".</summary>
    private static string Describe(ActivePortMapping mapping)
    {
        var external = mapping.ExternalAddress?.ToString() ?? "(external address unknown)";
        return string.Create(
            CultureInfo.InvariantCulture,
            $"Router forwards {external}:{mapping.ExternalPort} to this machine ({mapping.Protocol}).") +
            " Anyone on the internet can reach this port; only machines in your peer lists can sync.";
    }

    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "Shutdown path: a router that will not answer the delete must not stop the daemon " +
                        "stopping. The mapping expires on its own lifetime regardless.")]
    private async Task StopAsync()
    {
        if (_attempt is { } attempt)
        {
            _attempt = null;
            try
            {
                // Bounded by the mapper's own deadlines; its mapping, if it got one, is deleted.
                var result = await attempt.ConfigureAwait(false);
                if (result.Mapping is { } fresh)
                {
                    await fresh.DisposeAsync().ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _log?.Invoke($"port mapping: stopping an attempt failed: {ex.Message}");
            }
        }

        await ReplaceMappingAsync(null).ConfigureAwait(false);
    }

    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "As StopAsync: deleting from an unreachable router must not stop the daemon, and the " +
                        "mapping expires on its own lifetime regardless.")]
    private async Task ReplaceMappingAsync(ActivePortMapping? next)
    {
        var previous = _mapping;
        _mapping = next;

        if (previous is null)
        {
            return;
        }

        try
        {
            await previous.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log?.Invoke($"port mapping: deleting the old forwarding failed: {ex.Message}");
        }
    }
}
