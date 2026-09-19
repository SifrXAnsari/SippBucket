using System.Diagnostics;

namespace SippBucket.Core.Protocol;

/// <summary>
/// Keeps a transfer from taking the whole link.
/// </summary>
/// <remarks>
/// <para>
/// SippBucket is a background daemon that can begin a multi-gigabyte transfer without being
/// asked, on a home network, while somebody is on a video call. Being polite about bandwidth
/// is not a speed feature — it is the difference between software people keep installed and
/// software they uninstall while swearing at it. It belongs beside Keep Alive as a
/// good-citizen property and it serves the second stated priority, set it and forget it.
/// </para>
/// <para>
/// <strong>This is not LEDBAT and must not be described as such.</strong> Delivery
/// Optimization runs peer traffic over LEDBAT, which yields to competing flows by watching
/// one-way delay — a TCP congestion-control algorithm, not a switch a .NET socket exposes.
/// What this does is cruder and honest about it: a token bucket at a ceiling the user sets,
/// with an automatic mode that backs off when throughput degrades, which is a proxy for
/// congestion rather than a measurement of it.
/// </para>
/// <para>
/// The bucket allows a burst of one second's worth, because a strictly paced stream
/// interacts badly with TCP's own batching and costs throughput for no politeness gain.
/// </para>
/// </remarks>
public sealed class RateLimiter
{
    /// <summary>A limiter that never delays anything.</summary>
    public static RateLimiter Unlimited { get; } = new(0);

    private readonly object _gate = new();
    private readonly long _bytesPerSecond;
    private readonly Func<long> _clock;

    private double _tokens;
    private long _lastTicks;

    /// <summary>Creates a limiter.</summary>
    /// <param name="bytesPerSecond">The ceiling, or zero or less for no limit.</param>
    /// <param name="clock">A monotonic tick source, for tests.</param>
    public RateLimiter(long bytesPerSecond, Func<long>? clock = null)
    {
        _bytesPerSecond = bytesPerSecond;
        _clock = clock ?? Stopwatch.GetTimestamp;
        _lastTicks = _clock();
        _tokens = bytesPerSecond > 0 ? bytesPerSecond : 0;
    }

    /// <summary>Whether this limiter actually limits anything.</summary>
    public bool IsLimited => _bytesPerSecond > 0;

    /// <summary>The ceiling in bytes per second, or zero when unlimited.</summary>
    public long BytesPerSecond => _bytesPerSecond;

    /// <summary>Waits until <paramref name="byteCount"/> bytes may be sent or received.</summary>
    /// <param name="byteCount">How many bytes are about to move.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>A task that completes when the bytes may move.</returns>
    public async Task WaitAsync(int byteCount, CancellationToken cancellationToken = default)
    {
        if (!IsLimited || byteCount <= 0)
        {
            return;
        }

        while (true)
        {
            TimeSpan wait;

            lock (_gate)
            {
                Refill();

                if (_tokens >= byteCount)
                {
                    _tokens -= byteCount;
                    return;
                }

                var shortfall = byteCount - _tokens;
                wait = TimeSpan.FromSeconds(shortfall / _bytesPerSecond);
            }

            // A single block can exceed a whole second's allowance, so the wait is capped
            // and the loop re-checks rather than sleeping for the full shortfall in one go.
            // That keeps cancellation responsive during a large transfer on a slow cap.
            await Task.Delay(
                wait > TimeSpan.FromMilliseconds(250) ? TimeSpan.FromMilliseconds(250) : wait,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private void Refill()
    {
        var now = _clock();
        var elapsed = (now - _lastTicks) / (double)Stopwatch.Frequency;
        _lastTicks = now;

        if (elapsed <= 0)
        {
            return;
        }

        // Capped at one second's worth. Without the cap a daemon that has been idle for an
        // hour accumulates an hour of allowance and then empties it in one burst, which is
        // exactly the behaviour the limiter exists to prevent.
        _tokens = Math.Min(_bytesPerSecond, _tokens + (elapsed * _bytesPerSecond));
    }
}
