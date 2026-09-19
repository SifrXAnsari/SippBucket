using System.Text.Json;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Discovery;

/// <summary>
/// Which networks this machine has been allowed to announce itself on.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Per network, and off by default.</strong> Local discovery broadcasts a stable
/// device identifier every thirty seconds on every network the machine joins — a hotel, a
/// café, an office guest VLAN. That is a durable cross-network tracking beacon emitted by a
/// background daemon nobody is looking at, and agreeing to it once is not the same as
/// agreeing to it everywhere.
/// </para>
/// <para>
/// The anti-pattern is Windows' own firewall prompt, which offers Private and Public as
/// checkboxes on one dialog and defaults Private to checked. A user who ticks both once has
/// ticked them for every network they will ever join, and will never be asked again. The
/// decision is taken once, in the least informed moment, and then applied for years.
/// </para>
/// <para>
/// So consent is keyed per network and the answer for an unknown network is <em>no</em> —
/// not "ask later and meanwhile announce", which is the shape that makes a default-off
/// setting default-on in practice.
/// </para>
/// </remarks>
public sealed class NetworkConsent
{
    private readonly string _path;
    private readonly object _gate = new();
    private Dictionary<string, NetworkDecision> _decisions;

    /// <summary>Loads consent from a file, or starts empty.</summary>
    /// <param name="path">Where decisions are stored.</param>
    /// <exception cref="ArgumentException">The path was null or blank.</exception>
    public NetworkConsent(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        _path = path;
        _decisions = Load(path);
    }

    /// <summary>Every network a decision has been recorded for.</summary>
    public IReadOnlyCollection<NetworkDecision> Decisions
    {
        get
        {
            lock (_gate)
            {
                return [.. _decisions.Values];
            }
        }
    }

    /// <summary>
    /// Whether this machine may announce itself on a network.
    /// </summary>
    /// <param name="networkId">A stable identifier for the network.</param>
    /// <returns>True only when the network has been explicitly allowed.</returns>
    /// <remarks>
    /// An unknown network is a refusal, not a question deferred. The distinction matters:
    /// "we have not asked yet, so announce until they object" is how default-off settings
    /// become default-on. Answers written by another process — the window, while the daemon
    /// runs — are picked up here, because a consent screen whose Yes only took effect at the
    /// next restart would be a switch wired to nothing.
    /// </remarks>
    public bool MayAnnounceOn(string? networkId)
    {
        if (string.IsNullOrEmpty(networkId))
        {
            return false;
        }

        lock (_gate)
        {
            Reload();
            return _decisions.TryGetValue(networkId, out var decision) && decision.Allowed;
        }
    }

    /// <summary>Whether a network has been asked about at all.</summary>
    /// <param name="networkId">A stable identifier for the network.</param>
    /// <returns>True when a decision exists either way.</returns>
    public bool HasBeenAsked(string? networkId)
    {
        if (string.IsNullOrEmpty(networkId))
        {
            return false;
        }

        lock (_gate)
        {
            Reload();
            return _decisions.ContainsKey(networkId);
        }
    }

    /// <summary>Records a decision for one network.</summary>
    /// <param name="networkId">A stable identifier for the network.</param>
    /// <param name="displayName">What to call it in the interface.</param>
    /// <param name="allowed">Whether announcing is permitted here.</param>
    /// <exception cref="ArgumentException">The identifier was null or blank.</exception>
    public void Record(string networkId, string displayName, bool allowed)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(networkId);

        lock (_gate)
        {
            Reload();
            _decisions[networkId] = new NetworkDecision
            {
                NetworkId = networkId,
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? networkId : displayName,
                Allowed = allowed,
            };

            Save();
        }
    }

    /// <summary>Removes a decision, so the network is asked about again.</summary>
    /// <param name="networkId">A stable identifier for the network.</param>
    /// <returns>True when a decision was removed.</returns>
    public bool Forget(string networkId)
    {
        if (string.IsNullOrEmpty(networkId))
        {
            return false;
        }

        lock (_gate)
        {
            Reload();
            if (!_decisions.Remove(networkId))
            {
                return false;
            }

            Save();
            return true;
        }
    }

    /// <summary>Reads the file again, so another process's answers count. The caller holds the gate.</summary>
    private void Reload() => _decisions = Load(_path);

    /// <summary>Writes the file whole and swaps it in, so it is never half of two answers. The caller holds the gate.</summary>
    private void Save()
    {
        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var bytes = JsonSerializer.SerializeToUtf8Bytes(_decisions.Values.ToList(), SipJson.Readable);
        var temporary = $"{_path}.{Guid.NewGuid():N}.tmp";
        var moved = false;
        try
        {
            File.WriteAllBytes(temporary, bytes);

            if (File.Exists(_path))
            {
                SharingRetry.Run(() => File.Replace(temporary, _path, destinationBackupFileName: null));
            }
            else
            {
                SharingRetry.Run(() => File.Move(temporary, _path));
            }

            moved = true;
        }
        finally
        {
            if (!moved && File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }
    }

    private static Dictionary<string, NetworkDecision> Load(string path)
    {
        if (!File.Exists(path))
        {
            return new Dictionary<string, NetworkDecision>(StringComparer.Ordinal);
        }

        try
        {
            // Waited out, not failed closed, when a scanner holds the file for a moment
            // (D-69): failing closed is right for a damaged file, and wrong for one that is
            // merely busy, since it silently forgets every network the user allowed.
            var stored = JsonSerializer.Deserialize<List<NetworkDecision>>(
                SharingRetry.Run(() => File.ReadAllText(path)), SipJson.Readable) ?? [];

            return stored.ToDictionary(d => d.NetworkId, StringComparer.Ordinal);
        }
        catch (JsonException)
        {
            // A damaged consent file means no consent, never blanket consent. Failing
            // closed here costs a user one dialog; failing open announces them on a
            // network they never agreed to.
            return new Dictionary<string, NetworkDecision>(StringComparer.Ordinal);
        }
        catch (IOException)
        {
            return new Dictionary<string, NetworkDecision>(StringComparer.Ordinal);
        }
    }
}

/// <summary>One network, and what was decided about it.</summary>
public sealed record NetworkDecision
{
    /// <summary>A stable identifier for the network.</summary>
    public required string NetworkId { get; init; }

    /// <summary>What to call it in the interface.</summary>
    public required string DisplayName { get; init; }

    /// <summary>Whether announcing is permitted here.</summary>
    public required bool Allowed { get; init; }
}
