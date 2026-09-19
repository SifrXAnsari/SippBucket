using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using NSec.Cryptography;

namespace SippBucket.Core.Discovery;

/// <summary>
/// The announcement on the wire: a fixed 536-byte packet of a random nonce and 32 token
/// slots, saying nothing to anyone who was not given a key (docs/DISCOVERY.md).
/// </summary>
/// <remarks>
/// <para>
/// The packet that came before this carried a device ID, a machine name, a port and
/// repository IDs, in JSON, to everyone on the network: a durable cross-network tracking
/// beacon. This one carries none of that. Each token is a keyed MAC only its intended peer
/// can recognise, bound to a ten-minute time slot and to the sender's source address; unused
/// slots are random, so even the number of peers is hidden, and every packet from every
/// machine is the same size. To anyone without a key, the whole packet is indistinguishable
/// from random noise on the port.
/// </para>
/// <para>
/// <b>The token.</b> BLAKE2b, keyed with the 32-byte key the announcer minted for that one
/// peer, over <c>sippbucket-discovery-token-v1</c> ‖ <c>0x00</c> ‖ the slot as eight
/// big-endian bytes ‖ the packet's 16-byte nonce ‖ the sender's IPv4 source address, first
/// 16 bytes of the 256-bit output. The design page names BLAKE2b-128; this build computes
/// the keyed 256-bit form NSec provides and truncates, which is the same keyed-PRF security
/// at the same output length, and both ends are this code, so both compute it identically.
/// The page's appendix records the substitution.
/// </para>
/// <para>
/// <b>The slot</b> is Unix seconds divided by 600. The receiver accepts the previous,
/// current and next slot, so clocks may disagree by up to ten minutes; the slot itself never
/// travels, because a visible clock error would be a fingerprint. Recently seen nonces are
/// refused, so a captured packet replayed later, or from elsewhere on the subnet, matches
/// nothing — and the source address inside the MAC means a replay from a different address
/// fails the token itself.
/// </para>
/// <para>
/// <b>Fixed constants, deliberately.</b> The port, size, slot length and interval are not
/// settings, against this project's usual rule, because a non-default value would make one
/// machine's announcements stand out from every other copy of SippBucket: the anonymity of
/// the packet is the anonymity of the crowd. The master config can forbid announcing;
/// nothing in it can change what an announcement looks like.
/// </para>
/// </remarks>
public static class DiscoveryPacket
{
    /// <summary>Cheap rejection of anything else on the port.</summary>
    public const uint Magic = 0x5349_5042;

    /// <summary>The UDP port announcements are sent to and listened for on. Fixed on the wire.</summary>
    public const int Port = 28471;

    /// <summary>The wire version of the token packet. 1 and 2 were the JSON forms, refused for good.</summary>
    public const int CurrentVersion = 3;

    /// <summary>The nonce's length.</summary>
    public const int NonceSize = 16;

    /// <summary>One token's length.</summary>
    public const int TokenSize = 16;

    /// <summary>How many token slots every packet carries, used or not.</summary>
    public const int Slots = 32;

    /// <summary>Every packet's exact length: magic, version, nonce, and the slots.</summary>
    public const int PacketSize = 4 + 4 + NonceSize + (Slots * TokenSize);

    /// <summary>A discovery key's length: what one machine mints for one peer.</summary>
    public const int KeySize = 32;

    /// <summary>One slot's length in time.</summary>
    public static TimeSpan SlotLength { get; } = TimeSpan.FromMinutes(10);

    /// <summary>How often a consented adapter announces.</summary>
    public static TimeSpan AnnounceInterval { get; } = TimeSpan.FromSeconds(60);

    private static ReadOnlySpan<byte> TokenLabel => "sippbucket-discovery-token-v1\0"u8;

    /// <summary>The slot an instant falls in.</summary>
    /// <param name="nowUtc">The instant.</param>
    /// <returns>Unix seconds divided by 600.</returns>
    public static long SlotOf(DateTimeOffset nowUtc) =>
        nowUtc.ToUnixTimeSeconds() / (long)SlotLength.TotalSeconds;

    /// <summary>Builds one packet: a fresh nonce, one token per key, and random filler.</summary>
    /// <param name="keys">The keys of the peers announced to, at most <see cref="Slots"/> per packet.</param>
    /// <param name="slot">The current slot.</param>
    /// <param name="source">The IPv4 address the packet is sent from, which each token is bound to.</param>
    /// <returns>The 536 bytes to send.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="ArgumentException">Too many keys, a key of the wrong size, or a source that is not IPv4.</exception>
    public static byte[] Build(IReadOnlyList<byte[]> keys, long slot, IPAddress source)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(source);

        if (keys.Count > Slots)
        {
            throw new ArgumentException($"One packet carries at most {Slots} tokens; callers take turns past that.", nameof(keys));
        }

        var packet = new byte[PacketSize];
        BinaryPrimitives.WriteUInt32BigEndian(packet, Magic);
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(4), CurrentVersion);

        var nonce = packet.AsSpan(8, NonceSize);
        RandomNumberGenerator.Fill(nonce);

        // Filler first, so an unused slot is indistinguishable from a token; the real tokens
        // overwrite their slots. Which slots are real is randomised by the order keys arrive
        // in being unrelated to anything an observer sees.
        RandomNumberGenerator.Fill(packet.AsSpan(8 + NonceSize));

        for (var index = 0; index < keys.Count; index++)
        {
            var token = ComputeToken(keys[index], slot, nonce, source);
            token.CopyTo(packet.AsSpan(8 + NonceSize + (index * TokenSize)));
        }

        return packet;
    }

    /// <summary>
    /// Reads a packet's nonce, and refuses anything that is not exactly a packet of this
    /// version. Never throws: this parses unauthenticated input arriving at any rate.
    /// </summary>
    /// <param name="packet">The datagram.</param>
    /// <param name="nonce">The nonce, when the shape is right.</param>
    /// <returns>True when the packet is well formed.</returns>
    public static bool TryReadNonce(ReadOnlySpan<byte> packet, out byte[] nonce)
    {
        nonce = [];

        if (packet.Length != PacketSize ||
            BinaryPrimitives.ReadUInt32BigEndian(packet) != Magic ||
            BinaryPrimitives.ReadInt32BigEndian(packet[4..]) != CurrentVersion)
        {
            return false;
        }

        nonce = packet.Slice(8, NonceSize).ToArray();
        return true;
    }

    /// <summary>
    /// The peers whose tokens a packet carries, judged with the keys they gave this machine.
    /// </summary>
    /// <param name="packet">The datagram, already shape-checked by <see cref="TryReadNonce"/>.</param>
    /// <param name="source">The address the datagram came from: what each token is bound to.</param>
    /// <param name="candidates">Each known announcer's device ID and the key it minted for this machine.</param>
    /// <param name="nowUtc">The clock, for the slot and its neighbours.</param>
    /// <returns>The device IDs matched. Usually one; a packet matches per key, not per slot.</returns>
    /// <remarks>
    /// Cost per packet: at most three slots times one MAC per candidate, against 32 slots of
    /// constant-time comparison. Candidates are the machines this person paired and was given
    /// keys by — a handful — so a flood of random packets costs a handful of MACs each and
    /// matches nothing.
    /// </remarks>
    public static IReadOnlyList<string> Match(
        ReadOnlySpan<byte> packet,
        IPAddress source,
        IReadOnlyList<(string DeviceId, byte[] Key)> candidates,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(candidates);

        if (packet.Length != PacketSize || candidates.Count == 0)
        {
            return [];
        }

        var nonce = packet.Slice(8, NonceSize);
        var slots = packet[(8 + NonceSize)..];
        var current = SlotOf(nowUtc);

        var matched = new List<string>();
        foreach (var (deviceId, key) in candidates)
        {
            if (key.Length != KeySize)
            {
                continue;
            }

            for (var offset = -1; offset <= 1 && !matched.Contains(deviceId); offset++)
            {
                var token = ComputeToken(key, current + offset, nonce, source);

                for (var index = 0; index < Slots; index++)
                {
                    if (CryptographicOperations.FixedTimeEquals(
                            token, slots.Slice(index * TokenSize, TokenSize)))
                    {
                        matched.Add(deviceId);
                        break;
                    }
                }
            }
        }

        return matched;
    }

    /// <summary>One token: keyed BLAKE2b over the label, the slot, the nonce and the source.</summary>
    private static byte[] ComputeToken(byte[] key, long slot, ReadOnlySpan<byte> nonce, IPAddress source)
    {
        Span<byte> address = stackalloc byte[4];
        if (!source.TryWriteBytes(address, out var written) || written != 4)
        {
            throw new ArgumentException("A discovery token binds an IPv4 source address.", nameof(source));
        }

        var message = new byte[TokenLabel.Length + 8 + NonceSize + 4];
        TokenLabel.CopyTo(message);
        BinaryPrimitives.WriteInt64BigEndian(message.AsSpan(TokenLabel.Length), slot);
        nonce.CopyTo(message.AsSpan(TokenLabel.Length + 8));
        address.CopyTo(message.AsSpan(TokenLabel.Length + 8 + NonceSize));

        using var macKey = Key.Import(MacAlgorithm.Blake2b_256, key, KeyBlobFormat.RawSymmetricKey);
        var mac = MacAlgorithm.Blake2b_256.Mac(macKey, message);
        return mac.AsSpan(0, TokenSize).ToArray();
    }

    /// <summary>A fresh discovery key, as an announcer mints for one peer.</summary>
    /// <returns>32 random bytes.</returns>
    public static byte[] NewKey() => RandomNumberGenerator.GetBytes(KeySize);
}

/// <summary>
/// The nonces seen recently, so a captured packet replayed later matches nothing
/// (docs/DISCOVERY.md).
/// </summary>
/// <remarks>
/// Bounded both ways: a nonce is remembered for three slots — past that the slot rule
/// refuses the packet anyway — and at most <see cref="Capacity"/> are held, oldest out
/// first, so a flood of random nonces costs a fixed amount of memory and evicts only other
/// noise.
/// </remarks>
public sealed class ReplayGuard
{
    /// <summary>The most nonces remembered.</summary>
    public const int Capacity = 4096;

    private readonly Lock _gate = new();
    private readonly Queue<(byte[] Nonce, DateTimeOffset SeenUtc)> _order = new();
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

    /// <summary>Whether a nonce is fresh, remembering it when it is.</summary>
    /// <param name="nonce">The packet's nonce.</param>
    /// <param name="nowUtc">The clock.</param>
    /// <returns>False for a nonce seen within the last three slots.</returns>
    public bool IsFresh(ReadOnlySpan<byte> nonce, DateTimeOffset nowUtc)
    {
        var key = Convert.ToHexString(nonce);

        lock (_gate)
        {
            var horizon = nowUtc - (3 * DiscoveryPacket.SlotLength);
            while (_order.Count > 0 && (_order.Peek().SeenUtc < horizon || _order.Count >= Capacity))
            {
                _ = _seen.Remove(Convert.ToHexString(_order.Dequeue().Nonce));
            }

            if (!_seen.Add(key))
            {
                return false;
            }

            _order.Enqueue((nonce.ToArray(), nowUtc));
            return true;
        }
    }
}
