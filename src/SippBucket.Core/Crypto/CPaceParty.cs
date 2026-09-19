using System.Security.Cryptography;

namespace SippBucket.Core.Crypto;

/// <summary>Which side of a CPace run a party is.</summary>
internal enum CPaceRole
{
    /// <summary>Party A: sends first, and its message comes first in the transcript.</summary>
    Initiator = 0,

    /// <summary>Party B: answers.</summary>
    Responder = 1,
}

/// <summary>
/// One party's side of one CPace run, in the initiator-responder setting (draft section 7).
/// </summary>
/// <remarks>
/// <para>
/// Holds the secret scalar from the moment the share is computed until the run completes,
/// and then zeroes it. A run completes once: section 10.9 says "Secret scalars ya and yb
/// MUST NOT be reused", and an object that could be completed twice would be a way to reuse
/// one.
/// </para>
/// <para>
/// The shared point K is computed inside <see cref="Complete"/> and never leaves it.
/// Section 10.3: an implementation "MUST NOT expose K", because a leaked K may allow an
/// offline dictionary attack on the password — the one attack a PAKE exists to prevent.
/// </para>
/// </remarks>
internal sealed class CPaceParty : IDisposable
{
    private readonly byte[] _scalar;
    private readonly byte[] _sid;
    private bool _completed;

    private CPaceParty(CPaceRole role, byte[] scalar, byte[] share, byte[] associatedData, byte[] sid)
    {
        Role = role;
        _scalar = scalar;
        Share = share;
        AssociatedData = associatedData;
        _sid = sid;
    }

    /// <summary>Which side this party is.</summary>
    public CPaceRole Role { get; }

    /// <summary>This party's public share, Ya or Yb, to send.</summary>
    public byte[] Share { get; }

    /// <summary>This party's associated data, ADa or ADb, to send with the share.</summary>
    public byte[] AssociatedData { get; }

    /// <summary>Starts a run: computes the generator and this party's share.</summary>
    /// <param name="role">Which side this party is.</param>
    /// <param name="password">PRS, the shared low-entropy secret.</param>
    /// <param name="channelIdentifier">CI, identical on both sides.</param>
    /// <param name="sessionId">sid, identical on both sides.</param>
    /// <param name="associatedData">This party's AD, sent in the clear and authenticated.</param>
    /// <returns>The party, ready to send <see cref="Share"/>.</returns>
    public static CPaceParty Start(
        CPaceRole role,
        ReadOnlySpan<byte> password,
        byte[] channelIdentifier,
        byte[] sessionId,
        byte[] associatedData) =>
        Start(role, password, channelIdentifier, sessionId, associatedData, CPace.SampleScalar());

    /// <summary>
    /// Starts a run with a scalar chosen by the caller. The seam the draft's test vectors
    /// go through, since they fix ya and yb; nothing else may call it.
    /// </summary>
    /// <param name="role">Which side this party is.</param>
    /// <param name="password">PRS.</param>
    /// <param name="channelIdentifier">CI.</param>
    /// <param name="sessionId">sid.</param>
    /// <param name="associatedData">This party's AD.</param>
    /// <param name="scalar">The secret scalar, which this object now owns and zeroes.</param>
    /// <returns>The party.</returns>
    internal static CPaceParty Start(
        CPaceRole role,
        ReadOnlySpan<byte> password,
        byte[] channelIdentifier,
        byte[] sessionId,
        byte[] associatedData,
        byte[] scalar)
    {
        ArgumentNullException.ThrowIfNull(channelIdentifier);
        ArgumentNullException.ThrowIfNull(sessionId);
        ArgumentNullException.ThrowIfNull(associatedData);
        ArgumentNullException.ThrowIfNull(scalar);

        var generator = CPace.CalculateGenerator(password, channelIdentifier, sessionId);
        var share = CPace.ScalarMult(scalar, generator);

        return new CPaceParty(
            role,
            scalar,
            share,
            (byte[])associatedData.Clone(),
            (byte[])sessionId.Clone());
    }

    /// <summary>
    /// Completes the run with the other party's message and derives the session keys.
    /// </summary>
    /// <param name="remoteShare">The other party's share, untrusted.</param>
    /// <param name="remoteAssociatedData">The other party's AD, untrusted.</param>
    /// <returns>
    /// The keys, or null when the run must be aborted because K is the neutral element —
    /// which is what a share that does not decode, or a share of the identity, produces.
    /// </returns>
    /// <exception cref="InvalidOperationException">The run was already completed.</exception>
    public CPaceSessionKeys? Complete(byte[] remoteShare, byte[] remoteAssociatedData)
    {
        ArgumentNullException.ThrowIfNull(remoteShare);
        ArgumentNullException.ThrowIfNull(remoteAssociatedData);

        if (_completed)
        {
            throw new InvalidOperationException("A CPace run completes once; its scalar is gone.");
        }

        _completed = true;

        var k = CPace.ScalarMultVfy(_scalar, remoteShare);
        CryptographicOperations.ZeroMemory(_scalar);

        try
        {
            if (CPace.IsIdentity(k))
            {
                // Section 7.2: "B MUST abort if K=G.I", and likewise A.
                return null;
            }

            var transcript = Role == CPaceRole.Initiator
                ? CPace.TranscriptIr(Share, AssociatedData, remoteShare, remoteAssociatedData)
                : CPace.TranscriptIr(remoteShare, remoteAssociatedData, Share, AssociatedData);

            var isk = CPace.DeriveIsk(_sid, k, transcript);
            var macKey = CPace.MacKey(_sid, isk);

            return new CPaceSessionKeys(
                isk,
                macKey,
                CPace.ConfirmationTag(macKey, Share, AssociatedData),
                CPace.ConfirmationTag(macKey, remoteShare, remoteAssociatedData));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(k);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _completed = true;
        CryptographicOperations.ZeroMemory(_scalar);
    }
}

/// <summary>
/// What a completed CPace run yields: the intermediate session key and the explicit key
/// confirmation of draft section 10.4.
/// </summary>
/// <remarks>
/// Section 10.4 leaves key confirmation to the application and recommends it wherever
/// perfect forward security is wanted. Pairing wants more than that from it: confirmation
/// is the moment a wrong code is discovered, in both directions, before anything secret has
/// moved. The construction is the draft's own suggestion: mac_key = H(b"CPaceMac" || sid ||
/// ISK), and each party tags the message it sent, lv_cat(Y, AD). The draft gives no test
/// vectors for it; the tests pin it by deriving it independently from the ISK the vectors
/// do give.
/// </remarks>
internal sealed class CPaceSessionKeys : IDisposable
{
    private readonly byte[] _macKey;
    private readonly byte[] _expectedRemoteTag;

    internal CPaceSessionKeys(byte[] isk, byte[] macKey, byte[] ownTag, byte[] expectedRemoteTag)
    {
        Isk = isk;
        _macKey = macKey;
        OwnTag = ownTag;
        _expectedRemoteTag = expectedRemoteTag;
    }

    /// <summary>ISK. Feed it to a key-derivation function before use (section 10.3).</summary>
    public byte[] Isk { get; }

    /// <summary>This party's confirmation tag, to send.</summary>
    public byte[] OwnTag { get; }

    /// <summary>Checks the other party's confirmation tag, in constant time.</summary>
    /// <param name="tag">The tag the other party sent, untrusted.</param>
    /// <returns>True only when it proves the other party derived the same ISK.</returns>
    public bool IsRemoteTagValid(ReadOnlySpan<byte> tag) =>
        tag.Length == _expectedRemoteTag.Length &&
        CryptographicOperations.FixedTimeEquals(tag, _expectedRemoteTag);

    /// <inheritdoc />
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(Isk);
        CryptographicOperations.ZeroMemory(_macKey);
        CryptographicOperations.ZeroMemory(OwnTag);
        CryptographicOperations.ZeroMemory(_expectedRemoteTag);
    }
}
