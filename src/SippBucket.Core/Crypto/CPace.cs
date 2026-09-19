using System.Security.Cryptography;

namespace SippBucket.Core.Crypto;

/// <summary>
/// CPace, the balanced password-authenticated key exchange, in the suite
/// CPACE-RISTR255-SHA512.
/// </summary>
/// <remarks>
/// <para>
/// Implemented from draft-irtf-cfrg-cpace-21
/// (https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-21.txt), which was the current
/// revision on 2026-09-18. Section numbers below are that revision's. Every function here is
/// one the draft defines, under the draft's name, and each is pinned by the draft's own test
/// vectors in <c>CPaceTests</c>, byte for byte.
/// </para>
/// <para>
/// <strong>Why a PAKE at all.</strong> Two machines that have never met share only a short
/// code a person read out. Anything built from that code alone — a key derived from it, an
/// envelope sealed under it — can be taken away and tested offline at the attacker's own
/// speed. A PAKE is the construction where that is not possible. In the draft's words
/// (section 2), "CPace protects the passwords against offline dictionary attacks by
/// requiring adversaries to actively interact with a protocol party and by allowing for at
/// most one single password guess per active interaction"; the proof is [AHH21], cited in
/// section 10. That is what turns the five-attempt budget into the whole of the guessing
/// story, rather than one half of it. Section 10.3 names the one thing that would undo it:
/// the shared point K must never be exposed, because "a leaked K may enable offline
/// dictionary attack on the password". Nothing here returns K except
/// <see cref="ScalarMultVfy"/> to its own caller.
/// </para>
/// <para>
/// <strong>Where an implementation drifts, and so where the vectors are aimed:</strong>
/// the length prefixes (<see cref="PrependLen"/> is LEB128, not a fixed width), the zero
/// padding in <see cref="GeneratorString"/>, which is sized from the <em>prefixed</em>
/// lengths and is itself length-prefixed, and the order of every concatenation — generator
/// string DSI, PRS, padding, CI, sid; ISK prefix DSI_ISK, sid, K; transcript initiator
/// first.
/// </para>
/// <para>
/// The group operations come from libsodium through <see cref="Ristretto255"/>; SHA-512 and
/// HMAC come from <see cref="System.Security.Cryptography"/>. Nothing here is a new
/// primitive — this file is the composition the draft specifies, and only that.
/// </para>
/// </remarks>
internal static class CPace
{
    /// <summary>The input block size of SHA-512, H.s_in_bytes (section 6.2).</summary>
    public const int HashBlockSize = 128;

    /// <summary>Bytes in the intermediate session key: SHA-512's output.</summary>
    public const int IskSize = 64;

    /// <summary>Bytes in an explicit key-confirmation tag: HMAC-SHA-512's output.</summary>
    public const int TagSize = 64;

    /// <summary>G_Ristretto255.DSI (section 8.3).</summary>
    public static ReadOnlySpan<byte> Dsi => "CPaceRistretto255"u8;

    /// <summary>G.DSI || b"_ISK", the prefix of the session-key hash (section 7.2).</summary>
    public static ReadOnlySpan<byte> DsiIsk => "CPaceRistretto255_ISK"u8;

    /// <summary>The prefix of the key-confirmation MAC key (section 10.4).</summary>
    private static ReadOnlySpan<byte> MacKeyPrefix => "CPaceMac"u8;

    /// <summary>
    /// The octet string <paramref name="data"/> with its length prepended in LEB128
    /// (section 6.3, appendix A.1.1).
    /// </summary>
    /// <param name="data">The string to prefix.</param>
    /// <returns>The prefixed string.</returns>
    public static byte[] PrependLen(ReadOnlySpan<byte> data)
    {
        // Seven bits per byte, least significant first, bit 7 set while more follow. A
        // single byte below 128 — which is every length pairing uses — and more above, which
        // is exactly the boundary the appendix tests at 127 and 128.
        Span<byte> length = stackalloc byte[10];
        var used = 0;
        var remaining = (ulong)data.Length;

        do
        {
            var low = (byte)(remaining & 0x7F);
            remaining >>= 7;
            length[used++] = remaining == 0 ? low : (byte)(low | 0x80);
        }
        while (remaining != 0);

        var result = new byte[used + data.Length];
        length[..used].CopyTo(result);
        data.CopyTo(result.AsSpan(used));
        return result;
    }

    /// <summary>
    /// Length-value concatenation: every argument prefixed with its own length, in order
    /// (appendix A.1.3).
    /// </summary>
    /// <param name="parts">The strings.</param>
    /// <returns>prepend_len(a0) || prepend_len(a1) || ...</returns>
    public static byte[] LvCat(params ReadOnlySpan<byte[]> parts)
    {
        using var buffer = new MemoryStream();
        foreach (var part in parts)
        {
            buffer.Write(PrependLen(part));
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// generator_string(DSI, PRS, CI, sid, s_in_bytes) (section 8.1, appendix A.2).
    /// </summary>
    /// <param name="dsi">The group's domain-separation identifier.</param>
    /// <param name="prs">The password.</param>
    /// <param name="ci">The channel identifier.</param>
    /// <param name="sid">The session identifier.</param>
    /// <param name="sInBytes">The hash's input block size.</param>
    /// <returns>lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid).</returns>
    /// <remarks>
    /// The padding fills the rest of the hash's first block after the prefixed DSI and PRS,
    /// less one byte for the padding's own length prefix, so that for a short password the
    /// number of bytes hashed does not depend on its length. It is computed from the
    /// <em>prefixed</em> lengths; computing it from the raw ones is the classic slip, and
    /// the appendix vector's 100-byte pad would come out as 102.
    /// </remarks>
    public static byte[] GeneratorString(
        ReadOnlySpan<byte> dsi,
        ReadOnlySpan<byte> prs,
        ReadOnlySpan<byte> ci,
        ReadOnlySpan<byte> sid,
        int sInBytes)
    {
        var zeroPadding = Math.Max(
            0, sInBytes - 1 - PrependLen(prs).Length - PrependLen(dsi).Length);

        return LvCat(dsi.ToArray(), prs.ToArray(), new byte[zeroPadding], ci.ToArray(), sid.ToArray());
    }

    /// <summary>G.calculate_generator(H, PRS, CI, sid) for ristretto255 (section 8.3).</summary>
    /// <param name="prs">The password.</param>
    /// <param name="ci">The channel identifier.</param>
    /// <param name="sid">The session identifier.</param>
    /// <returns>The generator, encoded.</returns>
    /// <remarks>
    /// The generator string is hashed to 2 * field_size_bytes = 64 bytes, which is SHA-512's
    /// whole output, and mapped with the abstraction's element derivation — libsodium's
    /// <c>crypto_core_ristretto255_from_hash</c>. The draft returns the element in the
    /// internal representation; this returns its encoding, which is what libsodium's
    /// multiplication takes, and decoding an encoding the map just produced cannot fail.
    /// </remarks>
    public static byte[] CalculateGenerator(
        ReadOnlySpan<byte> prs,
        ReadOnlySpan<byte> ci,
        ReadOnlySpan<byte> sid)
    {
        var generatorString = GeneratorString(Dsi, prs, ci, sid, HashBlockSize);

        var hash = SHA512.HashData(generatorString);
        try
        {
            return Ristretto255.FromHash(hash);
        }
        finally
        {
            // The first block of that hash input is the password. Neither copy is needed.
            CryptographicOperations.ZeroMemory(generatorString);
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    /// <summary>G.sample_scalar() (section 8.3).</summary>
    /// <returns>A fresh secret scalar.</returns>
    /// <remarks>
    /// Section 8.3 permits either of two samplers: 32 random bytes with everything above bit
    /// 252 cleared, or "uniform sampling between 1 and (G.group_order - 1)". This is the
    /// second, and libsodium's <c>crypto_core_ristretto255_scalar_random</c> is documented to
    /// return exactly that interval. The draft notes the uniform sampler has a larger
    /// side-channel surface on embedded hardware; that is not this program's setting.
    /// Section 10.9: a scalar is never reused, so each call draws a new one.
    /// </remarks>
    public static byte[] SampleScalar() => Ristretto255.RandomScalar();

    /// <summary>G.scalar_mult(y, g): Y = encode(y * g) (section 8.3).</summary>
    /// <param name="scalar">The secret scalar.</param>
    /// <param name="generator">The encoded generator.</param>
    /// <returns>The public share.</returns>
    /// <exception cref="CryptographicException">
    /// The product was the identity, which a generator from the element-derivation map and a
    /// scalar in [1, L-1] cannot produce short of a broken hash.
    /// </exception>
    public static byte[] ScalarMult(byte[] scalar, byte[] generator)
    {
        if (!Ristretto255.TryScalarMultiply(scalar, generator, out var share))
        {
            throw new CryptographicException("CPace produced the neutral element as a public share.");
        }

        return share;
    }

    /// <summary>
    /// G.scalar_mult_vfy(y, X): encode(y * decode(X)), or G.I when X does not decode
    /// (section 8.3).
    /// </summary>
    /// <param name="scalar">The secret scalar.</param>
    /// <param name="element">The other party's encoded share, untrusted.</param>
    /// <returns>The product, or the neutral element's encoding.</returns>
    /// <remarks>
    /// The identity of ristretto255 encodes as 32 zero bytes, and libsodium reports an
    /// identity product as a failure, so both of the draft's conditions arrive here as the
    /// same false and both are returned as <see cref="Identity"/>. The caller then aborts,
    /// as section 7.2 requires: "B MUST abort if K=G.I".
    /// </remarks>
    public static byte[] ScalarMultVfy(byte[] scalar, byte[] element) =>
        Ristretto255.TryScalarMultiply(scalar, element, out var product)
            ? product
            : Identity;

    /// <summary>G.I: the encoding of the neutral element, 32 zero bytes (RFC 9496 section 4.3.2).</summary>
    public static byte[] Identity => new byte[Ristretto255.ElementSize];

    /// <summary>Whether an encoded element is the neutral element, in constant time.</summary>
    /// <param name="element">The encoding to test.</param>
    /// <returns>True for G.I.</returns>
    public static bool IsIdentity(ReadOnlySpan<byte> element) =>
        CryptographicOperations.FixedTimeEquals(element, Identity);

    /// <summary>
    /// transcript_ir(Ya, ADa, Yb, ADb): the initiator's message first (section 6.3, A.3.4).
    /// </summary>
    /// <param name="ya">The initiator's share.</param>
    /// <param name="ada">The initiator's associated data.</param>
    /// <param name="yb">The responder's share.</param>
    /// <param name="adb">The responder's associated data.</param>
    /// <returns>lv_cat(Ya, ADa) || lv_cat(Yb, ADb).</returns>
    public static byte[] TranscriptIr(byte[] ya, byte[] ada, byte[] yb, byte[] adb) =>
        [.. LvCat(ya, ada), .. LvCat(yb, adb)];

    /// <summary>
    /// transcript_oc(Ya, ADa, Yb, ADb): the two messages in lexicographic order (section 6.3,
    /// A.3.6).
    /// </summary>
    /// <param name="ya">One party's share.</param>
    /// <param name="ada">That party's associated data.</param>
    /// <param name="yb">The other party's share.</param>
    /// <param name="adb">The other party's associated data.</param>
    /// <returns>o_cat(lv_cat(Ya, ADa), lv_cat(Yb, ADb)).</returns>
    /// <remarks>
    /// The symmetric mode, for parties with no initiator and responder. Pairing does not use
    /// it — the joiner always dials and the offerer always answers, so the draft's
    /// initiator-responder transcript applies (section 6.3). It is here because the ordering
    /// rule is part of the suite, the appendix pins it with vectors, and a transcript
    /// function that has never been checked against them is one somebody will reach for
    /// later on the assumption that it was.
    /// </remarks>
    public static byte[] TranscriptOc(byte[] ya, byte[] ada, byte[] yb, byte[] adb) =>
        OCat(LvCat(ya, ada), LvCat(yb, adb));

    /// <summary>o_cat: b"oc", then the lexicographically larger string, then the other (A.3.2).</summary>
    /// <param name="first">One string.</param>
    /// <param name="second">The other.</param>
    /// <returns>The ordered concatenation.</returns>
    public static byte[] OCat(byte[] first, byte[] second) =>
        LexicographicallyLarger(first, second)
            ? [.. "oc"u8, .. first, .. second]
            : [.. "oc"u8, .. second, .. first];

    /// <summary>
    /// True when <paramref name="first"/> sorts after <paramref name="second"/>, comparing
    /// bytes and then lengths (A.3.1).
    /// </summary>
    /// <param name="first">One string.</param>
    /// <param name="second">The other.</param>
    /// <returns>Whether the first is larger.</returns>
    public static bool LexicographicallyLarger(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        var common = Math.Min(first.Length, second.Length);
        for (var i = 0; i < common; i++)
        {
            if (first[i] != second[i])
            {
                return first[i] > second[i];
            }
        }

        return first.Length > second.Length;
    }

    /// <summary>
    /// ISK = H.hash(lv_cat(G.DSI || b"_ISK", sid, K) || transcript) (section 7.2).
    /// </summary>
    /// <param name="sid">The session identifier.</param>
    /// <param name="k">The shared point.</param>
    /// <param name="transcript">The transcript, in the mode both parties agreed.</param>
    /// <returns>The intermediate session key.</returns>
    public static byte[] DeriveIsk(byte[] sid, byte[] k, byte[] transcript)
    {
        byte[] input = [.. LvCat(DsiIsk.ToArray(), sid, k), .. transcript];
        try
        {
            return SHA512.HashData(input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    /// <summary>
    /// mac_key = H.hash(b"CPaceMac" || sid || ISK), for explicit key confirmation
    /// (section 10.4).
    /// </summary>
    /// <param name="sid">The session identifier.</param>
    /// <param name="isk">The intermediate session key.</param>
    /// <returns>The MAC key.</returns>
    public static byte[] MacKey(byte[] sid, byte[] isk)
    {
        byte[] input = [.. MacKeyPrefix, .. sid, .. isk];
        try
        {
            return SHA512.HashData(input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    /// <summary>
    /// A party's key-confirmation tag: MAC(mac_key, lv_cat(Y, AD)) over the message that
    /// party sent (section 10.4), with HMAC-SHA-512 as the MAC.
    /// </summary>
    /// <param name="macKey">The MAC key.</param>
    /// <param name="share">The share the tagging party sent.</param>
    /// <param name="associatedData">The associated data it sent with it.</param>
    /// <returns>The tag.</returns>
    public static byte[] ConfirmationTag(byte[] macKey, byte[] share, byte[] associatedData) =>
        HMACSHA512.HashData(macKey, LvCat(share, associatedData));
}
