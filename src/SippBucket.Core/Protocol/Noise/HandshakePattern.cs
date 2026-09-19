namespace SippBucket.Core.Protocol.Noise;

/// <summary>A token in a Noise message pattern (Noise revision 34, section 5.3).</summary>
internal enum NoiseToken
{
    /// <summary><c>e</c>: an ephemeral public key.</summary>
    E,

    /// <summary><c>s</c>: a static public key, encrypted once a key exists.</summary>
    S,

    /// <summary><c>ee</c>: DH between the two ephemeral keys.</summary>
    Ee,

    /// <summary><c>es</c>: DH between the initiator's ephemeral and the responder's static key.</summary>
    Es,

    /// <summary><c>se</c>: DH between the initiator's static and the responder's ephemeral key.</summary>
    Se,

    /// <summary><c>ss</c>: DH between the two static keys.</summary>
    Ss,
}

/// <summary>
/// A Noise handshake pattern: the pre-messages and the message patterns (Noise revision 34,
/// section 7; https://noiseprotocol.org/noise.html).
/// </summary>
/// <remarks>
/// Only the patterns this build uses or checks itself against are defined. Messages alternate
/// direction starting with the initiator, which holds for every fundamental pattern in
/// section 7.4; pre-messages may carry only <c>s</c>, which holds for every one of them too.
/// </remarks>
internal sealed class HandshakePattern
{
    private HandshakePattern(
        string name,
        NoiseToken[] initiatorPreMessage,
        NoiseToken[] responderPreMessage,
        NoiseToken[][] messages)
    {
        Name = name;
        InitiatorPreMessage = initiatorPreMessage;
        ResponderPreMessage = responderPreMessage;
        Messages = messages;
    }

    /// <summary>
    /// <c>NN</c>: <c>-&gt; e</c> / <c>&lt;- e, ee</c>. No authentication. Here only to check the
    /// symmetric layer against a second published vector.
    /// </summary>
    public static HandshakePattern NN { get; } = new(
        "NN",
        [],
        [],
        [
            [NoiseToken.E],
            [NoiseToken.E, NoiseToken.Ee],
        ]);

    /// <summary>
    /// <c>XK</c>: <c>&lt;- s</c> / <c>...</c> / <c>-&gt; e, es</c> / <c>&lt;- e, ee</c> /
    /// <c>-&gt; s, se</c>. The responder's static key is known in advance; the initiator's
    /// travels encrypted in the third message.
    /// </summary>
    public static HandshakePattern XK { get; } = new(
        "XK",
        [],
        [NoiseToken.S],
        [
            [NoiseToken.E, NoiseToken.Es],
            [NoiseToken.E, NoiseToken.Ee],
            [NoiseToken.S, NoiseToken.Se],
        ]);

    /// <summary>The pattern's name as it appears in the protocol name.</summary>
    public string Name { get; }

    /// <summary>Public keys the responder already knows about the initiator.</summary>
    public IReadOnlyList<NoiseToken> InitiatorPreMessage { get; }

    /// <summary>Public keys the initiator already knows about the responder.</summary>
    public IReadOnlyList<NoiseToken> ResponderPreMessage { get; }

    /// <summary>The message patterns, initiator first, alternating.</summary>
    public IReadOnlyList<IReadOnlyList<NoiseToken>> Messages { get; }
}
