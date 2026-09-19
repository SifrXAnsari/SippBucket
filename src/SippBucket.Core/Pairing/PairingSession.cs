using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using SippBucket.Core.Crypto;

namespace SippBucket.Core.Pairing;

/// <summary>
/// One pairing window: a secret, a deadline, and a budget of wrong answers.
/// </summary>
/// <remarks>
/// <para>
/// The secret is either a spoken code (<see cref="PairingSession(TimeSpan?, Func{long}?)"/>)
/// or the longer one-time secret inside a pasted invite (<see cref="ForInvitation"/>). Both
/// are used the same way: as the password of a CPace run, one run per attempt.
/// </para>
/// <para>
/// The entropy of the code is not what defends this. Twelve symbols is 48 bits, and an
/// attacker managing an unrealistic 10,000 guesses a second for the full ten minutes still
/// only reaches about one in 47 million. <strong>The attempt budget is the control</strong>;
/// the length is there so that a bug in the budget is survivable rather than fatal.
/// </para>
/// <para>
/// With a PAKE, a guess is not a string compared against the code — the code never crosses
/// the network. A guess is a CPace run: the other machine commits to one password in its
/// share, this machine answers with the real one, and key confirmation either verifies or
/// does not. So an attempt is counted when this machine commits its answer, in
/// <see cref="BeginAttempt"/>, <em>before</em> anybody can know whether the confirmation will
/// verify. Each rule below exists because of a specific way this is got wrong:
/// </para>
/// <list type="bullet">
/// <item>The counter is incremented <em>before</em> the answer is computed, so a crash, a
/// dropped connection or a guesser who simply never sends a confirmation cannot hand the
/// attacker a fresh budget.</item>
/// <item>Accounting is serialised, because five simultaneous connections can otherwise all
/// read the counter before any of them writes it.</item>
/// <item>Expiry is measured on a <em>monotonic</em> clock, never wall time — otherwise
/// changing the system clock extends the window.</item>
/// <item>Wrong, expired, burnt and closed all produce the same thing on the wire. A closed
/// window still answers — with a share computed from a random password nobody holds — so
/// the other machine's key confirmation fails exactly as it would for a wrong code. Telling
/// them apart tells an attacker when a window is open, which is the more useful signal than
/// whether one guess was right.</item>
/// </list>
/// <para>
/// <strong>What 48 bits does and does not cover now.</strong> The old warning here was that
/// 48 bits is thin against an offline attack and must never protect anything a holder can
/// carry away. CPace is what makes that hold: section 2 of draft-irtf-cfrg-cpace-21 — "at
/// most one single password guess per active interaction". The code is not in any message,
/// and nothing that is in a message can be tested against a guess without talking to this
/// machine, which is counting.
/// </para>
/// </remarks>
public sealed class PairingSession
{
    /// <summary>How long a code is offered for.</summary>
    public static TimeSpan DefaultLifetime { get; } = TimeSpan.FromMinutes(10);

    /// <summary>How many wrong answers a code survives.</summary>
    public const int MaximumAttempts = 5;

    /// <summary>Bytes of randomness in an invitation's one-time secret.</summary>
    /// <remarks>
    /// 128 bits, against the spoken code's 48. It is pasted rather than read aloud, so its
    /// length costs nothing, and at this size even the length alone would hold if the
    /// budget failed completely.
    /// </remarks>
    public const int InvitationSecretSize = 16;

    /// <summary>Shortest gap between two attempts.</summary>
    /// <remarks>
    /// So the five-attempt budget cannot be spent in a single burst. Defence in depth: the
    /// budget is the real control and this only shapes how it is consumed.
    /// </remarks>
    public static TimeSpan MinimumInterval { get; } = TimeSpan.FromSeconds(1);

    private readonly Lock _gate = new();
    private readonly byte[] _password;
    private readonly string _display;
    private readonly long _startedTicks;
    private readonly long _lifetimeTicks;
    private readonly Func<long> _clock;

    private int _attempts;
    private long _lastAttemptTicks;
    private bool _consumed;
    private bool _burnt;
    private bool _cancelled;

    /// <summary>Opens a pairing window with a fresh spoken code.</summary>
    /// <param name="lifetime">How long the code is valid, or null for the default.</param>
    /// <param name="clock">
    /// A monotonic tick source, for tests. Defaults to <see cref="Stopwatch.GetTimestamp"/>.
    /// </param>
    public PairingSession(TimeSpan? lifetime = null, Func<long>? clock = null)
        : this(PairingCode.Generate(), lifetime, clock)
    {
    }

    private PairingSession(string code, TimeSpan? lifetime, Func<long>? clock)
        : this(PasswordForCode(code), PairingCode.Format(code), lifetime, clock)
    {
        Kind = PairingSecretKind.SpokenCode;
    }

    private PairingSession(byte[] password, string display, TimeSpan? lifetime, Func<long>? clock)
    {
        _password = password;
        _display = display;
        _clock = clock ?? Stopwatch.GetTimestamp;
        _startedTicks = _clock();
        _lastAttemptTicks = long.MinValue;

        var span = lifetime ?? DefaultLifetime;
        _lifetimeTicks = (long)(span.TotalSeconds * Stopwatch.Frequency);
    }

    /// <summary>
    /// Opens a pairing window for a pasted invitation, with a fresh 128-bit one-time secret.
    /// </summary>
    /// <param name="lifetime">How long the secret is valid, or null for the default.</param>
    /// <param name="clock">A monotonic tick source, for tests.</param>
    /// <returns>The window.</returns>
    /// <remarks>Same lifetime, same budget, same throttle as a spoken code.</remarks>
    public static PairingSession ForInvitation(TimeSpan? lifetime = null, Func<long>? clock = null)
    {
        var secret = RandomNumberGenerator.GetBytes(InvitationSecretSize);
        return new PairingSession(secret, PairingInvitation.EncodeSecret(secret), lifetime, clock)
        {
            Kind = PairingSecretKind.InvitationSecret,
        };
    }

    /// <summary>Whether this window's secret is spoken or pasted.</summary>
    public PairingSecretKind Kind { get; private init; }

    /// <summary>
    /// The secret, formatted for a person: the code in groups of four, or the invitation
    /// secret as it is written inside a <c>sip2_</c> string.
    /// </summary>
    /// <remarks>
    /// The only way the secret leaves this object for display. It has to — somebody has to
    /// read it out or paste it — but it is not a way to <em>use</em> the secret: the only
    /// path from here to a CPace run is <see cref="BeginAttempt"/>, which counts.
    /// </remarks>
    public string Display => _display;

    /// <summary>How many attempts have been counted.</summary>
    public int Attempts
    {
        get
        {
            lock (_gate)
            {
                return _attempts;
            }
        }
    }

    /// <summary>How long is left, floored at zero.</summary>
    public TimeSpan Remaining
    {
        get
        {
            var elapsed = _clock() - _startedTicks;
            var left = _lifetimeTicks - elapsed;
            return left <= 0
                ? TimeSpan.Zero
                : TimeSpan.FromSeconds(left / (double)Stopwatch.Frequency);
        }
    }

    /// <summary>True while this window would still start a counted attempt.</summary>
    public bool IsOpen
    {
        get
        {
            lock (_gate)
            {
                return !_consumed && !_burnt && !_cancelled && Remaining > TimeSpan.Zero;
            }
        }
    }

    /// <summary>Why the window is no longer open, for the machine that owns it.</summary>
    /// <remarks>
    /// For the local interface only. It is never sent to whoever is guessing — see
    /// <see cref="BeginAttempt"/>.
    /// </remarks>
    public PairingClosure Closure
    {
        get
        {
            lock (_gate)
            {
                if (_consumed)
                {
                    return PairingClosure.Used;
                }

                if (_burnt || _cancelled)
                {
                    return PairingClosure.TooManyAttempts;
                }

                return Remaining <= TimeSpan.Zero ? PairingClosure.Expired : PairingClosure.Open;
            }
        }
    }

    /// <summary>
    /// How long a caller must wait before an attempt will be counted rather than answered
    /// as a decoy.
    /// </summary>
    /// <returns>Zero when an attempt may be made now.</returns>
    /// <remarks>
    /// <para>
    /// Exposed so a server can <em>pace</em> rather than refuse. Refusing an early attempt
    /// rate-limits an attacker and also fails a legitimate user who mistyped once and
    /// retyped immediately — which is exactly what happened the first time this was run end
    /// to end: two <c>sip pair enter</c> invocations landed under a second apart and the
    /// <strong>correct</strong> code came back refused.
    /// </para>
    /// <para>
    /// Waiting achieves the same ceiling on guess rate with no false refusals, which is what
    /// a login throttle is supposed to do. The bound stays honest because the five-attempt
    /// budget is what actually ends the window; this only shapes how fast it can be spent.
    /// </para>
    /// </remarks>
    public TimeSpan TimeUntilNextAttempt()
    {
        lock (_gate)
        {
            if (_lastAttemptTicks == long.MinValue)
            {
                return TimeSpan.Zero;
            }

            var elapsed = (_clock() - _lastAttemptTicks) / (double)Stopwatch.Frequency;
            var remaining = MinimumInterval.TotalSeconds - elapsed;

            // A floor of one tick when there is anything left at all. Returning a
            // vanishingly small positive value would make a caller loop on Task.Delay(0)
            // and spin; returning zero while BeginAttempt still considers it too soon would
            // make the caller believe it is eligible when it is not.
            return remaining <= 0
                ? TimeSpan.Zero
                : TimeSpan.FromSeconds(Math.Max(remaining, 0.001));
        }
    }

    /// <summary>
    /// Starts one attempt: counts it, and hands back the means to answer exactly one CPace
    /// run with this window's secret.
    /// </summary>
    /// <returns>
    /// A live attempt when the window is open and not throttled, counted against the budget;
    /// otherwise a decoy that answers with a random password and is not counted.
    /// </returns>
    /// <remarks>
    /// Always returns something to answer with. A closed window answering differently from
    /// an open one — or not at all — would tell an attacker which it is. The decoy costs the
    /// same work as a live answer and fails confirmation for everybody, including the holder
    /// of the right code, which is the point: nothing distinguishes wrong from closed.
    /// </remarks>
    internal PairingAttempt BeginAttempt()
    {
        lock (_gate)
        {
            if (_consumed || _burnt || _cancelled || Remaining <= TimeSpan.Zero)
            {
                return PairingAttempt.Decoy();
            }

            var now = _clock();

            if (_lastAttemptTicks != long.MinValue &&
                now - _lastAttemptTicks < MinimumInterval.TotalSeconds * Stopwatch.Frequency)
            {
                // Too soon. Deliberately NOT counted against the budget: an attacker gains
                // nothing by being told to slow down, and counting it would let anyone who
                // can reach the port exhaust a legitimate user's attempts by flooding.
                return PairingAttempt.Decoy();
            }

            _lastAttemptTicks = now;

            // Counted BEFORE the answer exists. If this process dies, or the other machine
            // hangs up without confirming, the attempt is already spent rather than
            // forgotten.
            _attempts++;

            if (_attempts >= MaximumAttempts)
            {
                _burnt = true;
            }

            return PairingAttempt.Live((byte[])_password.Clone());
        }
    }

    /// <summary>
    /// Finishes an attempt with the other machine's key confirmation, and closes the window
    /// behind it if it verifies.
    /// </summary>
    /// <param name="attempt">The attempt, already answered.</param>
    /// <param name="initiatorTag">The confirmation tag the other machine sent.</param>
    /// <returns>Accepted, or refused with no reason given.</returns>
    /// <remarks>
    /// Verifies the tag itself rather than trusting a caller's boolean, so the only way to
    /// consume a window is a run in which the other machine proved it holds the secret.
    /// The fifth attempt may still succeed — it was counted, and the budget closed behind
    /// it — but not one begun after the window expired or was cancelled, and not a decoy.
    /// </remarks>
    internal PairingOffer Conclude(PairingAttempt attempt, ReadOnlySpan<byte> initiatorTag)
    {
        ArgumentNullException.ThrowIfNull(attempt);

        lock (_gate)
        {
            if (!attempt.IsLive || !attempt.IsConfirmedBy(initiatorTag))
            {
                return PairingOffer.Refused;
            }

            if (_consumed || _cancelled || Remaining <= TimeSpan.Zero)
            {
                return PairingOffer.Refused;
            }

            _consumed = true;
            _burnt = false;
            return PairingOffer.Accepted;
        }
    }

    /// <summary>Closes the window without waiting for it to expire.</summary>
    public void Cancel()
    {
        lock (_gate)
        {
            _cancelled = true;
        }
    }

    /// <summary>The CPace password for a spoken code: its canonical twelve symbols, in ASCII.</summary>
    /// <param name="normalisedCode">A code already through <see cref="PairingCode.TryNormalise"/>.</param>
    /// <returns>PRS.</returns>
    /// <remarks>
    /// Canonical, so that however it was typed — lower case, spaces, a forgiven S for 5 —
    /// both machines feed CPace the same bytes. The draft leaves the encoding of PRS to the
    /// application (section 4.3); every symbol is ASCII, so there is only one.
    /// </remarks>
    internal static byte[] PasswordForCode(string normalisedCode) =>
        Encoding.ASCII.GetBytes(normalisedCode);
}

/// <summary>Whether a pairing secret is read aloud or pasted.</summary>
public enum PairingSecretKind
{
    /// <summary>A twelve-symbol code, for <c>sip pair</c>.</summary>
    SpokenCode = 0,

    /// <summary>A 128-bit secret inside a <c>sip2_</c> invitation, for <c>sip invite</c>.</summary>
    InvitationSecret = 1,
}

/// <summary>
/// One counted attempt, or one decoy: the means to answer a single CPace run, and then to
/// check the other machine's confirmation.
/// </summary>
/// <remarks>
/// Holds a copy of the password only until <see cref="Respond"/> has computed the answer,
/// then zeroes it. It cannot be used to answer twice.
/// </remarks>
internal sealed class PairingAttempt : IDisposable
{
    private readonly byte[] _password;
    private CPaceParty? _party;
    private CPaceSessionKeys? _keys;
    private bool _responded;

    private PairingAttempt(byte[] password, bool isLive)
    {
        _password = password;
        IsLive = isLive;
    }

    /// <summary>Whether this attempt was counted and carries the real secret.</summary>
    public bool IsLive { get; }

    /// <summary>Yb, once <see cref="Respond"/> has succeeded.</summary>
    public byte[] Share => _party?.Share ?? throw NotAnswered();

    /// <summary>ADb, once <see cref="Respond"/> has succeeded.</summary>
    public byte[] AssociatedData => _party?.AssociatedData ?? throw NotAnswered();

    /// <summary>Tb, once <see cref="Respond"/> has succeeded.</summary>
    public byte[] Confirmation => _keys?.OwnTag ?? throw NotAnswered();

    /// <summary>ISK, once <see cref="Respond"/> has succeeded.</summary>
    public byte[] Isk => _keys?.Isk ?? throw NotAnswered();

    /// <summary>An attempt with the real secret.</summary>
    /// <param name="password">A copy of the secret, which this object zeroes.</param>
    /// <returns>The attempt.</returns>
    public static PairingAttempt Live(byte[] password) => new(password, isLive: true);

    /// <summary>An attempt with a random password nobody holds.</summary>
    /// <returns>The decoy.</returns>
    public static PairingAttempt Decoy() =>
        new(RandomNumberGenerator.GetBytes(PairingSession.InvitationSecretSize), isLive: false);

    /// <summary>Answers the other machine's CPace message as the responder.</summary>
    /// <param name="sessionId">sid.</param>
    /// <param name="remoteShare">Ya, untrusted.</param>
    /// <param name="remoteAssociatedData">ADa, untrusted.</param>
    /// <returns>False when the run must be aborted: Ya did not decode, or K was the identity.</returns>
    /// <exception cref="InvalidOperationException">This attempt already answered.</exception>
    public bool Respond(byte[] sessionId, byte[] remoteShare, byte[] remoteAssociatedData)
    {
        if (_responded)
        {
            throw new InvalidOperationException("An attempt answers one CPace run, once.");
        }

        _responded = true;

        try
        {
            _party = CPaceParty.Start(
                CPaceRole.Responder,
                _password,
                PairingProtocol.ChannelIdentifier,
                sessionId,
                PairingProtocol.OffererAssociatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(_password);
        }

        _keys = _party.Complete(remoteShare, remoteAssociatedData);
        return _keys is not null;
    }

    /// <summary>Whether the other machine's confirmation tag verifies.</summary>
    /// <param name="initiatorTag">Ta, untrusted.</param>
    /// <returns>True only when the other machine derived the same ISK.</returns>
    public bool IsConfirmedBy(ReadOnlySpan<byte> initiatorTag) =>
        _keys is not null && _keys.IsRemoteTagValid(initiatorTag);

    /// <inheritdoc />
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_password);
        _keys?.Dispose();
        _party?.Dispose();
    }

    private static InvalidOperationException NotAnswered() =>
        new("The attempt has not answered a CPace run.");
}

/// <summary>The result of concluding an attempt.</summary>
/// <remarks>
/// Two values, and no third. A refusal never says whether the code was wrong, expired,
/// burnt, or never existed — those distinctions tell an attacker when a pairing window is
/// open, which is more useful to them than knowing whether one guess was right.
/// </remarks>
public enum PairingOffer
{
    /// <summary>The attempt did not open the window. No further detail is given.</summary>
    Refused = 0,

    /// <summary>The other machine proved it holds the secret, and the window is now closed.</summary>
    Accepted = 1,
}

/// <summary>Why a pairing window is closed, for the machine that opened it.</summary>
public enum PairingClosure
{
    /// <summary>Still accepting attempts.</summary>
    Open = 0,

    /// <summary>The secret was used.</summary>
    Used = 1,

    /// <summary>The ten minutes ran out.</summary>
    Expired = 2,

    /// <summary>Too many wrong answers, or cancelled; a new code is needed.</summary>
    TooManyAttempts = 3,
}
