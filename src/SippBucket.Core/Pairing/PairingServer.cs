using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using SippBucket.Core.Crypto;
using SippBucket.Core.Platform;
using SippBucket.Core.Repository;

namespace SippBucket.Core.Pairing;

/// <summary>
/// Holds a pairing window open: answers CPace runs from a machine that has the code, and
/// hands it the repository once both sides have proved they hold the same one.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately <em>not</em> the sync port and <em>not</em> the <c>SecureChannel</c>. That
/// channel refuses anyone who is not already a known peer — which is correct, and which is
/// exactly why it cannot carry pairing: at this point the two machines have never met, so
/// there is no identity to verify and nothing in the peer list to check against.
/// </para>
/// <para>
/// <strong>It exists only while a code is live.</strong> Ten minutes, one success, five
/// wrong answers — then the listener closes, not merely stops answering. A permanently open
/// unauthenticated port would be a standing invitation; one that exists for ten minutes
/// after a deliberate human act is a different thing, and the difference is the whole
/// security argument.
/// </para>
/// <para>
/// A guess is one connection's CPace run, counted by <see cref="PairingSession"/> before the
/// answer is computed. Nothing distinguishes a wrong guess from a closed window from the
/// outside, and nothing secret is sent until both key confirmations have verified — see
/// <see cref="PairingProtocol"/> for the frames and the reasons for their order.
/// </para>
/// <para>
/// <strong>Connections, and what one of them can hold up (D-62).</strong> This used to
/// serve one connection at a time, with only the 20-second per-frame stall deadline, so a
/// connection that opened and said nothing held the window for 20 seconds, and one that sent
/// a byte every 19 seconds held it until the code expired. Neither spent an attempt. Now:
/// </para>
/// <list type="bullet">
/// <item>Up to <see cref="MaximumConnections"/> connections are served at once, so one that
/// stalls does not stop another. The cap is there so an unauthenticated caller cannot open
/// sockets without limit (standard C2).</item>
/// <item>Every connection has an overall deadline, <see cref="ConnectionDeadline"/>, however
/// steadily it dribbles.</item>
/// <item>Until a connection has made its guess, everything it sends must arrive within
/// <see cref="OpeningDeadline"/> of it connecting. A joining machine sends those two frames
/// without waiting on a person, so this costs it nothing.</item>
/// <item>When every place is taken, a new connection displaces one that has not yet made its
/// guess, from whichever remote address holds the most places, oldest first. A flood from one
/// address therefore displaces itself and never the machine that is actually pairing, which
/// has one connection from an address of its own. When nothing can be displaced, the new
/// connection is closed.</item>
/// </list>
/// <para>
/// <strong>What this does not change: the five attempts.</strong> The CPace draft bounds what
/// one run gives a guesser, "allowing for at most one single password guess per active
/// interaction" (draft-irtf-cfrg-cpace-21 section 2,
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-21.html). It says nothing about how
/// many runs to allow; that budget is this program's, in <see cref="PairingSession"/>, and it
/// is counted exactly where it was, when this machine commits its answer to a share. A
/// connection that is displaced, turned away, or cut off by a deadline before that point has
/// made no guess, and costs nothing. Guesses are still counted one at a time, a second
/// apart, through one gate, so serving connections side by side did not change the throttle
/// either: a joiner's share that arrives while another is being counted waits its turn
/// rather than being answered as a decoy.
/// </para>
/// <para>
/// What it cannot prevent: whoever holds <see cref="MaximumConnections"/> places with
/// connections that have each made a guess keeps a newcomer out, but that is spending the
/// budget, and five guesses end the window anyway. That trade is the five-attempt rule's
/// own, and it is the same one it always was.
/// </para>
/// <para>
/// This replaced an exchange in which the joining machine sent the code itself, in clear
/// JSON, and received the repository key sealed under an Argon2id derivation of that code.
/// The sealing was described as protection for "somebody holding a packet capture"; a
/// packet capture held the code, and a test that recorded one opened the envelope with it.
/// With CPace there is nothing in a capture to test a guess against (draft-irtf-cfrg-cpace
/// section 2), so there is no offline attack left for a slow hash to price, and the
/// envelope has gone rather than being kept as a second layer over nothing.
/// </para>
/// </remarks>
public sealed class PairingServer : IAsyncDisposable
{
    /// <summary>The TCP port a pairing offer is made on, relative to the sync port.</summary>
    /// <remarks>
    /// One above the sync port by convention, so a firewall rule for a repository covers
    /// both and a reader of a rule list can see they belong together.
    /// </remarks>
    public const int PortOffset = 1;

    /// <summary>How many connections are served at once.</summary>
    /// <remarks>
    /// More than <see cref="PairingSession.MaximumAttempts"/>, so that while the window is
    /// open there is always a place that is free or held by a connection yet to make its
    /// guess, which a newcomer can take.
    /// </remarks>
    public const int MaximumConnections = 8;

    private readonly SipRepository _repository;
    private readonly DeviceIdentity _identity;
    private readonly PairingSession _session;
    private readonly Action<string>? _log;
    private readonly int _syncPort;
    private readonly CancellationTokenSource _stopping = new();

    /// <summary>Guesses are counted one at a time, paced, through here.</summary>
    private readonly SemaphoreSlim _attemptGate = new(1, 1);

    /// <summary>Guards <see cref="_connections"/> and each connection's place in it.</summary>
    private readonly object _connectionsGate = new();

    /// <summary>
    /// Every connection still being served, including one displaced and not yet wound down,
    /// which no longer holds a place.
    /// </summary>
    private readonly List<Connection> _connections = [];

    /// <summary>
    /// Completes when an accepted exchange is genuinely finished, not merely decided.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This exists because of a race that only appeared when the CLI was run for real. The
    /// obvious loop — <c>while (server.IsOpen) await Task.Delay(...)</c> — tears the server
    /// down the instant the code is <em>verified</em>, which is before the repository has
    /// been sent back. The joining machine got "the other machine closed the connection"
    /// while the offering machine cheerfully reported success.
    /// </para>
    /// <para>
    /// <see cref="PairingSession.IsOpen"/> answers "may another attempt be counted?", which
    /// is a different question from "is this over?". Conflating them is what produced a
    /// teardown mid-handshake, so the two are separate and callers wait on this one.
    /// </para>
    /// </remarks>
    private readonly TaskCompletionSource _finished =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private TcpListener? _listener;
    private CancellationTokenSource? _accepting;
    private Task? _serving;
    private int _attemptsInFlight;
    private int _displaced;
    private int _turnedAway;
    private int _timedOut;
    private int _endedEarly;
    private int _otherProtocol;
    private int _badShare;
    private bool _disposed;

    /// <summary>Opens a pairing window. Call <see cref="Start"/> to listen.</summary>
    /// <param name="repository">The repository being shared.</param>
    /// <param name="identity">This machine's identity.</param>
    /// <param name="session">
    /// The pairing window, or null to open a fresh one with a spoken code. Pass
    /// <see cref="PairingSession.ForInvitation"/> for a pasted <c>sip2_</c> invite.
    /// </param>
    /// <param name="log">Optional sink for log lines.</param>
    /// <param name="syncPort">
    /// The port this machine serves peers on: its <c>server.listenPort</c> (D-40). The window
    /// opens on it plus <see cref="PortOffset"/>, and the joining machine records it. Null
    /// falls back to the port the repository's config recorded when it was created, for
    /// callers with no machine setting to hand.
    /// </param>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    public PairingServer(
        SipRepository repository,
        DeviceIdentity identity,
        PairingSession? session = null,
        Action<string>? log = null,
        int? syncPort = null)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(identity);

        _repository = repository;
        _identity = identity;
        _session = session ?? new PairingSession();
        _log = log;
        _syncPort = syncPort ?? repository.Config.ListenPort;
    }

    /// <summary>
    /// How long a connection has, from connecting, to deliver everything before its guess.
    /// </summary>
    public static TimeSpan OpeningDeadline { get; } = TimeSpan.FromSeconds(5);

    /// <summary>The longest any one connection is served, start to finish.</summary>
    /// <remarks>
    /// A whole exchange is two round trips of small frames, a CPace computation on each
    /// side, and at most a few seconds' wait for the guesses ahead of it to be counted. Thirty
    /// seconds is several times that on any link that can carry it at all.
    /// </remarks>
    public static TimeSpan ConnectionDeadline { get; } = TimeSpan.FromSeconds(30);

    /// <summary>The secret, formatted for a person: the code to read out, or the invite secret.</summary>
    public string Code => _session.Display;

    /// <summary>How long the window has left.</summary>
    public TimeSpan Remaining => _session.Remaining;

    /// <summary>Whether the window would still count an attempt.</summary>
    public bool IsOpen => _session.IsOpen;

    /// <summary>Why the window closed, when it has.</summary>
    public PairingClosure Closure => _session.Closure;

    /// <summary>The machine that paired, as recorded in this repository's peer list.</summary>
    /// <remarks>
    /// Null until the peer has been recorded <em>and</em> the repository sent — which can be
    /// never, even after the code was accepted, if the connection failed in between. The
    /// caller should say which.
    /// </remarks>
    public PeerRecord? PairedPeer { get; private set; }

    /// <summary>
    /// The record the paired machine's replaced, when this repository already listed that
    /// device: its name, address and port as they were.
    /// </summary>
    /// <remarks>
    /// Re-pairing a machine replaces its record, which keeps its place in the list and when it
    /// last synced, and takes the name and address pairing learned. That used to happen
    /// without a word, overwriting a name somebody chose by hand (D-64). Set when the record
    /// is written, just before the repository is sent, so it is there to report even when
    /// that send fails and <see cref="PairedPeer"/> stays null.
    /// </remarks>
    public PeerRecord? ReplacedPeer { get; private set; }

    /// <summary>The device ID of the machine that paired, once one has.</summary>
    public string? PairedWith => PairedPeer?.DeviceId;

    /// <summary>The port this server is listening on.</summary>
    public int Port { get; private set; }

    /// <summary>For tests: <see cref="OpeningDeadline"/>, shortened.</summary>
    internal TimeSpan OpeningLimit { get; init; } = OpeningDeadline;

    /// <summary>For tests: <see cref="ConnectionDeadline"/>, shortened.</summary>
    internal TimeSpan ConnectionLimit { get; init; } = ConnectionDeadline;

    /// <summary>For tests: how many places are held right now.</summary>
    internal int ConnectionsHeld
    {
        get
        {
            lock (_connectionsGate)
            {
                return _connections.Count(c => !c.WasDisplaced);
            }
        }
    }

    /// <summary>For tests: how many connections have been displaced so far.</summary>
    internal int Displacements => Volatile.Read(ref _displaced);

    /// <summary>
    /// For tests: awaited at each <see cref="CountingStep"/> of counting a guess, to stand in
    /// for this thread being preempted there.
    /// </summary>
    /// <remarks>
    /// The two races it exists to test are a few instructions wide and cannot be hit on
    /// purpose any other way: two shares that have both been paced and neither counted, and
    /// a guess that has been counted before it is known to be in flight. Null unless a test
    /// sets it; null, it costs one check per guess.
    /// </remarks>
    internal Func<CountingStep, Task>? CountingPause { get; init; }

    /// <summary>Starts accepting attempts.</summary>
    /// <exception cref="ObjectDisposedException">The server was disposed.</exception>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_listener is not null)
        {
            return;
        }

        _listener = new TcpListener(IPAddress.Any, _syncPort + PortOffset);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;

        _accepting = CancellationTokenSource.CreateLinkedTokenSource(_stopping.Token);
        _serving = ServeAsync(_accepting, _stopping.Token);
        _log?.Invoke($"pairing open on :{Port} for {_session.Remaining.TotalMinutes:0} minutes");
    }

    /// <summary>
    /// Waits until the window's outcome is final: paired, expired, or burnt.
    /// </summary>
    /// <param name="cancellationToken">Stops waiting.</param>
    /// <returns>Why the window closed.</returns>
    /// <exception cref="OperationCanceledException">The wait was cancelled.</exception>
    /// <remarks>
    /// Use this rather than polling <see cref="IsOpen"/>. That property goes false the
    /// moment the fifth attempt is counted or a code is accepted, and either can be before
    /// the exchange that closed it has finished — the fifth attempt might still be the right
    /// one, and an accepted one has still to send the repository. A caller that tore the
    /// server down on <see cref="IsOpen"/> would cut off the very exchange it was waiting
    /// for. That is not hypothetical; it is what the first end-to-end run did. Only an
    /// exchange whose guess is being counted, or has been, can still change the outcome, so a
    /// connection that has not got that far does not hold this up. One that has is waited
    /// for from just before its guess is counted, so the fifth guess cannot close the window
    /// and be missed in the same instant.
    /// </remarks>
    public async Task<PairingClosure> WaitForOutcomeAsync(
        CancellationToken cancellationToken = default)
    {
        while (!_finished.Task.IsCompleted)
        {
            if (!_session.IsOpen &&
                _session.Closure != PairingClosure.Used &&
                Volatile.Read(ref _attemptsInFlight) == 0)
            {
                // Expired or burnt, and nothing still running that could change that.
                return _session.Closure;
            }

            var tick = Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken);
            await Task.WhenAny(_finished.Task, tick).ConfigureAwait(false);

            // WhenAny does not throw for a cancelled tick, and without this a cancelled wait
            // would spin through that same completed delay for ever.
            cancellationToken.ThrowIfCancellationRequested();
        }

        await _finished.Task.ConfigureAwait(false);
        return _session.Closure;
    }

    /// <summary>Accepts until the window closes, then waits for every connection to end.</summary>
    private async Task ServeAsync(CancellationTokenSource accepting, CancellationToken stopping)
    {
        try
        {
            await AcceptLoopAsync(accepting, stopping).ConfigureAwait(false);
        }
        finally
        {
            Task[] running;
            lock (_connectionsGate)
            {
                running = [.. _connections.Select(c => c.Serving)];
            }

            // Each of these catches everything but cancellation of the whole server, which
            // it absorbs, so waiting on them cannot throw.
            await Task.WhenAll(running).ConfigureAwait(false);

            ReportCounts();
        }
    }

    private async Task AcceptLoopAsync(CancellationTokenSource accepting, CancellationToken stopping)
    {
        // Stops accepting when the window expires, not only when an attempt arrives to find
        // it expired, so the port closes on time with nobody knocking.
        accepting.CancelAfter(_session.Remaining);

        try
        {
            while (!accepting.IsCancellationRequested && _session.IsOpen)
            {
                var client = await _listener!.AcceptTcpClientAsync(accepting.Token)
                    .ConfigureAwait(false);

                Admit(client, stopping);
            }
        }
        catch (OperationCanceledException)
        {
            _log?.Invoke(stopping.IsCancellationRequested ? "pairing: stopped"
                : _session.Closure == PairingClosure.Expired ? "pairing: the code expired"
                : "pairing: closed");
        }
        catch (SocketException ex)
        {
            _log?.Invoke($"pairing: the listener failed ({ex.SocketErrorCode})");
        }
        catch (ObjectDisposedException)
        {
            _log?.Invoke("pairing: stopped");
        }
        finally
        {
            // The port exists only while a code is live. Closing it here rather than in
            // DisposeAsync is what makes that true for a caller that keeps this object.
            _listener!.Stop();
        }
    }

    /// <summary>Gives a new connection a place, displacing one if every place is taken.</summary>
    private void Admit(TcpClient client, CancellationToken stopping)
    {
        lock (_connectionsGate)
        {
            if (_connections.Count(c => !c.WasDisplaced) >= MaximumConnections)
            {
                var victim = ChooseDisplaced();

                if (victim is null)
                {
                    // Every place is held by a connection that has made its guess. Nothing
                    // here can be taken without cancelling a counted attempt.
                    client.Dispose();
                    LogOnce(ref _turnedAway,
                        $"pairing: turned a connection away; all {MaximumConnections} places are " +
                        "held by exchanges already under way");
                    return;
                }

                // It stays in the list, without a place, until it has wound down, so that
                // disposing the server still waits for it.
                victim.Displace();
                LogOnce(ref _displaced,
                    $"pairing: a connection from {victim.Remote} that had not made its guess gave " +
                    "way to a new one");
            }

            // Owned from here by RunAsync, which disposes it when the connection ends.
            var connection = new Connection(client, ConnectionLimit, stopping);
            _connections.Add(connection);

            // Started under the gate, so the connection cannot finish and remove itself
            // before it has been added, and ServeAsync's snapshot always has its task.
            connection.Serving = Task.Run(() => RunAsync(connection, stopping), CancellationToken.None);
        }
    }

    /// <summary>
    /// The connection to displace: not yet guessed, from the address holding the most
    /// places, the oldest of those. Null when every connection has made its guess.
    /// </summary>
    /// <remarks>
    /// By address first because a flood comes from somewhere. The machine that is really
    /// pairing has one connection, from its own address, and it is never the address with
    /// the most places while a flood is running, so the flood displaces itself. Oldest
    /// within an address because a joining machine sends its first frames the moment it
    /// connects, and the connection that has waited longest is the one least likely to be
    /// a machine that is about to.
    /// </remarks>
    private Connection? ChooseDisplaced()
    {
        var holding = _connections.Where(c => !c.WasDisplaced).ToList();
        var places = holding.GroupBy(c => c.Remote).ToDictionary(g => g.Key, g => g.Count());

        return holding
            .Where(c => !c.HasGuessed)
            .OrderByDescending(c => places[c.Remote])
            .ThenBy(c => c.AcceptedTicks)
            .FirstOrDefault();
    }

    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "An unauthenticated listener. Anything escaping closes the pairing " +
                        "window silently, which looks to the user like the code not working.")]
    private async Task RunAsync(Connection connection, CancellationToken stopping)
    {
        try
        {
            await ServeOneAsync(connection).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested)
        {
            // The server is being disposed; nothing to report.
        }
        catch (OperationCanceledException) when (connection.WasDisplaced)
        {
            // Reported when it was displaced.
        }
        catch (OperationCanceledException)
        {
            LogOnce(ref _timedOut,
                $"pairing: closed a connection from {connection.Remote} that ran past its " +
                "deadline");
        }
        catch (Exception ex)
        {
            // Never reported back to the caller. Which of these happened is information
            // about whether a window is open, and that is more useful to somebody guessing
            // than knowing one guess was wrong. Counted after the first: a stream of
            // malformed frames produces one of these per connection.
            LogOnce(ref _endedEarly, $"pairing: an exchange ended early ({ex.GetType().Name})");
        }
        finally
        {
            lock (_connectionsGate)
            {
                _connections.Remove(connection);
                connection.Finish();
            }

            connection.Dispose();

            // The window closes behind the attempt that closed it: used, or the fifth
            // counted. Serving side by side, the accept loop is waiting on the next
            // connection rather than looking, so it is told.
            if (!_session.IsOpen)
            {
                CancelAccepting();
            }
        }
    }

    private async Task ServeOneAsync(Connection connection)
    {
        var token = connection.Token;
        var remote = connection.Remote;
        var stream = connection.Client.GetStream();
        await using var _ = stream.ConfigureAwait(false);

        // Everything before the guess must arrive within the opening deadline, counted from
        // the connection, however steadily it dribbles.
        using var opening = CancellationTokenSource.CreateLinkedTokenSource(token);
        var openingLeft = OpeningLimit - Stopwatch.GetElapsedTime(connection.AcceptedTicks);
        opening.CancelAfter(openingLeft > TimeSpan.Zero ? openingLeft : TimeSpan.Zero);

        PairingHello? hello;
        PairingShareMessage? share;
        byte[] sessionId;

        try
        {
            // 1 and 2: versions and the two halves of the session identifier.
            hello = await PairingProtocol.ReadAsync<PairingHello>(stream, opening.Token)
                .ConfigureAwait(false);
            if (hello is null)
            {
                return;
            }

            if (hello.Protocol != PairingProtocol.Version)
            {
                // A version-1 joiner sends its code here in clear. It is never compared, never
                // counted and never logged; the reply tells the other machine why.
                await PairingProtocol.WriteAsync(
                    stream, new PairingHelloReply { Protocol = PairingProtocol.Version }, token)
                    .ConfigureAwait(false);
                LogOnce(
                    ref _otherProtocol,
                    $"pairing: refused a machine speaking pairing protocol {Math.Max(hello.Protocol, 1)}; " +
                    $"this one speaks {PairingProtocol.Version}. Update both to the same SippBucket.");
                return;
            }

            if (hello.Nonce is not { Length: PairingProtocol.NonceSize })
            {
                return;
            }

            var offererNonce = RandomNumberGenerator.GetBytes(PairingProtocol.NonceSize);
            await PairingProtocol.WriteAsync(
                stream,
                new PairingHelloReply { Protocol = PairingProtocol.Version, Nonce = offererNonce },
                token).ConfigureAwait(false);

            sessionId = PairingProtocol.SessionId(hello.Nonce, offererNonce);

            // 3: the joiner's CPace message. A malformed one is not a guess at the code, so it
            // costs nothing from the budget.
            share = await PairingProtocol.ReadAsync<PairingShareMessage>(stream, opening.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (opening.IsCancellationRequested && !token.IsCancellationRequested)
        {
            LogOnce(ref _timedOut,
                $"pairing: closed a connection from {remote} that had not made its guess within " +
                $"{OpeningLimit.TotalSeconds:0.#} s");
            return;
        }

        if (share?.Share is not { Length: Ristretto255.ElementSize } ||
            share.AssociatedData is null ||
            !share.AssociatedData.AsSpan().SequenceEqual(PairingProtocol.JoinerAssociatedData))
        {
            return;
        }

        // A guess is on the table: from here this connection is never displaced, because
        // displacing it would cancel somebody's answer, and the budget may be about to count it.
        lock (_connectionsGate)
        {
            connection.HasGuessed = true;
        }

        // 4: ONE attempt, counted before the answer is computed, against a budget that
        // burns at five. One at a time and paced, so connections served side by side cannot
        // land inside each other's throttle and be answered as decoys: without the gate, two
        // shares could both be paced before either was counted, and the second would then be
        // counted inside the first's second and answered with a random password.
        PairingAttempt attempt;
        await _attemptGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await PaceAsync(token).ConfigureAwait(false);
            await PauseForTestAsync(CountingStep.Paced).ConfigureAwait(false);

            // In flight BEFORE it is counted. The fifth count closes the window, and
            // WaitForOutcomeAsync reports a closed window with nothing in flight as burnt, so
            // counting first left an instant in which the fifth guess, which may be the right
            // one, was counted and not yet in flight, and a caller that looked then tore the
            // server down under it.
            Interlocked.Increment(ref _attemptsInFlight);
            var counted = false;
            try
            {
                attempt = _session.BeginAttempt();
                counted = true;
            }
            finally
            {
                if (!counted)
                {
                    Interlocked.Decrement(ref _attemptsInFlight);
                }
            }
        }
        finally
        {
            _attemptGate.Release();
        }

        try
        {
            using (attempt)
            {
                await PauseForTestAsync(CountingStep.Counted).ConfigureAwait(false);
                await AnswerAsync(stream, connection, sessionId, share, attempt, token)
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            Interlocked.Decrement(ref _attemptsInFlight);

            // Only once the exchange is over, whichever way it ended after acceptance.
            // Everything in AnswerAsync — sealing, writing, recording the peer — had to
            // finish or fail before anybody is told this is over.
            if (connection.Accepted)
            {
                _finished.TrySetResult();
            }
        }
    }

    /// <summary>Steps 4 to 6 for one counted attempt.</summary>
    /// <remarks>
    /// Marks the connection accepted the moment the session concludes in its favour, before
    /// the peer is recorded or the repository sent, so a send that then fails still ends the
    /// wait for an outcome rather than leaving it waiting on a success that will not come.
    /// </remarks>
    private async Task AnswerAsync(
        Stream stream,
        Connection connection,
        byte[] sessionId,
        PairingShareMessage share,
        PairingAttempt attempt,
        CancellationToken token)
    {
        var remote = connection.Remote;

        if (!attempt.Respond(sessionId, share.Share!, share.AssociatedData!))
        {
            // K was the identity: a share that does not decode, or a share of the
            // identity. Section 7.2 says abort, and nothing more is sent.
            LogOnce(ref _badShare, "pairing: refused a share that was not a valid group element");
            return;
        }

        await PairingProtocol.WriteAsync(
            stream,
            new PairingAnswer
            {
                Share = attempt.Share,
                AssociatedData = attempt.AssociatedData,
                Confirmation = attempt.Confirmation,
                Sealed = PairingProtocol.Seal(
                    new OffererIdentity { DeviceId = _identity.DeviceId },
                    attempt.Isk,
                    sessionId,
                    PairingProtocol.Purpose.OffererIdentity),
            },
            token).ConfigureAwait(false);

        // 5: the joiner's confirmation. A joiner with the wrong code learns so from our
        // tag and hangs up here, so a missing confirmation is the usual wrong answer.
        var confirmation = await PairingProtocol.ReadAsync<PairingConfirmation>(stream, token)
            .ConfigureAwait(false);

        if (confirmation?.Confirmation is null)
        {
            LogUnconfirmed(attempt);
            return;
        }

        if (!attempt.IsConfirmedBy(confirmation.Confirmation))
        {
            LogUnconfirmed(attempt);
            await RefuseAsync(stream, token).ConfigureAwait(false);
            return;
        }

        if (!PairingProtocol.TryOpen<JoinerIdentity>(
                confirmation.Sealed,
                attempt.Isk,
                sessionId,
                PairingProtocol.Purpose.JoinerIdentity,
                out var joiner) ||
            !PairingProtocol.IsDeviceId(joiner.DeviceId) ||
            !PairingProtocol.IsPort(joiner.ListenPort))
        {
            // The confirmation verified, so ISK matches — and the identity still did not
            // open. That is somebody in the middle substituting it. Refused before the
            // code is spent, so the person it belongs to can try again.
            _log?.Invoke("pairing: the other machine's identity did not verify; refused");
            await RefuseAsync(stream, token).ConfigureAwait(false);
            return;
        }

        // Never with itself: a joiner with this machine's own device ID holds a copied
        // device.key. Refused here as well as at the joiner, so an older or altered joiner
        // cannot get past it, and before the code is spent, so it still works for the machine
        // it was meant for.
        if (DeviceIdentity.IsSameDevice(joiner.DeviceId, _identity.DeviceId))
        {
            _log?.Invoke("pairing: the other machine has this machine's own device ID (a copied device.key); refused");
            await RefuseAsync(stream, token).ConfigureAwait(false);
            return;
        }

        if (_session.Conclude(attempt, confirmation.Confirmation) != PairingOffer.Accepted)
        {
            await RefuseAsync(stream, token).ConfigureAwait(false);
            return;
        }

        connection.Accepted = true;
        _log?.Invoke($"pairing: {joiner.DeviceId![..12]} at {remote} proved the code; sending the folder");

        // Recorded at the address the connection actually came from, and the port the
        // joiner said it serves on — under ISK, so nobody in the middle chose either.
        // Recorded BEFORE the repository is sent, so that "accepted" reaching the other
        // machine means this end already knows it. If the send then fails, the record
        // is harmless — that machine proved the code — and pairing it again replaces it.
        var peer = new PeerRecord
        {
            Name = NameFor(joiner),
            DeviceId = joiner.DeviceId!,
            Host = remote.ToString(),
            Port = joiner.ListenPort,
        };

        // Replaced rather than silently overwritten: a machine paired again keeps its place
        // and when it last synced, and what it was called is reported (D-64). Kept as soon
        // as it is written, so a send that fails below can still be reported with it.
        var replaced = _repository.Peers.AddOrReplace(peer);
        ReplacedPeer = replaced;

        // 6: only now does the key move, sealed to the machine that proved the code. The
        // invite names the port this machine's host serves every folder on, which is not the
        // folder's own recorded port once one listener serves them all (D-40).
        var invite = _repository.CreateInvite(_identity.DeviceId, _syncPort);
        await PairingProtocol.WriteAsync(
            stream,
            new PairingResultMessage
            {
                Accepted = true,
                Sealed = PairingProtocol.Seal(
                    invite, attempt.Isk, sessionId, PairingProtocol.Purpose.Repository),
            },
            token).ConfigureAwait(false);

        PairedPeer = peer;
        _log?.Invoke(replaced is null
            ? $"pairing: accepted {peer.DeviceId[..12]} at {peer.Host}"
            : $"pairing: accepted {peer.DeviceId[..12]} at {peer.Host}, replacing '{replaced.Name}' " +
              $"at {replaced.Host}:{replaced.Port}");
    }

    /// <summary>
    /// Waits out the throttle rather than refusing, so a user who mistyped and retyped at
    /// once is not told their right answer is wrong.
    /// </summary>
    /// <remarks>
    /// Loops rather than sleeping once for the computed remainder. The first version did
    /// sleep once, and it did not work: the wait lands exactly on the one-second boundary
    /// and Task.Delay is entitled to return a millisecond early, which leaves the attempt
    /// still inside the throttle. Re-asking until the answer is zero is self-correcting and
    /// needs no margin chosen by guesswork. Bounded by the session's own lifetime.
    /// </remarks>
    private async Task PaceAsync(CancellationToken cancellationToken)
    {
        while (_session.IsOpen)
        {
            var wait = _session.TimeUntilNextAttempt();
            if (wait <= TimeSpan.Zero)
            {
                break;
            }

            await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
        }
    }

    private void LogUnconfirmed(PairingAttempt attempt) =>
        _log?.Invoke(attempt.IsLive
            ? $"pairing: wrong code ({_session.Attempts} of {PairingSession.MaximumAttempts})"
            : "pairing: answered an attempt with the window closed or throttled; refused");

    /// <summary>
    /// Logs the first of a kind of event and counts the rest; <see cref="ReportCounts"/> gives
    /// the totals when the window ends.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Through here: every kind of line a connection can cause without spending one of the
    /// five guesses, which is what a flood of connections can repeat without end. Displaced,
    /// turned away, cut off by a deadline, ended early, spoke another pairing protocol, and
    /// sent a share that is not a group element. Before the last three were covered, a
    /// stream of malformed connections, served eight at a time, wrote one line each to the
    /// console of <c>sip pair offer</c> and <c>sip invite</c>.
    /// </para>
    /// <para>
    /// Not through here: a wrong code, an accepted one, an identity that did not verify, and
    /// an answer given with the window closed. Each follows a guess that was counted, of which
    /// there are five, or is the decoy answer to a connection that was already being served
    /// when the window closed, so they cannot run on, and each is worth reading as it happens.
    /// </para>
    /// </remarks>
    private void LogOnce(ref int count, string line)
    {
        if (Interlocked.Increment(ref count) == 1)
        {
            _log?.Invoke(line + " (more like this are counted, not logged)");
        }
    }

    /// <summary>The totals behind <see cref="LogOnce"/>, when any kind happened more than once.</summary>
    private void ReportCounts()
    {
        (int Count, string What)[] counts =
        [
            (_displaced, "displaced"),
            (_turnedAway, "turned away"),
            (_timedOut, "cut off by a deadline"),
            (_endedEarly, "ended early"),
            (_otherProtocol, "spoke another pairing protocol"),
            (_badShare, "sent a share that was not a group element"),
        ];

        if (counts.Any(c => c.Count > 1))
        {
            _log?.Invoke(
                "pairing: while the window was open, connections " +
                string.Join(", ", counts.Where(c => c.Count > 0).Select(c => $"{c.What}: {c.Count}")));
        }
    }

    private Task PauseForTestAsync(CountingStep step) =>
        CountingPause?.Invoke(step) ?? Task.CompletedTask;

    private void CancelAccepting()
    {
        try
        {
            _accepting?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Disposed after everything was served: accepting had already ended.
        }
    }

    private static string NameFor(JoinerIdentity joiner) =>
        string.IsNullOrWhiteSpace(joiner.MachineName) ||
        joiner.MachineName.Length > 64 ||
        joiner.MachineName.Any(DisplayText.IsInstruction)
            ? "paired"
            : joiner.MachineName;

    private static Task RefuseAsync(Stream stream, CancellationToken cancellationToken) =>
        // Identical for every reason. There is no field to put a reason in, so no future
        // change can accidentally start leaking one.
        PairingProtocol.WriteAsync(
            stream, new PairingResultMessage { Accepted = false }, cancellationToken);

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _session.Cancel();
        await _stopping.CancelAsync().ConfigureAwait(false);

        _listener?.Stop();

        if (_serving is not null)
        {
            await _serving.ConfigureAwait(false);
        }

        _listener?.Dispose();
        _accepting?.Dispose();
        _attemptGate.Dispose();
        _stopping.Dispose();
    }

    /// <summary>Where <see cref="CountingPause"/> is awaited.</summary>
    internal enum CountingStep
    {
        /// <summary>Holding the gate, paced, and not yet counted.</summary>
        Paced = 0,

        /// <summary>Counted, gate released, and not yet answered.</summary>
        Counted = 1,
    }

    /// <summary>One accepted connection, and what the displacement rule needs to know about it.</summary>
    private sealed class Connection : IDisposable
    {
        private readonly CancellationTokenSource _cancel;
        private bool _finished;

        public Connection(TcpClient client, TimeSpan deadline, CancellationToken stopping)
        {
            Client = client;
            Remote = RemoteOf(client);
            AcceptedTicks = Stopwatch.GetTimestamp();
            _cancel = CancellationTokenSource.CreateLinkedTokenSource(stopping);
            _cancel.CancelAfter(deadline);
        }

        public TcpClient Client { get; }

        public IPAddress Remote { get; }

        public long AcceptedTicks { get; }

        /// <summary>Cancelled by the overall deadline, by displacement, or by the server stopping.</summary>
        public CancellationToken Token => _cancel.Token;

        /// <summary>Set, under the server's gate, once a well-formed share has arrived.</summary>
        public bool HasGuessed { get; set; }

        /// <summary>Set once the session has concluded in this connection's favour.</summary>
        public bool Accepted { get; set; }

        public bool WasDisplaced { get; private set; }

        public Task Serving { get; set; } = Task.CompletedTask;

        /// <summary>Cancels the connection to make room. Called under the server's gate.</summary>
        public void Displace()
        {
            if (_finished)
            {
                return;
            }

            WasDisplaced = true;
            _cancel.Cancel();
        }

        /// <summary>Marks it over, under the server's gate, before it is disposed.</summary>
        /// <remarks>
        /// So a displacement decided at the same moment sees it finished and leaves its
        /// cancellation source alone, rather than cancelling one being disposed.
        /// </remarks>
        public void Finish() => _finished = true;

        public void Dispose()
        {
            Client.Dispose();
            _cancel.Dispose();
        }

        /// <summary>The remote address, or <see cref="IPAddress.None"/> if the socket cannot say.</summary>
        /// <remarks>
        /// Read on the accept loop, where an exception would end the loop and close the window
        /// for everyone. A connection that cannot report its address is served like any other,
        /// and for displacement every such connection counts as one address.
        /// </remarks>
        private static IPAddress RemoteOf(TcpClient client)
        {
            try
            {
                return client.Client.RemoteEndPoint is IPEndPoint endpoint ? endpoint.Address : IPAddress.None;
            }
            catch (SocketException)
            {
                return IPAddress.None;
            }
            catch (ObjectDisposedException)
            {
                return IPAddress.None;
            }
        }
    }
}
