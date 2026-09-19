using System.Net;
using System.Net.Sockets;

namespace SippBucket.Core.Protocol;

/// <summary>
/// The limits on connections that have been accepted and have not yet proved which device they
/// are (SEC-3), for every listener that serves paired machines: sync's
/// (<see cref="Sync.PeerHost"/>) and Direct Push's (<see cref="Push.Ssh.PushListener"/>).
/// </summary>
/// <remarks>
/// <para>
/// Anyone who can reach a port can open a connection, and until it has proved which device it
/// is, it is owed nothing. Each source address may hold <see cref="MaximumPerAddress"/>
/// unfinished handshakes, and the machine <see cref="Maximum"/>. At either limit the newcomer
/// is let in and an old unfinished handshake is closed instead: the arriving address's own
/// oldest, or, machine-wide, the oldest from whichever address holds the most, and when several
/// addresses tie for the most, the oldest connection held by any of them. Refusing newcomers
/// would let a flood that arrived first keep every real peer out; shedding the oldest from the
/// heaviest address means a flood costs its own connections.
/// </para>
/// <para>
/// What that guarantees, and no more: while one address holds more unfinished handshakes than a
/// real peer's address does, the real peer's handshake is never the one closed. A flood spread
/// thinly, one connection from each of as many addresses as the limit allows, ties every
/// address, and then the oldest handshake goes, whoever it belongs to; the peer's next attempt
/// is let in the same way.
/// </para>
/// <para>
/// Written once, here, when Direct Push became the second listener, so the two cannot come to
/// apply different rules. Each listener keeps its own deadline on the whole handshake; this
/// class only counts and chooses.
/// </para>
/// </remarks>
internal sealed class HandshakeAdmission
{
    private readonly Lock _gate = new();

    // Connections admitted and not yet released, oldest first, and how many each source address
    // holds. Both under _gate.
    private readonly LinkedList<Admitted> _pending = new();
    private readonly Dictionary<IPAddress, int> _pendingByAddress = [];

    /// <summary>Creates the limits.</summary>
    /// <param name="maximum">The most unfinished handshakes the machine holds.</param>
    /// <param name="maximumPerAddress">The most unfinished handshakes one source address holds.</param>
    /// <exception cref="ArgumentOutOfRangeException">A limit is not positive.</exception>
    public HandshakeAdmission(int maximum, int maximumPerAddress)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximum);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumPerAddress);

        Maximum = maximum;
        MaximumPerAddress = maximumPerAddress;
    }

    /// <summary>The most unfinished handshakes the machine holds.</summary>
    public int Maximum { get; }

    /// <summary>The most unfinished handshakes one source address holds.</summary>
    public int MaximumPerAddress { get; }

    /// <summary>How many connections are admitted and not yet released.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _pending.Count;
            }
        }
    }

    /// <summary>
    /// Counts a newly accepted socket as unauthenticated, closing an older one first when that
    /// would break a limit.
    /// </summary>
    /// <param name="socket">The accepted socket. Closing it is how a shed handshake is ended.</param>
    /// <returns>The connection's entry, to release once its handshake has ended.</returns>
    /// <remarks>
    /// The socket is taken at accept: the client object around it is its handler's to dispose,
    /// and a socket's disposal is safe from any thread, any number of times.
    /// </remarks>
    public Admitted Admit(Socket socket)
    {
        ArgumentNullException.ThrowIfNull(socket);
        return Admit(SourceOf(socket), socket.Dispose);
    }

    /// <summary>
    /// Counts a newly accepted connection as unauthenticated, closing an older one first when
    /// that would break a limit.
    /// </summary>
    /// <param name="address">Where it came from.</param>
    /// <param name="close">Ends it, if it is ever shed. Called at most once, outside the lock.</param>
    /// <returns>The connection's entry, to release once its handshake has ended.</returns>
    public Admitted Admit(IPAddress address, Action close)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(close);

        var admitted = new Admitted(this, address, close);
        Admitted? shed;

        lock (_gate)
        {
            shed = ChooseToShed(address);
            if (shed is not null)
            {
                Forget(shed);
                shed.MarkShed();
            }

            admitted.Node = _pending.AddLast(admitted);
            _pendingByAddress[address] = _pendingByAddress.GetValueOrDefault(address) + 1;
        }

        // Outside the lock: closing ends the shed connection's pending read, and its handler
        // reports that on its own task.
        shed?.Close();
        return admitted;
    }

    /// <summary>Where a connection came from, for the per-address limit.</summary>
    /// <param name="socket">The accepted socket.</param>
    /// <returns>Its remote address, IPv4 when it arrived as IPv4 mapped into IPv6.</returns>
    /// <remarks>
    /// Runs on an accept loop, where anything thrown would stop the listener, so a caller already
    /// gone by the time it is asked counts as one unknown address rather than throwing; its
    /// handler finds the connection closed and ends it.
    /// </remarks>
    internal static IPAddress SourceOf(Socket socket)
    {
        try
        {
            return socket.RemoteEndPoint is IPEndPoint remote
                ? (remote.Address.IsIPv4MappedToIPv6 ? remote.Address.MapToIPv4() : remote.Address)
                : IPAddress.None;
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            return IPAddress.None;
        }
    }

    /// <summary>
    /// Which unauthenticated connection to close to admit one more from
    /// <paramref name="arriving"/>, or null when nothing needs closing. The caller holds
    /// <see cref="_gate"/>.
    /// </summary>
    private Admitted? ChooseToShed(IPAddress arriving)
    {
        if (_pendingByAddress.GetValueOrDefault(arriving) >= MaximumPerAddress)
        {
            return OldestFrom(arriving);
        }

        if (_pending.Count < Maximum)
        {
            return null;
        }

        // The machine is full. The address holding the most pays, never whoever came last. When
        // several addresses hold the most, the oldest connection among them goes: the list is
        // oldest first, so that is the first entry found from an address at the maximum. Picking
        // an address first and then its oldest left the choice to the order the counts happened
        // to be stored in, which is not the order the connections arrived in.
        var most = _pendingByAddress.Values.Max();
        for (var node = _pending.First; node is not null; node = node.Next)
        {
            if (_pendingByAddress[node.Value.Address] == most)
            {
                return node.Value;
            }
        }

        return null;
    }

    /// <summary>The oldest unauthenticated connection from one address. The caller holds <see cref="_gate"/>.</summary>
    private Admitted? OldestFrom(IPAddress address)
    {
        for (var node = _pending.First; node is not null; node = node.Next)
        {
            if (node.Value.Address.Equals(address))
            {
                return node.Value;
            }
        }

        return null;
    }

    /// <summary>Stops counting a connection as unauthenticated. The caller holds <see cref="_gate"/>.</summary>
    private void Forget(Admitted admitted)
    {
        _pending.Remove(admitted.Node!);
        admitted.Node = null;

        var left = _pendingByAddress[admitted.Address] - 1;
        if (left == 0)
        {
            _pendingByAddress.Remove(admitted.Address);
        }
        else
        {
            _pendingByAddress[admitted.Address] = left;
        }
    }

    /// <summary>Ends a connection's handshake, however it ended.</summary>
    /// <returns>False when the connection had been shed to make room for another.</returns>
    private bool Release(Admitted admitted)
    {
        lock (_gate)
        {
            if (admitted.Node is null)
            {
                return false;
            }

            Forget(admitted);
            return true;
        }
    }

    /// <summary>A connection that has been accepted and has not yet proved which device it is.</summary>
    internal sealed class Admitted
    {
        private readonly HandshakeAdmission _owner;
        private readonly Action _close;
        private int _shed;

        public Admitted(HandshakeAdmission owner, IPAddress address, Action close)
        {
            _owner = owner;
            _close = close;
            Address = address;
        }

        /// <summary>Where it came from.</summary>
        public IPAddress Address { get; }

        /// <summary>Whether it was closed to make room for another.</summary>
        public bool WasShed => Volatile.Read(ref _shed) != 0;

        /// <summary>Its place among the unauthenticated connections, or null once it has left them.</summary>
        /// <remarks>Read and written only under the owner's lock.</remarks>
        internal LinkedListNode<Admitted>? Node { get; set; }

        /// <summary>
        /// Stops counting it as unauthenticated, once its handshake has ended however it ended.
        /// </summary>
        /// <returns>False when it had been shed to make room for another; it was closed, and must not be served.</returns>
        public bool Release() => _owner.Release(this);

        internal void MarkShed() => Volatile.Write(ref _shed, 1);

        /// <summary>Closes it, which ends whatever read or write its handshake is waiting on.</summary>
        internal void Close() => _close();
    }
}
