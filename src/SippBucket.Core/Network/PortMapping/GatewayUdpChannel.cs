using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// One UDP socket for one exchange with the gateway: sends to the gateway's port, and hands
/// back only datagrams that came from that address and that port.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why the source is checked here and not left to the operating system.</strong>
/// Connecting a UDP socket would make Windows discard datagrams from anywhere else ("Any
/// datagrams received from an address other than the destination address specified will be
/// discarded",
/// https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect). This
/// socket is deliberately left unconnected and the check is made in code, so that the rule
/// the port mapper depends on is one this project's tests can remove and watch fail, rather
/// than a property of the platform nobody here can switch off.
/// </para>
/// <para>
/// <strong>One socket per exchange.</strong> A late answer to an earlier request would
/// otherwise sit in the socket's queue and be read as the answer to the next one: a renewal
/// accepting the lifetime from the grant before it. A fresh socket per exchange means the
/// operating system drops anything addressed to the old one.
/// </para>
/// <para>
/// <strong>A random source port.</strong> RFC 6887 section 8.1: "The PCP client's source port
/// SHOULD be randomly generated". It is drawn from the dynamic range 49152 to 65535 and the
/// operating system is left to choose only if eight draws are all taken.
/// </para>
/// </remarks>
internal sealed class GatewayUdpChannel : IDisposable
{
    private const int DynamicPortFirst = 49152;
    private const int DynamicPortLast = 65535;
    private const int PortDraws = 8;

    private readonly Socket _socket;

    // A UDP payload is at most 65,507 bytes over IPv4, so every datagram fits whole and an
    // oversized one is seen at its real size rather than cut down to look acceptable.
    private readonly byte[] _buffer = new byte[65536];
    private bool _disposed;

    private GatewayUdpChannel(Socket socket, IPEndPoint server, IPAddress localAddress)
    {
        _socket = socket;
        Server = server;
        LocalAddress = localAddress;
    }

    /// <summary>The gateway's address and port: the only source anything is accepted from.</summary>
    public IPEndPoint Server { get; }

    /// <summary>This machine's address on the route to the gateway.</summary>
    public IPAddress LocalAddress { get; }

    /// <summary>How many datagrams were thrown away for coming from anywhere else.</summary>
    public int Ignored { get; private set; }

    /// <summary>Opens a socket on the address this machine would use to reach <paramref name="server"/>.</summary>
    /// <param name="server">The gateway's address and port.</param>
    /// <returns>The channel.</returns>
    /// <exception cref="SocketException">There is no route to the gateway.</exception>
    public static GatewayUdpChannel Open(IPEndPoint server)
    {
        ArgumentNullException.ThrowIfNull(server);

        var local = LocalAddressToward(server);
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            BindRandomPort(socket, local);
            return new GatewayUdpChannel(socket, server, local);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>The local address the operating system routes to <paramref name="server"/> from.</summary>
    /// <param name="server">Where the packets would go.</param>
    /// <returns>The address, IPv4.</returns>
    /// <exception cref="SocketException">There is no route.</exception>
    /// <remarks>
    /// Found by connecting a throwaway UDP socket, which sends nothing: "For a connectionless
    /// socket (for example, type SOCK_DGRAM), the operation performed by connect is merely to
    /// establish a default destination address"
    /// (https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect).
    /// This is the address a mapping is made to, which is what keeps it to this machine.
    /// </remarks>
    public static IPAddress LocalAddressToward(IPEndPoint server)
    {
        ArgumentNullException.ThrowIfNull(server);

        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        probe.Connect(server);
        return ((IPEndPoint)probe.LocalEndPoint!).Address;
    }

    /// <summary>Sends one datagram to the gateway.</summary>
    /// <param name="datagram">The datagram.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <returns>A task that completes when the datagram has been handed to the network.</returns>
    public async Task SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _socket.SendToAsync(datagram, SocketFlags.None, Server, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Waits for the next datagram from the gateway's address and port, until a deadline.
    /// </summary>
    /// <param name="deadline">A <see cref="Stopwatch"/> timestamp to give up at.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>A copy of the datagram, or null when the deadline passed first.</returns>
    public async Task<byte[]?> ReceiveAsync(long deadline, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var anywhere = new IPEndPoint(IPAddress.Any, 0);

        while (true)
        {
            var remaining = Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), deadline);
            if (remaining <= TimeSpan.Zero)
            {
                return null;
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(remaining);

            SocketReceiveFromResult received;
            try
            {
                received = await _socket
                    .ReceiveFromAsync(_buffer, SocketFlags.None, anywhere, timeout.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return null;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                // Windows reports an ICMP "port unreachable" for an earlier send as a reset on
                // the next receive. It means nothing answered on that port, which the deadline
                // already handles; it is not a reply and not a reason to stop listening.
                continue;
            }

            if (received.RemoteEndPoint is not IPEndPoint from ||
                !from.Address.Equals(Server.Address) ||
                from.Port != Server.Port)
            {
                Ignored++;
                continue;
            }

            return _buffer.AsSpan(0, received.ReceivedBytes).ToArray();
        }
    }

    /// <summary>Counts a datagram the caller read and then refused.</summary>
    public void CountIgnored() => Ignored++;

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _socket.Dispose();
    }

    private static void BindRandomPort(Socket socket, IPAddress local)
    {
        for (var draw = 0; draw < PortDraws; draw++)
        {
            var port = RandomNumberGenerator.GetInt32(DynamicPortFirst, DynamicPortLast + 1);
            if (TryBind(socket, new IPEndPoint(local, port)))
            {
                return;
            }
        }

        socket.Bind(new IPEndPoint(local, 0));
    }

    private static bool TryBind(Socket socket, IPEndPoint endpoint)
    {
        try
        {
            socket.Bind(endpoint);
            return true;
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.AccessDenied)
        {
            // Taken, or inside a range Windows has reserved for something else. The caller
            // draws again.
            return false;
        }
    }
}
