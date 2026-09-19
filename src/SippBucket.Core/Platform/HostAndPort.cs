using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SippBucket.Core.Platform;

/// <summary>
/// A host and a port as a person types them: <c>desktop</c>, <c>192.168.1.9:8471</c>, or an
/// IPv6 address in brackets, <c>[fe80::1]:8471</c>.
/// </summary>
/// <remarks>
/// <para>
/// The bracket form is RFC 3986's, section 3.2.2: "A host identified by an Internet Protocol
/// literal address, version 6 or later, is distinguished by enclosing the IP literal within
/// square brackets", and section 3.2.3 has the port follow the host "delimited from it by a
/// single colon" (https://www.rfc-editor.org/rfc/rfc3986). An IPv6 address is full of
/// colons, so without the brackets <c>2001:db8::1:8471</c> could be an address, or an
/// address and a port, and both readings parse. The old splitter took the last colon, so it
/// read <c>[::1]:8471</c> as the host <c>[::1]</c> and <c>2001:db8::1</c> as the host
/// <c>2001:db8:</c> on port 1 (D-63). This one refuses anything it would have to guess at,
/// and says what it expected.
/// </para>
/// <para>
/// Parsing an IPv6 address is not the same as reaching one: SippBucket listens on IPv4 only
/// until it can cross networks (D-05), so a peer recorded at an IPv6 address is recorded
/// correctly and will not connect yet. The help says so where addresses are described.
/// </para>
/// </remarks>
/// <param name="Host">A host name, an IPv4 address, or an IPv6 address without brackets.</param>
/// <param name="Port">A TCP port, 1 to 65535.</param>
public readonly record struct HostAndPort(string Host, int Port)
{
    /// <summary>Reads a host with an optional port.</summary>
    /// <param name="text">What was typed.</param>
    /// <param name="defaultPort">The port when none is given.</param>
    /// <param name="result">The host and port, when this returns true.</param>
    /// <param name="error">What is wrong with <paramref name="text"/>, when this returns false.</param>
    /// <returns>True when <paramref name="text"/> is a host with an optional port.</returns>
    public static bool TryParse(string? text, int defaultPort, out HostAndPort result, out string error)
    {
        result = default;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(text))
        {
            error = "An address is needed: a host name or IP address, optionally with :port.";
            return false;
        }

        var value = text.Trim();

        if (value.StartsWith('['))
        {
            return TryParseBracketed(value, defaultPort, out result, out error);
        }

        if (value.Contains(']', StringComparison.Ordinal))
        {
            error = $"'{value}' has a ']' with no '[' before it. An IPv6 address is written [address]:port.";
            return false;
        }

        var colons = value.Count(c => c == ':');

        if (colons > 1)
        {
            // Bare IPv6. Refused even when it parses, because a trailing ":8471" also parses
            // as part of the address, and guessing which was meant is how the old splitter
            // went wrong.
            error = $"'{value}' looks like an IPv6 address. Write it in brackets, " +
                    "[address] or [address]:port, so the port cannot be mistaken for part of it.";
            return false;
        }

        var host = colons == 0 ? value : value[..value.IndexOf(':', StringComparison.Ordinal)];

        if (host.Length == 0)
        {
            error = $"'{value}' has no host before the ':'.";
            return false;
        }

        if (host.Any(c => char.IsWhiteSpace(c) || char.IsControl(c) || c is '/' or '\\' or '['))
        {
            error = $"'{host}' is not a host name or IP address.";
            return false;
        }

        var port = defaultPort;
        if (colons == 1 && !TryParsePort(value[(host.Length + 1)..], out port, out error))
        {
            return false;
        }

        result = new HostAndPort(host, port);
        return true;
    }

    /// <summary>Reads a host with an optional port, or throws saying what is wrong.</summary>
    /// <param name="text">What was typed.</param>
    /// <param name="defaultPort">The port when none is given.</param>
    /// <returns>The host and port.</returns>
    /// <exception cref="FormatException"><paramref name="text"/> is not a host with an optional port.</exception>
    public static HostAndPort Parse(string text, int defaultPort) =>
        TryParse(text, defaultPort, out var result, out var error) ? result : throw new FormatException(error);

    /// <summary>Writes a host and port the way <see cref="TryParse"/> reads them back.</summary>
    /// <param name="host">The host. An IPv6 address is bracketed.</param>
    /// <param name="port">The port.</param>
    /// <returns><c>host:port</c>, or <c>[host]:port</c> for an IPv6 address.</returns>
    public static string Format(string? host, int port) =>
        host is not null && host.Contains(':', StringComparison.Ordinal)
            ? string.Create(CultureInfo.InvariantCulture, $"[{host}]:{port}")
            : string.Create(CultureInfo.InvariantCulture, $"{host}:{port}");

    /// <inheritdoc />
    public override string ToString() => Format(Host, Port);

    private static bool TryParseBracketed(string value, int defaultPort, out HostAndPort result, out string error)
    {
        result = default;
        error = string.Empty;

        var close = value.IndexOf(']', StringComparison.Ordinal);
        if (close < 0)
        {
            error = $"'{value}' is missing the ']' that closes the IPv6 address.";
            return false;
        }

        var inner = value[1..close];
        if (!IPAddress.TryParse(inner, out var address) || address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            error = $"'{inner}' is not an IPv6 address. Brackets are only for IPv6; write " +
                    "a host name or IPv4 address without them.";
            return false;
        }

        var rest = value[(close + 1)..];
        var port = defaultPort;

        if (rest.Length > 0)
        {
            if (rest[0] != ':')
            {
                error = $"'{value}' has '{rest}' after the ']'. Only :port may follow it.";
                return false;
            }

            if (!TryParsePort(rest[1..], out port, out error))
            {
                return false;
            }
        }

        result = new HostAndPort(inner, port);
        return true;
    }

    private static bool TryParsePort(string text, out int port, out string error)
    {
        error = string.Empty;

        // Digits only: int.TryParse on its own would take a sign, spaces and "+8471".
        if (text.Length is > 0 and <= 5 &&
            text.All(char.IsAsciiDigit) &&
            int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out port) &&
            port is >= 1 and <= 65535)
        {
            return true;
        }

        port = 0;
        error = $"'{text}' is not a port. A port is a number from 1 to 65535.";
        return false;
    }
}
