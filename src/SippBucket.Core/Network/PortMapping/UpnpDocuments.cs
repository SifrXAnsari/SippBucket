using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// Reading and writing the few UPnP documents the port mapper exchanges with a gateway: the
/// SSDP search and its answer, the device description, and the SOAP control messages.
/// </summary>
/// <remarks>
/// <para>
/// Everything a device sends is treated as hostile input. The caller has already bounded its
/// size. XML is read with DTD processing prohibited and no resolver, so a document that
/// declares a DTD, an entity expansion bomb, or an external entity pointing somewhere else on
/// the network is refused at its <c>DOCTYPE</c> rather than processed
/// (https://learn.microsoft.com/en-us/dotnet/api/system.xml.dtdprocessing). Every URL the
/// device gives must be plain <c>http</c> to the gateway's own IP address, so a description
/// cannot send this machine anywhere else.
/// </para>
/// <para>
/// Formats from the UPnP Device Architecture 2.0
/// (https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf):
/// the unicast M-SEARCH in section 1.3.2, the search response in 1.3.3, URL resolution in
/// 2.3 and the introduction to section 3, the action invocation in 3.2.1, the response in
/// 3.2.2 and the error response in 3.2.5. Actions and arguments from WANIPConnection:1
/// (https://openconnectivity.org/wp-content/uploads/2015/11/UPnP-gw-WANIPConnection-v1-Service.pdf)
/// section 2.4 and WANIPConnection:2
/// (https://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf) section 2.5.
/// </para>
/// </remarks>
internal static class UpnpDocuments
{
    /// <summary>What the search asks for: any Internet Gateway Device.</summary>
    /// <remarks>
    /// Version 1, because UDA 2.0 section 1.3.2 requires a device to "respond to M-SEARCH
    /// requests for any supported version", so an IGD:2 answers a search for IGD:1 too.
    /// </remarks>
    public const string SearchTarget = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";

    /// <summary>WANIPConnection version 2, preferred when a gateway offers it.</summary>
    public const string WanIpConnection2 = "urn:schemas-upnp-org:service:WANIPConnection:2";

    /// <summary>WANIPConnection version 1.</summary>
    public const string WanIpConnection1 = "urn:schemas-upnp-org:service:WANIPConnection:1";

    private static readonly XNamespace DeviceNamespace = "urn:schemas-upnp-org:device-1-0";
    private static readonly XNamespace SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace ControlNamespace = "urn:schemas-upnp-org:control-1-0";

    /// <summary>Builds the unicast M-SEARCH, UDA 2.0 section 1.3.2.</summary>
    /// <param name="device">The gateway's address and SSDP port.</param>
    /// <returns>The datagram.</returns>
    /// <remarks>
    /// The unicast form in section 1.3.2 lists HOST (the device's address and port), MAN and
    /// ST, with no MX. MX is sent as well, set to 1: the multicast form requires it and a
    /// device "shall silently discard and ignore" a multicast search without it (section
    /// 1.3.3), and a UPnP 1.0 device knows only that form. That MX helps such a device is this
    /// program's reasoning, not something measured on one.
    /// </remarks>
    public static byte[] SearchRequest(IPEndPoint device)
    {
        ArgumentNullException.ThrowIfNull(device);

        return Encoding.ASCII.GetBytes(string.Create(
            CultureInfo.InvariantCulture,
            $"M-SEARCH * HTTP/1.1\r\nHOST: {device.Address}:{device.Port}\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {SearchTarget}\r\n\r\n"));
    }

    /// <summary>
    /// Reads a search response, UDA 2.0 section 1.3.3, and returns its LOCATION when it is an
    /// answer to this search.
    /// </summary>
    /// <param name="datagram">The response, already known to come from the gateway's SSDP port.</param>
    /// <returns>The LOCATION field's value, or null when this is not a 200 answer to this search.</returns>
    public static string? ReadSearchResponse(ReadOnlySpan<byte> datagram)
    {
        var text = Encoding.ASCII.GetString(datagram);
        var lines = text.Split('\n');

        var status = lines[0].TrimEnd('\r').Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (status.Length < 2 ||
            !status[0].StartsWith("HTTP/1.", StringComparison.Ordinal) ||
            !string.Equals(status[1], "200", StringComparison.Ordinal))
        {
            return null;
        }

        string? location = null;
        string? target = null;

        foreach (var raw in lines.Skip(1))
        {
            var line = raw.TrimEnd('\r');
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                continue;
            }

            // "Field names are not case sensitive. All field values are case sensitive except
            // where noted" (section 1.3.3).
            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();

            if (name.Equals("LOCATION", StringComparison.OrdinalIgnoreCase))
            {
                location = value;
            }
            else if (name.Equals("ST", StringComparison.OrdinalIgnoreCase))
            {
                target = value;
            }
        }

        // "The response shall specify the same version as was contained in the search
        // request" (section 1.3.2).
        return string.Equals(target, SearchTarget, StringComparison.Ordinal) ? location : null;
    }

    /// <summary>
    /// Parses a URL a device gave, and accepts it only when it is plain HTTP to the gateway.
    /// </summary>
    /// <param name="text">The URL, absolute or relative.</param>
    /// <param name="baseUrl">What a relative URL is resolved against, or null to accept only absolute ones.</param>
    /// <param name="gateway">The gateway's address.</param>
    /// <param name="url">The absolute URL, when accepted.</param>
    /// <returns>True when the URL is <c>http</c> to the gateway's IP address with no user information.</returns>
    /// <remarks>
    /// A relative URL is resolved "in accordance with clause 5 of RFC 3986", against URLBase
    /// or the URL the description came from (UDA 2.0 section 2.3, and section 3 for the control
    /// URL). The host must be an IP literal, so no name is ever looked up, and it must be the
    /// gateway's, so a device cannot point this machine at another host on the network or
    /// beyond it.
    /// </remarks>
    public static bool TryGatewayUrl(string? text, Uri? baseUrl, IPAddress gateway, [NotNullWhen(true)] out Uri? url)
    {
        ArgumentNullException.ThrowIfNull(gateway);
        url = null;

        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var candidate = baseUrl is null
            ? Uri.TryCreate(text.Trim(), UriKind.Absolute, out var absolute) ? absolute : null
            : Uri.TryCreate(baseUrl, text.Trim(), out var resolved) ? resolved : null;

        if (candidate is null ||
            !candidate.IsAbsoluteUri ||
            !string.Equals(candidate.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal) ||
            candidate.HostNameType != UriHostNameType.IPv4 ||
            candidate.UserInfo.Length != 0 ||
            !IPAddress.TryParse(candidate.Host, out var host) ||
            !host.Equals(gateway))
        {
            return false;
        }

        url = candidate;
        return true;
    }

    /// <summary>Parses a document from a device, refusing DTDs and anything larger than the bytes given.</summary>
    /// <param name="document">The bytes, already bounded by the caller.</param>
    /// <returns>The document.</returns>
    /// <exception cref="XmlException">Not well-formed, or it declares a DTD.</exception>
    public static XDocument ParseXml(byte[] document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var settings = new XmlReaderSettings
        {
            // The DTD is where every XML expansion and external entity attack lives. No
            // UPnP document needs one; refusing it outright is simpler than reasoning about
            // which parts of one are safe.
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 0,
            MaxCharactersInDocument = document.Length,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
        };

        using var stream = new MemoryStream(document, writable: false);
        using var reader = XmlReader.Create(stream, settings);
        return XDocument.Load(reader, LoadOptions.None);
    }

    /// <summary>
    /// Finds the WANIPConnection service in a device description, preferring version 2.
    /// </summary>
    /// <param name="description">The description.</param>
    /// <param name="location">The URL it was fetched from.</param>
    /// <param name="gateway">The gateway's address.</param>
    /// <param name="refusedUrl">
    /// Set when the description has what was looked for but points it somewhere other than
    /// plain HTTP to the gateway: the URL, for the log. Null otherwise.
    /// </param>
    /// <returns>The service type and its control URL, or null when there is none this accepts.</returns>
    /// <remarks>
    /// Searched for anywhere under the root, the way UDA 2.0 section 2 asks a control point to
    /// find a service "even when it is embedded within another device type". The IGD templates
    /// put it under WANDevice and then WANConnectionDevice (InternetGatewayDevice:1 section
    /// 2.2), but the depth is not relied on.
    /// </remarks>
    public static (string ServiceType, Uri ControlUrl)? FindWanIpConnection(
        XDocument description,
        Uri location,
        IPAddress gateway,
        out string? refusedUrl)
    {
        ArgumentNullException.ThrowIfNull(description);
        ArgumentNullException.ThrowIfNull(location);
        refusedUrl = null;

        var root = description.Root;
        if (root is null || root.Name != DeviceNamespace + "root")
        {
            return null;
        }

        // URLBase is deprecated but "control points shall be able to process URLBase if it is
        // specified" (UDA 2.0 section 2.3). It must itself be the gateway.
        var baseUrl = location;
        var urlBase = root.Element(DeviceNamespace + "URLBase")?.Value;
        if (!string.IsNullOrWhiteSpace(urlBase))
        {
            if (!TryGatewayUrl(urlBase, null, gateway, out var declared))
            {
                refusedUrl = urlBase;
                return null;
            }

            baseUrl = declared;
        }

        foreach (var wanted in new[] { WanIpConnection2, WanIpConnection1 })
        {
            foreach (var service in root.Descendants(DeviceNamespace + "service"))
            {
                var type = service.Element(DeviceNamespace + "serviceType")?.Value.Trim();
                if (!string.Equals(type, wanted, StringComparison.Ordinal))
                {
                    continue;
                }

                var control = service.Element(DeviceNamespace + "controlURL")?.Value;
                if (TryGatewayUrl(control, baseUrl, gateway, out var controlUrl))
                {
                    return (wanted, controlUrl);
                }

                refusedUrl = control ?? "(none)";
                return null;
            }
        }

        return null;
    }

    /// <summary>Builds a SOAP action invocation body, UDA 2.0 section 3.2.1.</summary>
    /// <param name="serviceType">The service type, which is also the action's namespace.</param>
    /// <param name="action">The action's name.</param>
    /// <param name="arguments">The in arguments, in the order the service description lists them.</param>
    /// <returns>The body, UTF-8.</returns>
    public static byte[] ActionRequest(
        string serviceType,
        string action,
        IReadOnlyList<(string Name, string Value)> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);

        var body = new StringBuilder();
        body.Append("<?xml version=\"1.0\"?>")
            .Append("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" ")
            .Append("s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">")
            .Append("<s:Body>")
            .Append("<u:").Append(action).Append(" xmlns:u=\"").Append(serviceType).Append("\">");

        foreach (var (name, value) in arguments)
        {
            // Section 3.2.1: characters "reserved as markup ... shall be escaped".
            body.Append('<').Append(name).Append('>')
                .Append(SecurityElement.Escape(value))
                .Append("</").Append(name).Append('>');
        }

        body.Append("</u:").Append(action).Append('>')
            .Append("</s:Body>")
            .Append("</s:Envelope>");

        return Encoding.UTF8.GetBytes(body.ToString());
    }

    /// <summary>Reads an action response, UDA 2.0 section 3.2.2.</summary>
    /// <param name="document">The response body.</param>
    /// <param name="serviceType">The service type the action was invoked with.</param>
    /// <param name="action">The action's name.</param>
    /// <returns>The out arguments by name, or null when this is not that action's response.</returns>
    public static IReadOnlyDictionary<string, string>? ReadActionResponse(
        XDocument document,
        string serviceType,
        string action)
    {
        ArgumentNullException.ThrowIfNull(document);

        XNamespace service = serviceType;
        var response = document.Root?
            .Element(SoapNamespace + "Body")?
            .Elements()
            .FirstOrDefault();

        if (document.Root?.Name != SoapNamespace + "Envelope" ||
            response?.Name != service + (action + "Response"))
        {
            return null;
        }

        return response.Elements()
            .GroupBy(e => e.Name.LocalName, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.Ordinal);
    }

    /// <summary>Reads the UPnP error code from an error response, UDA 2.0 section 3.2.5.</summary>
    /// <param name="document">The response body.</param>
    /// <returns>The errorCode, or null when the document is not a UPnP fault.</returns>
    public static int? ReadErrorCode(XDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var code = document.Root?
            .Element(SoapNamespace + "Body")?
            .Element(SoapNamespace + "Fault")?
            .Element("detail")?
            .Element(ControlNamespace + "UPnPError")?
            .Element(ControlNamespace + "errorCode")?
            .Value;

        return int.TryParse(code?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;
    }

    /// <summary>Reads an IPv4 address from an out argument, or null when it is not one.</summary>
    /// <param name="text">The argument's value.</param>
    /// <returns>The address, or null for an empty, unparseable, IPv6 or all-zeros value.</returns>
    public static IPAddress? ReadIPv4(string? text) =>
        IPAddress.TryParse(text?.Trim(), out var address) &&
        address.AddressFamily == AddressFamily.InterNetwork &&
        !address.Equals(IPAddress.Any)
            ? address
            : null;
}
