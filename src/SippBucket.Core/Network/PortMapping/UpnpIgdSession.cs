using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Xml;
using System.Xml.Linq;

namespace SippBucket.Core.Network.PortMapping;

/// <summary>
/// A UPnP IGD port mapping for one TCP port: found by a unicast SSDP search of the gateway,
/// made with <c>AddPortMapping</c> on its WANIPConnection service, and removed with
/// <c>DeletePortMapping</c>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Only the gateway, only over plain HTTP to its own address.</strong> The search goes
/// to the gateway alone, never to the SSDP multicast group, and only an answer from the
/// gateway's address and SSDP port counts. The description it points to, the control URL in
/// the description and any URLBase must all be <c>http</c> to the gateway's IP address
/// (<see cref="UpnpDocuments.TryGatewayUrl"/>). Redirects are never followed and no proxy is
/// used, so every HTTP request this makes goes to the address the gateway was asked at.
/// </para>
/// <para>
/// <strong>Bounded.</strong> Every HTTP exchange has <see cref="PortMapperOptions.HttpTimeout"/>
/// for everything, reading included, and every body is refused past a byte limit, whatever
/// its Content-Length says or omits. XML is parsed only after that, with DTDs prohibited.
/// </para>
/// <para>
/// <strong>What it asks for, and what it refuses.</strong> <c>NewRemoteHost</c> empty (any
/// remote host), <c>NewExternalPort</c> and <c>NewInternalPort</c> both the one port it was
/// given, <c>NewProtocol</c> TCP, <c>NewInternalClient</c> this machine's own address, and a
/// lease of the requested lifetime capped at 3600 seconds: WANIPConnection:2 section 2.5.16.3
/// requires 1 to 604800 and recommends "no more than 3600 seconds". It never sends a lease of
/// 0, which in WANIPConnection:1 means a mapping that never expires (section 2.2.14), and
/// never an external port of 0, which means every external port not otherwise mapped
/// (section 2.2.16). A gateway that answers 725 OnlyPermanentLeasesSupported or 727
/// ExternalPortOnlySupportsWildcard is refused as <see cref="PortMappingFailure.Unsafe"/>
/// rather than given what it wants. There is no <c>AddAnyPortMapping</c>: it lets the gateway
/// pick another external port, and this never takes a port it was not given.
/// </para>
/// </remarks>
internal sealed class UpnpIgdSession : MappingSession
{
    private const string Description = "SippBucket";
    private const string Tcp = "TCP";

    // WANIPConnection:2 section 2.5.16.3.
    private const uint LongestLease = 3600;

    // WANIPConnection:1 section 2.4.16.4, and :2 section 2.5.16.6.
    private const int ConflictInMappingEntry = 718;
    private const int OnlyPermanentLeasesSupported = 725;
    private const int ExternalPortOnlySupportsWildcard = 727;

    private readonly SocketsHttpHandler _handler;
    private readonly HttpClient _http;
    private string? _serviceType;
    private Uri? _controlUrl;
    private bool _mapped;

    /// <summary>Creates a session. Nothing is sent until <see cref="FindAsync"/>.</summary>
    /// <param name="gateway">The gateway.</param>
    /// <param name="internalAddress">This machine's address on the route to it.</param>
    /// <param name="internalPort">The port to map.</param>
    /// <param name="options">Destinations and timings.</param>
    /// <param name="log">Optional sink for log lines.</param>
    public UpnpIgdSession(
        IPAddress gateway,
        IPAddress internalAddress,
        ushort internalPort,
        PortMapperOptions options,
        Action<string>? log)
        : base(gateway, internalAddress, internalPort, options, log)
    {
        _handler = new SocketsHttpHandler
        {
            // Never somewhere the gateway sends it, and never through a proxy: the only host
            // this talks to is the one it checked. Headers are capped at 16 KiB.
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            MaxResponseHeadersLength = 16,
            ConnectTimeout = options.HttpTimeout,
            PooledConnectionLifetime = TimeSpan.FromMinutes(1),
        };

        // The handler is this session's to dispose, not the client's, so both are fields and
        // both are disposed in DisposeAsync.
        _http = new HttpClient(_handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
    }

    /// <inheritdoc />
    public override PortMappingProtocol Protocol => PortMappingProtocol.UpnpIgd;

    /// <summary>
    /// Finds the gateway's WANIPConnection service: SSDP search, then the description.
    /// </summary>
    /// <param name="cancellationToken">Cancels the search.</param>
    /// <returns>Null when found, or why not.</returns>
    public async Task<SessionOutcome?> FindAsync(CancellationToken cancellationToken)
    {
        var (location, searchFailure) = await SearchAsync(cancellationToken).ConfigureAwait(false);
        if (searchFailure is not null)
        {
            return searchFailure;
        }

        var (body, fetchFailure) = await HttpAsync(
                new HttpRequestMessage(HttpMethod.Get, location),
                Options.MaximumDescriptionBytes,
                cancellationToken)
            .ConfigureAwait(false);

        if (fetchFailure is not null)
        {
            return fetchFailure;
        }

        if (body!.Status != HttpStatusCode.OK)
        {
            return Failed(PortMappingFailure.Refused, $"the description at {location} answered HTTP {(int)body.Status}");
        }

        var description = Parse(body.Bytes, out var parseFailure);
        if (description is null)
        {
            return Failed(PortMappingFailure.UntrustedAnswer, $"the description at {location} was refused: {parseFailure}");
        }

        var service = UpnpDocuments.FindWanIpConnection(description, location!, Gateway, out var refusedUrl);
        if (refusedUrl is not null)
        {
            return Failed(
                PortMappingFailure.UntrustedAnswer,
                $"the description at {location} points somewhere other than plain HTTP to {Gateway}: {Printable(refusedUrl)}");
        }

        if (service is null)
        {
            return Failed(PortMappingFailure.Refused, $"the description at {location} offers no WANIPConnection service");
        }

        (_serviceType, _controlUrl) = service.Value;
        return null;
    }

    /// <inheritdoc />
    public override async Task<SessionOutcome> RequestAsync(
        uint lifetimeSeconds,
        bool renewal,
        TimeSpan budget,
        CancellationToken cancellationToken)
    {
        if (_controlUrl is null)
        {
            var notFound = await FindAsync(cancellationToken).ConfigureAwait(false);
            if (notFound is not null)
            {
                return notFound;
            }
        }

        var lease = Math.Clamp(lifetimeSeconds, 1, LongestLease);
        var port = InternalPort.ToString(CultureInfo.InvariantCulture);

        // Every in argument, in the order the service description lists them
        // (WANIPConnection:1 table 16, :2 table 2-39), as UDA 2.0 section 3.2.1 requires.
        var (_, failure) = await InvokeAsync(
                "AddPortMapping",
                [
                    ("NewRemoteHost", ""),
                    ("NewExternalPort", port),
                    ("NewProtocol", Tcp),
                    ("NewInternalPort", port),
                    ("NewInternalClient", InternalAddress.ToString()),
                    ("NewEnabled", "1"),
                    ("NewPortMappingDescription", Description),
                    ("NewLeaseDuration", lease.ToString(CultureInfo.InvariantCulture)),
                ],
                budget,
                cancellationToken)
            .ConfigureAwait(false);

        if (failure is not null)
        {
            return failure;
        }

        _mapped = true;
        return SessionOutcome.Granted(new MappingGrant(InternalPort, null, TimeSpan.FromSeconds(lease)));
    }

    /// <inheritdoc />
    /// <remarks>WANIPConnection:1 section 2.4.18 and :2 section 2.5.20, <c>GetExternalIPAddress</c>.</remarks>
    public override async Task<IPAddress?> LookUpExternalAddressAsync(CancellationToken cancellationToken)
    {
        var (arguments, failure) = await InvokeAsync(
                "GetExternalIPAddress",
                [],
                Options.HttpTimeout,
                cancellationToken)
            .ConfigureAwait(false);

        return failure is null && arguments!.TryGetValue("NewExternalIPAddress", out var text)
            ? UpnpDocuments.ReadIPv4(text)
            : null;
    }

    /// <inheritdoc />
    /// <remarks>
    /// WANIPConnection:1 section 2.4.17 and :2 section 2.5.18: the mapping is named by
    /// <c>NewRemoteHost</c>, <c>NewExternalPort</c> and <c>NewProtocol</c>, the same three it
    /// was made with.
    /// </remarks>
    public override async Task<bool> DeleteAsync(TimeSpan budget, CancellationToken cancellationToken)
    {
        if (!_mapped || _controlUrl is null)
        {
            return true;
        }

        var (_, failure) = await InvokeAsync(
                "DeletePortMapping",
                [
                    ("NewRemoteHost", ""),
                    ("NewExternalPort", InternalPort.ToString(CultureInfo.InvariantCulture)),
                    ("NewProtocol", Tcp),
                ],
                budget,
                cancellationToken)
            .ConfigureAwait(false);

        if (failure is not null)
        {
            Log?.Invoke(failure.Detail);
            return false;
        }

        _mapped = false;
        return true;
    }

    /// <inheritdoc />
    public override ValueTask DisposeAsync()
    {
        _http.Dispose();
        _handler.Dispose();
        return base.DisposeAsync();
    }

    /// <summary>
    /// Sends the unicast M-SEARCH, UDA 2.0 section 1.3.2, and returns the LOCATION of the
    /// gateway's answer.
    /// </summary>
    private async Task<(Uri? Location, SessionOutcome? Failure)> SearchAsync(CancellationToken cancellationToken)
    {
        var channel = GatewayUdpChannel.Open(new IPEndPoint(Gateway, Options.SsdpPort));
        try
        {
            var request = UpnpDocuments.SearchRequest(channel.Server);

            for (var attempt = 0; attempt < Options.SsdpAttempts; attempt++)
            {
                await channel.SendAsync(request, cancellationToken).ConfigureAwait(false);

                var until = Stopwatch.GetTimestamp() + (long)(Options.SsdpWait.TotalSeconds * Stopwatch.Frequency);
                while (await channel.ReceiveAsync(until, cancellationToken).ConfigureAwait(false) is { } datagram)
                {
                    if (datagram.Length > Options.MaximumSearchResponseBytes ||
                        UpnpDocuments.ReadSearchResponse(datagram) is not { } location)
                    {
                        channel.CountIgnored();
                        continue;
                    }

                    // UDA 2.0 section 1.3.3: LOCATION is a "Single absolute URL".
                    if (!UpnpDocuments.TryGatewayUrl(location, null, Gateway, out var url))
                    {
                        return (null, Failed(
                            PortMappingFailure.UntrustedAnswer,
                            $"the search answer's LOCATION is not plain HTTP to {Gateway}: {Printable(location)}"));
                    }

                    return (url, null);
                }
            }

            return (null, Failed(
                PortMappingFailure.NoAnswer,
                $"no SSDP answer from {Gateway}:{Options.SsdpPort} after {Options.SsdpAttempts} searches"));
        }
        finally
        {
            Ignored += channel.Ignored;
            channel.Dispose();
        }
    }

    /// <summary>
    /// Invokes one action on the WANIPConnection service and returns its out arguments.
    /// </summary>
    private async Task<(IReadOnlyDictionary<string, string>? Arguments, SessionOutcome? Failure)> InvokeAsync(
        string action,
        IReadOnlyList<(string Name, string Value)> arguments,
        TimeSpan budget,
        CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, _controlUrl)
        {
            Content = new ByteArrayContent(UpnpDocuments.ActionRequest(_serviceType!, action, arguments)),
        };

        // UDA 2.0 section 3.2.1: CONTENT-TYPE "shall be text/xml; charset="utf-8"", and
        // SOAPACTION is the service type, a hash mark and the action, "all enclosed in double
        // quotes".
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("text/xml; charset=\"utf-8\"");
        request.Headers.TryAddWithoutValidation("SOAPACTION", $"\"{_serviceType}#{action}\"");

        var (body, failure) = await HttpAsync(request, Options.MaximumControlResponseBytes, cancellationToken, budget)
            .ConfigureAwait(false);

        if (failure is not null)
        {
            return (null, failure);
        }

        var document = Parse(body!.Bytes, out var parseFailure);
        if (document is null)
        {
            return (null, Failed(PortMappingFailure.UntrustedAnswer, $"{action}'s answer was refused: {parseFailure}"));
        }

        if (body.Status == HttpStatusCode.OK &&
            UpnpDocuments.ReadActionResponse(document, _serviceType!, action) is { } outArguments)
        {
            return (outArguments, null);
        }

        // UDA 2.0 section 3.2.5: an error is HTTP 500 with a SOAP Fault carrying UPnPError.
        var code = UpnpDocuments.ReadErrorCode(document);
        var said = code is null
            ? $"HTTP {(int)body.Status} without a UPnP error code"
            : $"UPnP error {code}";

        var kind = code switch
        {
            ConflictInMappingEntry => PortMappingFailure.ExternalPortInUse,
            OnlyPermanentLeasesSupported or ExternalPortOnlySupportsWildcard => PortMappingFailure.Unsafe,
            _ => PortMappingFailure.Refused,
        };

        return (null, Failed(kind, $"{Gateway} refused {action}: {said}"));
    }

    /// <summary>
    /// Sends one request and reads at most <paramref name="limit"/> bytes of the answer, all
    /// within the HTTP deadline.
    /// </summary>
    private async Task<(HttpBody? Body, SessionOutcome? Failure)> HttpAsync(
        HttpRequestMessage request,
        int limit,
        CancellationToken cancellationToken,
        TimeSpan? budget = null)
    {
        using (request)
        {
            var deadline = budget is { } given && given < Options.HttpTimeout ? given : Options.HttpTimeout;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(deadline);

            request.Headers.ConnectionClose = true;

            try
            {
                using var response = await _http
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
                    .ConfigureAwait(false);

                var status = (int)response.StatusCode;
                if (status is >= 300 and < 400)
                {
                    return (null, Failed(
                        PortMappingFailure.UntrustedAnswer,
                        $"{request.RequestUri} answered HTTP {status}, a redirect, which is never followed"));
                }

                if (response.Content.Headers.ContentLength > limit)
                {
                    return (null, Failed(
                        PortMappingFailure.UntrustedAnswer,
                        $"{request.RequestUri} announced {response.Content.Headers.ContentLength} bytes; at most {limit} are read"));
                }

                var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
                await using (stream.ConfigureAwait(false))
                {
                    var buffer = new byte[limit + 1];
                    var total = 0;
                    while (total < buffer.Length)
                    {
                        var read = await stream.ReadAsync(buffer.AsMemory(total), timeout.Token).ConfigureAwait(false);
                        if (read == 0)
                        {
                            break;
                        }

                        total += read;
                    }

                    if (total > limit)
                    {
                        return (null, Failed(
                            PortMappingFailure.UntrustedAnswer,
                            $"{request.RequestUri} sent more than {limit} bytes"));
                    }

                    return (new HttpBody(response.StatusCode, buffer[..total]), null);
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return (null, Failed(
                    PortMappingFailure.NoAnswer,
                    $"{request.RequestUri} did not answer within {deadline.TotalSeconds:0.#} s"));
            }
            catch (HttpRequestException ex)
            {
                return (null, Failed(PortMappingFailure.NoAnswer, $"{request.RequestUri} could not be reached: {ex.Message}"));
            }
            catch (IOException ex)
            {
                return (null, Failed(PortMappingFailure.NoAnswer, $"{request.RequestUri} broke off: {ex.Message}"));
            }
        }
    }

    private static XDocument? Parse(byte[] bytes, out string? failure)
    {
        try
        {
            failure = null;
            return UpnpDocuments.ParseXml(bytes);
        }
        catch (XmlException ex)
        {
            failure = ex.Message;
            return null;
        }
    }

    private static SessionOutcome Failed(PortMappingFailure failure, string detail) =>
        SessionOutcome.Failed(failure, "UPnP IGD: " + detail);

    /// <summary>A device's text, cut short and stripped of control characters, for a log line.</summary>
    private static string Printable(string text)
    {
        var shown = text.Length > 120 ? text[..120] + "..." : text;
        return new string([.. shown.Select(c => char.IsControl(c) ? '?' : c)]);
    }

    private sealed record HttpBody(HttpStatusCode Status, byte[] Bytes);
}
