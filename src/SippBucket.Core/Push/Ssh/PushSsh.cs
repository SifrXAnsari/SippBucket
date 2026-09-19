using System.Diagnostics;
using Microsoft.DevTunnels.Ssh;
using Microsoft.DevTunnels.Ssh.Algorithms;

namespace SippBucket.Core.Push.Ssh;

/// <summary>
/// How Direct Push uses SSH: the one configuration every session is built from, and the names
/// both ends agree on.
/// </summary>
/// <remarks>
/// <para>
/// <b>Strong algorithms only</b> (approval condition 3, docs/DIRECT-PUSH.md). Each list holds
/// exactly one algorithm, and both ends are SippBucket, so there is nothing to negotiate down
/// to:
/// </para>
/// <list type="bullet">
/// <item>key exchange <c>ecdh-sha2-nistp384</c> (RFC 5656): elliptic-curve Diffie-Hellman with
/// SHA-384;</item>
/// <item>host and user keys <c>ssh-ed25519</c> (RFC 8709), the device keys, through
/// <see cref="SshEd25519"/>;</item>
/// <item>encryption <c>aes256-gcm@openssh.com</c>: AES-256 in GCM mode, which authenticates each
/// packet itself;</item>
/// <item>MAC <c>hmac-sha2-512-etm@openssh.com</c>, which the library still negotiates beside an
/// authenticated cipher and GCM then leaves unused;</item>
/// <item>compression <c>none</c>, which in SSH is the name of no compression (RFC 4253 section
/// 6.2): compressing costs more than it saves at LAN speeds.</item>
/// </list>
/// <para>
/// The library negotiates the first algorithm both sides list and fails the key exchange when
/// there is none in common. It offers <c>none</c> as a cipher, MAC or key exchange only when a
/// list holds it, and none of these does, so no session can be set up without encryption (RFC
/// 4253 section 6.3 calls the none cipher "NOT RECOMMENDED"). An algorithm this machine cannot
/// run is refused when the configuration is built, rather than dropped from the list in silence.
/// </para>
/// <para>
/// <b>Public-key logins only.</b> The one authentication method offered is <c>publickey</c>
/// (RFC 4252 section 7). The library refuses every other method before any SippBucket code
/// runs, and verifies the signature before asking whether the key is accepted. One failed
/// attempt ends the session: a SippBucket client offers its device key once, and a stranger is
/// owed no second guess. No protocol extensions are offered.
/// </para>
/// <para>
/// <b>Nothing is traced.</b> The library writes to a <see cref="TraceSource"/>; the one each
/// session gets has no listeners and is switched off, so nothing it traces goes anywhere.
/// SippBucket writes its own log lines.
/// </para>
/// </remarks>
public static class PushSsh
{
    /// <summary>
    /// The channel type a push is delivered on: the one channel a SippBucket SSH server opens.
    /// </summary>
    /// <remarks>
    /// A private name, so it carries a domain its definer controls (RFC 4250 section 4.6.1).
    /// The server refuses every other channel type, the standard <c>session</c> channel
    /// included, so no shell, command, subsystem or forwarding can ever be asked for.
    /// </remarks>
    public const string PushChannelType = "sippbucket-push@sifrxansari.com";

    /// <summary>The user name every SippBucket client logs in as.</summary>
    /// <remarks>
    /// SSH requires one (RFC 4252 section 5). The key decides who the caller is; the server
    /// refuses any other name only so that nothing else is ever accepted.
    /// </remarks>
    public const string UserName = "sippbucket";

    /// <summary>The one authentication method offered (RFC 4252 section 7).</summary>
    public const string PublicKeyMethod = "publickey";

    /// <summary>The name of the <see cref="TraceSource"/> sessions are given.</summary>
    public const string TraceName = "SippBucket.DirectPush.Ssh";

    /// <summary>Builds the configuration every Direct Push session, client or server, uses.</summary>
    /// <returns>A new configuration; each session gets its own.</returns>
    /// <exception cref="PlatformNotSupportedException">
    /// This machine's cryptography cannot run one of the algorithms. Direct Push does not start
    /// rather than start with something weaker.
    /// </exception>
    public static SshSessionConfiguration CreateConfiguration()
    {
        var configuration = new SshSessionConfiguration(useSecurity: true, enableCompression: false, enableReconnect: false);

        OnlyThis(configuration.KeyExchangeAlgorithms, SshAlgorithms.KeyExchange.EcdhNistp384);
        OnlyThis(configuration.PublicKeyAlgorithms, new SshEd25519());
        OnlyThis(configuration.EncryptionAlgorithms, SshAlgorithms.Encryption.Aes256Gcm);
        OnlyThis(configuration.HmacAlgorithms, SshAlgorithms.Hmac.HmacSha512Etm);

        // SSH's name for no compression, which every implementation must support (RFC 4253
        // section 6.2). The library writes a null entry as "none".
        configuration.CompressionAlgorithms.Clear();
        configuration.CompressionAlgorithms.Add(SshAlgorithms.Compression.None);

        configuration.ProtocolExtensions.Clear();
        configuration.AuthenticationMethods.Clear();
        configuration.AuthenticationMethods.Add(PublicKeyMethod);

        configuration.MaxClientAuthenticationAttempts = 1;
        configuration.EnableKeyExchangeGuess = false;
        configuration.TraceChannelData = false;

        // Liveness is SippBucket's stall deadline on every read and write, the same one sync
        // uses, rather than SSH keep-alive messages.
        configuration.KeepAliveTimeoutInSeconds = 0;

        return configuration;
    }

    /// <summary>A trace source that goes nowhere, for the library to write to.</summary>
    /// <returns>A switched-off source with no listeners.</returns>
    public static TraceSource CreateTrace()
    {
        var trace = new TraceSource(TraceName, SourceLevels.Off);

        // A new source starts with the default listener, which writes to the debugger output.
        trace.Listeners.Clear();
        return trace;
    }

    private static void OnlyThis<T>(ICollection<T?> list, T algorithm)
        where T : SshAlgorithm
    {
        if (!algorithm.IsAvailable)
        {
            throw new PlatformNotSupportedException(
                $"This machine's cryptography cannot run {algorithm.Name}, which Direct Push requires, " +
                "so Direct Push does not start rather than use something weaker.");
        }

        list.Clear();
        list.Add(algorithm);
    }
}
