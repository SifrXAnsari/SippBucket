using System.Text;
using SippBucket.Core.Native;

namespace SippBucket.Core.Push;

/// <summary>Where a received file goes.</summary>
/// <remarks>The values are the engine's <c>SIPE_VERDICT_*</c> numbers.</remarks>
// CA1008 wants a zero member. The engine's numbering starts at 1 on purpose: a zeroed
// verdict must read as invalid — ToVerdict throws on it — never as a place a file goes.
#pragma warning disable CA1008
public enum ContentVerdict
{
    /// <summary>Its content matches its name, or its name claims nothing its content contradicts.</summary>
    Inbox = 1,

    /// <summary>Neither its name nor its content is a type SippBucket knows. It goes to the inbox, marked so.</summary>
    InboxUnrecognised = 2,

    /// <summary>It goes to quarantine; <see cref="ContentCheckResult.Reason"/> says why.</summary>
    Quarantine = 3,
}
#pragma warning restore CA1008

/// <summary>Why a received file is quarantined.</summary>
/// <remarks>The values are the engine's <c>SIPE_REASON_*</c> numbers, and are stored in quarantine records.</remarks>
public enum QuarantineReason
{
    /// <summary>It is not quarantined.</summary>
    None = 0,

    /// <summary>Its bytes are a program, or something Windows launches or mounts, whatever it is named.</summary>
    ExecutableContent = 1,

    /// <summary>Its name is a type Windows runs or installs, whatever it holds.</summary>
    ExecutableName = 2,

    /// <summary>Its bytes are not what its name says.</summary>
    Mismatch = 3,
}

/// <summary>What the content check decided about one file.</summary>
/// <param name="Verdict">Where the file goes.</param>
/// <param name="Reason">Why it is quarantined, or <see cref="QuarantineReason.None"/>.</param>
/// <param name="DetectedType">What its bytes are, as the engine's type number; 0 when unrecognised.</param>
/// <param name="ClaimedType">What its name claims, as the engine's type number; 0 when nothing.</param>
public sealed record ContentCheckResult(ContentVerdict Verdict, QuarantineReason Reason, uint DetectedType, uint ClaimedType)
{
    /// <summary>What its bytes are, for a person, such as "PNG image" or "unrecognised".</summary>
    public string DetectedName => ContentTypes.NameOf(DetectedType);

    /// <summary>
    /// The extension a file with this content usually has, without the dot, for releasing it
    /// under the name its content matches; empty when there is no single right one.
    /// </summary>
    public string DetectedExtension => ContentTypes.ExtensionOf(DetectedType);
}

/// <summary>Content type numbers, in words.</summary>
public static class ContentTypes
{
    /// <summary>The number the engine uses for content it does not recognise.</summary>
    public const uint Unknown = 0;

    /// <summary>A type's name for a person.</summary>
    /// <param name="type">The engine's type number.</param>
    /// <returns>Its name, or "type N" for a number this build's engine does not know.</returns>
    /// <remarks>
    /// A number stored by a newer build, in a quarantine record, can name a type this engine
    /// has never heard of; it is shown as a number rather than refused.
    /// </remarks>
    public static string NameOf(uint type) => SipEngine.TypeName(type) ?? $"type {type}";

    /// <summary>The extension a file of the type usually has, without the dot.</summary>
    /// <param name="type">The engine's type number.</param>
    /// <returns>The extension, or empty when there is none or the number is unknown.</returns>
    public static string ExtensionOf(uint type) => SipEngine.TypeExtension(type) ?? string.Empty;
}

/// <summary>
/// Checks a file's content against its name: Direct Push's rule 4 (docs/DIRECT-PUSH.md).
/// </summary>
/// <remarks>
/// <para>
/// The decision is the native engine's (<c>sipe_content_check</c>), made from the file's first
/// <see cref="HeadBytes"/> bytes and its name. An executable always goes to quarantine,
/// whatever it is named; a mismatch goes to quarantine; a file of a type SippBucket does not
/// recognise, whose content is not an executable, goes to the inbox marked unrecognised.
/// </para>
/// <para>
/// The receiving machine's decision is final. The sender runs the same check only to warn, to
/// save a wasted transfer, because a sender cannot be trusted to police itself.
/// </para>
/// <para>
/// <b>What it cannot do</b> (standard A3): it catches a disguised file, not a malicious one.
/// A genuine JPEG can carry a malformed payload, and a file can be valid as two formats at
/// once. The antivirus still scans whatever arrives, and SippBucket never gets in its way.
/// </para>
/// </remarks>
public static class ContentCheck
{
    /// <summary>How much of a file the check reads: <c>SIPE_CONTENT_HEAD_BYTES</c>.</summary>
    public const int HeadBytes = 65536;

    /// <summary>Checks a file from its first bytes and its name.</summary>
    /// <param name="head">The file's first bytes; only the first <see cref="HeadBytes"/> are read.</param>
    /// <param name="totalLength">The file's whole length.</param>
    /// <param name="fileName">The file's name as sent, without a directory.</param>
    /// <returns>The decision.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="fileName"/> was null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="totalLength"/> was negative.</exception>
    public static ContentCheckResult Check(ReadOnlySpan<byte> head, long totalLength, string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        ArgumentOutOfRangeException.ThrowIfNegative(totalLength);

        var bytes = head.Length > HeadBytes ? head[..HeadBytes].ToArray() : head.ToArray();
        var (verdict, reason, detected, claimed) =
            SipEngine.CheckContent(bytes, bytes.Length, totalLength, Encoding.UTF8.GetBytes(fileName));

        return new ContentCheckResult(ToVerdict(verdict), ToReason(reason), detected, claimed);
    }

    /// <summary>Checks a file on disk, under the name it was sent with.</summary>
    /// <param name="path">The file, as staged.</param>
    /// <param name="fileName">The name it was sent with, which is what is judged.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The decision.</returns>
    /// <exception cref="ArgumentException">A path or name was null or blank.</exception>
    /// <exception cref="IOException">The file could not be read.</exception>
    public static async Task<ContentCheckResult> CheckFileAsync(
        string path,
        string fileName,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 1, FileOptions.Asynchronous);
        await using (stream.ConfigureAwait(false))
        {
            var head = new byte[(int)Math.Min(HeadBytes, stream.Length)];
            await stream.ReadExactlyAsync(head, cancellationToken).ConfigureAwait(false);
            return Check(head, stream.Length, fileName);
        }
    }

    private static ContentVerdict ToVerdict(uint value) => value switch
    {
        1 => ContentVerdict.Inbox,
        2 => ContentVerdict.InboxUnrecognised,
        3 => ContentVerdict.Quarantine,
        _ => throw new InvalidOperationException($"The engine returned verdict {value}, which this build does not know."),
    };

    private static QuarantineReason ToReason(uint value) => value switch
    {
        0 => QuarantineReason.None,
        1 => QuarantineReason.ExecutableContent,
        2 => QuarantineReason.ExecutableName,
        3 => QuarantineReason.Mismatch,
        _ => throw new InvalidOperationException($"The engine returned reason {value}, which this build does not know."),
    };
}
