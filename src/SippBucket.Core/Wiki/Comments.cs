using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Crypto;
using SippBucket.Core.Model;
using SippBucket.Core.Platform;
using SippBucket.Core.Repository;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Wiki;

/// <summary>One comment on a page, as its file records it.</summary>
public sealed record PageComment
{
    /// <summary>The page commented on, folder-relative with forward slashes.</summary>
    public required string Page { get; init; }

    /// <summary>The device that wrote it, whose key signed it.</summary>
    public required string AuthorDeviceId { get; init; }

    /// <summary>When it was written, in UTC.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>The comment.</summary>
    public required string Text { get; init; }

    /// <summary>
    /// The Ed25519 signature of the canonical comment by <see cref="AuthorDeviceId"/>'s key,
    /// lowercase hexadecimal, under the comment's own context label.
    /// </summary>
    public required string Signature { get; init; }
}

/// <summary>A comment as read back: the comment, where it lives, and whether it proves its author.</summary>
public sealed record StoredComment
{
    /// <summary>The comment.</summary>
    public required PageComment Comment { get; init; }

    /// <summary>Its file, folder-relative.</summary>
    public required string File { get; init; }

    /// <summary>
    /// True when the signature is the named device's, over exactly this comment. A false here
    /// is shown, never hidden: the comment claims an author it cannot prove.
    /// </summary>
    public required bool Verifies { get; init; }

    /// <summary>The people named with <c>@</c> in the text, in order, first appearance only.</summary>
    public IReadOnlyList<string> Mentions => CommentStore.MentionsIn(Comment.Text);
}

/// <summary>
/// Comments on pages (T-01): one file per comment under <c>.sip-comments</c>, synced like
/// any other file, signed like a snapshot.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why files.</b> SippBucket moves files; comments that are files need no second channel,
/// arrive with the folder, work offline, and are covered by the folder's encryption at rest
/// and every machine's history. Each comment is one immutable file whose name no other
/// machine can collide with, so two people commenting at once merge without ever
/// conflicting; deleting the file deletes the comment, and that travels too.
/// </para>
/// <para>
/// <b>Why signed.</b> Every machine in the folder holds the key, so a comment's author field
/// would otherwise be a claim anyone could write. The device key signs the canonical bytes
/// under the comment's own label (D-52), and a comment whose signature does not verify is
/// listed with that said plainly.
/// </para>
/// <para>
/// Writing a comment is a team feature, gated where the command runs (T-05's model: teams
/// are people, and the switch is decided from the machines answered "someone else's").
/// Reading is just reading files.
/// </para>
/// </remarks>
public sealed class CommentStore
{
    /// <summary>The folder comments live under, at the working folder's root.</summary>
    public const string FolderName = ".sip-comments";

    /// <summary>The most characters one comment may hold.</summary>
    public const int LongestComment = 64 * 1024;

    /// <summary>The context label its signatures are made under (D-52).</summary>
    public const string SignatureLabel = "sippbucket-comment-v1";

    private const int CurrentSchema = 1;

    private readonly string _workingRoot;

    /// <summary>Creates a store over one folder's comments.</summary>
    /// <param name="workingRoot">The working folder.</param>
    /// <exception cref="ArgumentException"><paramref name="workingRoot"/> was null or blank.</exception>
    public CommentStore(string workingRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workingRoot);
        _workingRoot = workingRoot;
    }

    /// <summary>Writes one comment, signed by this machine.</summary>
    /// <param name="page">The page commented on, folder-relative.</param>
    /// <param name="text">The comment.</param>
    /// <param name="identity">This machine's identity, which signs it.</param>
    /// <param name="nowUtc">When, recorded on the comment.</param>
    /// <returns>The comment as stored, with its file.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    /// <exception cref="ArgumentException">The page path or the text cannot be a comment's.</exception>
    public StoredComment Add(string page, string text, DeviceIdentity identity, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(identity);

        var normalizedPage = NormalizePage(page);
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new ArgumentException("A comment needs some words.");
        }

        if (text.Length > LongestComment)
        {
            throw new ArgumentException(string.Create(
                CultureInfo.InvariantCulture,
                $"A comment holds at most {LongestComment} characters; this one is {text.Length}."));
        }

        var comment = new PageComment
        {
            Page = normalizedPage,
            AuthorDeviceId = identity.DeviceId,
            CreatedUtc = nowUtc,
            Text = text,
            Signature = Sign(identity, normalizedPage, nowUtc, text),
        };

        var folder = Path.Combine(_workingRoot, FolderName, normalizedPage.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(folder);

        // Named so no two machines, and no two comments here, can collide: the moment, this
        // device, and randomness. The file is written once and never edited.
        var stamp = nowUtc.UtcTicks.ToString("D19", CultureInfo.InvariantCulture);
        var name = $"{stamp}-{Short(identity.DeviceId)}-{Guid.NewGuid():N}"[..60] + ".json";
        var path = Path.Combine(folder, name);

        // Written whole inside .sip first, then moved: a comment file is synced the moment
        // it exists, and half of one must never be what another machine receives.
        var temporary = Path.Combine(
            _workingRoot, RepositoryLayout.MetadataDirectoryName, $"comment-{Guid.NewGuid():N}.tmp");
        Directory.CreateDirectory(Path.GetDirectoryName(temporary)!);
        try
        {
            File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(
                new StoredFile { Schema = CurrentSchema, Comment = comment }, SipJson.Readable));
            File.Move(temporary, path);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }

        return new StoredComment
        {
            Comment = comment,
            File = $"{FolderName}/{normalizedPage}/{name}",
            Verifies = true,
        };
    }

    /// <summary>Reads comments back, oldest first: every page's, or one page's.</summary>
    /// <param name="page">The page, or null for all.</param>
    /// <param name="unreadable">How many comment files could not be read as comments.</param>
    /// <returns>The comments, each with whether it proves its author.</returns>
    public IReadOnlyList<StoredComment> Load(string? page, out int unreadable)
    {
        unreadable = 0;
        var root = Path.Combine(_workingRoot, FolderName);
        if (page is not null)
        {
            root = Path.Combine(root, NormalizePage(page).Replace('/', Path.DirectorySeparatorChar));
        }

        if (!Directory.Exists(root))
        {
            return [];
        }

        var comments = new List<StoredComment>();
        foreach (var file in Directory.EnumerateFiles(root, "*.json", SearchOption.AllDirectories))
        {
            if (ReadOne(file) is { } comment)
            {
                comments.Add(comment);
            }
            else
            {
                unreadable++;
            }
        }

        return [.. comments.OrderBy(comment => comment.Comment.CreatedUtc)];
    }

    /// <summary>The people named with <c>@</c> in a text: letters, digits, <c>-</c> and <c>_</c>.</summary>
    /// <param name="text">The text.</param>
    /// <returns>Each name once, in order of first appearance, as written.</returns>
    public static IReadOnlyList<string> MentionsIn(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return [];
        }

        var mentions = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < text.Length - 1; i++)
        {
            if (text[i] != '@')
            {
                continue;
            }

            var end = i + 1;
            while (end < text.Length && end - i <= 40 &&
                   (char.IsLetterOrDigit(text[end]) || text[end] is '-' or '_'))
            {
                end++;
            }

            if (end > i + 1)
            {
                var name = text[(i + 1)..end];
                if (seen.Add(name))
                {
                    mentions.Add(name);
                }

                i = end - 1;
            }
        }

        return mentions;
    }

    /// <summary>One comment file, or null when it is not one this build reads.</summary>
    private StoredComment? ReadOne(string file)
    {
        byte[] bytes;
        try
        {
            bytes = SharingRetry.Run(() => File.ReadAllBytes(file));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        StoredFile? stored;
        try
        {
            stored = JsonSerializer.Deserialize<StoredFile>(bytes, SipJson.Readable);
        }
        catch (JsonException)
        {
            return null;
        }

        if (stored?.Comment is not { } comment ||
            comment.Text.Length > LongestComment ||
            !IsSafePage(comment.Page))
        {
            return null;
        }

        return new StoredComment
        {
            Comment = comment,
            File = Path.GetRelativePath(_workingRoot, file).Replace(Path.DirectorySeparatorChar, '/'),
            Verifies = Verify(comment),
        };
    }

    /// <summary>The canonical bytes a comment's signature covers.</summary>
    private static byte[] SignedBytes(string page, DateTimeOffset createdUtc, string text)
    {
        var writer = new CanonicalWriter();
        writer.Text(SignatureLabel);
        writer.UInt32(CurrentSchema);
        writer.Text(page);
        writer.Int64(createdUtc.UtcTicks);
        writer.Text(text);
        return writer.ToArray();
    }

    private static string Sign(DeviceIdentity identity, string page, DateTimeOffset createdUtc, string text)
    {
        var signature = identity.Sign(SignedBytes(page, createdUtc, text));
#pragma warning disable CA1308 // A signature is an identifier; lowercase hex is its wire form, as device IDs are.
        return Convert.ToHexString(signature).ToLowerInvariant();
#pragma warning restore CA1308
    }

    private static bool Verify(PageComment comment)
    {
        byte[] signature;
        try
        {
            signature = Convert.FromHexString(comment.Signature);
        }
        catch (FormatException)
        {
            return false;
        }

        if (signature.Length != SnapshotEncoding.SignatureSize)
        {
            return false;
        }

        byte[] signed;
        try
        {
            signed = SignedBytes(comment.Page, comment.CreatedUtc, comment.Text);
        }
        catch (ArgumentException)
        {
            // Text with no UTF-8 form cannot be what anyone signed.
            return false;
        }

        return DeviceIdentity.Verify(comment.AuthorDeviceId, signed, signature);
    }

    /// <summary>A page path fit to hold comments: relative, forward slashes, nothing tricky.</summary>
    private static string NormalizePage(string page)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(page);

        var normalized = page.Replace('\\', '/').TrimStart('/');
        while (normalized.StartsWith("./", StringComparison.Ordinal))
        {
            normalized = normalized[2..];
        }

        return IsSafePage(normalized)
            ? normalized
            : throw new ArgumentException(
                $"'{DisplayText.Printable(page, 260)}' is not a page path comments can be filed under.");
    }

    /// <summary>True for a relative path with no empty, dot or drive-shaped segment.</summary>
    private static bool IsSafePage(string page)
    {
        if (string.IsNullOrWhiteSpace(page) || page.Length > 500 ||
            page.Contains(':', StringComparison.Ordinal) ||
            page.Any(DisplayText.IsInstruction))
        {
            return false;
        }

        foreach (var segment in page.Split('/'))
        {
            if (segment.Length == 0 || segment is "." or ".." ||
                string.Equals(segment, FolderName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(segment, RepositoryLayout.MetadataDirectoryName, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static string Short(string deviceId) => deviceId[..Math.Min(8, deviceId.Length)];

    private sealed record StoredFile
    {
        public required int Schema { get; init; }

        public required PageComment Comment { get; init; }
    }
}
