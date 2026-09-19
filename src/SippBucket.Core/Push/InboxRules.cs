using SippBucket.Core.Machines;
using SippBucket.Core.Platform;
using SippBucket.Core.Repository;

namespace SippBucket.Core.Push;

/// <summary>
/// One forwarding rule: which files it takes, and the folder it moves them to.
/// </summary>
/// <remarks>
/// A condition left out matches anything; every condition given must match. A rule with no
/// conditions at all takes every file from the person's own machines, and nothing from anyone
/// else's.
/// </remarks>
public sealed record InboxRule
{
    /// <summary>The folder a matching file is moved to: a fully qualified path on a local drive.</summary>
    public required string Destination { get; init; }

    /// <summary>The sending machine's device ID, or null for any sender.</summary>
    /// <remarks>
    /// A device ID and never a name: names are labels and two machines can share one (D-25). The
    /// command line lets the person name the machine, and stores what it resolves to.
    /// </remarks>
    public string? From { get; init; }

    /// <summary>
    /// The file's type, as the extension its content has, such as <c>pdf</c> or <c>png</c>, or null
    /// for any type. It matches what the content is, not what the name says.
    /// </summary>
    public string? Type { get; init; }

    /// <summary>A pattern for the name it was sent with, using <c>*</c> and <c>?</c>, ignoring case; or null for any name.</summary>
    public string? NamePattern { get; init; }
}

/// <summary>
/// The person's own forwarding rules for the inbox, like email rules (docs/DIRECT-PUSH.md, rule 5).
/// </summary>
/// <remarks>
/// <para>
/// <b>The first matching rule wins</b>; a file no rule matches stays in the inbox.
/// <b>Nothing is overwritten</b>: a name already taken in the destination gets a numbered one
/// beside it. <b>Rules never apply to quarantine</b>: only a file that passed the content check
/// and was placed in the inbox is ever offered to them, so nothing leaves quarantine except by
/// the person's hand. <b>Rules never apply to another person's files unless the rule names that
/// person</b> (rule 7): a file from a machine that is not one of the person's own, or whose owner
/// was never answered, is forwarded only by a rule whose <see cref="InboxRule.From"/> is that
/// machine, so nothing another person sends is moved into a synced folder by default.
/// </para>
/// <para>
/// These are the person's own settings, kept per user, set with <c>sip inbox rules</c> and later
/// the window, unlike the master config.
/// </para>
/// </remarks>
public static class InboxRules
{
    /// <summary>The longest name pattern a rule may have, in characters.</summary>
    public const int MaximumPatternLength = PushName.MaximumLength;

    /// <summary>The first rule that applies to a file, or null when none does.</summary>
    /// <param name="rules">The rules, in the person's order.</param>
    /// <param name="entry">The file, as placed in the inbox.</param>
    /// <returns>The rule, or null.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    public static InboxRule? FirstMatch(IReadOnlyList<InboxRule> rules, InboxEntry entry)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(entry);

        return rules.FirstOrDefault(rule => Applies(rule, entry));
    }

    /// <summary>Whether one rule applies to a file.</summary>
    /// <param name="rule">The rule.</param>
    /// <param name="entry">The file, as placed in the inbox.</param>
    /// <returns>True when every condition the rule gives matches, and the sender is the person's own or is named.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    public static bool Applies(InboxRule rule, InboxEntry entry)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(entry);

        var namesSender = rule.From is not null &&
                          string.Equals(rule.From, entry.SenderDeviceId, StringComparison.OrdinalIgnoreCase);

        // Rule 7's default: another person's files are touched only by a rule that names them.
        if (!MachineOwnership.IsOwn(entry.SenderOwner) && !namesSender)
        {
            return false;
        }

        if (rule.From is not null && !namesSender)
        {
            return false;
        }

        if (rule.Type is not null &&
            !string.Equals(rule.Type, ContentTypes.ExtensionOf(entry.DetectedType), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return rule.NamePattern is null || Wildcard.IsMatch(entry.SentName, rule.NamePattern);
    }

    /// <summary>Whether a rule can be kept, and why not when it cannot.</summary>
    /// <param name="rule">The rule.</param>
    /// <param name="inbox">The inbox it would apply to.</param>
    /// <param name="reason">Why it cannot be kept, when this returns false.</param>
    /// <returns>True when it can.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    public static bool IsValid(InboxRule rule, PushInbox inbox, out string reason)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(inbox);

        if (string.IsNullOrWhiteSpace(rule.Destination) ||
            !Path.IsPathFullyQualified(rule.Destination) ||
            Path.GetPathRoot(rule.Destination) is not { Length: >= 2 } drive || drive[1] != ':')
        {
            reason = "the destination must be a folder on one of this machine's drives, written out in full";
            return false;
        }

        var destination = FolderPaths.Normalize(rule.Destination);
        if (FolderPaths.IsSameOrInside(destination, inbox.Quarantine.Folder) ||
            FolderPaths.IsSameOrInside(destination, inbox.MetadataFolder))
        {
            reason = "the destination cannot be the quarantine or SippBucket's own folder inside the inbox";
            return false;
        }

        if (string.Equals(destination, FolderPaths.Normalize(inbox.Root), StringComparison.OrdinalIgnoreCase))
        {
            reason = "the destination is the inbox itself";
            return false;
        }

        // A synced folder's own metadata is never a destination, as it is never a sync target:
        // a file dropped there could damage the folder's store (SafePath).
        if (destination.Split(Path.DirectorySeparatorChar).Any(segment =>
                string.Equals(segment, RepositoryLayout.MetadataDirectoryName, StringComparison.OrdinalIgnoreCase)))
        {
            reason = $"the destination is inside a synced folder's {RepositoryLayout.MetadataDirectoryName} metadata";
            return false;
        }

        if (rule.From is not null && !PeerRegistry.IsWellFormedDeviceId(rule.From))
        {
            reason = "the sender must be a machine's 64-character device ID";
            return false;
        }

        if (rule.Type is not null && (rule.Type.Length == 0 || !rule.Type.All(char.IsAsciiLetterOrDigit)))
        {
            reason = "the type must be an extension such as pdf or png, without the dot";
            return false;
        }

        if (rule.NamePattern is not null &&
            (rule.NamePattern.Length is 0 or > MaximumPatternLength ||
             rule.NamePattern.Any(c => char.IsControl(c) || c is '/' or '\\' or ':' or '"' or '<' or '>' or '|')))
        {
            reason = string.Create(
                System.Globalization.CultureInfo.InvariantCulture,
                $"the name pattern must be 1 to {MaximumPatternLength} characters, with no folder separators");
            return false;
        }

        reason = string.Empty;
        return true;
    }

    /// <summary>
    /// Moves a file placed in the inbox to where a rule sends it, under a free name. The caller
    /// holds the inbox's lock.
    /// </summary>
    /// <param name="inbox">The inbox.</param>
    /// <param name="placedName">The file's name in the inbox.</param>
    /// <param name="rule">The rule.</param>
    /// <returns>The full path it now has.</returns>
    /// <exception cref="IOException">The folder could not be created or the file moved; it stays in the inbox.</exception>
    /// <exception cref="UnauthorizedAccessException">The destination is not the person's to write; it stays in the inbox.</exception>
    internal static string Forward(PushInbox inbox, string placedName, InboxRule rule)
    {
        Directory.CreateDirectory(rule.Destination);
        var name = PushInbox.MoveUnderFreeName(Path.Combine(inbox.Root, placedName), rule.Destination, placedName);
        return Path.Combine(rule.Destination, name);
    }

}

/// <summary>Matches names against patterns with <c>*</c> and <c>?</c>, ignoring case, in linear space.</summary>
/// <remarks>
/// No regular expression, so no pattern a person types can make matching slow: the classic
/// two-pointer match with one backtrack point, at worst the name's length times the pattern's.
/// </remarks>
internal static class Wildcard
{
    /// <summary>Whether a name matches a pattern.</summary>
    /// <param name="text">The name.</param>
    /// <param name="pattern">The pattern: <c>*</c> matches any run of characters, <c>?</c> any one.</param>
    /// <returns>True when the whole name matches the whole pattern.</returns>
    public static bool IsMatch(string text, string pattern)
    {
        int t = 0, p = 0, star = -1, resume = 0;

        while (t < text.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || Same(pattern[p], text[t])))
            {
                t++;
                p++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                resume = t;
            }
            else if (star >= 0)
            {
                p = star + 1;
                t = ++resume;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }

    private static bool Same(char left, char right) =>
        left == right || char.ToUpperInvariant(left) == char.ToUpperInvariant(right);
}
