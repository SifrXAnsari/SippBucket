using System.Globalization;
using SippBucket.Core.Crypto;
using SippBucket.Core.Machines;
using SippBucket.Core.Model;
using SippBucket.Core.Platform;
using SippBucket.Core.Push;
using SippBucket.Core.Repository;
using SippBucket.Core.Wiki;

namespace SippBucket.Cli;

/// <summary>
/// The wiki over a folder (T-01): <c>sip pages</c>, <c>sip search</c> and
/// <c>sip comments</c>. The pages are the folder's own Markdown files, opened in whatever
/// editor the owner likes; these commands are the map, the search and the margins.
/// </summary>
internal static class WikiCommands
{
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitUsage = 2;

    private const int MostHits = 20;

    /// <summary><c>sip pages [links &lt;page&gt;]</c>: the page tree, or one page's links.</summary>
    /// <param name="args">What followed <c>pages</c>.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> PagesAsync(string[] args)
    {
        using var repository = CommandLine.OpenFolder(Directory.GetCurrentDirectory());
        if (await HeadSnapshotAsync(repository).ConfigureAwait(false) is not { } head)
        {
            return Fail("No snapshots yet, so no pages are saved. 'sip save' records the folder.");
        }

        var index = await PageIndex.BuildAsync(repository, head.Snapshot).ConfigureAwait(false);

        if (args.Length == 0)
        {
            return Tree(index);
        }

        if (args.Length == 2 && string.Equals(args[0], "links", StringComparison.OrdinalIgnoreCase))
        {
            return Links(index, args[1]);
        }

        return Usage("sip pages | sip pages links <page>");
    }

    private static int Tree(WikiIndex index)
    {
        if (index.Pages.Count == 0)
        {
            Console.WriteLine("No pages: no saved .md files. A folder of Markdown files synced by");
            Console.WriteLine("SippBucket is a private wiki; this command is its map.");
            return ExitSuccess;
        }

        string? lastFolder = null;
        foreach (var page in index.Pages)
        {
            var slash = page.LastIndexOf('/');
            var folder = slash < 0 ? string.Empty : page[..slash];
            var name = slash < 0 ? page : page[(slash + 1)..];

            if (!string.Equals(folder, lastFolder, StringComparison.Ordinal))
            {
                lastFolder = folder;
                if (folder.Length > 0)
                {
                    Console.WriteLine($"{folder}/");
                }
            }

            var indent = folder.Length == 0 ? string.Empty : "  ";
            var outgoing = index.LinksFrom(page).Count(link => link.ResolvedPage is not null);
            var incoming = index.BacklinksTo(page).Count;
            var counts = outgoing + incoming == 0
                ? string.Empty
                : string.Create(CultureInfo.InvariantCulture, $"   ({outgoing} out, {incoming} in)");

            Console.WriteLine($"{indent}{name}{counts}");
        }

        Console.WriteLine();
        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"{index.Pages.Count} page(s), as of the newest save. 'sip pages links <page>' shows one's links."));
        return ExitSuccess;
    }

    private static int Links(WikiIndex index, string typed)
    {
        if (index.FindPage(typed) is not { } page)
        {
            return Fail($"No saved page is called '{DisplayText.Printable(typed, 260)}'. 'sip pages' lists them.");
        }

        Console.WriteLine(page);

        var links = index.LinksFrom(page);
        Console.WriteLine();
        if (links.Count == 0)
        {
            Console.WriteLine("Links out: none.");
        }
        else
        {
            Console.WriteLine("Links out:");
            foreach (var link in links)
            {
                Console.WriteLine(link.ResolvedPage is { } to
                    ? $"  {to}"
                    : $"  {DisplayText.Printable(link.Target, 200)}   (not a page here: outside, an asset, or still to be written)");
            }
        }

        var backlinks = index.BacklinksTo(page);
        Console.WriteLine();
        if (backlinks.Count == 0)
        {
            Console.WriteLine("Linked from: nothing yet.");
        }
        else
        {
            Console.WriteLine("Linked from:");
            foreach (var from in backlinks)
            {
                Console.WriteLine($"  {from}");
            }
        }

        return ExitSuccess;
    }

    /// <summary><c>sip search &lt;words&gt;</c>: find pages, here and only here.</summary>
    /// <param name="args">The words; all are required.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> SearchAsync(string[] args)
    {
        if (args.Length == 0)
        {
            return Usage("sip search <word>... - every word is required.");
        }

        using var repository = CommandLine.OpenFolder(Directory.GetCurrentDirectory());
        if (await HeadSnapshotAsync(repository).ConfigureAwait(false) is not { } head)
        {
            return Fail("No snapshots yet, so nothing is saved to search. 'sip save' records the folder.");
        }

        var index = await SearchIndex.BuildAsync(repository, head.Snapshot).ConfigureAwait(false);
        var hits = index.Find(string.Join(' ', args), MostHits);

        if (hits.Count == 0)
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"Nothing saved matches all of that, across {index.PageCount} page(s) and every file name."));
            return ExitSuccess;
        }

        foreach (var hit in hits)
        {
            Console.WriteLine(hit.LineNumber > 0
                ? $"{hit.Path}:{hit.LineNumber.ToString(CultureInfo.InvariantCulture)}: {hit.Line}"
                : $"{hit.Path}   (matched by name)");
        }

        Console.WriteLine();
        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"{hits.Count} file(s), best first, as of the newest save. The search ran here; nothing left this machine."));
        return ExitSuccess;
    }

    /// <summary><c>sip comments</c>: read, write and filter the margins of the pages.</summary>
    /// <param name="args">What followed <c>comments</c>.</param>
    /// <returns>The exit code.</returns>
    public static async Task<int> CommentsAsync(string[] args)
    {
        using var repository = CommandLine.OpenFolder(Directory.GetCurrentDirectory());
        var store = new CommentStore(repository.Layout.WorkingRoot);

        if (args.Length == 0)
        {
            return List(repository, store, page: null, mentioning: null);
        }

        switch (args[0].ToUpperInvariant())
        {
            case "ADD":
            {
                if (args.Length < 3)
                {
                    return Usage("sip comments add <page> <text>...");
                }

                var team = TeamFeatures
                    .ForThisUser(() => PairedMachines.AllDeviceIds(WatchedFolders.Load()))
                    .Decide();
                if (!team.On)
                {
                    return Fail(team.Why);
                }

                using var identity = DeviceIdentity.LoadOrCreate(AppPaths.DeviceKeyFile);
                var added = store.Add(
                    args[1], string.Join(' ', args[2..]), identity, DateTimeOffset.UtcNow);

                Console.WriteLine($"Commented on {added.Comment.Page}.");
                if (added.Mentions.Count > 0)
                {
                    Console.WriteLine($"Mentions: {string.Join(", ", added.Mentions.Select(m => "@" + m))}. " +
                        "They see it when the folder syncs to them; there is no other channel.");
                }

                Console.WriteLine("The comment is a file under .sip-comments and syncs like any other.");
                return ExitSuccess;
            }

            case "MENTIONS":
            {
                if (args.Length != 2)
                {
                    return Usage("sip comments mentions <name> - comments that say @<name>.");
                }

                return List(repository, store, page: null, mentioning: args[1]);
            }

            default:
                return args.Length == 1
                    ? List(repository, store, page: args[0], mentioning: null)
                    : Usage("sip comments [<page>] | add <page> <text>... | mentions <name>");
        }
    }

    private static int List(SipRepository repository, CommentStore store, string? page, string? mentioning)
    {
        IReadOnlyList<StoredComment> comments;
        int unreadable;
        try
        {
            comments = store.Load(page, out unreadable);
        }
        catch (ArgumentException ex)
        {
            return Fail(ex.Message);
        }

        if (mentioning is not null)
        {
            comments = [.. comments.Where(comment =>
                comment.Mentions.Any(name => string.Equals(name, mentioning, StringComparison.OrdinalIgnoreCase)))];
        }

        if (comments.Count == 0)
        {
            Console.WriteLine(mentioning is not null
                ? $"No comment mentions @{DisplayText.Printable(mentioning, 40)}."
                : page is not null
                    ? $"No comments on '{DisplayText.Printable(page, 260)}' yet."
                    : "No comments yet. 'sip comments add <page> <text>' writes one; it is a team feature.");
            return NoteUnreadable(unreadable);
        }

        var labels = DeviceNames.For(repository);
        foreach (var comment in comments)
        {
            var who = DeviceNames.Label(labels, comment.Comment.AuthorDeviceId);
            var when = comment.Comment.CreatedUtc.ToLocalTime()
                .ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
            var proof = comment.Verifies ? string.Empty : "  [signature DOES NOT VERIFY]";

            Console.WriteLine(page is null
                ? $"{when}  {who}  on {comment.Comment.Page}{proof}"
                : $"{when}  {who}{proof}");
            Console.WriteLine($"  {DisplayText.Printable(comment.Comment.Text, 2000)}");
        }

        Console.WriteLine();
        Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"{comments.Count} comment(s), oldest first."));
        return NoteUnreadable(unreadable);
    }

    private static int NoteUnreadable(int unreadable)
    {
        if (unreadable > 0)
        {
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"{unreadable} file(s) under .sip-comments are not comments this build reads; they were left alone."));
        }

        return ExitSuccess;
    }

    /// <summary>Head with its snapshot, or null before the first save.</summary>
    private static async Task<SaveResult?> HeadSnapshotAsync(SipRepository repository)
    {
        var head = repository.GetHead();
        if (head.IsEmpty)
        {
            return null;
        }

        var snapshot = await repository.GetSnapshotAsync(head).ConfigureAwait(false);
        return new SaveResult { SnapshotId = head, Snapshot = snapshot };
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"sip: {message}");
        return ExitFailure;
    }

    private static int Usage(string message)
    {
        Console.Error.WriteLine($"sip: {message}");
        return ExitUsage;
    }
}
