using System.Globalization;
using System.Text;
using SippBucket.Core.Crypto;
using SippBucket.Core.Model;
using SippBucket.Core.Repository;
using SippBucket.Core.Storage;
using SippBucket.Core.Text;

namespace SippBucket.Core.Wiki;

/// <summary>One file a search found.</summary>
public sealed record SearchHit
{
    /// <summary>The file, folder-relative.</summary>
    public required string Path { get; init; }

    /// <summary>How strongly it matched: occurrences, with the file's own name counting extra.</summary>
    public required int Score { get; init; }

    /// <summary>
    /// The first line holding a searched word, trimmed; empty when only the name matched.
    /// </summary>
    public required string Line { get; init; }

    /// <summary>One-based line of <see cref="Line"/>, or 0 when only the name matched.</summary>
    public required int LineNumber { get; init; }
}

/// <summary>
/// Search across one snapshot's files, run here and only here (T-01): an inverted index in
/// the engine, built from the store, sent nowhere.
/// </summary>
/// <remarks>
/// <para>
/// Words are runs of letters and digits, two characters or longer, compared lower-case.
/// Page content — Markdown and plain text up to 8 MiB — is indexed line by line; every
/// file's own name is indexed too, with extra weight, which is what makes a Word document
/// findable by what it is called even though its bytes are not read. A query is every word
/// it holds, all required.
/// </para>
/// <para>
/// The index is built from a snapshot, so what is saved is what is found; the daemon saves
/// as you work, and every machine at the same head finds the same things.
/// </para>
/// </remarks>
public sealed class SearchIndex
{
    /// <summary>The most bytes of one file that are read for content.</summary>
    public const long LargestIndexedFile = 8 * 1024 * 1024;

    /// <summary>What a match in the file's own name counts for, against 1 per content hit.</summary>
    private const int NameWeight = 5;

    private const int ShortestWord = 2;
    private const int LongestWord = 64;
    private const int LongestSnippet = 200;

    private readonly Dictionary<string, Dictionary<string, Posting>> _postings;

    private SearchIndex(Dictionary<string, Dictionary<string, Posting>> postings, int files, int pages)
    {
        _postings = postings;
        FileCount = files;
        PageCount = pages;
    }

    /// <summary>How many files the index covers by name.</summary>
    public int FileCount { get; }

    /// <summary>How many of them were read as pages, content and all.</summary>
    public int PageCount { get; }

    /// <summary>Builds the index over one snapshot.</summary>
    /// <param name="repository">The repository the pages' blocks are read from.</param>
    /// <param name="snapshot">The snapshot, usually head.</param>
    /// <param name="cancellationToken">Cancels the build.</param>
    /// <returns>The index.</returns>
    /// <exception cref="ArgumentNullException">An argument was null.</exception>
    public static async Task<SearchIndex> BuildAsync(
        SipRepository repository,
        Snapshot snapshot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(snapshot);

        var postings = new Dictionary<string, Dictionary<string, Posting>>(StringComparer.Ordinal);
        var pages = 0;

        foreach (var file in snapshot.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var word in WordsOf(file.Path))
            {
                Count(postings, word, file.Path, NameWeight, line: null, lineNumber: 0);
            }

            if (!IsIndexedContent(file.Path) || file.Size > LargestIndexedFile)
            {
                continue;
            }

            byte[] bytes;
            try
            {
                bytes = await repository.ReadFileAsync(file, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is BlockNotFoundException or CorruptBlockException)
            {
                continue;
            }

            if (LineDiff.LooksBinary(bytes))
            {
                continue;
            }

            pages++;
            var number = 0;
            foreach (var rawLine in Encoding.UTF8.GetString(bytes).Split('\n'))
            {
                number++;
                var line = rawLine.TrimEnd('\r');
                foreach (var word in WordsOf(line))
                {
                    Count(postings, word, file.Path, 1, line, number);
                }
            }
        }

        return new SearchIndex(postings, snapshot.Files.Count, pages);
    }

    /// <summary>Finds the files holding every one of the words.</summary>
    /// <param name="query">What was typed; every word in it is required.</param>
    /// <param name="limit">The most hits returned.</param>
    /// <returns>Hits, strongest first, then by path. Empty when the query holds no words.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="query"/> was null.</exception>
    public IReadOnlyList<SearchHit> Find(string query, int limit)
    {
        ArgumentNullException.ThrowIfNull(query);

        var words = WordsOf(query).Distinct(StringComparer.Ordinal).ToList();
        if (words.Count == 0)
        {
            return [];
        }

        Dictionary<string, int>? scores = null;
        foreach (var word in words)
        {
            if (!_postings.TryGetValue(word, out var files))
            {
                return [];
            }

            if (scores is null)
            {
                scores = files.ToDictionary(pair => pair.Key, pair => pair.Value.Count, StringComparer.Ordinal);
                continue;
            }

            foreach (var path in scores.Keys.ToList())
            {
                if (files.TryGetValue(path, out var posting))
                {
                    scores[path] += posting.Count;
                }
                else
                {
                    _ = scores.Remove(path);
                }
            }
        }

        return scores is null
            ? []
            : [.. scores
                .OrderByDescending(pair => pair.Value)
                .ThenBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Take(Math.Max(1, limit))
                .Select(pair => Hit(pair.Key, pair.Value, words))];
    }

    private SearchHit Hit(string path, int score, IReadOnlyList<string> words)
    {
        foreach (var word in words)
        {
            if (_postings[word].TryGetValue(path, out var posting) && posting.Line is not null)
            {
                return new SearchHit
                {
                    Path = path,
                    Score = score,
                    Line = posting.Line,
                    LineNumber = posting.LineNumber,
                };
            }
        }

        return new SearchHit { Path = path, Score = score, Line = string.Empty, LineNumber = 0 };
    }

    private static void Count(
        Dictionary<string, Dictionary<string, Posting>> postings,
        string word,
        string path,
        int weight,
        string? line,
        int lineNumber)
    {
        if (!postings.TryGetValue(word, out var files))
        {
            files = new Dictionary<string, Posting>(StringComparer.Ordinal);
            postings[word] = files;
        }

        if (!files.TryGetValue(path, out var posting))
        {
            posting = new Posting();
            files[path] = posting;
        }

        posting.Count += weight;
        if (posting.Line is null && line is not null)
        {
            var trimmed = line.Trim();
            posting.Line = trimmed.Length > LongestSnippet ? trimmed[..LongestSnippet] : trimmed;
            posting.LineNumber = lineNumber;
        }
    }

    /// <summary>Whether a file's bytes are read for the index, beside its name.</summary>
    private static bool IsIndexedContent(string path)
    {
        var extension = System.IO.Path.GetExtension(path);
        return string.Equals(extension, ".md", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(extension, ".markdown", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(extension, ".txt", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The words of one piece of text, lower-cased: runs of letters and digits, one-character
    /// runs dropped, runs past 64 kept as their first 64 — queries are cut the same way, so
    /// the two sides always agree.
    /// </summary>
    private static IEnumerable<string> WordsOf(string text)
    {
        var word = new StringBuilder();
        foreach (var character in text)
        {
            if (char.IsLetterOrDigit(character))
            {
                if (word.Length < LongestWord)
                {
                    _ = word.Append(char.ToLower(character, CultureInfo.InvariantCulture));
                }

                continue;
            }

            if (word.Length >= ShortestWord)
            {
                yield return word.ToString();
            }

            _ = word.Clear();
        }

        if (word.Length >= ShortestWord)
        {
            yield return word.ToString();
        }
    }

    private sealed class Posting
    {
        public int Count { get; set; }

        public string? Line { get; set; }

        public int LineNumber { get; set; }
    }
}
