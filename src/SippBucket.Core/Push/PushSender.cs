using System.Buffers;
using System.Globalization;
using NSec.Cryptography;
using SippBucket.Core.Crypto;
using SippBucket.Core.Hashing;
using SippBucket.Core.Push.Ssh;

namespace SippBucket.Core.Push;

/// <summary>The machine a push goes to, as this machine's pairing records know it.</summary>
/// <param name="Name">The name this machine knows it by, for messages.</param>
/// <param name="DeviceId">Its device ID: the only host key accepted.</param>
/// <param name="Host">Its address or name.</param>
/// <param name="Port">Its Direct Push port.</param>
public sealed record PushTarget(string Name, string DeviceId, string Host, int Port);

/// <summary>One file ready to be offered: where it is, what it is called, and what it is.</summary>
/// <param name="Path">Where it is on this machine.</param>
/// <param name="Name">The name it is offered under: its own.</param>
/// <param name="Size">Its length when it was read.</param>
/// <param name="Hash">The BLAKE2b-256 of its content when it was read.</param>
/// <param name="Check">What this machine's content check made of it.</param>
public sealed record PushFile(string Path, string Name, long Size, ContentHash Hash, ContentCheckResult Check)
{
    /// <summary>
    /// Whether the receiving machine's content check will very likely put it in quarantine. This
    /// machine's check only warns: the receiving machine decides.
    /// </summary>
    public bool WillBeQuarantined => Check.Verdict == ContentVerdict.Quarantine;
}

/// <summary>A path that cannot be sent, and why.</summary>
/// <param name="Path">The path as given.</param>
/// <param name="Reason">Why it cannot be sent.</param>
public sealed record PushPlanProblem(string Path, string Reason);

/// <summary>What a push will send, and what it cannot.</summary>
/// <param name="Files">The files, in the order given.</param>
/// <param name="Problems">The paths that cannot be sent.</param>
public sealed record PushPlan(IReadOnlyList<PushFile> Files, IReadOnlyList<PushPlanProblem> Problems)
{
    /// <summary>The total length of the files, in bytes.</summary>
    public long TotalBytes => Files.Sum(file => file.Size);
}

/// <summary>How far a push has got.</summary>
/// <param name="Name">The file being sent.</param>
/// <param name="BytesSent">How much of the whole push has been sent.</param>
/// <param name="BytesTotal">How much the whole push will send, counting only files the receiving machine accepted.</param>
public sealed record PushProgress(string Name, long BytesSent, long BytesTotal);

/// <summary>What became of one file.</summary>
/// <param name="File">The file.</param>
/// <param name="Outcome">Where it ended up on the receiving machine.</param>
/// <param name="Quarantine">Why it is in quarantine there, when it is.</param>
/// <param name="Refusal">Why it was not kept, when it was not.</param>
/// <param name="DetectedType">What the receiving machine found it to be, when it received it.</param>
public sealed record PushFileResult(
    PushFile File,
    FileOutcome Outcome,
    QuarantineReason Quarantine,
    FileRefusal Refusal,
    uint DetectedType);

/// <summary>What became of one batch.</summary>
/// <param name="Refusal">Why the whole batch was refused, or <see cref="BatchRefusal.None"/>.</param>
/// <param name="Detail">The receiving machine's sentence, when it refused the batch.</param>
/// <param name="Files">What became of each file, in order; empty when the batch was refused.</param>
public sealed record PushBatchResult(BatchRefusal Refusal, string Detail, IReadOnlyList<PushFileResult> Files);

/// <summary>
/// The sending side of Direct Push: reads what is to be sent, warns about what the receiving
/// machine will quarantine, and delivers it in batches over one connection each
/// (docs/DIRECT-PUSH.md, rules 4 and 6).
/// </summary>
/// <remarks>
/// <para>
/// <b>Its own check only warns.</b> Each file is read once before it is offered, for its hash and
/// for the content check, which runs here too, "only to save a wasted transfer, because a sender
/// cannot be trusted to police itself" (rule 4). A file it expects the receiving machine to
/// quarantine is marked, so the person can think again before sending; the receiving machine's
/// decision is the one that counts.
/// </para>
/// <para>
/// <b>Fast by design</b> (rule 6): one connection for each batch, the files the receiving machine
/// accepted streamed back to back with no round trip between them. Its receipts wait in the
/// channel while the files go and are read once the last byte is sent: they are small, and a
/// receipt can only follow a file's last byte, so reading them sooner would only mean waiting
/// through a large file's transfer with nothing owed. A selection larger than
/// <see cref="PushWire.MaximumFiles"/> goes as several batches, one after another.
/// </para>
/// <para>
/// A file that changes between being read and being sent does not arrive: the receiving machine
/// finds it does not hash to what was offered and refuses it. One that gets shorter part way
/// stops the batch, because the rest of the channel would no longer line up.
/// </para>
/// </remarks>
public static class PushSender
{
    private const int CopyBuffer = 256 * 1024;

    /// <summary>Reads what is to be sent: each file's name, size, hash, and what the content check makes of it.</summary>
    /// <param name="paths">The files, in the order they should go.</param>
    /// <param name="cancellationToken">Stops reading.</param>
    /// <returns>The files that can be sent, and why any others cannot.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="paths"/> was null.</exception>
    public static async Task<PushPlan> PlanAsync(IEnumerable<string> paths, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(paths);

        var files = new List<PushFile>();
        var problems = new List<PushPlanProblem>();

        foreach (var path in paths)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                problems.Add(new PushPlanProblem(path ?? string.Empty, "no path was given"));
                continue;
            }

            var full = Path.GetFullPath(path);
            if (Directory.Exists(full))
            {
                problems.Add(new PushPlanProblem(path, "it is a folder; Direct Push sends files"));
                continue;
            }

            var name = Path.GetFileName(full);
            if (!PushName.IsAcceptable(name, out var reason))
            {
                problems.Add(new PushPlanProblem(path, $"its name cannot be sent as it is: {reason}"));
                continue;
            }

            try
            {
                files.Add(await ReadAsync(full, name, cancellationToken).ConfigureAwait(false));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                problems.Add(new PushPlanProblem(path, ex is FileNotFoundException ? "there is no such file" : ex.Message));
            }
        }

        return new PushPlan(files, problems);
    }

    /// <summary>Sends every file in a plan to one machine, in batches.</summary>
    /// <param name="identity">This machine's identity. Borrowed.</param>
    /// <param name="target">The machine to send to.</param>
    /// <param name="files">The files, from <see cref="PlanAsync"/>.</param>
    /// <param name="tuning">The deadlines, or null for the defaults.</param>
    /// <param name="progress">Told how far the push has got, or null.</param>
    /// <param name="onFile">Told what became of each file as its receipt arrives, or null.</param>
    /// <param name="cancellationToken">Stops sending; the batch in progress stops where it is.</param>
    /// <returns>What became of each batch, in order. A batch refused whole stops the push there.</returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="PushException">The connection could not be made, was refused, or failed part way.</exception>
    /// <exception cref="Protocol.PeerStalledException">The receiving machine stopped making progress.</exception>
    /// <exception cref="IOException">A file could not be read while it was being sent.</exception>
    public static async Task<IReadOnlyList<PushBatchResult>> SendAsync(
        DeviceIdentity identity,
        PushTarget target,
        IReadOnlyList<PushFile> files,
        PushTuning? tuning,
        IProgress<PushProgress>? progress,
        Action<PushFileResult>? onFile,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(files);

        var chosen = tuning ?? PushTuning.Default;
        var results = new List<PushBatchResult>();

        foreach (var batch in files.Chunk(PushWire.MaximumFiles))
        {
            var result = await SendBatchAsync(identity, target, batch, chosen, progress, onFile, cancellationToken).ConfigureAwait(false);
            results.Add(result);

            if (result.Refusal != BatchRefusal.None)
            {
                break;
            }
        }

        return results;
    }

    private static async Task<PushFile> ReadAsync(string path, string name, CancellationToken cancellationToken)
    {
        IncrementalHash.Initialize(HashAlgorithm.Blake2b_256, out var state);
        var buffer = ArrayPool<byte>.Shared.Rent(CopyBuffer);

        try
        {
            var input = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 1, FileOptions.Asynchronous | FileOptions.SequentialScan);

            await using (input.ConfigureAwait(false))
            {
                var head = new byte[(int)Math.Min(ContentCheck.HeadBytes, input.Length)];
                long size = 0;

                while (true)
                {
                    var read = await input.ReadAsync(buffer.AsMemory(0, CopyBuffer), cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    IncrementalHash.Update(ref state, buffer.AsSpan(0, read));

                    if (size < head.Length)
                    {
                        var kept = (int)Math.Min(read, head.Length - size);
                        buffer.AsSpan(0, kept).CopyTo(head.AsSpan((int)size));
                    }

                    size += read;
                }

                var digest = new byte[ContentHash.SizeInBytes];
                IncrementalHash.Finalize(ref state, digest);

                // Judged on what was read, which is what will be offered.
                var check = ContentCheck.Check(head.AsSpan(0, (int)Math.Min(head.Length, size)), size, name);
                return new PushFile(path, name, size, new ContentHash(digest), check);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task<PushBatchResult> SendBatchAsync(
        DeviceIdentity identity,
        PushTarget target,
        PushFile[] files,
        PushTuning tuning,
        IProgress<PushProgress>? progress,
        Action<PushFileResult>? onFile,
        CancellationToken cancellationToken)
    {
        var link = await PushLink.ConnectAsync(identity, target.Host, target.Port, target.DeviceId, tuning, cancellationToken)
            .ConfigureAwait(false);

        await using (link.ConfigureAwait(false))
        {
            var channel = link.Channel;
            var stall = tuning.StallTimeout;

            await PushWire.WriteAsync(channel, new PushOffer(PushWire.Version, Guid.NewGuid(), files.Length), stall, cancellationToken)
                .ConfigureAwait(false);
            for (var index = 0; index < files.Length; index++)
            {
                var file = files[index];
                await PushWire.WriteAsync(channel, new PushFileOffer(index, file.Name, file.Size, file.Hash), stall, cancellationToken)
                    .ConfigureAwait(false);
            }

            var answer = await PushWire.ReadAsync(channel, stall, cancellationToken).ConfigureAwait(false) as PushAnswer
                ?? throw new PushException(PushFault.UnexpectedMessage, $"{target.Name} did not answer the offer.");

            if (answer.Refusal != BatchRefusal.None)
            {
                return new PushBatchResult(answer.Refusal, answer.Detail, []);
            }

            if (answer.Version != PushWire.Version || answer.Files.Count != files.Length)
            {
                throw new PushException(
                    PushFault.UnexpectedMessage,
                    $"{target.Name} answered an offer of {files.Length} files with decisions for {answer.Files.Count}.");
            }

            var results = new PushFileResult?[files.Length];
            var accepted = new List<int>();
            for (var index = 0; index < files.Length; index++)
            {
                if (answer.Files[index] == FileRefusal.None)
                {
                    accepted.Add(index);
                }
                else
                {
                    results[index] = new PushFileResult(files[index], FileOutcome.Refused, QuarantineReason.None, answer.Files[index], 0);
                    onFile?.Invoke(results[index]!);
                }
            }

            // The receipts wait in the channel while the files go: at most a few dozen bytes each,
            // well inside its window, so the receiving machine never waits on this side to read.
            await SendContentsAsync(channel, files, accepted, progress, cancellationToken).ConfigureAwait(false);
            await ReadReceiptsAsync(channel, files, accepted, results, stall, onFile, target.Name, cancellationToken)
                .ConfigureAwait(false);

            return new PushBatchResult(BatchRefusal.None, string.Empty, [.. results.Select(result => result!)]);
        }
    }

    private static async Task SendContentsAsync(
        Stream channel,
        PushFile[] files,
        List<int> accepted,
        IProgress<PushProgress>? progress,
        CancellationToken cancellationToken)
    {
        var total = accepted.Sum(index => files[index].Size);
        long sent = 0;
        var buffer = ArrayPool<byte>.Shared.Rent(CopyBuffer);

        try
        {
            foreach (var index in accepted)
            {
                var file = files[index];
                progress?.Report(new PushProgress(file.Name, sent, total));

                var input = new FileStream(
                    file.Path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 1, FileOptions.Asynchronous | FileOptions.SequentialScan);

                await using (input.ConfigureAwait(false))
                {
                    long remaining = file.Size;
                    while (remaining > 0)
                    {
                        var wanted = (int)Math.Min(CopyBuffer, remaining);
                        var read = await input.ReadAsync(buffer.AsMemory(0, wanted), cancellationToken).ConfigureAwait(false);
                        if (read == 0)
                        {
                            throw new IOException(string.Create(
                                CultureInfo.InvariantCulture,
                                $"'{file.Name}' got shorter while it was being sent ({file.Size - remaining} of {file.Size} bytes), so the rest of this batch was stopped."));
                        }

                        await channel.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                        remaining -= read;
                        sent += read;
                        progress?.Report(new PushProgress(file.Name, sent, total));
                    }
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task ReadReceiptsAsync(
        Stream channel,
        PushFile[] files,
        List<int> accepted,
        PushFileResult?[] results,
        TimeSpan stall,
        Action<PushFileResult>? onFile,
        string targetName,
        CancellationToken cancellationToken)
    {
        foreach (var expected in accepted)
        {
            var message = await PushWire.ReadAsync(channel, stall, cancellationToken).ConfigureAwait(false);
            if (message is not PushFileReceipt receipt || receipt.Index != expected)
            {
                throw new PushException(
                    PushFault.UnexpectedMessage,
                    string.Create(CultureInfo.InvariantCulture, $"{targetName} sent something other than the receipt for file {expected}."));
            }

            results[expected] = new PushFileResult(files[expected], receipt.Outcome, receipt.Quarantine, receipt.Refusal, receipt.DetectedType);
            onFile?.Invoke(results[expected]!);
        }

        if (await PushWire.ReadAsync(channel, stall, cancellationToken).ConfigureAwait(false) is not PushBatchReceipt)
        {
            throw new PushException(PushFault.UnexpectedMessage, $"{targetName} did not end the batch with its receipt.");
        }
    }
}
