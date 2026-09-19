using System.Text.Json;
using SippBucket.Core.Serialization;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Platform;

/// <summary>
/// The list of repository folders the tray keeps in sync, stored per user so the daemon
/// picks up where it left off after a restart.
/// </summary>
/// <remarks>
/// <para>
/// Here in the core, beside the data directory it lives in, because the command line reads it
/// too: Direct Push is per machine, and a machine paired with any one of these folders is one
/// <c>sip push</c> may send to.
/// </para>
/// <para>
/// Another program's brief hold on <c>watched.json</c>, a scanner reading it just after it was
/// written or a backup tool, is waited out (D-69, <see cref="SharingRetry"/>). Before, a read
/// that met one failed with an <see cref="IOException"/> as the tray started.
/// </para>
/// <para>
/// A save is written beside the list and swapped in whole, so the list is always either the old
/// one or the new one. It used to be written in place, and a save cut short, by a crash or a
/// full disk, left a truncated file the next start could not parse.
/// </para>
/// <para>
/// The path-taking overloads are what the parameterless ones call, with the list in the data
/// directory; tests use them with a list of their own, because the data directory comes from
/// a process-wide environment variable.
/// </para>
/// </remarks>
public static class WatchedFolders
{
    /// <summary>The device key's file, in the data directory beside the list.</summary>
    /// <remarks>
    /// The same directory the command line uses, from the same definition, so the tray and the
    /// console it opens can never disagree about which device this is.
    /// </remarks>
    public static string DeviceKeyFile => Path.Combine(DataDirectory, "device.key");

    private static string DataDirectory => UserDataDirectory.Resolve();

    private static string ListFile => Path.Combine(DataDirectory, "watched.json");

    /// <summary>Reads this person's watch list.</summary>
    /// <returns>Every folder on it that still exists; empty when there is no list.</returns>
    public static IReadOnlyList<string> Load() => Load(ListFile);

    /// <summary>Replaces this person's watch list whole.</summary>
    /// <param name="folders">The folders it should hold.</param>
    public static void Save(IReadOnlyList<string> folders) => Save(ListFile, folders);

    /// <summary>Adds a folder to this person's watch list, if it is not already on it.</summary>
    /// <param name="folder">The folder.</param>
    public static void Add(string folder) => Add(ListFile, folder);

    /// <summary>Takes a folder off this person's watch list.</summary>
    /// <param name="folder">The folder.</param>
    public static void Remove(string folder) => Remove(ListFile, folder);

    /// <summary>Reads a watch list.</summary>
    /// <param name="listFile">The list.</param>
    /// <returns>Every folder on it that still exists; empty when there is no list.</returns>
    public static IReadOnlyList<string> Load(string listFile)
    {
        string json;
        try
        {
            json = SharingRetry.Run(() => File.ReadAllText(listFile));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return [];
        }

        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        var folders = JsonSerializer.Deserialize<List<string>>(json, SipJson.Readable) ?? [];

        // A folder can be moved or deleted between runs. Dropping the dead ones here keeps
        // the tray from failing on startup for a folder that is simply gone.
        return folders.Where(Directory.Exists).ToList();
    }

    /// <summary>Replaces a watch list whole.</summary>
    /// <param name="listFile">The list.</param>
    /// <param name="folders">The folders it should hold.</param>
    /// <exception cref="ArgumentException">The list's path has no directory.</exception>
    public static void Save(string listFile, IReadOnlyList<string> folders)
    {
        var directory = Path.GetDirectoryName(listFile)
            ?? throw new ArgumentException("The list has no directory.", nameof(listFile));
        Directory.CreateDirectory(directory);

        var temporary = $"{listFile}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(folders, SipJson.Readable));

            // ReplaceFile over an existing list, as master.json is replaced: a reader that
            // shares only reading and writing makes it fail with a sharing violation, which is
            // waited out. A plain move over the list fails against that reader with access
            // denied instead, which cannot be told from a list this account may not write.
            if (File.Exists(listFile))
            {
                SharingRetry.Run(() => File.Replace(temporary, listFile, destinationBackupFileName: null));
            }
            else
            {
                SharingRetry.Run(() => File.Move(temporary, listFile));
            }
        }
        finally
        {
            if (File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }
    }

    /// <summary>Adds a folder to a watch list, if it is not already on it.</summary>
    /// <param name="listFile">The list.</param>
    /// <param name="folder">The folder.</param>
    public static void Add(string listFile, string folder)
    {
        var folders = Load(listFile).ToList();
        if (folders.Any(f => string.Equals(f, folder, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        folders.Add(folder);
        Save(listFile, folders);
    }

    /// <summary>Takes a folder off a watch list.</summary>
    /// <param name="listFile">The list.</param>
    /// <param name="folder">The folder.</param>
    public static void Remove(string listFile, string folder)
    {
        var folders = Load(listFile)
            .Where(f => !string.Equals(f, folder, StringComparison.OrdinalIgnoreCase))
            .ToList();
        Save(listFile, folders);
    }
}
