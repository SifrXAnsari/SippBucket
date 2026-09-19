using System.Buffers;
using System.Text;
using System.Text.Json;
using SippBucket.Core.Storage;

namespace SippBucket.Core.Configuration;

/// <summary>
/// Writes one setting into <c>master.json</c>, for <c>sip config set</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>What a write keeps.</b> Everything else in the file: other settings, keys this build
/// does not know (a newer build's file must survive an older build's <c>set</c>), and comments,
/// because the file exists to be annotated. The file is re-read token by token and written
/// back with only the one value changed; layout is normalised to indented JSON, and a line
/// comment comes back as a block comment with the same text.
/// </para>
/// <para>
/// <b>What a write refuses.</b> A value outside the setting's limits, which would only be
/// ignored on the next read; and a file that is not valid JSON, which is left exactly as it
/// is rather than overwritten, since it is somebody's hand edit. With administrator rights it
/// also refuses a folder or file that is a link to somewhere else, or that an account other
/// than an administrator made (<see cref="UntrustedLocationException"/>), before reading
/// anything.
/// </para>
/// <para>
/// <b>How it lands.</b> Written beside the file, then swapped in whole: <c>ReplaceFile</c>
/// when a file is already there, which preserves the replaced file's DACL, the permissions the
/// installer gives it (ReplaceFileW, Remarks:
/// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew), and a
/// plain rename when there is none. A reader sees the old file or the new one, never half of
/// either. The result carries the hidden attribute, set explicitly every time rather than
/// trusted to survive the swap. Writing in place would be the wrong way round for a hidden
/// file in any case: CreateFile with <c>CREATE_ALWAYS</c> "fails and sets the last error to
/// ERROR_ACCESS_DENIED if the file exists and has the FILE_ATTRIBUTE_HIDDEN ... attribute"
/// unless the same attributes are passed (CreateFileW:
/// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), which is
/// what <see cref="File.WriteAllText(string, string?)"/> would have run into on the second
/// write.
/// </para>
/// </remarks>
public static class MasterConfigWriter
{
    /// <summary>
    /// Sets one setting in the file at <paramref name="path"/>, creating the file if needed,
    /// as a process without administrator rights.
    /// </summary>
    /// <param name="path">The file.</param>
    /// <param name="setting">The setting.</param>
    /// <param name="value">Its new value, within the setting's limits.</param>
    /// <exception cref="ArgumentOutOfRangeException">The value is outside the setting's limits.</exception>
    /// <exception cref="FormatException">The existing file is not valid JSON; it was not changed.</exception>
    /// <exception cref="IOException">The file could not be written.</exception>
    /// <exception cref="UnauthorizedAccessException">This process may not write it.</exception>
    public static void Set(string path, MasterSetting setting, int value) =>
        Set(path, setting, value, writingAsAdministrator: false);

    /// <summary>Sets one setting in the file at <paramref name="path"/>, creating the file if needed.</summary>
    /// <param name="path">The file.</param>
    /// <param name="setting">The setting.</param>
    /// <param name="value">Its new value, within the setting's limits.</param>
    /// <param name="writingAsAdministrator">
    /// True when this process has administrator rights, as the elevated copy <c>sip config set</c>
    /// starts does. The folder and the file are then checked first, and refused if they are a
    /// link to somewhere else or were made by an account that is not an administrator
    /// (<see cref="UntrustedLocationException"/>): an administrator's rights must never write
    /// through a location a standard account could have prepared.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">The value is outside the setting's limits.</exception>
    /// <exception cref="FormatException">The existing file is not valid JSON; it was not changed.</exception>
    /// <exception cref="IOException">The file could not be written.</exception>
    /// <exception cref="UnauthorizedAccessException">
    /// This process may not write it, or, as <see cref="UntrustedLocationException"/>, its
    /// location was refused; nothing was written.
    /// </exception>
    public static void Set(string path, MasterSetting setting, int value, bool writingAsAdministrator)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(setting);

        if (value < setting.Minimum || value > setting.Maximum)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value), value, $"{setting.Key} must be {setting.DescribeLimits()}.");
        }

        if (writingAsAdministrator)
        {
            // Before anything is read, not only before the write: reading the file through a
            // junction with administrator rights and copying it into master.json would hand
            // its contents to whoever made the junction.
            var directory = Path.GetDirectoryName(path)
                ?? throw new ArgumentException("The path has no directory.", nameof(path));
            Directory.CreateDirectory(directory);
            MasterConfigLocation.Check(directory, path);
        }

        string? existing;
        try
        {
            existing = SharingRetry.Run(() =>
            {
                using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(file);
                return reader.ReadToEnd();
            });
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            existing = null;
        }

        WriteAtomically(path, Rewrite(existing, setting, value));
    }

    /// <summary>
    /// Decides how <c>sip config set</c> may write the file from this process.
    /// </summary>
    /// <param name="locationOverridden">
    /// True when <c>SIPPBUCKET_DATA_DIR</c> points the file at a sandbox, which needs no
    /// administrator rights.
    /// </param>
    /// <param name="processIsElevated">True when this process already runs elevated.</param>
    /// <param name="isElevatedRelaunch">True when this process is the elevated copy started to do the write.</param>
    /// <returns>How to write.</returns>
    /// <remarks>
    /// A pure function so the decision can be tested without anybody being elevated. The one
    /// case that must never happen is a loop: a relaunch that comes back still not elevated,
    /// because UAC is off or the account is not an administrator, is refused rather than
    /// relaunched again.
    /// </remarks>
    public static ConfigWriteRoute Route(bool locationOverridden, bool processIsElevated, bool isElevatedRelaunch)
    {
        if (locationOverridden || processIsElevated)
        {
            return ConfigWriteRoute.WriteHere;
        }

        return isElevatedRelaunch ? ConfigWriteRoute.Refuse : ConfigWriteRoute.RelaunchElevated;
    }

    /// <summary>The file's new text: <paramref name="existing"/> with one value set.</summary>
    /// <param name="existing">The file's current text, or null when there is no file.</param>
    /// <param name="setting">The setting.</param>
    /// <param name="value">Its new value.</param>
    /// <returns>UTF-8 bytes to write.</returns>
    /// <exception cref="FormatException"><paramref name="existing"/> is not valid JSON, or not an object.</exception>
    internal static byte[] Rewrite(string? existing, MasterSetting setting, int value)
    {
        var output = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(output, new JsonWriterOptions { Indented = true }))
        {
            if (string.IsNullOrWhiteSpace(existing))
            {
                writer.WriteStartObject();
                writer.WriteNumber("schema", MasterConfig.CurrentSchema);
                WriteSection(writer, setting, value);
                writer.WriteEndObject();
            }
            else
            {
                try
                {
                    Copy(Encoding.UTF8.GetBytes(existing), writer, setting, value);
                }
                catch (Exception ex) when (ex is JsonException or InvalidOperationException)
                {
                    // InvalidOperationException is the writer refusing a shape the reader
                    // accepted, such as a comment where the output cannot hold one. Either
                    // way the file is not rewritten by guesswork.
                    throw new FormatException(
                        $"{MasterConfig.FileName} could not be copied ({ex.Message}). It was left exactly as it " +
                        "is; fix it or delete it, then try again.",
                        ex);
                }
            }
        }

        return output.WrittenSpan.ToArray();
    }

    /// <summary>Copies the document, replacing or adding the one setting.</summary>
    private static void Copy(byte[] existing, Utf8JsonWriter writer, MasterSetting setting, int value)
    {
        var reader = new Utf8JsonReader(existing, new JsonReaderOptions
        {
            CommentHandling = JsonCommentHandling.Allow,
            AllowTrailingCommas = true,
            MaxDepth = 16,
        });

        var written = false;
        var sawSchema = false;
        var inTargetSection = false;

        // A comment between a property name and its value has nowhere to go in the output
        // until the value is written, so it is held and written after it.
        var held = new List<string>();
        var afterName = false;

        if (!reader.Read())
        {
            throw new FormatException($"{MasterConfig.FileName} is empty of JSON.");
        }

        while (reader.TokenType == JsonTokenType.Comment)
        {
            writer.WriteCommentValue(SafeComment(reader.GetComment()));
            if (!reader.Read())
            {
                throw new FormatException($"{MasterConfig.FileName} holds only comments.");
            }
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new FormatException($"{MasterConfig.FileName} is not a JSON object.");
        }

        writer.WriteStartObject();

        while (reader.Read())
        {
            var depth = reader.CurrentDepth;

            switch (reader.TokenType)
            {
                case JsonTokenType.Comment:
                    if (afterName)
                    {
                        held.Add(SafeComment(reader.GetComment()));
                    }
                    else
                    {
                        writer.WriteCommentValue(SafeComment(reader.GetComment()));
                    }

                    continue;

                case JsonTokenType.PropertyName:
                {
                    var name = reader.GetString()!;

                    if (depth == 1 && string.Equals(name, "schema", StringComparison.OrdinalIgnoreCase))
                    {
                        sawSchema = true;
                    }

                    if (depth == 1 && string.Equals(name, setting.Section, StringComparison.OrdinalIgnoreCase))
                    {
                        Next(ref reader, held);
                        if (reader.TokenType == JsonTokenType.StartObject)
                        {
                            writer.WritePropertyName(name);
                            writer.WriteStartObject();
                            Flush(writer, held);
                            inTargetSection = true;
                        }
                        else
                        {
                            // Not an object, so none of its settings were being read anyway:
                            // replaced by a section holding the one setting being set.
                            reader.Skip();
                            WriteSection(writer, setting, value);
                            Flush(writer, held);
                            written = true;
                        }

                        continue;
                    }

                    if (depth == 2 && inTargetSection && string.Equals(name, setting.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        Next(ref reader, held);
                        reader.Skip();
                        writer.WriteNumber(setting.Name, value);
                        Flush(writer, held);
                        written = true;
                        continue;
                    }

                    writer.WritePropertyName(name);
                    afterName = true;
                    continue;
                }

                case JsonTokenType.StartObject:
                    writer.WriteStartObject();
                    break;

                case JsonTokenType.StartArray:
                    writer.WriteStartArray();
                    break;

                case JsonTokenType.EndArray:
                    writer.WriteEndArray();
                    break;

                case JsonTokenType.EndObject:
                    if (depth == 1 && inTargetSection)
                    {
                        if (!written)
                        {
                            writer.WriteNumber(setting.Name, value);
                            written = true;
                        }

                        inTargetSection = false;
                    }

                    if (depth == 0)
                    {
                        if (!sawSchema)
                        {
                            writer.WriteNumber("schema", MasterConfig.CurrentSchema);
                        }

                        if (!written)
                        {
                            WriteSection(writer, setting, value);
                            written = true;
                        }
                    }

                    writer.WriteEndObject();
                    break;

                case JsonTokenType.String:
                    writer.WriteStringValue(reader.GetString());
                    break;

                case JsonTokenType.Number:
                    // The number's own text, so 3.0 stays 3.0 and a value this build would
                    // fall back on is kept for the person to see, not rewritten into another.
                    writer.WriteRawValue(reader.ValueSpan, skipInputValidation: false);
                    break;

                case JsonTokenType.True:
                case JsonTokenType.False:
                    writer.WriteBooleanValue(reader.GetBoolean());
                    break;

                case JsonTokenType.Null:
                    writer.WriteNullValue();
                    break;

                default:
                    throw new FormatException($"{MasterConfig.FileName} holds a token this build cannot copy.");
            }

            afterName = false;
            Flush(writer, held);
        }
    }

    /// <summary>Moves to the value after a property name, holding any comments on the way.</summary>
    private static void Next(ref Utf8JsonReader reader, List<string> held)
    {
        while (reader.Read())
        {
            if (reader.TokenType != JsonTokenType.Comment)
            {
                return;
            }

            held.Add(SafeComment(reader.GetComment()));
        }

        throw new FormatException($"{MasterConfig.FileName} ends after a property name.");
    }

    private static void Flush(Utf8JsonWriter writer, List<string> held)
    {
        foreach (var comment in held)
        {
            writer.WriteCommentValue(comment);
        }

        held.Clear();
    }

    private static void WriteSection(Utf8JsonWriter writer, MasterSetting setting, int value)
    {
        writer.WriteStartObject(setting.Section);
        writer.WriteNumber(setting.Name, value);
        writer.WriteEndObject();
    }

    /// <summary>
    /// A comment's text made safe to write as a block comment, which cannot contain its own
    /// terminator.
    /// </summary>
    private static string SafeComment(string text) =>
        text.Replace("*/", "* /", StringComparison.Ordinal);

    private static void WriteAtomically(string path, byte[] bytes)
    {
        var directory = Path.GetDirectoryName(path)
            ?? throw new ArgumentException("The path has no directory.", nameof(path));
        Directory.CreateDirectory(directory);

        var temporary = Path.Combine(directory, $"{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            // Another program's brief hold on the file, such as the tray reading it at the same
            // moment or a scanner, is waited out (D-69).
            if (File.Exists(path))
            {
                SharingRetry.Run(() => File.Replace(temporary, path, destinationBackupFileName: null));
            }
            else
            {
                SharingRetry.Run(() => File.Move(temporary, path));
            }

            File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.Hidden);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                SharingRetry.Run(() => File.Delete(temporary));
            }
        }
    }
}

/// <summary>How <c>sip config set</c> writes <c>master.json</c>.</summary>
public enum ConfigWriteRoute
{
    /// <summary>Write it from this process: a sandbox, or already elevated.</summary>
    WriteHere,

    /// <summary>Start this program again elevated, through UAC, to do just the one write.</summary>
    RelaunchElevated,

    /// <summary>This is the elevated copy and it is not elevated: stop, rather than loop.</summary>
    Refuse,
}
