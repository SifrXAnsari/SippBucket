using System.Text.Json;
using System.Text.Json.Serialization;
using SippBucket.Core.Hashing;

namespace SippBucket.Core.Serialization;

/// <summary>
/// Reads and writes a <see cref="ContentHash"/> as its hexadecimal string form.
/// </summary>
/// <remarks>
/// An empty hash is written as an empty string, which is how a root snapshot records that
/// it has no parent.
/// </remarks>
public sealed class ContentHashJsonConverter : JsonConverter<ContentHash>
{
    /// <inheritdoc />
    public override ContentHash Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        var text = reader.GetString();
        if (string.IsNullOrEmpty(text))
        {
            return default;
        }

        if (!ContentHash.TryParse(text, out var hash))
        {
            throw new JsonException($"'{text}' is not a valid content hash.");
        }

        return hash;
    }

    /// <inheritdoc />
    public override void Write(
        Utf8JsonWriter writer,
        ContentHash value,
        JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStringValue(value.IsEmpty ? string.Empty : value.ToString());
    }
}
