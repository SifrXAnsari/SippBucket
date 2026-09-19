using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace SippBucket.Core.Serialization;

/// <summary>
/// The single JSON configuration used for everything SippBucket writes to disk or sends
/// over the wire.
/// </summary>
/// <remarks>
/// One shared options instance matters for more than tidiness: a snapshot is identified by
/// the hash of its serialized bytes, so two machines must produce byte-identical JSON for
/// the same snapshot or they will disagree about its identity.
/// </remarks>
public static class SipJson
{
    /// <summary>Options for on-disk files, indented so a power user can read them.</summary>
    public static JsonSerializerOptions Readable { get; } = Build(indented: true);

    /// <summary>
    /// Options for anything that gets hashed or sent over the wire. Compact and stable.
    /// </summary>
    public static JsonSerializerOptions Canonical { get; } = Build(indented: false);

    private static JsonSerializerOptions Build(bool indented)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = indented,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            NumberHandling = JsonNumberHandling.Strict,

            // Stated explicitly rather than left to default. Freezing the options with
            // MakeReadOnly requires a resolver to be present, and naming it here keeps the
            // choice visible if this is ever moved to source generation.
            TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
        };

        options.Converters.Add(new ContentHashJsonConverter());
        options.Converters.Add(new JsonStringEnumConverter());
        options.MakeReadOnly();
        return options;
    }
}
