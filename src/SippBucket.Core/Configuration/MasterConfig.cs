using System.Globalization;
using System.Text.Json;
using SippBucket.Core.Health;
using SippBucket.Core.Platform;
using SippBucket.Core.Protocol;
using SippBucket.Core.Push;
using SippBucket.Core.Storage;
using SippBucket.Core.Sync;

namespace SippBucket.Core.Configuration;

/// <summary>
/// The machine's settings, from <c>master.json</c>: what each setting is, and where each
/// value came from.
/// </summary>
/// <remarks>
/// <para>
/// Built to docs/MASTER-CONFIG.md, which was agreed with the user and is the single source for
/// what this file is. In short: one file per machine, never synced, in
/// <c>C:\ProgramData\SippBucket</c>, which every account can read and only an administrator
/// can change. It is there so nobody breaks their server by accident; it is not a place to
/// hide behaviour, and nothing in it can change what SippBucket tells the user.
/// </para>
/// <para>
/// "Only an administrator" rests on the folder's permissions, which the installer sets (task
/// <c>pack</c>). Without it the folder inherits ProgramData's, which grant Users
/// <c>(OI)(CI)(RX)</c> and, on folders only, <c>(CI)(WD,AD,WEA,WA)</c> (measured with
/// <c>icacls C:\ProgramData</c> on the machine this was built on, 2026-09-18): any account can then create
/// the folder, a junction in its place, or <c>master.json</c> while it does not exist, and
/// none can change one an administrator wrote. The elevated writer refuses a folder or file
/// another account made and a folder or file that is a link (<see cref="MasterConfigLocation"/>);
/// <c>sip help config</c> says so.
/// </para>
/// <para>
/// <b>A bad value can never break the server.</b> A missing file is every default. A value of
/// the wrong type, or outside its limits, is ignored and its default used. A syntax error
/// anywhere means every default. An unknown key is reported and changes nothing, so a newer
/// file does not break an older build. Every one of those is recorded in
/// <see cref="Problems"/>, which <c>sip config check</c> and <c>sip doctor</c> print, and
/// loading never throws for anything the file contains.
/// </para>
/// <para>
/// JSON with comments and trailing commas (System.Text.Json's
/// <see cref="JsonCommentHandling.Skip"/> and <see cref="JsonDocumentOptions.AllowTrailingCommas"/>),
/// so it can be annotated. Section and key names are matched ignoring case.
/// </para>
/// </remarks>
public sealed class MasterConfig
{
    /// <summary>The file's name.</summary>
    public const string FileName = "master.json";

    /// <summary>The schema this build writes, and the newest it fully understands.</summary>
    public const int CurrentSchema = 1;

    private const string SchemaKey = "schema";

    private const long KiB = 1024;
    private const long MiB = 1024 * 1024;

    private static readonly JsonDocumentOptions ReadOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        MaxDepth = 16,
    };

    private readonly Dictionary<MasterSetting, SettingValue> _values;

    private MasterConfig(string path, bool fileExists, Dictionary<MasterSetting, SettingValue> values, IReadOnlyList<ConfigProblem> problems)
    {
        Path = path;
        FileExists = fileExists;
        _values = values;
        Problems = problems;
    }

    /// <summary>Where the file is, or would be.</summary>
    public string Path { get; }

    /// <summary>Whether the file existed when this was read.</summary>
    public bool FileExists { get; }

    /// <summary>Every setting's value now in effect, in <see cref="MasterSettings.All"/> order.</summary>
    public IReadOnlyList<SettingValue> Values => [.. MasterSettings.All.Select(setting => _values[setting])];

    /// <summary>Everything in the file that was not used as written, and why.</summary>
    public IReadOnlyList<ConfigProblem> Problems { get; }

    /// <summary>The port this machine serves every folder on.</summary>
    public int ListenPort => ValueOf(MasterSettings.ListenPort);

    /// <summary>Whether the daemon asks the router to forward the sync port here (D-05).</summary>
    public bool PortMappingEnabled => ValueOf(MasterSettings.PortMappingEnabled) == 1;

    /// <summary>How long each router mapping is asked to last.</summary>
    public TimeSpan PortMappingLifetime => TimeSpan.FromMinutes(ValueOf(MasterSettings.PortMappingLifetime));

    /// <summary>The machine's upload ceiling for blocks (D-29): unlimited at the default of 0.</summary>
    /// <remarks>A fresh limiter per read, because a limiter carries clock state; callers keep the one they take.</remarks>
    public RateLimiter UploadLimit => new(ValueOf(MasterSettings.UploadCeiling) * KiB);

    /// <summary>The machine's download ceiling for blocks (D-29): unlimited at the default of 0.</summary>
    public RateLimiter DownloadLimit => new(ValueOf(MasterSettings.DownloadCeiling) * KiB);

    /// <summary>The sync timings in effect, as the sync engine, the daemon and the host take them.</summary>
    public SyncTuning Sync => SyncTuning.Default with
    {
        PollInterval = TimeSpan.FromSeconds(ValueOf(MasterSettings.PollInterval)),
        DebounceInterval = TimeSpan.FromSeconds(ValueOf(MasterSettings.DebounceInterval)),
        ConnectTimeout = TimeSpan.FromSeconds(ValueOf(MasterSettings.ConnectTimeout)),
        StallTimeout = TimeSpan.FromSeconds(ValueOf(MasterSettings.StallTimeout)),
        IdleTimeout = TimeSpan.FromSeconds(ValueOf(MasterSettings.IdleTimeout)),
    };

    /// <summary>Direct Push's port and limits in effect, with every size in bytes.</summary>
    public PushSettings Push => new()
    {
        Port = ValueOf(MasterSettings.PushPort),
        WindowBytes = ValueOf(MasterSettings.PushWindow) * KiB,
        QuarantineCapBytes = ValueOf(MasterSettings.QuarantineCap) * MiB,
        PersonInboxCapBytes = ValueOf(MasterSettings.PersonInboxCap) * MiB,
        LargestFileBytes = ValueOf(MasterSettings.LargestFile) * MiB,
        LargestMessageBytes = ValueOf(MasterSettings.LargestMessage) * KiB,
        MessagesPerMinute = ValueOf(MasterSettings.MessageRate),
    };

    /// <summary>Peer health's thresholds in effect.</summary>
    public HealthSettings Health => new()
    {
        FaultsPerDay = ValueOf(MasterSettings.FaultsPerDay),
        ClockSkew = TimeSpan.FromMinutes(ValueOf(MasterSettings.ClockSkew)),
        MassChangePercent = ValueOf(MasterSettings.MassChangePercent),
        MassChangeMinimumFiles = ValueOf(MasterSettings.MassChangeMinimumFiles),
        RandomChangePercent = ValueOf(MasterSettings.RandomChangePercent),
        RenameWaveMinimumFiles = ValueOf(MasterSettings.RenameWaveMinimumFiles),
    };

    /// <summary>The value in effect for one setting.</summary>
    /// <param name="setting">The setting.</param>
    /// <returns>Its value.</returns>
    public int ValueOf(MasterSetting setting)
    {
        ArgumentNullException.ThrowIfNull(setting);
        return _values[setting].Value;
    }

    /// <summary>
    /// Where <c>master.json</c> is for this process: the data-directory override when one is
    /// set, otherwise <c>C:\ProgramData\SippBucket</c>.
    /// </summary>
    /// <returns>A fully qualified path.</returns>
    public static string ResolvePath() =>
        PathFor(Environment.GetEnvironmentVariable(UserDataDirectory.OverrideVariable));

    /// <summary>Whether this process reads <c>master.json</c> from an override rather than ProgramData.</summary>
    /// <returns>True when <c>SIPPBUCKET_DATA_DIR</c> names a fully qualified directory.</returns>
    public static bool IsLocationOverridden() =>
        IsOverride(Environment.GetEnvironmentVariable(UserDataDirectory.OverrideVariable));

    /// <summary>Where <c>master.json</c> is, given the value of the data-directory override.</summary>
    /// <param name="dataDirectoryOverride">The value of <c>SIPPBUCKET_DATA_DIR</c>, or null.</param>
    /// <returns>A fully qualified path.</returns>
    /// <remarks>
    /// The same rule <see cref="UserDataDirectory"/> applies, so a sandbox is one sandbox: a
    /// fully qualified override moves the device key, the watch list and this file together,
    /// and a relative one is ignored for all three. Tests, the e2e harness and anyone trying
    /// SippBucket out therefore never read or write <c>ProgramData</c>.
    /// </remarks>
    public static string PathFor(string? dataDirectoryOverride) =>
        System.IO.Path.Combine(
            IsOverride(dataDirectoryOverride)
                ? dataDirectoryOverride!
                : System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "SippBucket"),
            FileName);

    /// <summary>Reads this machine's <c>master.json</c>.</summary>
    /// <returns>The settings in effect.</returns>
    public static MasterConfig Load() => Load(ResolvePath());

    /// <summary>Reads a <c>master.json</c>.</summary>
    /// <param name="path">The file.</param>
    /// <returns>The settings in effect. Never throws for anything the file contains.</returns>
    /// <remarks>
    /// A file that exists and cannot be read at all, after another program's brief hold has
    /// been waited out (D-69), is treated like a syntax error: every default, and the reason
    /// reported. Refusing to start the daemon over a settings file is the one outcome the
    /// file must never cause.
    /// </remarks>
    public static MasterConfig Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        string text;
        try
        {
            text = SharingRetry.Run(() =>
            {
                using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(file);
                return reader.ReadToEnd();
            });
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return Defaults(path, fileExists: false, []);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Defaults(
                path,
                fileExists: true,
                [new ConfigProblem(ConfigProblemKind.Unreadable, null, $"{FileName} could not be read ({ex.Message}); every setting is at its default")]);
        }

        return Parse(text, path);
    }

    /// <summary>Reads settings from the text of a <c>master.json</c>.</summary>
    /// <param name="json">The file's text.</param>
    /// <param name="path">Where it came from, for reports.</param>
    /// <returns>The settings in effect. Never throws for anything the text contains.</returns>
    public static MasterConfig Parse(string json, string path)
    {
        ArgumentNullException.ThrowIfNull(json);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, ReadOptions);
        }
        catch (JsonException ex)
        {
            var where = ex.LineNumber is { } line
                ? string.Create(CultureInfo.InvariantCulture, $" at line {line + 1}")
                : string.Empty;
            return Defaults(
                path,
                fileExists: true,
                [new ConfigProblem(ConfigProblemKind.SyntaxError, null, $"{FileName} is not valid JSON{where}; every setting is at its default")]);
        }

        using (document)
        {
            return Interpret(document.RootElement, path);
        }
    }

    private static MasterConfig Interpret(JsonElement root, string path)
    {
        var problems = new List<ConfigProblem>();
        var values = DefaultValues();

        if (root.ValueKind != JsonValueKind.Object)
        {
            problems.Add(new ConfigProblem(
                ConfigProblemKind.SyntaxError, null, $"{FileName} is not a JSON object; every setting is at its default"));
            return new MasterConfig(path, fileExists: true, values, problems);
        }

        var sawSchema = false;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var property in root.EnumerateObject())
        {
            if (!seen.Add(property.Name))
            {
                problems.Add(new ConfigProblem(
                    ConfigProblemKind.DuplicateKey, property.Name, $"'{property.Name}' appears more than once; only the first is used"));
                continue;
            }

            if (string.Equals(property.Name, SchemaKey, StringComparison.OrdinalIgnoreCase))
            {
                sawSchema = true;
                CheckSchema(property.Value, problems);
                continue;
            }

            var section = MasterSettings.Sections.FirstOrDefault(
                name => string.Equals(name, property.Name, StringComparison.OrdinalIgnoreCase));

            if (section is null)
            {
                problems.Add(new ConfigProblem(
                    ConfigProblemKind.UnknownKey, property.Name, $"'{property.Name}' is not a setting this build knows; it was ignored"));
                continue;
            }

            if (property.Value.ValueKind != JsonValueKind.Object)
            {
                problems.Add(new ConfigProblem(
                    ConfigProblemKind.InvalidValue, section, $"'{section}' is not an object; every setting in it is at its default"));
                continue;
            }

            ReadSection(section, property.Value, values, problems);
        }

        if (!sawSchema)
        {
            problems.Add(new ConfigProblem(
                ConfigProblemKind.SchemaMissing, SchemaKey, $"there is no 'schema'; it was read as schema {CurrentSchema}"));
        }

        CheckPortsApart(values, problems);
        return new MasterConfig(path, fileExists: true, values, problems);
    }

    /// <summary>
    /// Reports a Direct Push port that is the sync port or the pairing port beside it.
    /// </summary>
    /// <remarks>
    /// Each value is valid alone, so neither falls back: which one the person meant to move is
    /// theirs to say, and quietly listening somewhere else would be a port nobody chose. Direct
    /// Push does not start while the two clash and says why, and sync is untouched, so the
    /// clash can never break the server.
    /// </remarks>
    private static void CheckPortsApart(Dictionary<MasterSetting, SettingValue> values, List<ConfigProblem> problems)
    {
        var listen = values[MasterSettings.ListenPort].Value;
        var push = values[MasterSettings.PushPort].Value;

        if (push != listen && push != listen + 1)
        {
            return;
        }

        var what = push == listen ? "the sync port" : "the pairing port beside it";
        problems.Add(new ConfigProblem(
            ConfigProblemKind.PortClash,
            MasterSettings.PushPort.Key,
            string.Create(
                CultureInfo.InvariantCulture,
                $"'{MasterSettings.PushPort.Key}' is {push}, which is {what} (server.listenPort {listen}); " +
                $"Direct Push will not start until one of them is moved")));
    }

    private static void ReadSection(
        string section,
        JsonElement body,
        Dictionary<MasterSetting, SettingValue> values,
        List<ConfigProblem> problems)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in body.EnumerateObject())
        {
            var key = $"{section}.{entry.Name}";

            if (!seen.Add(entry.Name))
            {
                problems.Add(new ConfigProblem(
                    ConfigProblemKind.DuplicateKey, key, $"'{key}' appears more than once; only the first is used"));
                continue;
            }

            var setting = MasterSettings.Find(key);
            if (setting is null)
            {
                problems.Add(new ConfigProblem(
                    ConfigProblemKind.UnknownKey, key, $"'{key}' is not a setting this build knows; it was ignored"));
                continue;
            }

            var why = setting.Check(entry.Value, out var value);
            if (why is null)
            {
                values[setting] = new SettingValue(setting, value, SettingSource.File, null);
                continue;
            }

            var fallback = string.Create(
                CultureInfo.InvariantCulture,
                $"'{setting.Key}' {why}; the default, {setting.Default}, is used");
            values[setting] = new SettingValue(setting, setting.Default, SettingSource.FellBack, fallback);
            problems.Add(new ConfigProblem(ConfigProblemKind.InvalidValue, setting.Key, fallback));
        }
    }

    private static void CheckSchema(JsonElement value, List<ConfigProblem> problems)
    {
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var schema) || schema < 1)
        {
            problems.Add(new ConfigProblem(
                ConfigProblemKind.SchemaInvalid, SchemaKey, $"'schema' is not a schema number; it was read as schema {CurrentSchema}"));
            return;
        }

        if (schema > CurrentSchema)
        {
            problems.Add(new ConfigProblem(
                ConfigProblemKind.SchemaNewer,
                SchemaKey,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"'schema' is {schema}, written for a newer build; the settings this build knows were still read")));
        }
    }

    private static MasterConfig Defaults(string path, bool fileExists, IReadOnlyList<ConfigProblem> problems) =>
        new(path, fileExists, DefaultValues(), problems);

    private static Dictionary<MasterSetting, SettingValue> DefaultValues() =>
        MasterSettings.All.ToDictionary(
            setting => setting,
            setting => new SettingValue(setting, setting.Default, SettingSource.Default, null));

    private static bool IsOverride(string? value) =>
        !string.IsNullOrWhiteSpace(value) && System.IO.Path.IsPathFullyQualified(value);
}

/// <summary>Where a setting's value came from.</summary>
public enum SettingSource
{
    /// <summary>The file does not set it, or there is no file: the built-in default.</summary>
    Default,

    /// <summary>The file sets it, and the value was used.</summary>
    File,

    /// <summary>The file sets it badly: the default was used instead, and it was reported.</summary>
    FellBack,
}

/// <summary>One setting's value in effect.</summary>
/// <param name="Setting">The setting.</param>
/// <param name="Value">Its value.</param>
/// <param name="Source">Where the value came from.</param>
/// <param name="Problem">Why the file's value was not used, when <paramref name="Source"/> is <see cref="SettingSource.FellBack"/>.</param>
public sealed record SettingValue(MasterSetting Setting, int Value, SettingSource Source, string? Problem)
{
    /// <summary>Whether the value in effect differs from the built-in default.</summary>
    public bool DiffersFromDefault => Value != Setting.Default;
}

/// <summary>What kind of thing in <c>master.json</c> was not used as written.</summary>
public enum ConfigProblemKind
{
    /// <summary>The file is not valid JSON, or not an object: every setting is at its default.</summary>
    SyntaxError,

    /// <summary>The file exists and could not be read: every setting is at its default.</summary>
    Unreadable,

    /// <summary>A value is of the wrong type or outside its limits: its default is used.</summary>
    InvalidValue,

    /// <summary>A key this build does not know: ignored.</summary>
    UnknownKey,

    /// <summary>A key given twice: only the first is used.</summary>
    DuplicateKey,

    /// <summary>No <c>schema</c> field: read as the current schema.</summary>
    SchemaMissing,

    /// <summary>A <c>schema</c> that is not a schema number: read as the current schema.</summary>
    SchemaInvalid,

    /// <summary>A <c>schema</c> newer than this build: what this build knows is still read.</summary>
    SchemaNewer,

    /// <summary>
    /// Two ports that are each valid alone and cannot both be used: Direct Push's is the sync
    /// port or the pairing port. Neither falls back; Direct Push does not start until one moves.
    /// </summary>
    PortClash,
}

/// <summary>One thing in <c>master.json</c> that was not used as written.</summary>
/// <param name="Kind">What kind of problem it is.</param>
/// <param name="Key">The key it concerns, or null when it concerns the whole file.</param>
/// <param name="Message">What happened, for a person.</param>
public sealed record ConfigProblem(ConfigProblemKind Kind, string? Key, string Message);
