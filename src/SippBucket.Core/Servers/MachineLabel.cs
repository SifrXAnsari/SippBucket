using System.Text;
using SippBucket.Core.Platform;

namespace SippBucket.Core.Servers;

/// <summary>
/// A machine's readable description, from its firmware: "Dell Inspiron 15 3511",
/// "MSI Katana 15 B13VFK". Shown beside a server's number ("Server 1 (Dell Inspiron 15 3511)")
/// and carried as the <c>label</c> of its <c>sippbucket.server/1</c> record.
/// </summary>
/// <remarks>
/// <para>
/// Display only, and never compared: two machines of one model have one label. The rules,
/// decided while building Server.ID and recorded in docs/SERVER-ID.md:
/// </para>
/// <list type="bullet">
/// <item><description>The system's manufacturer and product name when both are real. Custom
/// desktop boards usually fill those with placeholders ("System manufacturer", "System Product
/// Name"), so next the baseboard's manufacturer and product; then a manufacturer
/// alone.</description></item>
/// <item><description>Lenovo writes a machine-type code as the product name
/// ("20KHCTO1WW") and the model's name as the version ("ThinkPad X1 Carbon 6th"), so for Lenovo
/// the version is used when it is real.</description></item>
/// <item><description>A well-known manufacturer is written the way people say it: "Dell Inc."
/// is "Dell", "Micro-Star International Co., Ltd." is "MSI", "ASUSTeK COMPUTER INC." is
/// "ASUS". Any other loses a trailing company form ("Inc.", "Co., Ltd.",
/// "GmbH").</description></item>
/// <item><description>A product that already begins with the manufacturer's name is not given it
/// twice: "HP" and "HP EliteBook 840 G5" make "HP EliteBook 840 G5".</description></item>
/// <item><description>Control characters become spaces, runs of spaces become one, and the
/// result is cut to <see cref="MaximumLength"/> characters.</description></item>
/// </list>
/// </remarks>
public static class MachineLabel
{
    /// <summary>The longest label, which is also the most a record may carry.</summary>
    public const int MaximumLength = 64;

    // Matched at the start of the manufacturer's name, ignoring case, and only up to a word's
    // end, so "HP" is not "HPE".
    private static readonly (string Prefix, string Name)[] KnownMakers =
    [
        ("Dell", "Dell"),
        ("Hewlett-Packard", "HP"),
        ("HP", "HP"),
        ("Lenovo", "Lenovo"),
        ("ASUSTeK", "ASUS"),
        ("ASUS", "ASUS"),
        ("Micro-Star", "MSI"),
        ("MSI", "MSI"),
        ("Gigabyte", "Gigabyte"),
        ("Acer", "Acer"),
        ("Microsoft", "Microsoft"),
        ("Apple", "Apple"),
        ("Samsung", "Samsung"),
        ("Intel", "Intel"),
        ("ASRock", "ASRock"),
        ("Toshiba", "Toshiba"),
        ("Dynabook", "Dynabook"),
        ("Fujitsu", "Fujitsu"),
        ("Sony", "Sony"),
        ("LG Electronics", "LG"),
        ("Huawei", "Huawei"),
        ("Razer", "Razer"),
        ("Framework", "Framework"),
        ("Google", "Google"),
        ("System76", "System76"),
        ("Medion", "Medion"),
        ("VMware", "VMware"),
        ("innotek", "VirtualBox"),
        ("QEMU", "QEMU"),
    ];

    // Removed from the end of any other manufacturer's name, one at a time, with the commas
    // and spaces before them.
    private static readonly string[] CompanyForms =
    [
        "Co.,Ltd.", "Co.,Ltd", "Co., Ltd.", "Co., Ltd", "Co. Ltd.", "Co. Ltd", "Ltd.", "Ltd", "Inc.", "Inc",
        "Corporation", "Corp.", "Corp", "GmbH", "LLC", "Limited", "AG", "S.A.", "B.V.", "Co.", "Co",
    ];

    /// <summary>The label the firmware's tables give.</summary>
    /// <param name="tables">The tables, or null when they could not be read.</param>
    /// <returns>The label, or null when no manufacturer is real.</returns>
    public static string? From(FirmwareTables? tables)
    {
        if (tables is null)
        {
            return null;
        }

        if (tables.SystemMaker.IsReal && tables.SystemProduct.IsReal)
        {
            var maker = MakerName(tables.SystemMaker.Text);
            var product = string.Equals(maker, "Lenovo", StringComparison.Ordinal) && tables.SystemVersion.IsReal
                ? tables.SystemVersion.Text
                : tables.SystemProduct.Text;
            return Compose(maker, product);
        }

        if (tables.BoardMaker.IsReal && tables.BoardProduct.IsReal)
        {
            return Compose(MakerName(tables.BoardMaker.Text), tables.BoardProduct.Text);
        }

        if (tables.SystemMaker.IsReal)
        {
            return Compose(MakerName(tables.SystemMaker.Text), null);
        }

        return tables.BoardMaker.IsReal ? Compose(MakerName(tables.BoardMaker.Text), null) : null;
    }

    /// <summary>A manufacturer's name as people say it.</summary>
    /// <param name="maker">The name the firmware gives.</param>
    /// <returns>The short name of a well-known maker, or the name without its company form.</returns>
    internal static string MakerName(string maker)
    {
        ArgumentNullException.ThrowIfNull(maker);

        var name = Clean(maker);
        foreach (var (prefix, known) in KnownMakers)
        {
            if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                (name.Length == prefix.Length || !char.IsLetter(name[prefix.Length])))
            {
                return known;
            }
        }

        var stripped = true;
        while (stripped)
        {
            stripped = false;
            foreach (var form in CompanyForms)
            {
                if (name.Length > form.Length &&
                    name.EndsWith(form, StringComparison.OrdinalIgnoreCase) &&
                    name[name.Length - form.Length - 1] is ' ' or ',')
                {
                    name = name[..^form.Length].TrimEnd(' ', ',');
                    stripped = true;
                    break;
                }
            }
        }

        return name;
    }

    private static string? Compose(string maker, string? product)
    {
        var cleanProduct = product is null ? string.Empty : Clean(product);
        var label = cleanProduct.Length == 0
            ? maker
            : cleanProduct.StartsWith(maker, StringComparison.OrdinalIgnoreCase)
                ? cleanProduct
                : $"{maker} {cleanProduct}";

        label = label.Trim();
        if (label.Length == 0)
        {
            return null;
        }

        return label.Length <= MaximumLength ? label : label[..MaximumLength].TrimEnd();
    }

    /// <summary>
    /// Characters that are instructions to the display (<see cref="DisplayText"/>) as spaces, and
    /// runs of spaces as one, so no machine's own label is one its peers refuse.
    /// </summary>
    private static string Clean(string text)
    {
        var builder = new StringBuilder(text.Length);
        var space = false;
        foreach (var c in text)
        {
            if (DisplayText.IsInstruction(c) || char.IsWhiteSpace(c))
            {
                space = builder.Length > 0;
                continue;
            }

            if (space)
            {
                builder.Append(' ');
                space = false;
            }

            builder.Append(c);
        }

        return builder.ToString();
    }
}
