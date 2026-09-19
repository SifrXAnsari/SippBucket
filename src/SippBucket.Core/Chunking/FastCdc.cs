using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace SippBucket.Core.Chunking;

/// <summary>
/// FastCDC content-defined chunking: block boundaries chosen by the bytes themselves rather
/// than by their offset, so an insertion moves only the boundaries next to it.
/// </summary>
/// <remarks>
/// <para>
/// Fixed-size blocks (D-22) cut a file every N bytes. Insert one byte at the front and every
/// cut moves, every block hash changes, and the whole file is stored and sent again. A
/// content-defined cut is placed where a rolling hash of the last 48 bytes happens to match
/// a mask, so after an edit the cuts fall back into step within about one chunk and every
/// later block is one the store already holds.
/// </para>
/// <para>
/// Sources. The algorithm is W. Xia et al., "FastCDC: a Fast and Efficient Content-Defined
/// Chunking Approach for Data Deduplication", USENIX ATC 2016,
/// https://www.usenix.org/system/files/conference/atc16/atc16-paper-xia.pdf, read for this
/// code: §4.2 (the gear hash, and masks padded with zero bits so the effective window is
/// 48 bytes), §4.3 (no cut is considered below the minimum size), §4.4 (normalized
/// chunking: a stricter mask before the expected size and a looser one after it), §4.5
/// Algorithm 1, and §5.4, which finds normalization level 2 the sweet spot for
/// deduplication. The "rolling two bytes each time" loop is from the 2020 journal version,
/// W. Xia et al., "The Design of Fast Content-Defined Chunking for Data Deduplication Based
/// Storage Systems", IEEE TPDS 31(9), https://ieeexplore.ieee.org/document/9055082. That
/// paper is paywalled and was <em>not</em> read directly; the loop follows the reference
/// implementation that cites it, the <c>fastcdc</c> crate's v2020 module (fastcdc 5.0.0),
/// https://github.com/nlfiedler/fastcdc-rs/blob/master/src/v2020/mod.rs — <c>cut_gear</c>
/// and <c>scan_region</c>. The one published vector of that crate that needs no external
/// file (<c>test_cut_all_zeros</c>) is reproduced byte for byte, and the tests check the
/// two-byte loop against the paper's one-byte Algorithm 1 on pseudo-random input. The
/// crate's other vectors chunk a JPEG fixture that was not fetched, so agreement with the
/// crate beyond those is by construction, not by measurement.
/// </para>
/// <para>
/// <strong>The gear table and the masks fix every boundary forever.</strong> Change either
/// and every file chunked afterwards splits differently from every file chunked before, so
/// nothing deduplicates across the change. That is why entries record
/// <see cref="Name"/>, and why a different table or mask is a different name rather than a
/// new release of this one.
/// </para>
/// </remarks>
public static class FastCdc
{
    /// <summary>
    /// The name recorded in <c>FileEntry.Chunker</c> for entries this chunker produced.
    /// </summary>
    public const string Name = "fastcdc2020-v1";

    /// <summary>
    /// Normalized chunking level: how many bits stricter the mask is before the average
    /// size, and how many bits looser after it.
    /// </summary>
    /// <remarks>
    /// Level 2 because §5.4 of the 2016 paper measured it as the sweet spot: "NC touches the
    /// sweet spot of deduplication ratio at the normalization level of 2". Higher levels
    /// squeeze chunk sizes towards the average until they behave like fixed-size blocks,
    /// which is the defect this exists to remove. The reference crate defaults to level 1;
    /// the paper's evaluation is the better authority for a default.
    /// </remarks>
    public const int NormalizationLevel = 2;

    /// <summary>The average chunk size for small files, in bytes.</summary>
    /// <remarks>
    /// Equal to <see cref="BlockSizer.MinimumBlockSize"/> on purpose. Every block is its own
    /// file in the store, and the filesystem was measured at 68–76% of a cold save
    /// (<c>sipnative/README.md</c>), so a smaller average would buy finer deduplication with
    /// a slower save of every file. Holding the average where fixed-size blocks already were
    /// keeps the number of blocks per file about where it was.
    /// </remarks>
    public const int SmallestAverage = 128 * 1024;

    /// <summary>The average chunk size for the largest files, in bytes.</summary>
    /// <remarks>
    /// The maximum chunk is four times the average, and no block may exceed
    /// <see cref="BlockSizer.MaximumBlockSize"/>, so 4 MiB is as high as the average can go.
    /// Past about 7.8 GiB a file therefore has more than <see cref="TargetChunkCount"/>
    /// chunks: a 64 GiB file at a 4 MiB average is on the order of 16,000, where fixed-size
    /// blocks stepped up to 16 MiB and had 4,096. That is the price of the hard 16 MiB
    /// ceiling, paid in manifest length on files that size.
    /// </remarks>
    public const int LargestAverage = 4 * 1024 * 1024;

    /// <summary>
    /// The number of chunks a file is aimed at before its average size is doubled. The same
    /// target <see cref="BlockSizer"/> uses, so a manifest stays about as long as it was.
    /// </summary>
    public const int TargetChunkCount = 2000;

    private static readonly FastCdcParameters[] Tiers = BuildTiers();

    /// <summary>
    /// The 256-entry gear table: the rolling hash adds one of these per byte.
    /// </summary>
    /// <remarks>
    /// Generated, not transcribed. Entry <c>i</c> is the first eight bytes, read big-endian,
    /// of the MD5 digest of 64 bytes all equal to <c>i</c> — the derivation the reference
    /// implementation publishes for its own <c>GEAR</c> table (fastcdc-rs,
    /// <c>examples/table64.rs</c>, which credits the authors' C reference in the destor
    /// repository), so this is that table. A test regenerates all 256 entries from the
    /// derivation and compares, and checks eleven of them against the reference's source
    /// text. MD5 has no security role: the table only has to look random, and a published
    /// derivation is what lets anyone reproduce it. Public so that it can be checked, not so
    /// that it can be varied.
    /// </remarks>
    public static ReadOnlySpan<ulong> Gear =>
    [
        0x3B5D3C7D207E37DC, 0x784D68BA91123086, 0xCD52880F882E7298, 0xEACF8E4E19FDCCA7,
        0xC31F385DFBD1632B, 0x1D5F27001E25ABE6, 0x83130BDE3C9AD991, 0xC4B225676E9B7649,
        0xAA329B29E08EB499, 0xB67FCBD21E577D58, 0x0027BAAADA2ACF6B, 0xE3EF2D5AC73C2226,
        0x0890F24D6ED312B7, 0xA809E036851D7C7E, 0xF0A6FE5E0013D81B, 0x1D026304452CEC14,
        0x03864632648E248F, 0xCDAACF3DCD92B9B4, 0xF5E012E63C187856, 0x8862F9D3821C00B6,
        0xA82F7338750F6F8A, 0x1E583DC6C1CB0B6F, 0x7A3145B69743A7F1, 0xABB20FEE404807EB,
        0xB14B3CFE07B83A5D, 0xB9DC27898ADB9A0F, 0x3703F5E91BAA62BE, 0xCF0BB866815F7D98,
        0x3D9867C41EA9DCD3, 0x1BE1FA65442BF22C, 0x14300DA4C55631D9, 0xE698E9CBC6545C99,
        0x4763107EC64E92A5, 0xC65821FC65696A24, 0x76196C064822F0B7, 0x485BE841F3525E01,
        0xF652BC9C85974FF5, 0xCAD8352FACE9E3E9, 0x2A6ED1DCEB35E98E, 0xC6F483BADC11680F,
        0x3CFD8C17E9CF12F1, 0x89B83C5E2EA56471, 0xAE665CFD24E392A9, 0xEC33C4E504CB8915,
        0x3FB9B15FC9FE7451, 0xD7FD1FD1945F2195, 0x31ADE0853443EFD8, 0x255EFC9863E1E2D2,
        0x10EAB6008D5642CF, 0x46F04863257AC804, 0xA52DC42A789A27D3, 0xDAAADF9CE77AF565,
        0x6B479CD53D87FEBB, 0x6309E2D3F93DB72F, 0xC5738FFBAA1FF9D6, 0x6BD57F3F25AF7968,
        0x67605486D90D0A4A, 0xE14D0B9663BFBDAE, 0xB7BBD8D816EB0414, 0xDEF8A4F16B35A116,
        0xE7932D85AAAFFED6, 0x08161CBAE90CFD48, 0x855507BEB294F08B, 0x91234EA6FFD399B2,
        0xAD70CF4B2435F302, 0xD289A97565BC2D27, 0x8E558437FFCA99DE, 0x96D2704B7115C040,
        0x0889BBCDFC660E41, 0x5E0D4E67DC92128D, 0x72A9F8917063ED97, 0x438B69D409E016E3,
        0xDF4FED8A5D8A4397, 0x00F41DCF41D403F7, 0x4814EB038E52603F, 0x9DAFBACC58E2D651,
        0xFE2F458E4BE170AF, 0x4457EC414DF6A940, 0x06E62F1451123314, 0xBD1014D173BA92CC,
        0xDEF318E25ED57760, 0x9FEA0DE9DFCA8525, 0x459DE1E76C20624B, 0xAEEC189617E2D666,
        0x126A2C06AB5A83CB, 0xB1321532360F6132, 0x65421503DBB40123, 0x2D67C287EA089AB3,
        0x6C93BFF5A56BD6B6, 0x4FFB2036CAB6D98D, 0xCE7B785B1BE7AD4F, 0xEDB42EF6189FD163,
        0xDC905288703988F6, 0x365F9C1D2C691884, 0xC640583680D99BFE, 0x3CD4624C07593EC6,
        0x7F1EA8D85D7C5805, 0x014842D480B57149, 0x0B649BCB5A828688, 0xBCD5708ED79B18F0,
        0xE987C862FBD2F2F0, 0x982731671F0CD82C, 0xBAF13E8B16D8C063, 0x8EA3109CBD951BBA,
        0xD141045BFB385CAD, 0x2ACBC1A0AF1F7D30, 0xE6444D89DF03BFDF, 0xA18CC771B8188FF9,
        0x9834429DB01C39BB, 0x214ADD07FE086A1F, 0x8F07C19B1F6B3FF9, 0x56A297B1BF4FFE55,
        0x94D558E493C54FC7, 0x40BFC24C764552CB, 0x931A706F8A8520CB, 0x32229D322935BD52,
        0x2560D0F5DC4FEFAF, 0x9DBCC48355969BB6, 0x0FD81C3985C0B56A, 0xE03817E1560F2BDA,
        0xC1BB4F81D892B2D5, 0xB0C4864F4E28D2D7, 0x3ECC49F9D9D6C263, 0x51307E99B52BA65E,
        0x8AF2B688DA84A752, 0xF5D72523B91B20B6, 0x6D95FF1FF4634806, 0x562F21555458339A,
        0xC0CE47F889336346, 0x487823E5089B40D8, 0xE4727C7EBC6D9592, 0x5A8F7277E94970BA,
        0xFCA2F406B1C8BB50, 0x5B1F8A95F1791070, 0xD304AF9FC9028605, 0x5440AB7FC930E748,
        0x312D25FBCA2AB5A1, 0x10F4A4B234A4D575, 0x90301D55047E7473, 0x3B6372886C61591E,
        0x293402B77C444E06, 0x451F34A4D3E97DD7, 0x3158D814D81BC57B, 0x034942425B9BDA69,
        0xE2032FF9E532D9BB, 0x62AE066B8B2179E5, 0x9545E10C2F8D71D8, 0x7FF7483EB2D23FC0,
        0x00945FCEBDC98D86, 0x8764BBBE99B26CA2, 0x1B1EC62284C0BFC3, 0x58E0FCC4F0AA362B,
        0x5F4ABEFA878D458D, 0xFD74AC2F9607C519, 0xA4E3FB37DF8CBFA9, 0xBF697E43CAC574E5,
        0x86F14A3F68F4CD53, 0x24A23D076F1CE522, 0xE725CD8048868CC8, 0xBF3C729EB2464362,
        0xD8F6CD57B3CC1ED8, 0x6329E52425541577, 0x62AA688AD5AE1AC0, 0x0A242566269BF845,
        0x168B1A4753ACA74B, 0xF789AFEFFF2E7E3C, 0x6C3362093B6FCCDB, 0x4CE8F50BD28C09B2,
        0x006A2DB95AE8AA93, 0x975B0D623C3D1A8C, 0x18605D3935338C5B, 0x5BB6F6136CAD3C71,
        0x0F53A20701F8D8A6, 0xAB8C5AD2E7E93C67, 0x40B5AC5127ACAA29, 0x8C7BF63C2075895F,
        0x78BD9F7E014A805C, 0xB2C9E9F4F9C8C032, 0xEFD6049827EB91F3, 0x2BE459F482C16FBD,
        0xD92CE0C5745AAA8C, 0x0AAA8FB298D965B9, 0x2B37F92C6C803B15, 0x8C54A5E94E0F0E78,
        0x95F9B6E90C0A3032, 0xE7939FAA436C7874, 0xD16BFE8F6A8A40C9, 0x44982B86263FD2FA,
        0xE285FB39F984E583, 0x779A8DF72D7619D3, 0xF2D79A8DE8D5DD1E, 0xD1037354D66684E2,
        0x004C82A4E668A8E5, 0x31D40A7668B044E6, 0xD70578538BD02C11, 0xDB45431078C5F482,
        0x977121BB7F6A51AD, 0x73D5CCBD34EFF8DD, 0xE437A07D356E17CD, 0x47B2782043C95627,
        0x9FB251413E41D49A, 0xCCD70B60652513D3, 0x1C95B31E8A1B49B2, 0xCAE73DFD1BCB4C1B,
        0x34D98331B1F5B70F, 0x784E39F22338D92F, 0x18613D4A064DF420, 0xF1D8DAE25F0BCEBE,
        0x33F77C15AE855EFC, 0x3C88B3B912EB109C, 0x956A2EC96BAFEEA5, 0x1AA005B5E0AD0E87,
        0x5500D70527C4BB8E, 0xE36C57196421CC44, 0x13C4D286CC36EE39, 0x5654A23D818B2A81,
        0x77B1DC13D161ABDC, 0x734F44DE5F8D5EB5, 0x60717E174A6C89A2, 0xD47D9649266A211E,
        0x5B13A4322BB69E90, 0xF7669609F8B5FC3C, 0x21E6AC55BEDCDAC9, 0x9B56B62B61166DEA,
        0xF48F66B939797E9C, 0x35F332F9C0E6AE9A, 0xCC733F6A9A878DB0, 0x3DA161E41CC108C2,
        0xB7D74AE535914D51, 0x4D493B0B11D36469, 0xCE264D1DFBA9741A, 0xA9D1F2DC7436DC06,
        0x70738016604C2A27, 0x231D36E96E93F3D5, 0x7666881197838D19, 0x4A2A83090AAAD40C,
        0xF1E761591668B35D, 0x7363236497F730A7, 0x301080E37379DD4D, 0x502DEA2971827042,
        0xC2C5EB858F32625F, 0x786AFB9EDFAFBDFF, 0xDAEE0D868490B2A4, 0x617366B3268609F6,
        0xAE0E35A0FE46173E, 0xD1A07DE93E824F11, 0x079B8B115EA4CCA8, 0x93A99274558FAEBB,
        0xFB1E6E22E08A03B3, 0xEA635FDBA3698DD0, 0xCF53659328503A5C, 0xCDE3B31E6FD5D780,
        0x8E3E4221D3614413, 0xEF14D0D86BF1A22C, 0xE1D830D3F16C5DDB, 0xAABD2B2A451504E1,
    ];

    /// <summary>
    /// Cut-point masks indexed by bit count: entry <c>n</c> has exactly <c>n</c> one bits,
    /// so a byte position passes it with probability 2^-n. Entries 0 to 4 are unused.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The paper publishes masks only for its 8 KiB example (§4.5 Algorithm 1: MaskS
    /// 0x0003590703530000, MaskA 0x0000d90303530000, MaskL 0x0000d90003530000) and says
    /// they are "empirically derived values where the padded zero bits are almost evenly
    /// distributed". This table is the reference crate's <c>MASKS</c>, whose entries up to
    /// 128 KiB come from the authors' C reference (destor) and the rest from restic-FastCDC.
    /// It agrees with the paper's MaskA and MaskL exactly. Its 15-bit entry differs from the
    /// paper's 15-bit MaskS in where the bits sit, not in how many there are; this code uses
    /// the table's, so that it and the reference implementation cut identically.
    /// </para>
    /// <para>
    /// Every one bit is below bit 48, which is what makes the effective window 48 bytes: the
    /// hash shifts left once per byte, so bit <c>k</c> depends only on the last <c>k + 1</c>
    /// bytes. A test checks each entry's bit count and its highest bit.
    /// </para>
    /// </remarks>
    public static ReadOnlySpan<ulong> Masks =>
    [
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000001804110, 0x0000000001803110, 0x0000000018035100,
        0x0000001800035300, 0x0000019000353000, 0x0000590003530000, 0x0000D90003530000,
        0x0000D90103530000, 0x0000D90303530000, 0x0000D90313530000, 0x0000D90F03530000,
        0x0000D90303537000, 0x0000D90703537000, 0x0000D90707537000, 0x0000D91707537000,
        0x0000D91747537000, 0x0000D91767537000, 0x0000D93767537000, 0x0000D93777537000,
        0x0000D93777577000, 0x0000DB3777577000,
    ];

    /// <summary>Chooses the chunk sizes for a file of the given length.</summary>
    /// <param name="fileSizeInBytes">The length of the file, in bytes.</param>
    /// <returns>
    /// Parameters whose average is a power of two from <see cref="SmallestAverage"/> to
    /// <see cref="LargestAverage"/>, with the minimum a quarter of it and the maximum four
    /// times it.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">The size was negative.</exception>
    /// <remarks>
    /// <para>
    /// The average starts at <see cref="SmallestAverage"/> and doubles while the file would
    /// otherwise have more than <see cref="TargetChunkCount"/> chunks, exactly as
    /// <see cref="BlockSizer"/> steps its block size, so the tiers change just past
    /// 250 MiB, 500 MiB, 1000 MiB, about 1.95 GiB and about 3.9 GiB. The rule is written
    /// out here rather than calling <see cref="BlockSizer"/>, because these tiers are part
    /// of what <see cref="Name"/> means and must not move if the fixed-size rule ever does.
    /// </para>
    /// <para>
    /// <strong>A tier boundary is the one place a size change re-chunks the whole
    /// file.</strong> A file that grows from 249 MiB to 251 MiB doubles its average, every
    /// mask changes, and not one boundary survives, so that save stores the file again in
    /// full. Content-defined chunking only resynchronises when both versions are chunked
    /// with the same parameters. The alternative, one average for every size, would either
    /// give small files pointlessly large blocks or give a 64 GiB file half a million of
    /// them; crossing a tier costs one full store, once.
    /// </para>
    /// <para>
    /// Minimum a quarter of the average: the 2016 paper's Algorithm 1 uses 2 KiB against an
    /// 8 KiB average. Maximum four times the average rather than the paper's eight, so that
    /// the largest tier stays inside <see cref="BlockSizer.MaximumBlockSize"/>; with
    /// level-2 normalization, input whose hash bits are uniformly random reaches four times
    /// the average with probability about e^-12 (the loose mask passes one byte in
    /// average/4, over three averages of bytes), so the lower ceiling binds almost only on
    /// data with no boundaries at all, such as a run of zeros.
    /// </para>
    /// </remarks>
    public static FastCdcParameters ForFileSize(long fileSizeInBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(fileSizeInBytes);

        var tier = 0;
        long average = SmallestAverage;
        while (average < LargestAverage && fileSizeInBytes / average > TargetChunkCount)
        {
            average <<= 1;
            tier++;
        }

        return Tiers[tier];
    }

    /// <summary>
    /// The parameters of the tier with the given average, for reproducing an entry that
    /// recorded it.
    /// </summary>
    /// <param name="average">An average chunk size, in bytes.</param>
    /// <param name="parameters">The tier's parameters, when there is one.</param>
    /// <returns>
    /// True when <paramref name="average"/> is one of the tiers <see cref="ForFileSize"/>
    /// can choose. Anything else was not written by this chunker, and is refused rather than
    /// reproduced with sizes this chunker never uses.
    /// </returns>
    public static bool TryGetTier(int average, [NotNullWhen(true)] out FastCdcParameters? parameters)
    {
        foreach (var tier in Tiers)
        {
            if (tier.Average == average)
            {
                parameters = tier;
                return true;
            }
        }

        parameters = null;
        return false;
    }

    /// <summary>Finds where the next chunk ends.</summary>
    /// <param name="data">
    /// The bytes from the start of the chunk. Pass at least <c>parameters.Maximum</c> bytes
    /// unless these are the last bytes of the file: a shorter span is treated as the end of
    /// the input.
    /// </param>
    /// <param name="parameters">The chunk sizes and masks.</param>
    /// <returns>
    /// The length of the chunk: <c>data.Length</c> when that is at most the minimum, and
    /// otherwise between the minimum and the maximum inclusive. Never zero for non-empty
    /// input.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="parameters"/> was null.</exception>
    public static int FindCut(ReadOnlySpan<byte> data, FastCdcParameters parameters) =>
        FindCut(data, parameters, out _);

    /// <summary>Finds where the next chunk ends, and reports the rolling hash there.</summary>
    /// <param name="data">The bytes from the start of the chunk. See the other overload.</param>
    /// <param name="parameters">The chunk sizes and masks.</param>
    /// <param name="gearHash">
    /// The gear hash at the cut. Nothing in SippBucket uses it; it is exposed because the
    /// reference implementation's published test vectors include it, and reproducing them
    /// byte for byte is how the table and the loop are known to match.
    /// </param>
    /// <returns>The length of the chunk. See the other overload.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="parameters"/> was null.</exception>
    /// <remarks>
    /// <para>
    /// This is Algorithm 1 of the 2016 paper with two bytes rolled per iteration. Rolling one
    /// byte is <c>hash = (hash &lt;&lt; 1) + Gear[b]</c> and tests <c>hash &amp; mask</c>.
    /// Two bytes <c>a, b</c> are <c>hash = (hash &lt;&lt; 2) + (Gear[a] &lt;&lt; 1)</c>,
    /// tested against <c>mask &lt;&lt; 1</c> — the one-byte value doubled, so zero under the
    /// doubled mask exactly when it was zero under the mask, since no mask has bit 63 set —
    /// then <c>+ Gear[b]</c>, which is the one-byte value again, tested against the mask.
    /// Same cut points, half the loop iterations.
    /// </para>
    /// <para>
    /// Like the reference, the byte that completes the matching window is the first byte of
    /// the <em>next</em> chunk (Algorithm 1 returns <c>i</c> and the chunk is
    /// <c>src[0..i)</c>), and the scan steps in pairs, so when the input ends on an odd
    /// length its last byte is never tested as a cut. The paper's one-byte loop could cut
    /// one byte before the end there; this cannot, which spares a one-byte final chunk.
    /// </para>
    /// </remarks>
    public static int FindCut(ReadOnlySpan<byte> data, FastCdcParameters parameters, out ulong gearHash)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        var length = data.Length;
        if (length <= parameters.Minimum)
        {
            gearHash = 0;
            return length;
        }

        var center = parameters.Average;
        if (length > parameters.Maximum)
        {
            length = parameters.Maximum;
        }
        else if (length < center)
        {
            center = length;
        }

        var gear = Gear;
        var strict = parameters.StrictMask;
        var strictShifted = strict << 1;
        var loose = parameters.LooseMask;
        var looseShifted = loose << 1;

        // Sub-minimum cut-point skipping (§4.3): the scan starts at the minimum with a
        // zero hash, so nothing before it can be a cut.
        ulong hash = 0;
        var i = parameters.Minimum;
        var centerEven = center & ~1;
        var endEven = length & ~1;

        for (; i < centerEven; i += 2)
        {
            hash = (hash << 2) + (gear[data[i]] << 1);
            if ((hash & strictShifted) == 0)
            {
                gearHash = hash;
                return i;
            }

            hash += gear[data[i + 1]];
            if ((hash & strict) == 0)
            {
                gearHash = hash;
                return i + 1;
            }
        }

        for (; i < endEven; i += 2)
        {
            hash = (hash << 2) + (gear[data[i]] << 1);
            if ((hash & looseShifted) == 0)
            {
                gearHash = hash;
                return i;
            }

            hash += gear[data[i + 1]];
            if ((hash & loose) == 0)
            {
                gearHash = hash;
                return i + 1;
            }
        }

        // No cut: the chunk runs to the maximum, or to the end of the input. The odd final
        // byte still enters the hash, as in the reference, so the reported hash matches.
        if ((length & 1) != 0)
        {
            hash = (hash << 1) + gear[data[length - 1]];
        }

        gearHash = hash;
        return length;
    }

    /// <summary>Splits a stream into chunks as it is read.</summary>
    /// <param name="stream">The stream to split, read from its current position to its end.</param>
    /// <param name="parameters">The chunk sizes, normally from <see cref="ForFileSize"/>.</param>
    /// <param name="lengthHint">
    /// How long the stream is expected to be. Only sizes the first buffer: a stream that
    /// turns out longer is still read to the end, and one that turns out shorter is fine.
    /// </param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>
    /// Each chunk in order. <strong>A chunk is a view of a buffer that the next chunk
    /// reuses</strong>, so finish with it — hash it, store it — before asking for the next.
    /// Concatenated, the chunks are exactly the stream's bytes.
    /// </returns>
    /// <exception cref="ArgumentNullException">A required argument was null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="lengthHint"/> was negative.</exception>
    /// <remarks>
    /// Memory is bounded by the chunk size, never by the file: the buffer holds at most two
    /// maximum chunks, and a small file gets a buffer no bigger than itself. A cut is only
    /// searched for once a full maximum chunk is buffered or the stream has ended, because
    /// <see cref="FindCut(ReadOnlySpan{byte}, FastCdcParameters)"/> reads a short span as the
    /// end of the input, and a short read from a stream is not the end of it.
    /// </remarks>
    public static IAsyncEnumerable<ReadOnlyMemory<byte>> SplitAsync(
        Stream stream,
        FastCdcParameters parameters,
        long lengthHint,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentOutOfRangeException.ThrowIfNegative(lengthHint);

        return SplitCoreAsync(stream, parameters, lengthHint, cancellationToken);
    }

    /// <summary>The most bytes <see cref="SplitAsync"/> will ever hold for these parameters.</summary>
    /// <param name="parameters">The chunk sizes.</param>
    /// <returns>Twice the maximum chunk.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="parameters"/> was null.</exception>
    /// <remarks>
    /// Two maximum chunks rather than one so that the buffer is compacted once per maximum
    /// chunk consumed rather than once per chunk.
    /// </remarks>
    public static int BufferLimit(FastCdcParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        return 2 * parameters.Maximum;
    }

    private static async IAsyncEnumerable<ReadOnlyMemory<byte>> SplitCoreAsync(
        Stream stream,
        FastCdcParameters parameters,
        long lengthHint,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var limit = BufferLimit(parameters);

        // Plus one so that a file exactly as long as the hint reaches end-of-stream without
        // first growing a full buffer just to learn there is nothing more.
        var buffer = new byte[(int)Math.Min(lengthHint, limit - 1) + 1];
        var start = 0;
        var end = 0;
        var endOfStream = false;

        while (true)
        {
            while (!endOfStream && end - start < parameters.Maximum)
            {
                if (end == buffer.Length)
                {
                    if (start > 0)
                    {
                        buffer.AsSpan(start, end - start).CopyTo(buffer);
                        end -= start;
                        start = 0;
                    }
                    else
                    {
                        // Longer than the hint said: the file grew, or the hint was a guess.
                        // Only reachable while the buffer is smaller than one maximum chunk.
                        Array.Resize(ref buffer, limit);
                    }
                }

                var read = await stream
                    .ReadAsync(buffer.AsMemory(end), cancellationToken)
                    .ConfigureAwait(false);

                if (read == 0)
                {
                    endOfStream = true;
                }
                else
                {
                    end += read;
                }
            }

            if (start == end)
            {
                yield break;
            }

            var cut = FindCut(buffer.AsSpan(start, end - start), parameters);
            yield return buffer.AsMemory(start, cut);
            start += cut;
        }
    }

    private static FastCdcParameters[] BuildTiers()
    {
        var tiers = new List<FastCdcParameters>();
        for (var average = SmallestAverage; average <= LargestAverage; average <<= 1)
        {
            tiers.Add(FastCdcParameters.Create(average / 4, average, average * 4, NormalizationLevel));
        }

        return [.. tiers];
    }
}

/// <summary>The sizes and masks for one FastCDC split.</summary>
/// <remarks>
/// Sizes follow the paper's names: <see cref="Average"/> is its NormalSize, the expected chunk
/// size, where the scan switches from <see cref="StrictMask"/> (its MaskS) to
/// <see cref="LooseMask"/> (its MaskL).
/// </remarks>
public sealed record FastCdcParameters
{
    private FastCdcParameters(int minimum, int average, int maximum, int level, ulong strict, ulong loose)
    {
        Minimum = minimum;
        Average = average;
        Maximum = maximum;
        NormalizationLevel = level;
        StrictMask = strict;
        LooseMask = loose;
    }

    /// <summary>No cut is considered before this many bytes.</summary>
    public int Minimum { get; }

    /// <summary>The expected chunk size, where the mask changes. A power of two.</summary>
    public int Average { get; }

    /// <summary>A chunk that finds no cut ends here.</summary>
    public int Maximum { get; }

    /// <summary>How many bits the masks are adjusted either side of the average.</summary>
    public int NormalizationLevel { get; }

    /// <summary>
    /// The mask used before <see cref="Average"/>: log2(average) plus the level in one bits,
    /// so cuts are rarer there than the average alone would make them.
    /// </summary>
    public ulong StrictMask { get; }

    /// <summary>
    /// The mask used from <see cref="Average"/> on: log2(average) minus the level in one
    /// bits, so a chunk that has passed the average is pulled towards a cut.
    /// </summary>
    public ulong LooseMask { get; }

    /// <summary>Builds and checks a parameter set.</summary>
    /// <param name="minimum">The minimum chunk size. Even, and greater than zero.</param>
    /// <param name="average">The average chunk size. A power of two, at least the minimum.</param>
    /// <param name="maximum">
    /// The maximum chunk size. Even, at least the average, and no more than
    /// <see cref="BlockSizer.MaximumBlockSize"/>.
    /// </param>
    /// <param name="normalizationLevel">From 0 (no normalization) to 3.</param>
    /// <returns>The parameters.</returns>
    /// <exception cref="ArgumentOutOfRangeException">A value was out of range.</exception>
    /// <remarks>
    /// Sizes must be even because the scan steps in pairs from the minimum: an odd minimum
    /// would let the first pair straddle it and allow a chunk one byte short of it.
    /// </remarks>
    public static FastCdcParameters Create(int minimum, int average, int maximum, int normalizationLevel)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(minimum);
        ArgumentOutOfRangeException.ThrowIfLessThan(average, minimum);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximum, average);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximum, BlockSizer.MaximumBlockSize);
        ArgumentOutOfRangeException.ThrowIfNegative(normalizationLevel);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(normalizationLevel, 3);

        if ((minimum & 1) != 0 || (maximum & 1) != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(minimum), "The minimum and maximum chunk sizes must be even.");
        }

        if (!BitOperations.IsPow2(average))
        {
            throw new ArgumentOutOfRangeException(
                nameof(average), average, "The average chunk size must be a power of two.");
        }

        var bits = BitOperations.Log2((uint)average);
        var masks = FastCdc.Masks;
        if (bits - normalizationLevel < 5 || bits + normalizationLevel >= masks.Length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(average), average, "There is no mask for that average at that level.");
        }

        return new FastCdcParameters(
            minimum,
            average,
            maximum,
            normalizationLevel,
            masks[bits + normalizationLevel],
            masks[bits - normalizationLevel]);
    }
}
