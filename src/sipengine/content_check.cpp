// content_check.cpp - what a received file really is, and where it may go.
//
// Direct Push's rule 4 (docs/DIRECT-PUSH.md): the receiving machine checks each file's bytes
// against its name. A mismatch goes to quarantine, an executable always goes to quarantine,
// and a file whose type is recognised by neither goes to the inbox marked unrecognised.
//
// What this code may do, and why it is safe to do it in native code:
//   - It reads only inside the caller's buffers. Every read of the file's bytes goes through
//     Has(), or indexes a span already cut to the length checked, so no index can leave a
//     buffer. The self-test runs every signature at every truncated length, and it and the
//     fuzz entry point are built under ASan and UBSan by build.ps1's audit.
//   - It allocates nothing, keeps no state, and throws nothing.
//
// What it cannot do, stated where the claim is made (standard A3): it catches a DISGUISED
// file, not a MALICIOUS one. A genuine JPEG can carry a malformed payload, and a file can be
// valid as two formats at once. The antivirus still scans whatever arrives.

#include "content_check.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <span>
#include <string_view>

namespace sipengine::content {
namespace {

using Bytes = std::span<const std::uint8_t>;

// ------------------------------------------------------------------------------------------
// Bounded reading. Nothing below indexes the file's bytes except through these, or through a
// span these have already cut to a checked length.
// ------------------------------------------------------------------------------------------

/// A byte as an unsigned 32-bit value, so no comparison or mask mixes signedness.
[[nodiscard]] constexpr std::uint32_t U(std::uint8_t b) noexcept { return b; }

/// Whether bytes holds count bytes starting at offset. Written so neither sum can wrap.
[[nodiscard]] constexpr bool Has(Bytes bytes, std::size_t offset, std::size_t count) noexcept
{
    return offset <= bytes.size() && count <= bytes.size() - offset;
}

/// Whether bytes holds exactly expected at offset.
[[nodiscard]] bool At(Bytes bytes, std::size_t offset, Bytes expected) noexcept
{
    if (!Has(bytes, offset, expected.size())) {
        return false;
    }

    const Bytes window = bytes.subspan(offset, expected.size());
    return std::equal(expected.begin(), expected.end(), window.begin());
}

/// Whether bytes holds the ASCII text expected at offset, exactly.
[[nodiscard]] bool AtText(Bytes bytes, std::size_t offset, std::string_view expected) noexcept
{
    if (!Has(bytes, offset, expected.size())) {
        return false;
    }

    const Bytes window = bytes.subspan(offset, expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        if (U(window[i]) != U(static_cast<std::uint8_t>(expected[i]))) {
            return false;
        }
    }

    return true;
}

[[nodiscard]] constexpr std::uint32_t LowerAscii(std::uint32_t c) noexcept
{
    return (c >= U('A') && c <= U('Z')) ? c + (U('a') - U('A')) : c;
}

/// Whether bytes starts with the lower-case ASCII text expected, ignoring ASCII case.
[[nodiscard]] bool StartsNoCase(Bytes bytes, std::string_view expected) noexcept
{
    if (!Has(bytes, 0, expected.size())) {
        return false;
    }

    const Bytes window = bytes.first(expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        if (LowerAscii(U(window[i])) != U(static_cast<std::uint8_t>(expected[i]))) {
            return false;
        }
    }

    return true;
}

[[nodiscard]] std::optional<std::uint32_t> Le16(Bytes bytes, std::size_t offset) noexcept
{
    if (!Has(bytes, offset, 2)) {
        return std::nullopt;
    }

    const Bytes w = bytes.subspan(offset, 2);
    return U(w[0]) | (U(w[1]) << 8U);
}

[[nodiscard]] std::optional<std::uint32_t> Le32(Bytes bytes, std::size_t offset) noexcept
{
    if (!Has(bytes, offset, 4)) {
        return std::nullopt;
    }

    const Bytes w = bytes.subspan(offset, 4);
    return U(w[0]) | (U(w[1]) << 8U) | (U(w[2]) << 16U) | (U(w[3]) << 24U);
}

[[nodiscard]] std::optional<std::uint32_t> Be32(Bytes bytes, std::size_t offset) noexcept
{
    if (!Has(bytes, offset, 4)) {
        return std::nullopt;
    }

    const Bytes w = bytes.subspan(offset, 4);
    return (U(w[0]) << 24U) | (U(w[1]) << 16U) | (U(w[2]) << 8U) | U(w[3]);
}

/// The byte at offset, widened, or nothing past the end.
[[nodiscard]] std::optional<std::uint32_t> ByteAt(Bytes bytes, std::size_t offset) noexcept
{
    if (!Has(bytes, offset, 1)) {
        return std::nullopt;
    }

    return U(bytes.subspan(offset, 1)[0]);
}

/// Whether any of the first count bytes is zero.
[[nodiscard]] bool HasZero(Bytes bytes, std::size_t count) noexcept
{
    const Bytes head = bytes.first(std::min(bytes.size(), count));
    return std::find(head.begin(), head.end(), std::uint8_t{0}) != head.end();
}

/// Whether the ASCII text expected occurs anywhere in bytes.
[[nodiscard]] bool Contains(Bytes bytes, std::string_view expected) noexcept
{
    if (expected.empty() || bytes.size() < expected.size()) {
        return false;
    }

    for (std::size_t offset = 0; offset <= bytes.size() - expected.size(); ++offset) {
        if (AtText(bytes, offset, expected)) {
            return true;
        }
    }

    return false;
}

[[nodiscard]] constexpr Detection Program(Type type) noexcept { return Detection{type, true}; }

[[nodiscard]] constexpr Detection Plain(Type type) noexcept { return Detection{type, false}; }

// ------------------------------------------------------------------------------------------
// Signatures. Byte strings with anything unprintable in them are spelled as arrays.
// ------------------------------------------------------------------------------------------

constexpr std::array<std::uint8_t, 4> PeSignature{'P', 'E', 0x00, 0x00};
constexpr std::array<std::uint8_t, 4> ElfMagic{0x7F, 'E', 'L', 'F'};
constexpr std::array<std::uint8_t, 4> MachO32Be{0xFE, 0xED, 0xFA, 0xCE};
constexpr std::array<std::uint8_t, 4> MachO32Le{0xCE, 0xFA, 0xED, 0xFE};
constexpr std::array<std::uint8_t, 4> MachO64Be{0xFE, 0xED, 0xFA, 0xCF};
constexpr std::array<std::uint8_t, 4> MachO64Le{0xCF, 0xFA, 0xED, 0xFE};
constexpr std::array<std::uint8_t, 4> CafeBabe{0xCA, 0xFE, 0xBA, 0xBE};
constexpr std::array<std::uint8_t, 4> CafeBabf{0xCA, 0xFE, 0xBA, 0xBF};
constexpr std::array<std::uint8_t, 3> Utf8Bom{0xEF, 0xBB, 0xBF};
constexpr std::array<std::uint8_t, 2> Utf16LeBom{0xFF, 0xFE};
constexpr std::array<std::uint8_t, 2> Utf16BeBom{0xFE, 0xFF};
constexpr std::array<std::uint8_t, 4> Utf32BeBom{0x00, 0x00, 0xFE, 0xFF};
constexpr std::array<std::uint8_t, 4> WasmMagic{0x00, 'a', 's', 'm'};
constexpr std::array<std::uint8_t, 4> DexMagic{'d', 'e', 'x', 0x0A};

// Compiled HTML Help: "ITSF", then version 3 ([MS-CHM]'s ITSF header, as file(1) reads it).
constexpr std::array<std::uint8_t, 8> ChmMagic{'I', 'T', 'S', 'F', 0x03, 0x00, 0x00, 0x00};

// A Windows shortcut: header size 0x4C, then CLSID {00021401-0000-0000-C000-000000000046}
// ([MS-SHLLINK] 2.1, ShellLinkHeader: HeaderSize and LinkCLSID).
constexpr std::array<std::uint8_t, 20> ShortcutHeader{
    0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};

// A compound file ([MS-CFB] 2.2, Header Signature).
constexpr std::array<std::uint8_t, 8> OleMagic{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};

// The root storage's CLSID for Windows Installer databases and validation modules, patches
// and transforms: {000C1084-...}, {000C1086-...} and {000C1082-...}, all ending
// C000-000000000046, as a GUID is laid out on disk. The same values file(1) recognises them
// by at offset 80 of the directory entry, in its magic database's ole2compounddocs, read
// 2026-09-19 (https://github.com/file/file/blob/master/magic/Magdir/ole2compounddocs).
constexpr auto InstallerClsids = std::to_array<std::array<std::uint8_t, 16>>({
    {0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
    {0x86, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
    {0x82, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
});

constexpr std::array<std::uint8_t, 8> PngMagic{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
constexpr std::array<std::uint8_t, 3> JpegMagic{0xFF, 0xD8, 0xFF};
constexpr std::array<std::uint8_t, 4> TiffLe{'I', 'I', 0x2A, 0x00};
constexpr std::array<std::uint8_t, 4> TiffBe{'M', 'M', 0x00, 0x2A};
constexpr std::array<std::uint8_t, 4> IcoMagic{0x00, 0x00, 0x01, 0x00};
constexpr std::array<std::uint8_t, 4> CurMagic{0x00, 0x00, 0x02, 0x00};
constexpr std::array<std::uint8_t, 2> JpegXlCodestream{0xFF, 0x0A};
constexpr std::array<std::uint8_t, 12> JpegXlContainer{
    0x00, 0x00, 0x00, 0x0C, 'J', 'X', 'L', ' ', 0x0D, 0x0A, 0x87, 0x0A};
constexpr std::array<std::uint8_t, 6> PsdMagic{'8', 'B', 'P', 'S', 0x00, 0x01};
constexpr std::array<std::uint8_t, 6> PsbMagic{'8', 'B', 'P', 'S', 0x00, 0x02};

constexpr std::array<std::uint8_t, 5> OggMagic{'O', 'g', 'g', 'S', 0x00};
constexpr std::array<std::uint8_t, 8> MidiMagic{'M', 'T', 'h', 'd', 0x00, 0x00, 0x00, 0x06};
constexpr std::array<std::uint8_t, 4> EbmlMagic{0x1A, 0x45, 0xDF, 0xA3};
constexpr std::array<std::uint8_t, 16> AsfMagic{
    0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C};
constexpr std::array<std::uint8_t, 4> FlvMagic{'F', 'L', 'V', 0x01};
constexpr std::array<std::uint8_t, 4> MpegPsMagic{0x00, 0x00, 0x01, 0xBA};

constexpr std::array<std::uint8_t, 4> EpsBinary{0xC5, 0xD0, 0xD3, 0xC6};
constexpr std::array<std::uint8_t, 4> ZipLocal{'P', 'K', 0x03, 0x04};
constexpr std::array<std::uint8_t, 4> ZipEmpty{'P', 'K', 0x05, 0x06};
constexpr std::array<std::uint8_t, 4> ZipSpanned{'P', 'K', 0x07, 0x08};
constexpr std::array<std::uint8_t, 6> SevenZipMagic{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
constexpr std::array<std::uint8_t, 7> Rar4Magic{'R', 'a', 'r', '!', 0x1A, 0x07, 0x00};
constexpr std::array<std::uint8_t, 8> Rar5Magic{'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00};
constexpr std::array<std::uint8_t, 3> GzipMagic{0x1F, 0x8B, 0x08};
constexpr std::array<std::uint8_t, 6> XzMagic{0xFD, '7', 'z', 'X', 'Z', 0x00};
constexpr std::array<std::uint8_t, 4> ZstdMagic{0x28, 0xB5, 0x2F, 0xFD};
constexpr std::array<std::uint8_t, 8> CabMagic{'M', 'S', 'C', 'F', 0x00, 0x00, 0x00, 0x00};

// bzip2's first block begins with the digits of pi, 0x314159265359.
constexpr std::array<std::uint8_t, 6> Bzip2Block{0x31, 0x41, 0x59, 0x26, 0x53, 0x59};

// The dynamic VHD header repeats the footer's cookie; VHDX starts with its file identifier.
constexpr std::string_view VhdCookie = "conectix";
constexpr std::string_view VhdxIdentifier = "vhdxfile";

// ISO 9660 and UDF: the volume descriptor set starts at sector 16 of 2048 bytes, and each
// descriptor's identifier follows its one-byte type (ECMA-119 8.1, ECMA-167 2/9.1).
constexpr std::size_t VolumeDescriptorIdentifier = 0x8001;

// ------------------------------------------------------------------------------------------
// Programs, and things Windows launches or mounts.
// ------------------------------------------------------------------------------------------

/// Whether a compound file's root storage is a Windows Installer package.
[[nodiscard]] bool IsInstallerStorage(Bytes bytes) noexcept
{
    // [MS-CFB] 2.2: the sector shift is at 0x1E (9 or 12, for 512- or 4096-byte sectors) and
    // the first directory sector's number at 0x30. Sector n starts at (n + 1) << shift, and
    // the directory's first entry is the root storage, whose CLSID is at 0x50 ([MS-CFB]
    // 2.6.1). When the directory lies beyond the head the engine reads, the package is not
    // recognised as one, and the file stays an ordinary compound file.
    const std::optional<std::uint32_t> shift = Le16(bytes, 0x1E);
    const std::optional<std::uint32_t> first = Le32(bytes, 0x30);
    if (!shift || !first || (*shift != 9U && *shift != 12U)) {
        return false;
    }

    const std::uint64_t directory = (static_cast<std::uint64_t>(*first) + 1U) << *shift;
    if (directory > bytes.size()) {
        return false;
    }

    const std::size_t clsid = static_cast<std::size_t>(directory) + 0x50U;
    return std::any_of(InstallerClsids.begin(), InstallerClsids.end(),
                       [&](const std::array<std::uint8_t, 16>& candidate) noexcept { return At(bytes, clsid, candidate); });
}

[[nodiscard]] Detection DosOrWindows(Bytes bytes) noexcept
{
    if (!AtText(bytes, 0, "MZ")) {
        return {};
    }

    // The PE header's offset is at 0x3C of the DOS header (PE Format, "MS-DOS Stub").
    if (const std::optional<std::uint32_t> header = Le32(bytes, 0x3C); header && At(bytes, *header, PeSignature)) {
        return Program(Type::WindowsProgram);
    }

    // A DOS header is binary. A text file that merely begins "MZ" has no zero byte in the
    // header's 64 bytes, and stays text.
    return HasZero(bytes, 64) ? Program(Type::DosProgram) : Detection{};
}

[[nodiscard]] Detection DiskImageOf(Bytes bytes) noexcept
{
    if (AtText(bytes, 0, VhdxIdentifier) || AtText(bytes, 0, VhdCookie) ||
        AtText(bytes, VolumeDescriptorIdentifier, "CD001") || AtText(bytes, VolumeDescriptorIdentifier, "BEA01")) {
        return Program(Type::DiskImage);
    }

    return {};
}

/// Content that runs, or that Windows opens as something that can run, whatever its name.
[[nodiscard]] Detection Programs(Bytes bytes) noexcept
{
    if (const Detection dos = DosOrWindows(bytes); dos.executable) {
        return dos;
    }

    if (At(bytes, 0, ElfMagic)) {
        return Program(Type::Elf);
    }

    if (At(bytes, 0, MachO32Be) || At(bytes, 0, MachO32Le) || At(bytes, 0, MachO64Be) || At(bytes, 0, MachO64Le)) {
        return Program(Type::MachO);
    }

    if (At(bytes, 0, CafeBabf)) {
        return Program(Type::MachOFat);
    }

    if (At(bytes, 0, CafeBabe)) {
        // The same four bytes open a universal Mach-O binary and a Java class. A universal
        // binary counts its architectures next, a handful; a class file has its minor and
        // major version there, and major versions start at 45 (the rule file(1) uses).
        const std::optional<std::uint32_t> next = Be32(bytes, 4);
        return Program(next && *next > 0U && *next < 45U ? Type::MachOFat : Type::JavaClass);
    }

    // A script names its interpreter on its first line; with a byte order mark in front it
    // no longer runs on Unix, and is still quarantined, because it is still a script.
    if (AtText(bytes, 0, "#!") || (At(bytes, 0, Utf8Bom) && AtText(bytes, Utf8Bom.size(), "#!"))) {
        return Program(Type::Script);
    }

    if (At(bytes, 0, ShortcutHeader)) {
        return Program(Type::Shortcut);
    }

    // Windows Script Encoder output starts with its marker ("#@~^"), for .vbe and .jse.
    if (AtText(bytes, 0, "#@~^")) {
        return Program(Type::EncodedScript);
    }

    if (At(bytes, 0, WasmMagic)) {
        return Program(Type::WebAssembly);
    }

    if (At(bytes, 0, DexMagic)) {
        return Program(Type::AndroidDex);
    }

    // Compiled HTML Help runs script when opened, which is why Windows blocks .chm by name.
    if (At(bytes, 0, ChmMagic)) {
        return Program(Type::CompiledHelp);
    }

    if (At(bytes, 0, OleMagic) && IsInstallerStorage(bytes)) {
        return Program(Type::WindowsInstaller);
    }

    return DiskImageOf(bytes);
}

// ------------------------------------------------------------------------------------------
// Formats with a signature strong enough to trust before looking at whether it is text.
// ------------------------------------------------------------------------------------------

/// ISO base media files (ISO/IEC 14496-12): a size, 'ftyp', then the major brand.
[[nodiscard]] Type IsoMedia(Bytes bytes) noexcept
{
    const std::optional<std::uint32_t> size = Be32(bytes, 0);

    if (!AtText(bytes, 4, "ftyp")) {
        // QuickTime files from before 'ftyp' start straight with an atom.
        const bool atom = AtText(bytes, 4, "moov") || AtText(bytes, 4, "mdat") || AtText(bytes, 4, "wide") ||
                          AtText(bytes, 4, "free") || AtText(bytes, 4, "skip") || AtText(bytes, 4, "pnot");
        return size && *size >= 8U && atom ? Type::QuickTime : Type::Unknown;
    }

    if (!size || *size < 16U || !Has(bytes, 8, 4)) {
        return Type::Unknown;
    }

    for (const std::string_view brand : {"heic", "heix", "hevc", "hevx", "heim", "heis", "hevm", "hevs", "mif1", "msf1"}) {
        if (AtText(bytes, 8, brand)) {
            return Type::Heif;
        }
    }

    if (AtText(bytes, 8, "avif") || AtText(bytes, 8, "avis")) {
        return Type::Avif;
    }

    if (AtText(bytes, 8, "M4A ") || AtText(bytes, 8, "M4B ") || AtText(bytes, 8, "M4P ")) {
        return Type::M4a;
    }

    if (AtText(bytes, 8, "qt  ")) {
        return Type::QuickTime;
    }

    if (AtText(bytes, 8, "3gp") || AtText(bytes, 8, "3g2")) {
        return Type::ThreeGp;
    }

    return Type::Mp4;
}

/// A bitmap: "BM", then reserved fields that must be zero, and the pixel data's offset past
/// the headers (BITMAPFILEHEADER).
[[nodiscard]] bool IsBitmap(Bytes bytes) noexcept
{
    const std::optional<std::uint32_t> reserved = Le32(bytes, 6);
    const std::optional<std::uint32_t> pixels = Le32(bytes, 10);
    return AtText(bytes, 0, "BM") && reserved && *reserved == 0U && pixels && *pixels >= 26U;
}

/// An icon or cursor: a zero reserved word, the resource type, a count of 1 to 255, and room
/// for at least one directory entry.
[[nodiscard]] bool IsIcon(Bytes bytes) noexcept
{
    const std::optional<std::uint32_t> count = Le16(bytes, 4);
    return (At(bytes, 0, IcoMagic) || At(bytes, 0, CurMagic)) && count && *count >= 1U && *count <= 255U &&
           Has(bytes, 6, 16);
}

/// ID3v2: "ID3", a major version from 2 to 4, a zero revision, and a size of four 7-bit bytes.
[[nodiscard]] bool IsId3(Bytes bytes) noexcept
{
    if (!AtText(bytes, 0, "ID3") || !Has(bytes, 0, 10)) {
        return false;
    }

    const Bytes header = bytes.first(10);
    const bool version = U(header[3]) >= 2U && U(header[3]) <= 4U && U(header[4]) == 0U;
    const bool size = (U(header[6]) & 0x80U) == 0U && (U(header[7]) & 0x80U) == 0U &&
                      (U(header[8]) & 0x80U) == 0U && (U(header[9]) & 0x80U) == 0U;
    return version && size;
}

[[nodiscard]] Type Images(Bytes bytes) noexcept
{
    if (At(bytes, 0, PngMagic)) {
        return Type::Png;
    }

    if (At(bytes, 0, JpegMagic)) {
        return Type::Jpeg;
    }

    if (AtText(bytes, 0, "GIF87a") || AtText(bytes, 0, "GIF89a")) {
        return Type::Gif;
    }

    if (IsBitmap(bytes)) {
        return Type::Bmp;
    }

    if (At(bytes, 0, TiffLe) || At(bytes, 0, TiffBe)) {
        return Type::Tiff;
    }

    if (AtText(bytes, 0, "RIFF") && AtText(bytes, 8, "WEBP")) {
        return Type::Webp;
    }

    if (IsIcon(bytes)) {
        return Type::Ico;
    }

    if (At(bytes, 0, PsdMagic) || At(bytes, 0, PsbMagic)) {
        return Type::Psd;
    }

    if (At(bytes, 0, JpegXlCodestream) || At(bytes, 0, JpegXlContainer)) {
        return Type::JpegXl;
    }

    return Type::Unknown;
}

[[nodiscard]] Type AudioAndVideo(Bytes bytes) noexcept
{
    if (const Type media = IsoMedia(bytes); media != Type::Unknown) {
        return media;
    }

    if (IsId3(bytes)) {
        return Type::Mp3;
    }

    if ((AtText(bytes, 0, "RIFF") || AtText(bytes, 0, "RF64")) && AtText(bytes, 8, "WAVE")) {
        return Type::Wav;
    }

    if (AtText(bytes, 0, "RIFF") && AtText(bytes, 8, "AVI ")) {
        return Type::Avi;
    }

    // The first metadata block is STREAMINFO: type 0, with or without the last-block bit.
    if (const std::optional<std::uint32_t> block = ByteAt(bytes, 4); AtText(bytes, 0, "fLaC") && block &&
                                                                      (*block & 0x7FU) == 0U) {
        return Type::Flac;
    }

    if (At(bytes, 0, OggMagic)) {
        return Type::Ogg;
    }

    if (At(bytes, 0, MidiMagic)) {
        return Type::Midi;
    }

    if (AtText(bytes, 0, "FORM") && (AtText(bytes, 8, "AIFF") || AtText(bytes, 8, "AIFC"))) {
        return Type::Aiff;
    }

    if (At(bytes, 0, EbmlMagic)) {
        return Type::Matroska;
    }

    if (At(bytes, 0, AsfMagic)) {
        return Type::Asf;
    }

    if (At(bytes, 0, FlvMagic)) {
        return Type::Flv;
    }

    if (At(bytes, 0, MpegPsMagic)) {
        return Type::MpegPs;
    }

    return Type::Unknown;
}

[[nodiscard]] Type DocumentsAndArchives(Bytes bytes) noexcept
{
    if (AtText(bytes, 0, "%PDF-")) {
        return Type::Pdf;
    }

    if (AtText(bytes, 0, "{\\rtf")) {
        return Type::Rtf;
    }

    if (At(bytes, 0, OleMagic)) {
        return Type::Ole;
    }

    if (AtText(bytes, 0, "%!PS") || At(bytes, 0, EpsBinary)) {
        return Type::PostScript;
    }

    if (At(bytes, 0, ZipLocal) || At(bytes, 0, ZipEmpty) || At(bytes, 0, ZipSpanned)) {
        return Type::Zip;
    }

    if (At(bytes, 0, SevenZipMagic)) {
        return Type::SevenZip;
    }

    if (At(bytes, 0, Rar4Magic) || At(bytes, 0, Rar5Magic)) {
        return Type::Rar;
    }

    if (At(bytes, 0, GzipMagic)) {
        return Type::Gzip;
    }

    if (const std::optional<std::uint32_t> level = ByteAt(bytes, 3);
        AtText(bytes, 0, "BZh") && At(bytes, 4, Bzip2Block) && level && *level >= U('1') && *level <= U('9')) {
        return Type::Bzip2;
    }

    if (At(bytes, 0, XzMagic)) {
        return Type::Xz;
    }

    if (At(bytes, 0, ZstdMagic)) {
        return Type::Zstd;
    }

    // POSIX ustar: the magic sits at 257 of the first 512-byte header.
    if (AtText(bytes, 257, "ustar")) {
        return Type::Tar;
    }

    if (At(bytes, 0, CabMagic)) {
        return Type::Cab;
    }

    return Type::Unknown;
}

[[nodiscard]] Type StrongFormat(Bytes bytes) noexcept
{
    if (const Type image = Images(bytes); image != Type::Unknown) {
        return image;
    }

    if (const Type media = AudioAndVideo(bytes); media != Type::Unknown) {
        return media;
    }

    return DocumentsAndArchives(bytes);
}

// ------------------------------------------------------------------------------------------
// Text, and the formats too weak to trust over text.
// ------------------------------------------------------------------------------------------

/// Control characters plain text may hold: backspace, tab, the line breaks, form feed, the
/// DOS end-of-file mark and escape (colour codes in logs).
[[nodiscard]] constexpr bool IsTextControl(std::uint32_t c) noexcept
{
    return c == 0x08U || c == 0x09U || c == 0x0AU || c == 0x0BU || c == 0x0CU || c == 0x0DU || c == 0x1AU ||
           c == 0x1BU;
}

[[nodiscard]] constexpr bool IsSpace(std::uint32_t c) noexcept
{
    return c == U(' ') || c == U('\t') || c == U('\r') || c == U('\n') || c == U('\f') || c == U('\v');
}

// Text, HTML or XML; or Unknown when the bytes are not text. Any byte order mark is text.
// Otherwise text is bytes with no zero and no control character outside IsTextControl.
// Bytes above 0x7F are allowed, so text saved in an older Windows code page is still text.
[[nodiscard]] Type TextKind(Bytes bytes) noexcept
{
    if (At(bytes, 0, Utf16LeBom) || At(bytes, 0, Utf16BeBom) || At(bytes, 0, Utf32BeBom)) {
        return Type::Text;
    }

    for (const std::uint8_t b : bytes) {
        if (const std::uint32_t c = U(b); c == 0U || (c < 0x20U && !IsTextControl(c))) {
            return Type::Unknown;
        }
    }

    Bytes rest = At(bytes, 0, Utf8Bom) ? bytes.subspan(Utf8Bom.size()) : bytes;
    while (!rest.empty() && IsSpace(U(rest.front()))) {
        rest = rest.subspan(1);
    }

    if (StartsNoCase(rest, "<!doctype html") || StartsNoCase(rest, "<html")) {
        return Type::Html;
    }

    if (StartsNoCase(rest, "<?xml") || StartsNoCase(rest, "<svg")) {
        return Type::Xml;
    }

    return Type::Text;
}

/// MPEG audio from a frame header: an 11-bit sync, then the header's fields. ADTS AAC has
/// the same sync with a zero layer (ISO/IEC 11172-3 and 13818-7).
[[nodiscard]] Type MpegAudio(Bytes bytes) noexcept
{
    if (!Has(bytes, 0, 4)) {
        return Type::Unknown;
    }

    const Bytes header = bytes.first(4);
    const std::uint32_t second = U(header[1]);
    const std::uint32_t third = U(header[2]);

    if (U(header[0]) != 0xFFU) {
        return Type::Unknown;
    }

    if ((second & 0xF6U) == 0xF0U) {
        return Type::Aac;
    }

    if ((second & 0xE0U) != 0xE0U) {
        return Type::Unknown;
    }

    const std::uint32_t layer = (second >> 1U) & 0x03U;
    const std::uint32_t bitrate = (third >> 4U) & 0x0FU;
    const std::uint32_t rate = (third >> 2U) & 0x03U;
    return layer != 0U && bitrate != 0x0FU && rate != 0x03U ? Type::Mp3 : Type::Unknown;
}

/// An MPEG transport stream: the sync byte 0x47 opening three packets in a row, of 188
/// bytes, or of 192 for the Blu-ray form with a four-byte timestamp in front.
[[nodiscard]] bool IsTransportStream(Bytes bytes) noexcept
{
    const auto syncAt = [&](std::size_t offset) noexcept {
        const std::optional<std::uint32_t> b = ByteAt(bytes, offset);
        return b && *b == 0x47U;
    };

    return (syncAt(0) && syncAt(188) && syncAt(376)) || (syncAt(4) && syncAt(196) && syncAt(388));
}

[[nodiscard]] Type WeakFormat(Bytes bytes) noexcept
{
    return IsTransportStream(bytes) ? Type::MpegTs : MpegAudio(bytes);
}

// ------------------------------------------------------------------------------------------
// Names.
// ------------------------------------------------------------------------------------------

/// What a name's extension claims: the types a file so named may hold. The first is the
/// type the name claims; unused places are Unknown, which nothing matches.
struct NameRule {
    std::string_view extension;
    std::array<Type, 6> accepts;
};

constexpr std::array<Type, 6> TextFamily{Type::Text, Type::Html, Type::Xml, Type::Rtf};
constexpr std::array<Type, 6> IsoVideo{Type::Mp4, Type::QuickTime, Type::M4a, Type::ThreeGp};

// Only extensions whose content is certain. An extension not listed claims nothing, and its
// file is judged by its content alone.
constexpr auto NameRules = std::to_array<NameRule>({
    {"png", {Type::Png}}, {"jpg", {Type::Jpeg}}, {"jpeg", {Type::Jpeg}}, {"jpe", {Type::Jpeg}},
    {"jfif", {Type::Jpeg}}, {"pjpeg", {Type::Jpeg}}, {"pjp", {Type::Jpeg}}, {"gif", {Type::Gif}},
    {"bmp", {Type::Bmp}}, {"dib", {Type::Bmp}}, {"tif", {Type::Tiff}}, {"tiff", {Type::Tiff}},
    {"webp", {Type::Webp}}, {"ico", {Type::Ico}}, {"cur", {Type::Ico}}, {"heic", {Type::Heif}},
    {"heif", {Type::Heif}}, {"heics", {Type::Heif}}, {"heifs", {Type::Heif}}, {"avif", {Type::Avif}},
    {"psd", {Type::Psd}}, {"psb", {Type::Psd}}, {"jxl", {Type::JpegXl}},
    {"svg", {Type::Xml, Type::Text, Type::Html}},

    {"mp3", {Type::Mp3}}, {"wav", {Type::Wav}}, {"flac", {Type::Flac}}, {"ogg", {Type::Ogg}},
    {"oga", {Type::Ogg}}, {"ogv", {Type::Ogg}}, {"opus", {Type::Ogg}}, {"m4a", {Type::M4a, Type::Mp4}},
    {"m4b", {Type::M4a, Type::Mp4}}, {"aac", {Type::Aac, Type::M4a, Type::Mp4}}, {"mid", {Type::Midi}},
    {"midi", {Type::Midi}}, {"aif", {Type::Aiff}}, {"aiff", {Type::Aiff}}, {"aifc", {Type::Aiff}},
    {"wma", {Type::Asf}},

    {"mp4", IsoVideo}, {"m4v", {Type::Mp4, Type::QuickTime}}, {"mov", {Type::QuickTime, Type::Mp4}},
    {"qt", {Type::QuickTime, Type::Mp4}}, {"3gp", {Type::ThreeGp, Type::Mp4}}, {"3g2", {Type::ThreeGp, Type::Mp4}},
    {"mkv", {Type::Matroska}}, {"mka", {Type::Matroska}}, {"mk3d", {Type::Matroska}}, {"webm", {Type::Matroska}},
    {"avi", {Type::Avi}}, {"wmv", {Type::Asf}}, {"asf", {Type::Asf}}, {"flv", {Type::Flv}},
    {"m2ts", {Type::MpegTs}}, {"mts", {Type::MpegTs}}, {"ts", {Type::MpegTs, Type::Text}},
    {"mpg", {Type::MpegPs}}, {"mpeg", {Type::MpegPs}}, {"vob", {Type::MpegPs}},

    {"pdf", {Type::Pdf}}, {"rtf", {Type::Rtf}},
    // Word and Excel have always saved other formats under their old extensions.
    {"doc", {Type::Ole, Type::Rtf, Type::Html, Type::Xml}}, {"xls", {Type::Ole, Type::Html, Type::Xml, Type::Text}},
    {"dot", {Type::Ole}}, {"xlt", {Type::Ole}}, {"ppt", {Type::Ole}}, {"pot", {Type::Ole}},
    {"pps", {Type::Ole}}, {"msg", {Type::Ole}}, {"vsd", {Type::Ole}}, {"pub", {Type::Ole}},
    {"docx", {Type::Zip}}, {"docm", {Type::Zip}}, {"dotx", {Type::Zip}}, {"dotm", {Type::Zip}},
    {"xlsx", {Type::Zip}}, {"xlsm", {Type::Zip}}, {"xltx", {Type::Zip}}, {"pptx", {Type::Zip}},
    {"pptm", {Type::Zip}}, {"ppsx", {Type::Zip}}, {"potx", {Type::Zip}}, {"vsdx", {Type::Zip}},
    {"odt", {Type::Zip}}, {"ods", {Type::Zip}}, {"odp", {Type::Zip}}, {"odg", {Type::Zip}},
    {"epub", {Type::Zip}}, {"xps", {Type::Zip}}, {"oxps", {Type::Zip}},
    {"ps", {Type::PostScript}}, {"eps", {Type::PostScript}},

    {"zip", {Type::Zip}}, {"7z", {Type::SevenZip}}, {"rar", {Type::Rar}}, {"gz", {Type::Gzip}},
    {"tgz", {Type::Gzip}}, {"bz2", {Type::Bzip2}}, {"tbz2", {Type::Bzip2}}, {"xz", {Type::Xz}},
    {"txz", {Type::Xz}}, {"zst", {Type::Zstd}}, {"tar", {Type::Tar}},

    {"txt", TextFamily}, {"text", TextFamily}, {"md", TextFamily}, {"markdown", TextFamily},
    {"csv", TextFamily}, {"tsv", TextFamily}, {"log", TextFamily}, {"ini", TextFamily},
    {"cfg", TextFamily}, {"conf", TextFamily}, {"yaml", TextFamily}, {"yml", TextFamily},
    {"toml", TextFamily}, {"json", TextFamily}, {"xml", TextFamily}, {"html", TextFamily},
    {"htm", TextFamily}, {"xhtml", TextFamily}, {"css", TextFamily}, {"tex", TextFamily},
    {"srt", TextFamily}, {"vtt", TextFamily}, {"sql", TextFamily}, {"c", TextFamily},
    {"h", TextFamily}, {"cpp", TextFamily}, {"hpp", TextFamily}, {"cs", TextFamily},
});

// Names Windows runs or installs. The attachment types Outlook blocks, from Microsoft's
// published list, read 2026-09-19 ("Blocked attachments in Outlook",
// https://support.microsoft.com/en-us/office/blocked-attachments-in-outlook-434752e1-02d3-4e90-9124-8b81e49a8519),
// then SippBucket's additions: packages Windows installs and program files it loads that the
// list leaves out, and PowerShell's script modules.
constexpr auto ExecutableExtensions = std::to_array<std::string_view>({
    // Microsoft's list.
    "ade", "adp", "apk", "app", "appcontent-ms", "application", "appref-ms", "appx", "asp", "aspx",
    "asx", "bas", "bat", "bgi", "cab", "cdxml", "cer", "chm", "cmd", "cnt",
    "com", "cpl", "crt", "csh", "der", "diagcab", "exe", "fxp", "gadget", "grp",
    "hlp", "hpj", "hta", "htc", "img", "inf", "ins", "iso", "isp", "its",
    "jar", "jnlp", "js", "jse", "ksh", "library-ms", "lnk", "mad", "maf", "mag",
    "mam", "maq", "mar", "mas", "mat", "mau", "mav", "maw", "mcf", "mda",
    "mdb", "mde", "mdt", "mdw", "mdz", "msc", "mht", "mhtml", "msh", "msh1",
    "msh2", "mshxml", "msh1xml", "msh2xml", "msi", "msp", "mst", "msu", "ops", "osd",
    "pcd", "pif", "pl", "plg", "prf", "prg", "printerexport", "ps1", "ps1xml", "ps2",
    "ps2xml", "psc1", "psc2", "psd1", "psdm1", "pssc", "pst", "py", "pyc", "pyo",
    "pyw", "pyz", "pyzw", "reg", "scf", "scr", "sct", "search-ms", "settingcontent-ms", "shb",
    "shs", "theme", "tmp", "udl", "url", "vb", "vbe", "vbp", "vbs", "vhd",
    "vhdx", "vsmacros", "vsw", "webpnp", "website", "ws", "wsb", "wsc", "wsf", "wsh",
    "xbap", "xll", "xnk",
    // SippBucket's additions.
    "appinstaller", "appxbundle", "msix", "msixbundle", "psm1", "dll", "ocx", "sys", "drv", "efi",
});

/// The longest extension worth looking up. Longer ones are in no list.
constexpr std::size_t LongestExtension = 32;

// A name's extension, lower-cased ASCII, into storage the caller owns. Judged as Windows
// opens the file: only the last path component counts, and trailing dots and spaces are
// dropped, so "run.exe." and "run.exe " are "exe". The extension is what follows the last
// dot. None when there is no dot, the dot is last, or the extension is longer than
// LongestExtension.
[[nodiscard]] std::string_view NameExtension(Bytes name, std::array<char, LongestExtension>& storage) noexcept
{
    std::size_t end = name.size();
    while (end > 0U && (U(name[end - 1U]) == U('.') || U(name[end - 1U]) == U(' '))) {
        --end;
    }

    std::size_t start = end;
    while (start > 0U && U(name[start - 1U]) != U('/') && U(name[start - 1U]) != U('\\')) {
        --start;
    }

    const Bytes component = name.subspan(start, end - start);
    const auto dot = std::find(component.rbegin(), component.rend(), std::uint8_t{'.'});
    if (dot == component.rend()) {
        return {};
    }

    // Everything after the last dot: the distance back from the end to the dot counts them.
    const auto length = static_cast<std::size_t>(std::distance(component.rbegin(), dot));
    if (length == 0U || length > storage.size()) {
        return {};
    }

    const Bytes extension = component.last(length);
    const std::span<char> out(storage);
    for (std::size_t i = 0; i < length; ++i) {
        out[i] = static_cast<char>(LowerAscii(U(extension[i])));
    }

    return std::string_view(storage.data(), length);
}

[[nodiscard]] const NameRule* RuleFor(std::string_view extension) noexcept
{
    // Not auto*: a std::array iterator is a class, not a pointer, in MSVC's library.
    const auto found = std::find_if(NameRules.begin(), NameRules.end(),
                                    [&](const NameRule& rule) noexcept { return rule.extension == extension; });
    return found == NameRules.end() ? nullptr : &*found;
}

[[nodiscard]] bool IsExecutableName(std::string_view extension) noexcept
{
    return std::find(ExecutableExtensions.begin(), ExecutableExtensions.end(), extension) != ExecutableExtensions.end();
}

[[nodiscard]] bool Accepts(const NameRule& rule, Type type) noexcept
{
    return type != Type::Unknown && std::find(rule.accepts.begin(), rule.accepts.end(), type) != rule.accepts.end();
}

// ------------------------------------------------------------------------------------------
// Type information, for people and for releasing a file under the name its content matches.
// ------------------------------------------------------------------------------------------

struct TypeInfo {
    Type type;
    std::string_view name;
    std::string_view extension;
};

constexpr auto TypeInfos = std::to_array<TypeInfo>({
    {Type::Unknown, "unrecognised", ""},
    {Type::Png, "PNG image", "png"},
    {Type::Jpeg, "JPEG image", "jpg"},
    {Type::Gif, "GIF image", "gif"},
    {Type::Bmp, "bitmap image", "bmp"},
    {Type::Tiff, "TIFF image", "tif"},
    {Type::Webp, "WebP image", "webp"},
    {Type::Ico, "icon", "ico"},
    {Type::Heif, "HEIF image", "heic"},
    {Type::Avif, "AVIF image", "avif"},
    {Type::Psd, "Photoshop image", "psd"},
    {Type::JpegXl, "JPEG XL image", "jxl"},
    {Type::Mp3, "MP3 audio", "mp3"},
    {Type::Wav, "WAV audio", "wav"},
    {Type::Flac, "FLAC audio", "flac"},
    {Type::Ogg, "Ogg media", "ogg"},
    {Type::M4a, "MPEG-4 audio", "m4a"},
    {Type::Aac, "AAC audio", "aac"},
    {Type::Midi, "MIDI music", "mid"},
    {Type::Aiff, "AIFF audio", "aiff"},
    {Type::Mp4, "MPEG-4 video", "mp4"},
    {Type::QuickTime, "QuickTime video", "mov"},
    {Type::Matroska, "Matroska or WebM video", "mkv"},
    {Type::Avi, "AVI video", "avi"},
    {Type::Asf, "Windows Media file", "wmv"},
    {Type::Flv, "Flash video", "flv"},
    {Type::MpegTs, "MPEG transport stream", "ts"},
    {Type::MpegPs, "MPEG video", "mpg"},
    {Type::ThreeGp, "3GP video", "3gp"},
    {Type::Pdf, "PDF document", "pdf"},
    {Type::Rtf, "RTF document", "rtf"},
    // Word, Excel, PowerPoint and Outlook all use it, so no one extension is right.
    {Type::Ole, "Office 97-2003 document", ""},
    {Type::PostScript, "PostScript document", "ps"},
    {Type::Zip, "ZIP archive or Office document", "zip"},
    {Type::SevenZip, "7-Zip archive", "7z"},
    {Type::Rar, "RAR archive", "rar"},
    {Type::Gzip, "gzip archive", "gz"},
    {Type::Bzip2, "bzip2 archive", "bz2"},
    {Type::Xz, "xz archive", "xz"},
    {Type::Zstd, "Zstandard archive", "zst"},
    {Type::Tar, "tar archive", "tar"},
    {Type::Cab, "Windows cabinet", "cab"},
    {Type::Text, "text", "txt"},
    {Type::Html, "HTML page", "html"},
    {Type::Xml, "XML document", "xml"},
    {Type::WindowsProgram, "Windows program", "exe"},
    {Type::DosProgram, "DOS program", "exe"},
    {Type::Elf, "Linux or Unix program", ""},
    {Type::MachO, "macOS program", ""},
    {Type::MachOFat, "macOS program", ""},
    {Type::JavaClass, "Java program", "class"},
    {Type::Script, "script", ""},
    {Type::Shortcut, "Windows shortcut", "lnk"},
    {Type::WindowsInstaller, "Windows Installer package", "msi"},
    {Type::EncodedScript, "encoded Windows script", "vbe"},
    {Type::WebAssembly, "WebAssembly program", "wasm"},
    {Type::AndroidDex, "Android program", "dex"},
    {Type::CompiledHelp, "compiled help file", "chm"},
    {Type::DiskImage, "disk image", "iso"},
});

[[nodiscard]] const TypeInfo* InfoFor(std::uint32_t type) noexcept
{
    const auto found = std::find_if(TypeInfos.begin(), TypeInfos.end(), [&](const TypeInfo& info) noexcept {
        return static_cast<std::uint32_t>(info.type) == type;
    });
    return found == TypeInfos.end() ? nullptr : &*found;
}

}  // namespace

Detection Identify(std::span<const std::uint8_t> head, std::uint64_t total) noexcept
{
    const Bytes bytes = head.first(std::min<std::size_t>(head.size(), SIPE_CONTENT_HEAD_BYTES));

    if (bytes.empty()) {
        // An empty file holds nothing a text name could contradict. Bytes promised and not
        // given are not known to be anything.
        return Plain(total == 0U ? Type::Text : Type::Unknown);
    }

    if (const Detection program = Programs(bytes); program.executable) {
        return program;
    }

    if (const Type strong = StrongFormat(bytes); strong != Type::Unknown) {
        return Plain(strong);
    }

    if (const Type text = TextKind(bytes); text != Type::Unknown) {
        return Plain(text);
    }

    return Plain(WeakFormat(bytes));
}

Result Check(std::span<const std::uint8_t> head, std::uint64_t total, std::span<const std::uint8_t> name) noexcept
{
    Detection detected = Identify(head, total);

    std::array<char, LongestExtension> storage{};
    const std::string_view extension = NameExtension(name, storage);
    const NameRule* rule = extension.empty() ? nullptr : RuleFor(extension);
    const bool executableName = !extension.empty() && IsExecutableName(extension);
    const Type claimed = rule == nullptr ? Type::Unknown : rule->accepts.front();

    // Acrobat's own tolerance: a PDF's header may follow up to 1024 bytes of something else.
    // Honoured only for a file named as a PDF, so text that mentions "%PDF-" stays text.
    if (rule != nullptr && Accepts(*rule, Type::Pdf) && detected.type != Type::Pdf && !detected.executable &&
        Contains(head.first(std::min<std::size_t>(head.size(), 1024U)), "%PDF-")) {
        detected = Plain(Type::Pdf);
    }

    if (detected.executable) {
        return Result{SIPE_VERDICT_QUARANTINE, SIPE_REASON_EXECUTABLE_CONTENT, detected.type, claimed};
    }

    if (executableName) {
        return Result{SIPE_VERDICT_QUARANTINE, SIPE_REASON_EXECUTABLE_NAME, detected.type, claimed};
    }

    if (rule != nullptr) {
        return Accepts(*rule, detected.type)
                   ? Result{SIPE_VERDICT_INBOX, SIPE_REASON_NONE, detected.type, claimed}
                   : Result{SIPE_VERDICT_QUARANTINE, SIPE_REASON_MISMATCH, detected.type, claimed};
    }

    return detected.type == Type::Unknown
               ? Result{SIPE_VERDICT_INBOX_UNRECOGNISED, SIPE_REASON_NONE, detected.type, claimed}
               : Result{SIPE_VERDICT_INBOX, SIPE_REASON_NONE, detected.type, claimed};
}

std::optional<std::string_view> NameOf(std::uint32_t type) noexcept
{
    const TypeInfo* info = InfoFor(type);
    return info == nullptr ? std::nullopt : std::optional<std::string_view>(info->name);
}

std::optional<std::string_view> ExtensionOf(std::uint32_t type) noexcept
{
    const TypeInfo* info = InfoFor(type);
    return info == nullptr ? std::nullopt : std::optional<std::string_view>(info->extension);
}

}  // namespace sipengine::content
