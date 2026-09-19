// content_check.hpp - the content check's C++ surface, shared by the exports and the
// self-test. Nothing here crosses the DLL boundary; sipengine.h is the ABI.

#ifndef SIPENGINE_CONTENT_CHECK_HPP
#define SIPENGINE_CONTENT_CHECK_HPP

#include "sipengine.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace sipengine::content {

/// A content type. Every value is the ABI's SIPE_TYPE_* number for it.
enum class Type : std::uint32_t {
    Unknown = SIPE_TYPE_UNKNOWN,

    Png = SIPE_TYPE_PNG,
    Jpeg = SIPE_TYPE_JPEG,
    Gif = SIPE_TYPE_GIF,
    Bmp = SIPE_TYPE_BMP,
    Tiff = SIPE_TYPE_TIFF,
    Webp = SIPE_TYPE_WEBP,
    Ico = SIPE_TYPE_ICO,
    Heif = SIPE_TYPE_HEIF,
    Avif = SIPE_TYPE_AVIF,
    Psd = SIPE_TYPE_PSD,
    JpegXl = SIPE_TYPE_JPEG_XL,

    Mp3 = SIPE_TYPE_MP3,
    Wav = SIPE_TYPE_WAV,
    Flac = SIPE_TYPE_FLAC,
    Ogg = SIPE_TYPE_OGG,
    M4a = SIPE_TYPE_M4A,
    Aac = SIPE_TYPE_AAC,
    Midi = SIPE_TYPE_MIDI,
    Aiff = SIPE_TYPE_AIFF,

    Mp4 = SIPE_TYPE_MP4,
    QuickTime = SIPE_TYPE_QUICKTIME,
    Matroska = SIPE_TYPE_MATROSKA,
    Avi = SIPE_TYPE_AVI,
    Asf = SIPE_TYPE_ASF,
    Flv = SIPE_TYPE_FLV,
    MpegTs = SIPE_TYPE_MPEG_TS,
    MpegPs = SIPE_TYPE_MPEG_PS,
    ThreeGp = SIPE_TYPE_3GP,

    Pdf = SIPE_TYPE_PDF,
    Rtf = SIPE_TYPE_RTF,
    Ole = SIPE_TYPE_OLE,
    PostScript = SIPE_TYPE_POSTSCRIPT,

    Zip = SIPE_TYPE_ZIP,
    SevenZip = SIPE_TYPE_7Z,
    Rar = SIPE_TYPE_RAR,
    Gzip = SIPE_TYPE_GZIP,
    Bzip2 = SIPE_TYPE_BZIP2,
    Xz = SIPE_TYPE_XZ,
    Zstd = SIPE_TYPE_ZSTD,
    Tar = SIPE_TYPE_TAR,
    Cab = SIPE_TYPE_CAB,

    Text = SIPE_TYPE_TEXT,
    Html = SIPE_TYPE_HTML,
    Xml = SIPE_TYPE_XML,

    WindowsProgram = SIPE_TYPE_WINDOWS_PROGRAM,
    DosProgram = SIPE_TYPE_DOS_PROGRAM,
    Elf = SIPE_TYPE_ELF,
    MachO = SIPE_TYPE_MACHO,
    MachOFat = SIPE_TYPE_MACHO_FAT,
    JavaClass = SIPE_TYPE_JAVA_CLASS,
    Script = SIPE_TYPE_SCRIPT,
    Shortcut = SIPE_TYPE_SHORTCUT,
    WindowsInstaller = SIPE_TYPE_WINDOWS_INSTALLER,
    EncodedScript = SIPE_TYPE_ENCODED_SCRIPT,
    WebAssembly = SIPE_TYPE_WEBASSEMBLY,
    AndroidDex = SIPE_TYPE_ANDROID_DEX,
    CompiledHelp = SIPE_TYPE_COMPILED_HELP,
    DiskImage = SIPE_TYPE_DISK_IMAGE,
};

/// What a file's bytes are.
struct Detection {
    Type type = Type::Unknown;

    /// A program, or something Windows launches or mounts: quarantined whatever it is named.
    bool executable = false;
};

/// Where a received file goes, and why.
struct Result {
    std::uint32_t verdict = SIPE_VERDICT_INBOX_UNRECOGNISED;
    std::uint32_t reason = SIPE_REASON_NONE;
    Type detected = Type::Unknown;
    Type claimed = Type::Unknown;
};

/// Identifies a file from its first bytes. Reads at most SIPE_CONTENT_HEAD_BYTES of head.
[[nodiscard]] Detection Identify(std::span<const std::uint8_t> head, std::uint64_t total) noexcept;

/// The whole check: the file's bytes against its name. See sipe_content_check.
[[nodiscard]] Result Check(std::span<const std::uint8_t> head,
                           std::uint64_t total,
                           std::span<const std::uint8_t> name) noexcept;

/// A type's name for a person, or nothing for a number that is not a type.
[[nodiscard]] std::optional<std::string_view> NameOf(std::uint32_t type) noexcept;

/// The extension a file of the type usually has, without the dot, or nothing for a number
/// that is not a type. Empty for a type with no usual extension.
[[nodiscard]] std::optional<std::string_view> ExtensionOf(std::uint32_t type) noexcept;

}  // namespace sipengine::content

#endif  // SIPENGINE_CONTENT_CHECK_HPP
