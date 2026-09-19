// selftest.cpp - known answers for the engine, through its exported C ABI.
//
// Built by build.ps1 from the same sources as the DLL, and run after every build; the audit
// builds it again under AddressSanitizer and UndefinedBehaviorSanitizer. It has six parts:
//
//   1. Every content type the engine names, from a minimal instance of its signature.
//   2. The verdicts: what a name and a content decide together, including the tricks
//      (trailing dots, capitals, a text file that begins "MZ", Acrobat's PDF tolerance).
//   3. Robustness: every signature, and a name, cut to every shorter length. None may read
//      past what it was given, which is what the sanitizer builds are for; each must still
//      return a verdict.
//   4. SMBIOS tables built as DSP0134 lays them out: every value found where it is, every
//      placeholder rule, every shape of table (short structures, no strings, no marker,
//      damage), and a table cut at every length.
//   5. This machine's own tables, read through GetSystemFirmwareTable as whoever runs the
//      build. It prints which values the machine has, and never the values themselves.
//   6. The randomness test: exact figures for samples whose statistic is known by hand, a
//      seeded pseudo-random sample, text, and the limits on what is judged.
//
// It asserts values, never wording (standard B3). Exit code 0 when every check passed, 1 when
// any failed, 2 when the report itself could not be written, 3 when the run stopped on an
// exception before it finished (the reason is on stderr).

#include "sipengine.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <initializer_list>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace std::string_view_literals;

using Buffer = std::vector<std::uint8_t>;

/// Counts checks and prints each failure as it happens.
class Tally {
public:
    void Report(bool ok, std::string_view what, std::string_view detail = {})
    {
        if (ok) {
            ++passes_;
            return;
        }

        ++failures_;
        std::cout << "FAIL " << what;
        if (!detail.empty()) {
            std::cout << ": " << detail;
        }

        std::cout << '\n';
    }

    [[nodiscard]] int Passes() const noexcept { return passes_; }

    [[nodiscard]] int Failures() const noexcept { return failures_; }

private:
    int passes_ = 0;
    int failures_ = 0;
};

Buffer Of(std::initializer_list<unsigned> bytes)
{
    Buffer out;
    out.reserve(bytes.size());
    for (const unsigned b : bytes) {
        out.push_back(static_cast<std::uint8_t>(b));
    }

    return out;
}

Buffer Text(std::string_view text)
{
    Buffer out;
    out.reserve(text.size());
    for (const char c : text) {
        out.push_back(static_cast<std::uint8_t>(c));
    }

    return out;
}

std::string AsString(const Buffer& bytes, std::size_t length)
{
    std::string out;
    for (std::size_t i = 0; i < length && i < bytes.size(); ++i) {
        out.push_back(static_cast<char>(bytes[i]));
    }

    return out;
}

/// bytes, padded with zeros to at least size.
Buffer Padded(Buffer bytes, std::size_t size)
{
    if (bytes.size() < size) {
        bytes.resize(size, std::uint8_t{0});
    }

    return bytes;
}

/// size zero bytes with text written at offset.
Buffer At(std::size_t size, std::size_t offset, std::string_view text)
{
    Buffer out(size, std::uint8_t{0});
    for (std::size_t i = 0; i < text.size() && offset + i < size; ++i) {
        out.at(offset + i) = static_cast<std::uint8_t>(text[i]);
    }

    return out;
}

void Put32Le(Buffer& bytes, std::size_t offset, std::uint32_t value)
{
    for (std::size_t i = 0; i < 4U; ++i) {
        bytes.at(offset + i) = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFU);
    }
}

void Put16Le(Buffer& bytes, std::size_t offset, std::uint32_t value)
{
    bytes.at(offset) = static_cast<std::uint8_t>(value & 0xFFU);
    bytes.at(offset + 1U) = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
}

struct Verdict {
    std::int32_t code = SIPE_ERR_UNKNOWN;
    std::uint32_t verdict = 0U;
    std::uint32_t reason = 0U;
    std::uint32_t detected = 0U;
    std::uint32_t claimed = 0U;
};

Verdict Run(const Buffer& head, std::size_t headLength, std::uint64_t total, std::string_view name)
{
    std::array<std::uint32_t, SIPE_CONTENT_FIELDS> fields{};
    const Buffer nameBytes = Text(name);

    Verdict v;
    v.code = sipe_content_check(
        headLength == 0U ? nullptr : head.data(), headLength, total,
        nameBytes.empty() ? nullptr : nameBytes.data(), nameBytes.size(),
        fields.data(), fields.size());
    v.verdict = fields[SIPE_FIELD_VERDICT];
    v.reason = fields[SIPE_FIELD_REASON];
    v.detected = fields[SIPE_FIELD_DETECTED];
    v.claimed = fields[SIPE_FIELD_CLAIMED];
    return v;
}

Verdict Run(const Buffer& head, std::string_view name)
{
    return Run(head, head.size(), head.size(), name);
}

std::string Describe(const Verdict& v)
{
    return "code " + std::to_string(v.code) + ", verdict " + std::to_string(v.verdict) + ", reason " +
           std::to_string(v.reason) + ", detected " + std::to_string(v.detected) + ", claimed " +
           std::to_string(v.claimed);
}

// ------------------------------------------------------------------------------------------
// Samples: the smallest bytes each signature needs.
// ------------------------------------------------------------------------------------------

Buffer PeProgram()
{
    Buffer b = Padded(Text("MZ"), 0x80);
    Put32Le(b, 0x3C, 0x40);
    b.at(0x40) = static_cast<std::uint8_t>('P');
    b.at(0x41) = static_cast<std::uint8_t>('E');
    return b;
}

Buffer IsoMedia(std::string_view brand)
{
    Buffer b = Padded(Of({0x00, 0x00, 0x00, 0x18}), 24);
    constexpr std::string_view ftyp = "ftyp";
    for (std::size_t i = 0; i < 4U; ++i) {
        b.at(4U + i) = static_cast<std::uint8_t>(ftyp[i]);
        b.at(8U + i) = static_cast<std::uint8_t>(brand.at(i));
    }

    return b;
}

/// A compound file whose directory is sector 0, at 512, and whose root storage has clsid.
Buffer CompoundFile(const Buffer& clsid)
{
    Buffer b = Padded(Of({0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}), 1024);
    Put16Le(b, 0x1E, 9);  // 512-byte sectors
    Put32Le(b, 0x30, 0);  // the first directory sector is sector 0, at (0 + 1) << 9
    for (std::size_t i = 0; i < clsid.size(); ++i) {
        b.at(512U + 0x50U + i) = clsid[i];
    }

    return b;
}

Buffer MsiClsid()
{
    return Of({0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46});
}

Buffer Bitmap()
{
    Buffer b = Padded(Text("BM"), 64);
    Put32Le(b, 2, 64);
    Put32Le(b, 10, 54);
    return b;
}

/// Three 188-byte packets. Real streams are full of bytes below 0x20, as this one is.
Buffer TransportStream()
{
    constexpr std::uint8_t sync{0x47};
    Buffer b(std::size_t{3} * 188U, std::uint8_t{0});
    b.at(0) = sync;
    b.at(188) = sync;
    b.at(376) = sync;
    return b;
}

struct Sample {
    std::string_view name;
    Buffer bytes;
    std::uint32_t type;
};

std::vector<Sample> Samples()
{
    return {
        {"PNG", Of({0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}), SIPE_TYPE_PNG},
        {"JPEG", Of({0xFF, 0xD8, 0xFF, 0xE0}), SIPE_TYPE_JPEG},
        {"GIF", Text("GIF89a"), SIPE_TYPE_GIF},
        {"BMP", Bitmap(), SIPE_TYPE_BMP},
        {"TIFF", Of({'I', 'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00}), SIPE_TYPE_TIFF},
        {"WebP", At(16, 0, "RIFF\x10\x00\x00\x00WEBPVP8 "sv), SIPE_TYPE_WEBP},
        {"icon", Padded(Of({0x00, 0x00, 0x01, 0x00, 0x01, 0x00}), 22), SIPE_TYPE_ICO},
        {"HEIF", IsoMedia("heic"), SIPE_TYPE_HEIF},
        {"AVIF", IsoMedia("avif"), SIPE_TYPE_AVIF},
        {"Photoshop", Padded(Of({'8', 'B', 'P', 'S', 0x00, 0x01}), 26), SIPE_TYPE_PSD},
        {"JPEG XL", Of({0xFF, 0x0A, 0x00, 0x00}), SIPE_TYPE_JPEG_XL},
        {"MP3 with ID3", Padded(Of({'I', 'D', '3', 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21}), 64), SIPE_TYPE_MP3},
        {"MP3 frame", Padded(Of({0xFF, 0xFB, 0x90, 0x64}), 64), SIPE_TYPE_MP3},
        {"AAC", Padded(Of({0xFF, 0xF1, 0x50, 0x80}), 64), SIPE_TYPE_AAC},
        {"WAV", At(16, 0, "RIFF\x24\x00\x00\x00WAVEfmt "sv), SIPE_TYPE_WAV},
        {"FLAC", Padded(Of({'f', 'L', 'a', 'C', 0x00, 0x00, 0x00, 0x22}), 42), SIPE_TYPE_FLAC},
        {"Ogg", Padded(Of({'O', 'g', 'g', 'S', 0x00, 0x02}), 27), SIPE_TYPE_OGG},
        {"M4A", IsoMedia("M4A "), SIPE_TYPE_M4A},
        {"MIDI", Padded(Of({'M', 'T', 'h', 'd', 0x00, 0x00, 0x00, 0x06}), 14), SIPE_TYPE_MIDI},
        {"AIFF", At(12, 0, "FORM\x00\x00\x00\x04" "AIFF"sv), SIPE_TYPE_AIFF},
        {"MP4", IsoMedia("isom"), SIPE_TYPE_MP4},
        {"QuickTime", IsoMedia("qt  "), SIPE_TYPE_QUICKTIME},
        {"Matroska", Padded(Of({0x1A, 0x45, 0xDF, 0xA3}), 32), SIPE_TYPE_MATROSKA},
        {"AVI", At(16, 0, "RIFF\x24\x00\x00\x00" "AVI LIST"sv), SIPE_TYPE_AVI},
        {"ASF", Of({0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C}),
         SIPE_TYPE_ASF},
        {"FLV", Padded(Of({'F', 'L', 'V', 0x01, 0x05}), 9), SIPE_TYPE_FLV},
        {"MPEG transport stream", TransportStream(), SIPE_TYPE_MPEG_TS},
        {"MPEG program stream", Padded(Of({0x00, 0x00, 0x01, 0xBA}), 14), SIPE_TYPE_MPEG_PS},
        {"3GP", IsoMedia("3gp5"), SIPE_TYPE_3GP},
        {"PDF", Text("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n"), SIPE_TYPE_PDF},
        {"RTF", Text("{\\rtf1\\ansi hello}"), SIPE_TYPE_RTF},
        {"compound file", CompoundFile(Buffer(16, std::uint8_t{0})), SIPE_TYPE_OLE},
        {"PostScript", Text("%!PS-Adobe-3.0\n"), SIPE_TYPE_POSTSCRIPT},
        {"ZIP", Padded(Of({'P', 'K', 0x03, 0x04, 0x14, 0x00}), 30), SIPE_TYPE_ZIP},
        {"7-Zip", Padded(Of({'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}), 32), SIPE_TYPE_7Z},
        {"RAR", Padded(Of({'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00}), 16), SIPE_TYPE_RAR},
        {"gzip", Padded(Of({0x1F, 0x8B, 0x08, 0x00}), 18), SIPE_TYPE_GZIP},
        {"bzip2", Of({'B', 'Z', 'h', '9', 0x31, 0x41, 0x59, 0x26, 0x53, 0x59}), SIPE_TYPE_BZIP2},
        {"xz", Padded(Of({0xFD, '7', 'z', 'X', 'Z', 0x00}), 12), SIPE_TYPE_XZ},
        {"Zstandard", Padded(Of({0x28, 0xB5, 0x2F, 0xFD}), 12), SIPE_TYPE_ZSTD},
        {"tar", At(512, 257, "ustar"), SIPE_TYPE_TAR},
        {"cabinet", Padded(Of({'M', 'S', 'C', 'F', 0x00, 0x00, 0x00, 0x00}), 36), SIPE_TYPE_CAB},
        {"text", Text("Shopping list\r\n- milk\r\n- bread\r\n"), SIPE_TYPE_TEXT},
        {"text in an old code page", Text("Caf\xE9 cr\xE8me\n"), SIPE_TYPE_TEXT},
        {"UTF-16 text", Of({0xFF, 0xFE, 'h', 0x00, 'i', 0x00}), SIPE_TYPE_TEXT},
        {"HTML", Text("\xEF\xBB\xBF  <!DOCTYPE html><html><body>hi</body></html>"), SIPE_TYPE_HTML},
        {"XML", Text("<?xml version=\"1.0\"?><a/>"), SIPE_TYPE_XML},
        {"SVG", Text("<svg xmlns=\"http://www.w3.org/2000/svg\"/>"), SIPE_TYPE_XML},
        {"Windows program", PeProgram(), SIPE_TYPE_WINDOWS_PROGRAM},
        {"DOS program", Padded(Text("MZ"), 64), SIPE_TYPE_DOS_PROGRAM},
        {"ELF", Padded(Of({0x7F, 'E', 'L', 'F', 0x02, 0x01}), 64), SIPE_TYPE_ELF},
        {"Mach-O", Padded(Of({0xCF, 0xFA, 0xED, 0xFE}), 32), SIPE_TYPE_MACHO},
        {"universal Mach-O", Padded(Of({0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02}), 48), SIPE_TYPE_MACHO_FAT},
        {"Java class", Padded(Of({0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34}), 16), SIPE_TYPE_JAVA_CLASS},
        {"script", Text("#!/bin/sh\necho hi\n"), SIPE_TYPE_SCRIPT},
        {"script behind a byte order mark", Text("\xEF\xBB\xBF#!/usr/bin/env python\n"), SIPE_TYPE_SCRIPT},
        {"shortcut",
         Padded(Of({0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x46}),
                76),
         SIPE_TYPE_SHORTCUT},
        {"Windows Installer", CompoundFile(MsiClsid()), SIPE_TYPE_WINDOWS_INSTALLER},
        {"encoded script", Text("#@~^CgAAAA==vv\n"), SIPE_TYPE_ENCODED_SCRIPT},
        {"WebAssembly", Of({0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}), SIPE_TYPE_WEBASSEMBLY},
        {"Android", Text("dex\n035"), SIPE_TYPE_ANDROID_DEX},
        {"compiled help", Padded(Of({'I', 'T', 'S', 'F', 0x03, 0x00, 0x00, 0x00}), 96), SIPE_TYPE_COMPILED_HELP},
        {"ISO 9660 image", At(0x8800, 0x8001, "CD001"), SIPE_TYPE_DISK_IMAGE},
        {"VHDX", Padded(Text("vhdxfile"), 64), SIPE_TYPE_DISK_IMAGE},
    };
}

// ------------------------------------------------------------------------------------------
// The checks.
// ------------------------------------------------------------------------------------------

void ExpectVerdict(Tally& tally, std::string_view what, const Buffer& content, std::string_view name,
                   std::uint32_t verdict, std::uint32_t reason, std::uint32_t detected)
{
    const Verdict v = Run(content, name);
    tally.Report(v.code == SIPE_OK && v.verdict == verdict && v.reason == reason && v.detected == detected, what,
                 Describe(v));
}

void AbiAndArguments(Tally& tally)
{
    tally.Report(sipe_abi_version() == SIPE_ABI_VERSION, "sipe_abi_version returns SIPE_ABI_VERSION");

    std::array<std::uint32_t, SIPE_CONTENT_FIELDS> fields{};
    const Buffer head = Text("hello");
    const Buffer name = Text("a.txt");

    tally.Report(sipe_content_check(nullptr, 5, 5, name.data(), name.size(), fields.data(), fields.size()) ==
                     SIPE_ERR_NULL_ARG,
                 "a missing head with a length is refused");
    tally.Report(sipe_content_check(head.data(), head.size(), 5, nullptr, 5, fields.data(), fields.size()) ==
                     SIPE_ERR_NULL_ARG,
                 "a missing name with a length is refused");
    tally.Report(sipe_content_check(head.data(), head.size(), 5, name.data(), name.size(), nullptr, 4) ==
                     SIPE_ERR_NULL_ARG,
                 "a missing result array is refused");
    tally.Report(sipe_content_check(head.data(), head.size(), 5, name.data(), name.size(), fields.data(), 3) ==
                     SIPE_ERR_CAPACITY,
                 "a result array too small is refused");
    tally.Report(sipe_content_check(nullptr, 0, 0, nullptr, 0, fields.data(), fields.size()) == SIPE_OK,
                 "an empty file with no name is judged");

    Buffer text(64, std::uint8_t{0});
    std::size_t length = 0;
    tally.Report(sipe_content_type_name(SIPE_TYPE_PNG, text.data(), text.size(), &length) == SIPE_OK &&
                     AsString(text, length) == "PNG image",
                 "a type's name is written");
    tally.Report(sipe_content_type_extension(SIPE_TYPE_DISK_IMAGE, text.data(), text.size(), &length) == SIPE_OK &&
                     AsString(text, length) == "iso",
                 "a type's extension is written");
    tally.Report(sipe_content_type_name(9999, text.data(), text.size(), &length) == SIPE_ERR_UNKNOWN && length == 0U,
                 "a number that is not a type is refused");
    tally.Report(sipe_content_type_name(SIPE_TYPE_PNG, nullptr, 0, &length) == SIPE_ERR_CAPACITY && length == 9U,
                 "the length is reported when the buffer is too small");
    tally.Report(sipe_content_type_name(SIPE_TYPE_PNG, text.data(), text.size(), nullptr) == SIPE_ERR_NULL_ARG,
                 "a missing length is refused");
}

void EveryTypeHasANameAndAnExtension(Tally& tally)
{
    constexpr auto types = std::to_array<std::uint32_t>({
        SIPE_TYPE_UNKNOWN, SIPE_TYPE_PNG, SIPE_TYPE_JPEG, SIPE_TYPE_GIF, SIPE_TYPE_BMP, SIPE_TYPE_TIFF,
        SIPE_TYPE_WEBP, SIPE_TYPE_ICO, SIPE_TYPE_HEIF, SIPE_TYPE_AVIF, SIPE_TYPE_PSD, SIPE_TYPE_JPEG_XL,
        SIPE_TYPE_MP3, SIPE_TYPE_WAV, SIPE_TYPE_FLAC, SIPE_TYPE_OGG, SIPE_TYPE_M4A, SIPE_TYPE_AAC,
        SIPE_TYPE_MIDI, SIPE_TYPE_AIFF, SIPE_TYPE_MP4, SIPE_TYPE_QUICKTIME, SIPE_TYPE_MATROSKA, SIPE_TYPE_AVI,
        SIPE_TYPE_ASF, SIPE_TYPE_FLV, SIPE_TYPE_MPEG_TS, SIPE_TYPE_MPEG_PS, SIPE_TYPE_3GP, SIPE_TYPE_PDF,
        SIPE_TYPE_RTF, SIPE_TYPE_OLE, SIPE_TYPE_POSTSCRIPT, SIPE_TYPE_ZIP, SIPE_TYPE_7Z, SIPE_TYPE_RAR,
        SIPE_TYPE_GZIP, SIPE_TYPE_BZIP2, SIPE_TYPE_XZ, SIPE_TYPE_ZSTD, SIPE_TYPE_TAR, SIPE_TYPE_CAB,
        SIPE_TYPE_TEXT, SIPE_TYPE_HTML, SIPE_TYPE_XML, SIPE_TYPE_WINDOWS_PROGRAM, SIPE_TYPE_DOS_PROGRAM,
        SIPE_TYPE_ELF, SIPE_TYPE_MACHO, SIPE_TYPE_MACHO_FAT, SIPE_TYPE_JAVA_CLASS, SIPE_TYPE_SCRIPT,
        SIPE_TYPE_SHORTCUT, SIPE_TYPE_WINDOWS_INSTALLER, SIPE_TYPE_ENCODED_SCRIPT, SIPE_TYPE_WEBASSEMBLY,
        SIPE_TYPE_ANDROID_DEX, SIPE_TYPE_COMPILED_HELP, SIPE_TYPE_DISK_IMAGE,
    });

    for (const std::uint32_t type : types) {
        std::size_t length = 0;
        const bool named = sipe_content_type_name(type, nullptr, 0, &length) != SIPE_ERR_UNKNOWN && length > 0U;
        const bool extended = sipe_content_type_extension(type, nullptr, 0, &length) != SIPE_ERR_UNKNOWN;
        tally.Report(named && extended, "every type has a name and an extension entry", "type " + std::to_string(type));
    }
}

void EverySignatureIsRecognised(Tally& tally)
{
    for (const Sample& sample : Samples()) {
        // Named with an extension nothing claims, so the content alone decides.
        const Verdict v = Run(sample.bytes, "sample.unclaimed");
        tally.Report(v.code == SIPE_OK && v.detected == sample.type, "recognised: " + std::string(sample.name),
                     Describe(v));
    }
}

void Verdicts(Tally& tally)
{
    const Buffer png = Of({0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A});
    const Buffer text = Text("Shopping list\n- milk\n");
    const Buffer binary = Of({0x00, 0x01, 0x02, 0x03, 0xFE, 0xFD, 0x10, 0x00});

    ExpectVerdict(tally, "content matching its name goes to the inbox", png, "photo.png", SIPE_VERDICT_INBOX,
                  SIPE_REASON_NONE, SIPE_TYPE_PNG);
    ExpectVerdict(tally, "content contradicting its name is quarantined", png, "photo.jpg", SIPE_VERDICT_QUARANTINE,
                  SIPE_REASON_MISMATCH, SIPE_TYPE_PNG);
    ExpectVerdict(tally, "a program is quarantined whatever it is named", PeProgram(), "holiday.jpg",
                  SIPE_VERDICT_QUARANTINE, SIPE_REASON_EXECUTABLE_CONTENT, SIPE_TYPE_WINDOWS_PROGRAM);
    ExpectVerdict(tally, "a program named as one is quarantined for its content", PeProgram(), "setup.exe",
                  SIPE_VERDICT_QUARANTINE, SIPE_REASON_EXECUTABLE_CONTENT, SIPE_TYPE_WINDOWS_PROGRAM);
    ExpectVerdict(tally, "text named as a batch file is quarantined for its name", text, "run.bat",
                  SIPE_VERDICT_QUARANTINE, SIPE_REASON_EXECUTABLE_NAME, SIPE_TYPE_TEXT);
    ExpectVerdict(tally, "an executable name in capitals is still one", text, "RUN.BAT", SIPE_VERDICT_QUARANTINE,
                  SIPE_REASON_EXECUTABLE_NAME, SIPE_TYPE_TEXT);
    ExpectVerdict(tally, "trailing dots are dropped, as Windows drops them", text, "run.bat...",
                  SIPE_VERDICT_QUARANTINE, SIPE_REASON_EXECUTABLE_NAME, SIPE_TYPE_TEXT);
    ExpectVerdict(tally, "trailing spaces are dropped, as Windows drops them", text, "run.bat  ",
                  SIPE_VERDICT_QUARANTINE, SIPE_REASON_EXECUTABLE_NAME, SIPE_TYPE_TEXT);
    ExpectVerdict(tally, "only the last extension counts", text, "invoice.pdf.exe", SIPE_VERDICT_QUARANTINE,
                  SIPE_REASON_EXECUTABLE_NAME, SIPE_TYPE_TEXT);
    ExpectVerdict(tally, "only the last path component counts", text, "notes.txt\\evil.js", SIPE_VERDICT_QUARANTINE,
                  SIPE_REASON_EXECUTABLE_NAME, SIPE_TYPE_TEXT);
    ExpectVerdict(tally, "text named as text goes to the inbox", text, "notes.txt", SIPE_VERDICT_INBOX,
                  SIPE_REASON_NONE, SIPE_TYPE_TEXT);
    ExpectVerdict(tally, "HTML named as text goes to the inbox", Text("<html><body>hi</body></html>"), "page.txt",
                  SIPE_VERDICT_INBOX, SIPE_REASON_NONE, SIPE_TYPE_HTML);
    ExpectVerdict(tally, "unknown content under a known name is a mismatch", binary, "report.pdf",
                  SIPE_VERDICT_QUARANTINE, SIPE_REASON_MISMATCH, SIPE_TYPE_UNKNOWN);
    ExpectVerdict(tally, "unknown content under an unknown name is unrecognised", binary, "data.bin",
                  SIPE_VERDICT_INBOX_UNRECOGNISED, SIPE_REASON_NONE, SIPE_TYPE_UNKNOWN);
    ExpectVerdict(tally, "unknown content with no extension is unrecognised", binary, "README",
                  SIPE_VERDICT_INBOX_UNRECOGNISED, SIPE_REASON_NONE, SIPE_TYPE_UNKNOWN);
    ExpectVerdict(tally, "known content under a name claiming nothing goes to the inbox", png, "data.bin",
                  SIPE_VERDICT_INBOX, SIPE_REASON_NONE, SIPE_TYPE_PNG);
    ExpectVerdict(tally, "a dot file's name is its extension, and claims nothing", text, ".gitignore",
                  SIPE_VERDICT_INBOX, SIPE_REASON_NONE, SIPE_TYPE_TEXT);
    ExpectVerdict(tally, "an empty file named as text goes to the inbox", Buffer{}, "empty.txt", SIPE_VERDICT_INBOX,
                  SIPE_REASON_NONE, SIPE_TYPE_TEXT);
    ExpectVerdict(tally, "an empty file named as an image is a mismatch", Buffer{}, "empty.png",
                  SIPE_VERDICT_QUARANTINE, SIPE_REASON_MISMATCH, SIPE_TYPE_TEXT);
    ExpectVerdict(tally, "a Windows Installer package named as a document is a program", CompoundFile(MsiClsid()),
                  "report.doc", SIPE_VERDICT_QUARANTINE, SIPE_REASON_EXECUTABLE_CONTENT,
                  SIPE_TYPE_WINDOWS_INSTALLER);
    ExpectVerdict(tally, "an ordinary compound file named as a document goes to the inbox",
                  CompoundFile(Buffer(16, std::uint8_t{0})), "report.doc", SIPE_VERDICT_INBOX, SIPE_REASON_NONE,
                  SIPE_TYPE_OLE);
    ExpectVerdict(tally, "a QuickTime brand under .mp4 is the same family", IsoMedia("qt  "), "clip.mp4",
                  SIPE_VERDICT_INBOX, SIPE_REASON_NONE, SIPE_TYPE_QUICKTIME);
    ExpectVerdict(tally, "a text file that begins MZ is text", Text("MZ is where we met.\n"), "notes.txt",
                  SIPE_VERDICT_INBOX, SIPE_REASON_NONE, SIPE_TYPE_TEXT);
    ExpectVerdict(tally, "a text file that begins ID3 is text", Text("ID3 tags explained\n"), "notes.txt",
                  SIPE_VERDICT_INBOX, SIPE_REASON_NONE, SIPE_TYPE_TEXT);
    ExpectVerdict(tally, "text that mentions %PDF- stays text", Text("The file starts %PDF-1.4, see?\n"),
                  "notes.txt", SIPE_VERDICT_INBOX, SIPE_REASON_NONE, SIPE_TYPE_TEXT);

    Buffer late(500, std::uint8_t{0x01});
    for (const std::uint8_t b : Text("%PDF-1.4\n")) {
        late.push_back(b);
    }

    ExpectVerdict(tally, "a PDF header within 1024 bytes counts for a file named as a PDF", late, "scan.pdf",
                  SIPE_VERDICT_INBOX, SIPE_REASON_NONE, SIPE_TYPE_PDF);
    ExpectVerdict(tally, "and for nothing else", late, "scan.dat", SIPE_VERDICT_INBOX_UNRECOGNISED, SIPE_REASON_NONE,
                  SIPE_TYPE_UNKNOWN);

    const Verdict claimed = Run(png, "photo.jpg");
    tally.Report(claimed.claimed == SIPE_TYPE_JPEG, "the type a name claims is reported", Describe(claimed));

    // A head given short of the whole file is judged on what was given, and not beyond it.
    const Verdict cut = Run(PeProgram(), 2, 1U << 20U, "setup.jpg");
    tally.Report(cut.code == SIPE_OK && cut.verdict == SIPE_VERDICT_QUARANTINE,
                 "two bytes of a program under an image name are judged", Describe(cut));
}

void EveryTruncationIsSafe(Tally& tally)
{
    // Every signature cut to every shorter length: nothing may read past the length given,
    // which the sanitizer build catches, and every call must still return a verdict.
    for (const Sample& sample : Samples()) {
        bool ok = true;
        for (std::size_t length = 0; length <= sample.bytes.size(); ++length) {
            const Verdict v = Run(sample.bytes, length, sample.bytes.size(), "sample.bin");
            ok = ok && v.code == SIPE_OK && v.verdict >= SIPE_VERDICT_INBOX && v.verdict <= SIPE_VERDICT_QUARANTINE;
        }

        tally.Report(ok, "every truncation is judged: " + std::string(sample.name));
    }

    // A name cut to every shorter length.
    constexpr std::string_view name = "a.long.name.with.dots.and a space .exe. . ";
    const Buffer text = Text("hello");
    bool named = true;
    for (std::size_t length = 0; length <= name.size(); ++length) {
        const Verdict v = Run(text, name.substr(0, length));
        named = named && v.code == SIPE_OK;
    }

    tally.Report(named, "every truncation of a name is judged");

    // An extension longer than any the engine looks up claims nothing.
    const Verdict longName = Run(text, "x." + std::string(40, 'e'));
    tally.Report(longName.code == SIPE_OK && longName.claimed == SIPE_TYPE_UNKNOWN &&
                     longName.verdict == SIPE_VERDICT_INBOX,
                 "an extension longer than any listed claims nothing", Describe(longName));
}

// ------------------------------------------------------------------------------------------
// SMBIOS: tables built the way DSP0134 lays them out.
// ------------------------------------------------------------------------------------------

using Uuid = std::array<std::uint8_t, 16>;

constexpr Uuid SampleUuid{0x4C, 0x4C, 0x45, 0x44, 0x00, 0x33, 0x51, 0x10,
                          0x80, 0x4E, 0xB5, 0xC0, 0x4F, 0x52, 0x39, 0x32};

/// The first count bytes of bytes.
Buffer First(const Buffer& bytes, std::size_t count)
{
    Buffer out;
    for (std::size_t i = 0; i < count && i < bytes.size(); ++i) {
        out.push_back(bytes.at(i));
    }

    return out;
}

/// A structure's formatted area: its type and length, a zero handle, and zeros up to length.
Buffer Formatted(std::uint32_t type, std::size_t length)
{
    Buffer b(length, std::uint8_t{0});
    b.at(0) = static_cast<std::uint8_t>(type);
    b.at(1) = static_cast<std::uint8_t>(length);
    return b;
}

/// Writes value at offset, when the formatted area reaches that far.
void SetField(Buffer& formatted, std::size_t offset, std::uint8_t value)
{
    if (offset < formatted.size()) {
        formatted.at(offset) = value;
    }
}

/// Type 1, System Information, at SMBIOS 2.4's length unless told otherwise: strings 1 to 4
/// for the manufacturer, product name, version and serial number, then the UUID.
Buffer SystemInformation(const Uuid& uuid, std::size_t length = 0x1B)
{
    Buffer b = Formatted(1, length);
    SetField(b, 0x04, 1);
    SetField(b, 0x05, 2);
    SetField(b, 0x06, 3);
    SetField(b, 0x07, 4);
    for (std::size_t i = 0; i < uuid.size(); ++i) {
        SetField(b, 0x08U + i, uuid.at(i));
    }

    return b;
}

/// Type 2, Baseboard Information: strings 1 to 4 for the manufacturer, product, version and
/// serial number.
Buffer Baseboard()
{
    Buffer b = Formatted(2, 0x0F);
    SetField(b, 0x04, 1);
    SetField(b, 0x05, 2);
    SetField(b, 0x06, 3);
    SetField(b, 0x07, 4);
    return b;
}

/// Appends a structure: its formatted area, then its strings, each ended by a zero byte, and
/// the set ended by one more; two zero bytes when it has none.
void Append(Buffer& table, const Buffer& formatted, std::initializer_list<std::string_view> strings = {})
{
    table.insert(table.end(), formatted.begin(), formatted.end());
    for (const std::string_view s : strings) {
        for (const char c : s) {
            table.push_back(static_cast<std::uint8_t>(c));
        }

        table.push_back(std::uint8_t{0});
    }

    if (strings.size() == 0U) {
        table.push_back(std::uint8_t{0});
    }

    table.push_back(std::uint8_t{0});
}

/// The end-of-table structure, type 127.
void End(Buffer& table)
{
    Append(table, Formatted(127, 4));
}

/// A RawSMBIOSData: the 8-byte header GetSystemFirmwareTable writes, then the table.
Buffer Raw(const Buffer& table, std::uint8_t major = 3, std::uint8_t minor = 4)
{
    Buffer raw(8, std::uint8_t{0});
    raw.at(1) = major;
    raw.at(2) = minor;
    Put32Le(raw, 4, static_cast<std::uint32_t>(table.size()));
    raw.insert(raw.end(), table.begin(), table.end());
    return raw;
}

/// The table most checks start from: a machine whose values are all real.
Buffer RealTable()
{
    Buffer table;
    Append(table, Formatted(0, 0x18), {"Vendor", "1.0", "01/01/2026"});
    Append(table, SystemInformation(SampleUuid), {"Dell Inc.", "Inspiron 15 3511", "1.2", "7QA2MF9"});
    Append(table, Baseboard(), {"Dell Inc.", "0ABCDE", "A00", "/7QA2MF9/CN1296319N00AB/"});
    End(table);
    return table;
}

struct Smbios {
    std::int32_t code = SIPE_ERR_UNKNOWN;
    std::array<std::uint32_t, SIPE_SMBIOS_FIELDS> fields{};
};

Smbios Identify(const Buffer& raw, std::size_t length)
{
    Smbios s;
    s.code = sipe_smbios_identity(length == 0U ? nullptr : raw.data(), length, s.fields.data(), s.fields.size());
    return s;
}

Smbios Identify(const Buffer& raw)
{
    return Identify(raw, raw.size());
}

/// Part 0 (state), 1 (offset) or 2 (length) of a value.
std::uint32_t Field(const Smbios& s, std::uint32_t value, std::uint32_t part)
{
    return s.fields.at(SIPE_SMBIOS_FIELD_VALUES + (3U * value) + part);
}

std::uint32_t StateOf(const Smbios& s, std::uint32_t value)
{
    return Field(s, value, 0);
}

/// A value's bytes, as text.
std::string TextOf(const Smbios& s, const Buffer& raw, std::uint32_t value)
{
    const std::size_t offset = Field(s, value, 1);
    const std::size_t length = Field(s, value, 2);
    if (offset > raw.size() || length > raw.size() - offset) {
        return "(outside the buffer)";
    }

    std::string out;
    for (std::size_t i = 0; i < length; ++i) {
        out.push_back(static_cast<char>(raw.at(offset + i)));
    }

    return out;
}

/// Whether every value lies inside a buffer of size bytes, and every absent one is empty.
bool InBounds(const Smbios& s, std::size_t size)
{
    for (std::uint32_t value = 0; value < SIPE_SMBIOS_VALUES; ++value) {
        const std::uint64_t end = std::uint64_t{Field(s, value, 1)} + Field(s, value, 2);
        const bool absentIsEmpty =
            StateOf(s, value) != SIPE_SMBIOS_ABSENT || (Field(s, value, 1) == 0U && Field(s, value, 2) == 0U);
        if (end > size || !absentIsEmpty) {
            return false;
        }
    }

    return true;
}

std::string DescribeSmbios(const Smbios& s)
{
    std::string out = "code " + std::to_string(s.code) + ", fields";
    for (const std::uint32_t field : s.fields) {
        out += ' ';
        out += std::to_string(field);
    }

    return out;
}

/// The state the engine gives a text value, as the system's manufacturer or the board's serial.
std::uint32_t TextState(std::uint32_t value, std::string_view text)
{
    const std::string_view maker = value == SIPE_SMBIOS_SYSTEM_MAKER ? text : "Maker";
    const std::string_view serial = value == SIPE_SMBIOS_BOARD_SERIAL ? text : "SERIAL-A1B2C3";

    Buffer table;
    Append(table, SystemInformation(SampleUuid), {maker, "Product", "1.0", "Serial"});
    Append(table, Baseboard(), {"Maker", "Board", "1.0", serial});
    End(table);

    const Smbios s = Identify(Raw(table));
    return s.code == SIPE_OK ? StateOf(s, value) : SIPE_SMBIOS_ABSENT;
}

/// The state the engine gives a system UUID.
std::uint32_t UuidState(const Uuid& uuid)
{
    Buffer table;
    Append(table, SystemInformation(uuid), {"Maker", "Product", "1.0", "Serial"});
    End(table);

    const Smbios s = Identify(Raw(table));
    return s.code == SIPE_OK ? StateOf(s, SIPE_SMBIOS_UUID) : SIPE_SMBIOS_ABSENT;
}

Uuid Filled(std::uint8_t value)
{
    Uuid uuid{};
    uuid.fill(value);
    return uuid;
}

void SmbiosArguments(Tally& tally)
{
    std::array<std::uint32_t, SIPE_SMBIOS_FIELDS> fields{};
    const Buffer raw = Raw(RealTable());

    tally.Report(sipe_smbios_identity(nullptr, 8, fields.data(), fields.size()) == SIPE_ERR_NULL_ARG,
                 "smbios: a missing table with a length is refused");
    tally.Report(sipe_smbios_identity(raw.data(), raw.size(), nullptr, fields.size()) == SIPE_ERR_NULL_ARG,
                 "smbios: a missing result array is refused");
    tally.Report(sipe_smbios_identity(raw.data(), raw.size(), fields.data(), SIPE_SMBIOS_FIELDS - 1U) ==
                     SIPE_ERR_CAPACITY,
                 "smbios: a result array too small is refused");
    tally.Report(sipe_smbios_identity(nullptr, 0, fields.data(), fields.size()) == SIPE_ERR_MALFORMED,
                 "smbios: nothing at all is not a table");
    tally.Report(sipe_smbios_identity(raw.data(), 7, fields.data(), fields.size()) == SIPE_ERR_MALFORMED,
                 "smbios: less than the header is not a table");

    std::size_t length = 0;
    std::uint32_t osError = 0;
    tally.Report(sipe_smbios_read(nullptr, 16, &length, &osError) == SIPE_ERR_NULL_ARG,
                 "smbios: a missing buffer with a capacity is refused");
    tally.Report(sipe_smbios_read(nullptr, 0, nullptr, &osError) == SIPE_ERR_NULL_ARG,
                 "smbios: a missing length is refused");
    tally.Report(sipe_smbios_read(nullptr, 0, &length, nullptr) == SIPE_ERR_NULL_ARG,
                 "smbios: a missing error code is refused");
}

void SmbiosValuesAreFound(Tally& tally)
{
    const Buffer raw = Raw(RealTable(), 3, 4);
    const Smbios s = Identify(raw);
    const bool ok = s.code == SIPE_OK;

    tally.Report(ok && s.fields.at(SIPE_SMBIOS_FIELD_VERSION) == 0x0304U, "smbios: the version is the header's",
                 DescribeSmbios(s));
    tally.Report(ok && s.fields.at(SIPE_SMBIOS_FIELD_ENDING) == SIPE_SMBIOS_ENDED_AT_MARKER,
                 "smbios: the walk ends at the marker", DescribeSmbios(s));
    tally.Report(ok && InBounds(s, raw.size()), "smbios: every value lies inside the buffer", DescribeSmbios(s));

    const Buffer uuid(SampleUuid.begin(), SampleUuid.end());
    tally.Report(ok && StateOf(s, SIPE_SMBIOS_UUID) == SIPE_SMBIOS_PRESENT &&
                     TextOf(s, raw, SIPE_SMBIOS_UUID) == AsString(uuid, uuid.size()),
                 "smbios: the UUID is found, as stored", DescribeSmbios(s));

    struct Expected {
        std::uint32_t value;
        std::string_view text;
    };

    for (const Expected& expected : std::to_array<Expected>({
             {SIPE_SMBIOS_SYSTEM_MAKER, "Dell Inc."},
             {SIPE_SMBIOS_SYSTEM_PRODUCT, "Inspiron 15 3511"},
             {SIPE_SMBIOS_SYSTEM_VERSION, "1.2"},
             {SIPE_SMBIOS_BOARD_MAKER, "Dell Inc."},
             {SIPE_SMBIOS_BOARD_PRODUCT, "0ABCDE"},
             {SIPE_SMBIOS_BOARD_SERIAL, "/7QA2MF9/CN1296319N00AB/"},
         })) {
        tally.Report(ok && StateOf(s, expected.value) == SIPE_SMBIOS_PRESENT &&
                         TextOf(s, raw, expected.value) == expected.text,
                     "smbios: found: " + std::string(expected.text), DescribeSmbios(s));
    }
}

void SmbiosTableShapes(Tally& tally)
{
    {
        Buffer table;
        Append(table, SystemInformation(SampleUuid), {"  Dell Inc.  ", "Inspiron", "1.2", "Serial"});
        End(table);
        const Buffer raw = Raw(table);
        const Smbios s = Identify(raw);
        tally.Report(s.code == SIPE_OK && TextOf(s, raw, SIPE_SMBIOS_SYSTEM_MAKER) == "Dell Inc.",
                     "smbios: the spaces at either end of a value are dropped", DescribeSmbios(s));
    }

    {
        Buffer table;
        Append(table, SystemInformation(SampleUuid, 0x08), {"Maker", "Product", "1.0", "Serial"});
        End(table);
        const Smbios s = Identify(Raw(table, 2, 0));
        tally.Report(s.code == SIPE_OK && StateOf(s, SIPE_SMBIOS_UUID) == SIPE_SMBIOS_ABSENT &&
                         StateOf(s, SIPE_SMBIOS_SYSTEM_MAKER) == SIPE_SMBIOS_PRESENT,
                     "smbios: SMBIOS 2.0's type 1 has names and no UUID", DescribeSmbios(s));
    }

    {
        Buffer table;
        Append(table, SystemInformation(SampleUuid, 0x10), {"Maker", "Product", "1.0", "Serial"});
        End(table);
        const Smbios s = Identify(Raw(table));
        tally.Report(s.code == SIPE_OK && StateOf(s, SIPE_SMBIOS_UUID) == SIPE_SMBIOS_ABSENT,
                     "smbios: a UUID only partly inside its structure is not read", DescribeSmbios(s));
    }

    {
        Buffer table;
        Append(table, Formatted(1, 4), {"Maker"});
        End(table);
        const Smbios s = Identify(Raw(table));
        tally.Report(s.code == SIPE_OK && StateOf(s, SIPE_SMBIOS_SYSTEM_MAKER) == SIPE_SMBIOS_ABSENT &&
                         StateOf(s, SIPE_SMBIOS_UUID) == SIPE_SMBIOS_ABSENT,
                     "smbios: a structure that is only its header has no values", DescribeSmbios(s));
    }

    {
        Buffer board = Baseboard();
        SetField(board, 0x04, 0);  // the manufacturer: no string
        SetField(board, 0x07, 9);  // the serial number: the ninth of four
        Buffer table;
        Append(table, board, {"Maker", "Board", "1.0", "Serial1234"});
        End(table);
        const Smbios s = Identify(Raw(table));
        tally.Report(s.code == SIPE_OK && StateOf(s, SIPE_SMBIOS_BOARD_MAKER) == SIPE_SMBIOS_ABSENT &&
                         StateOf(s, SIPE_SMBIOS_BOARD_SERIAL) == SIPE_SMBIOS_ABSENT &&
                         StateOf(s, SIPE_SMBIOS_BOARD_PRODUCT) == SIPE_SMBIOS_PRESENT,
                     "smbios: string number 0, or one past the set, names nothing", DescribeSmbios(s));
    }

    {
        const Buffer bare = Formatted(2, 0x0F);
        Buffer table;
        Append(table, bare);
        Append(table, SystemInformation(SampleUuid), {"Maker", "Product", "1.0", "Serial"});
        End(table);
        const Smbios s = Identify(Raw(table));
        tally.Report(s.code == SIPE_OK && StateOf(s, SIPE_SMBIOS_BOARD_SERIAL) == SIPE_SMBIOS_ABSENT &&
                         StateOf(s, SIPE_SMBIOS_SYSTEM_MAKER) == SIPE_SMBIOS_PRESENT &&
                         s.fields.at(SIPE_SMBIOS_FIELD_ENDING) == SIPE_SMBIOS_ENDED_AT_MARKER,
                     "smbios: a structure with no strings is walked past", DescribeSmbios(s));
    }

    {
        Buffer table;
        Append(table, SystemInformation(SampleUuid), {"Maker", "Product", "1.0", "Serial"});
        End(table);
        const Smbios s = Identify(Raw(table));
        tally.Report(s.code == SIPE_OK && StateOf(s, SIPE_SMBIOS_BOARD_MAKER) == SIPE_SMBIOS_ABSENT &&
                         StateOf(s, SIPE_SMBIOS_BOARD_SERIAL) == SIPE_SMBIOS_ABSENT,
                     "smbios: with no type 2, the board's values are absent", DescribeSmbios(s));
    }

    {
        Buffer table;
        Append(table, Baseboard(), {"Maker", "Board", "1.0", "FIRST-1234"});
        Append(table, Baseboard(), {"Maker", "Board", "1.0", "SECOND-5678"});
        End(table);
        const Buffer raw = Raw(table);
        const Smbios s = Identify(raw);
        tally.Report(s.code == SIPE_OK && TextOf(s, raw, SIPE_SMBIOS_BOARD_SERIAL) == "FIRST-1234",
                     "smbios: of two type 2 structures, the first counts", DescribeSmbios(s));
    }

    {
        Buffer table;
        Append(table, SystemInformation(SampleUuid), {"Maker", "Product", "1.0", "Serial"});
        const Smbios s = Identify(Raw(table));
        tally.Report(s.code == SIPE_OK && s.fields.at(SIPE_SMBIOS_FIELD_ENDING) == SIPE_SMBIOS_ENDED_AT_LENGTH &&
                         StateOf(s, SIPE_SMBIOS_SYSTEM_MAKER) == SIPE_SMBIOS_PRESENT,
                     "smbios: a table with no marker ends at its length", DescribeSmbios(s));
    }

    {
        Buffer table;
        Append(table, SystemInformation(SampleUuid), {"Maker", "Product", "1.0", "Serial"});
        Append(table, Formatted(2, 2));
        Append(table, Baseboard(), {"Maker", "Board", "1.0", "Serial1234"});
        End(table);
        const Smbios s = Identify(Raw(table));
        tally.Report(s.code == SIPE_OK && s.fields.at(SIPE_SMBIOS_FIELD_ENDING) == SIPE_SMBIOS_ENDED_AT_DAMAGE &&
                         StateOf(s, SIPE_SMBIOS_SYSTEM_MAKER) == SIPE_SMBIOS_PRESENT &&
                         StateOf(s, SIPE_SMBIOS_BOARD_SERIAL) == SIPE_SMBIOS_ABSENT,
                     "smbios: a structure under 4 bytes stops the walk, keeping what came before",
                     DescribeSmbios(s));
    }

    {
        Buffer table;
        Append(table, SystemInformation(SampleUuid), {"Maker", "Product", "1.0", "Serial"});
        const Buffer board = Baseboard();
        table.insert(table.end(), board.begin(), board.end());
        for (const char c : std::string_view("Maker")) {
            table.push_back(static_cast<std::uint8_t>(c));
        }

        const Smbios s = Identify(Raw(table));
        tally.Report(s.code == SIPE_OK && s.fields.at(SIPE_SMBIOS_FIELD_ENDING) == SIPE_SMBIOS_ENDED_AT_DAMAGE &&
                         StateOf(s, SIPE_SMBIOS_SYSTEM_MAKER) == SIPE_SMBIOS_PRESENT &&
                         StateOf(s, SIPE_SMBIOS_BOARD_MAKER) == SIPE_SMBIOS_ABSENT,
                     "smbios: strings that never end stop the walk", DescribeSmbios(s));
    }
}

void SmbiosPlaceholders(Tally& tally)
{
    // Any text: words for nothing and field names, in any case, and nothing but spaces.
    for (const std::string_view text : {"To be filled by O.E.M.", "TO BE FILLED BY O.E.M.", "To Be Filled By O.E.M",
                                        "Default string", "DEFAULT STRING", "System manufacturer",
                                        "System Product Name", "Not Specified", "N/A", "None", "OEM", "O.E.M.",
                                        "Unknown", "INVALID", "x.x", "   ", "Type2 - Board Vendor Name1",
                                        "Type1 - TBD by OEM"}) {
        tally.Report(TextState(SIPE_SMBIOS_SYSTEM_MAKER, text) == SIPE_SMBIOS_PLACEHOLDER,
                     "smbios: a placeholder name: \"" + std::string(text) + "\"");
        tally.Report(TextState(SIPE_SMBIOS_BOARD_SERIAL, text) == SIPE_SMBIOS_PLACEHOLDER,
                     "smbios: a placeholder serial: \"" + std::string(text) + "\"");
    }

    // Serial numbers alone: a field's name, fewer than four characters, one character repeated.
    for (const std::string_view text : {"System Serial Number", "Base Board Serial Number", "Chassis Serial Number",
                                        "Type2 - Board Serial Number", "0", "AB1", "00000000", "FFFFFFFF",
                                        "ff-FF-ff-FF", "0000 0000 0000", "........", "-- --"}) {
        tally.Report(TextState(SIPE_SMBIOS_BOARD_SERIAL, text) == SIPE_SMBIOS_PLACEHOLDER,
                     "smbios: a placeholder serial: \"" + std::string(text) + "\"");
    }

    // Real values stay real, including short names, which the serial rules would catch.
    for (const std::string_view text : {"MT7012345678901", "PF2ABCDE", "/7QA2MF9/CN1296319N00AB/", "AB12",
                                        "Type 2 board 77", "Typewriter 5000"}) {
        tally.Report(TextState(SIPE_SMBIOS_BOARD_SERIAL, text) == SIPE_SMBIOS_PRESENT,
                     "smbios: a real serial: \"" + std::string(text) + "\"");
    }

    for (const std::string_view text : {"HP", "LG", "X1", "Dell Inc.", "Micro-Star International Co., Ltd."}) {
        tally.Report(TextState(SIPE_SMBIOS_SYSTEM_MAKER, text) == SIPE_SMBIOS_PRESENT,
                     "smbios: a real name: \"" + std::string(text) + "\"");
    }

    // The UUID: all one byte, or the well-known default. One byte off either is real.
    const Uuid defaultUuid{0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05,
                           0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09};
    tally.Report(UuidState(Filled(0x00)) == SIPE_SMBIOS_PLACEHOLDER, "smbios: a UUID of all 00h is a placeholder");
    tally.Report(UuidState(Filled(0xFF)) == SIPE_SMBIOS_PLACEHOLDER, "smbios: a UUID of all FFh is a placeholder");
    tally.Report(UuidState(Filled(0x20)) == SIPE_SMBIOS_PLACEHOLDER, "smbios: a UUID of one repeated byte is a placeholder");
    tally.Report(UuidState(defaultUuid) == SIPE_SMBIOS_PLACEHOLDER,
                 "smbios: 03000200-0400-0500-0006-000700080009 is a placeholder");

    Uuid almostZero = Filled(0x00);
    almostZero.back() = 0x01;
    Uuid almostDefault = defaultUuid;
    almostDefault.back() = 0x0A;
    tally.Report(UuidState(almostZero) == SIPE_SMBIOS_PRESENT, "smbios: a UUID one byte off all 00h is real");
    tally.Report(UuidState(almostDefault) == SIPE_SMBIOS_PRESENT, "smbios: a UUID one byte off the default is real");
    tally.Report(UuidState(SampleUuid) == SIPE_SMBIOS_PRESENT, "smbios: an ordinary UUID is real");
}

void SmbiosTruncations(Tally& tally)
{
    const Buffer table = RealTable();

    // The table cut at every length, its header saying so: read as far as it goes, and never
    // past it, which the sanitizer builds catch.
    bool cut = true;
    for (std::size_t length = 0; length <= table.size(); ++length) {
        const Buffer raw = Raw(First(table, length));
        const Smbios s = Identify(raw);
        cut = cut && s.code == SIPE_OK && InBounds(s, raw.size());
    }

    tally.Report(cut, "smbios: a table cut at every length is read as far as it goes");

    // The whole buffer cut short of what its header claims: refused, at every length.
    const Buffer raw = Raw(table);
    bool refused = true;
    for (std::size_t length = 0; length < raw.size(); ++length) {
        refused = refused && Identify(raw, length).code == SIPE_ERR_MALFORMED;
    }

    tally.Report(refused, "smbios: a buffer shorter than its header claims is refused at every length");
}

const char* StateWord(std::uint32_t state)
{
    switch (state) {
        case SIPE_SMBIOS_PRESENT:
            return "present";
        case SIPE_SMBIOS_PLACEHOLDER:
            return "a placeholder";
        default:
            return "absent";
    }
}

void ThisMachinesTables(Tally& tally)
{
    std::size_t needed = 0;
    std::uint32_t osError = 0;
    const std::int32_t sized = sipe_smbios_read(nullptr, 0, &needed, &osError);
    tally.Report(sized == SIPE_ERR_CAPACITY && needed > 8U, "this machine: the tables' size is given",
                 "code " + std::to_string(sized) + ", size " + std::to_string(needed) + ", Windows error " +
                     std::to_string(osError));
    if (sized != SIPE_ERR_CAPACITY || needed <= 8U) {
        return;
    }

    Buffer raw(needed, std::uint8_t{0});
    std::size_t written = 0;
    const std::int32_t read = sipe_smbios_read(raw.data(), raw.size(), &written, &osError);
    tally.Report(read == SIPE_OK && written > 8U && written <= raw.size(), "this machine: the tables are read",
                 "code " + std::to_string(read) + ", written " + std::to_string(written) + ", Windows error " +
                     std::to_string(osError));
    if (read != SIPE_OK) {
        return;
    }

    Buffer tooSmall(4, std::uint8_t{0});
    std::size_t wanted = 0;
    tally.Report(sipe_smbios_read(tooSmall.data(), tooSmall.size(), &wanted, &osError) == SIPE_ERR_CAPACITY &&
                     wanted == written,
                 "this machine: a buffer too small is told the size it needs");

    const Smbios s = Identify(raw, written);
    tally.Report(s.code == SIPE_OK && s.fields.at(SIPE_SMBIOS_FIELD_ENDING) != SIPE_SMBIOS_ENDED_AT_DAMAGE &&
                     InBounds(s, written),
                 "this machine: the tables are read without damage", DescribeSmbios(s));
    if (s.code != SIPE_OK) {
        return;
    }

    // Which values this machine has, for whoever reads the build log. States only: the values
    // themselves never leave the engine's caller (docs/SERVER-ID.md).
    const std::uint32_t version = s.fields.at(SIPE_SMBIOS_FIELD_VERSION);
    std::cout << "this machine: SMBIOS " << (version >> 8U) << '.' << (version & 0xFFU) << "; system UUID "
              << StateWord(StateOf(s, SIPE_SMBIOS_UUID)) << "; baseboard serial number "
              << StateWord(StateOf(s, SIPE_SMBIOS_BOARD_SERIAL)) << '\n';
}

// ------------------------------------------------------------------------------------------
// The randomness test.
// ------------------------------------------------------------------------------------------

struct Judged {
    std::int32_t code = SIPE_ERR_UNKNOWN;
    std::array<std::uint32_t, SIPE_RANDOMNESS_FIELDS> fields{};
};

Judged Judge(const Buffer& sample)
{
    Judged j;
    j.code = sipe_randomness(sample.empty() ? nullptr : sample.data(), sample.size(), j.fields.data(), j.fields.size());
    return j;
}

std::string DescribeJudged(const Judged& j)
{
    return "code " + std::to_string(j.code) + ", verdict " + std::to_string(j.fields[SIPE_RANDOMNESS_FIELD_VERDICT]) +
           ", entropy " + std::to_string(j.fields[SIPE_RANDOMNESS_FIELD_ENTROPY]) + ", chi " +
           std::to_string(j.fields[SIPE_RANDOMNESS_FIELD_CHI]) + ", judged " +
           std::to_string(j.fields[SIPE_RANDOMNESS_FIELD_JUDGED]);
}

/// SplitMix64 (Steele, Lea and Flood, 2014): a small, well-mixed generator, seeded, so the
/// sample is the same on every build.
Buffer PseudoRandom(std::size_t size, std::uint64_t seed)
{
    Buffer out;
    out.reserve(size);
    std::uint64_t state = seed;
    while (out.size() < size) {
        state += 0x9E3779B97F4A7C15ULL;
        std::uint64_t z = state;
        z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
        z ^= z >> 31U;
        for (std::size_t i = 0; i < 8U && out.size() < size; ++i) {
            out.push_back(static_cast<std::uint8_t>((z >> (8U * i)) & 0xFFU));
        }
    }

    return out;
}

void Randomness(Tally& tally)
{
    std::array<std::uint32_t, SIPE_RANDOMNESS_FIELDS> fields{};
    const Buffer some = Text("x");
    tally.Report(sipe_randomness(nullptr, 5, fields.data(), fields.size()) == SIPE_ERR_NULL_ARG,
                 "randomness: a missing sample with a length is refused");
    tally.Report(sipe_randomness(some.data(), some.size(), nullptr, fields.size()) == SIPE_ERR_NULL_ARG,
                 "randomness: a missing result array is refused");
    tally.Report(sipe_randomness(some.data(), some.size(), fields.data(), SIPE_RANDOMNESS_FIELDS - 1U) ==
                     SIPE_ERR_CAPACITY,
                 "randomness: a result array too small is refused");

    const Judged empty = Judge(Buffer{});
    tally.Report(empty.code == SIPE_OK && empty.fields[SIPE_RANDOMNESS_FIELD_VERDICT] == SIPE_RANDOMNESS_TOO_SMALL &&
                     empty.fields[SIPE_RANDOMNESS_FIELD_JUDGED] == 0U,
                 "randomness: nothing is too small to judge", DescribeJudged(empty));

    const Judged shortSample = Judge(PseudoRandom(SIPE_RANDOMNESS_MINIMUM_BYTES - 1U, 7));
    tally.Report(shortSample.code == SIPE_OK &&
                     shortSample.fields[SIPE_RANDOMNESS_FIELD_VERDICT] == SIPE_RANDOMNESS_TOO_SMALL,
                 "randomness: one byte short of the minimum is not judged", DescribeJudged(shortSample));

    // 65,536 zero bytes: one value holds every byte. chi-square = 256 * 65536^2 / 65536 - 65536
    // = 255 * 65536 = 16,711,680, so 1,671,168,000 hundredths; entropy 0.
    const Judged zeros = Judge(Buffer(65536, std::uint8_t{0}));
    tally.Report(zeros.code == SIPE_OK && zeros.fields[SIPE_RANDOMNESS_FIELD_VERDICT] == SIPE_RANDOMNESS_STRUCTURED &&
                     zeros.fields[SIPE_RANDOMNESS_FIELD_CHI] == 1671168000U &&
                     zeros.fields[SIPE_RANDOMNESS_FIELD_ENTROPY] == 0U,
                 "randomness: zeros are structured, with the statistic worked by hand", DescribeJudged(zeros));

    // Every value exactly 256 times: chi-square 0 and entropy 8 bits exactly. Too even to be
    // random, which is what a counter looks like.
    Buffer counter;
    counter.reserve(65536);
    for (std::size_t i = 0; i < 65536U; ++i) {
        counter.push_back(static_cast<std::uint8_t>(i & 0xFFU));
    }

    const Judged even = Judge(counter);
    tally.Report(even.code == SIPE_OK && even.fields[SIPE_RANDOMNESS_FIELD_VERDICT] == SIPE_RANDOMNESS_STRUCTURED &&
                     even.fields[SIPE_RANDOMNESS_FIELD_CHI] == 0U &&
                     even.fields[SIPE_RANDOMNESS_FIELD_ENTROPY] == 8000U,
                 "randomness: a counter is too even to be random", DescribeJudged(even));

    const Judged random = Judge(PseudoRandom(65536, 0x5151BADC0FFEEULL));
    tally.Report(random.code == SIPE_OK && random.fields[SIPE_RANDOMNESS_FIELD_VERDICT] == SIPE_RANDOMNESS_RANDOM &&
                     random.fields[SIPE_RANDOMNESS_FIELD_ENTROPY] > 7990U,
                 "randomness: seeded pseudo-random bytes are random-looking", DescribeJudged(random));

    std::string prose;
    while (prose.size() < 65536U) {
        prose += "The quick brown fox jumps over the lazy dog, and the report is due on Friday.\r\n";
    }

    const Judged text = Judge(Text(prose));
    tally.Report(text.code == SIPE_OK && text.fields[SIPE_RANDOMNESS_FIELD_VERDICT] == SIPE_RANDOMNESS_STRUCTURED,
                 "randomness: text is structured", DescribeJudged(text));

    // Only the first 64 KiB are judged: random bytes followed by zeros are random-looking.
    Buffer longer = PseudoRandom(65536, 0x5151BADC0FFEEULL);
    longer.resize(70000, std::uint8_t{0});
    const Judged cut = Judge(longer);
    tally.Report(cut.code == SIPE_OK && cut.fields[SIPE_RANDOMNESS_FIELD_VERDICT] == SIPE_RANDOMNESS_RANDOM &&
                     cut.fields[SIPE_RANDOMNESS_FIELD_JUDGED] == SIPE_RANDOMNESS_SAMPLE_BYTES,
                 "randomness: only the first 64 KiB are judged", DescribeJudged(cut));
}

/// main's handlers write through C stdio, never std::cerr: an insertion into a stream can
/// itself throw, and a throw from a handler would escape main. Returns 3 once the reason is
/// written, or 2 when even that could not be written.
int Stopped(const char* why) noexcept
{
    const bool written = std::fputs("the self-test stopped: ", stderr) != EOF && std::fputs(why, stderr) != EOF &&
                         std::fputc('\n', stderr) != EOF && std::fflush(stderr) == 0;
    return written ? 3 : 2;
}

}  // namespace

int main()
{
    // Everything the harness builds its samples with can throw bad_alloc. Caught here, so a
    // harness that ran out of memory reports that, rather than a pass it never reached.
    try {
        Tally tally;

        AbiAndArguments(tally);
        EveryTypeHasANameAndAnExtension(tally);
        EverySignatureIsRecognised(tally);
        Verdicts(tally);
        EveryTruncationIsSafe(tally);

        SmbiosArguments(tally);
        SmbiosValuesAreFound(tally);
        SmbiosTableShapes(tally);
        SmbiosPlaceholders(tally);
        SmbiosTruncations(tally);
        ThisMachinesTables(tally);

        Randomness(tally);

        std::cout << tally.Passes() << " passed, " << tally.Failures() << " failed\n";
        std::cout.flush();

        if (std::cout.fail()) {
            return 2;
        }

        return tally.Failures() == 0 ? 0 : 1;
    }
    catch (const std::exception& ex) {
        return Stopped(ex.what());
    }
    catch (...) {
        return Stopped("an exception that is not a std::exception");
    }
}
