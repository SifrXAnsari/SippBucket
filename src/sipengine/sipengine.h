/*
 * sipengine.h - the exported C ABI of SippBucket's native engine.
 *
 * The engine is C++20 behind this C surface. It holds the self-contained work that fits
 * native code: pure computation over buffers the caller owns. Today that is:
 *
 *   - the content check Direct Push runs on every file it receives (docs/DIRECT-PUSH.md,
 *     rule 4);
 *   - reading the firmware's SMBIOS tables, which Server.ID's permanent ID is made from
 *     (docs/SERVER-ID.md);
 *   - the randomness test peer health's mass-change hold judges content by
 *     (docs/PEER-HEALTH.md).
 *
 * DESIGN RULES, the ones sipnative measured and set (see ../sipnative/README.md):
 *
 *   - Every parameter is blittable: pointers, size_t (nuint in C#), fixed-width integers,
 *     and int32_t return codes. No strings, no bools, no structs with padding.
 *   - Errors come back as a return code. There is no SetLastError; where Windows gives an
 *     error code, it comes back in an out parameter.
 *   - The caller owns every buffer. The engine allocates nothing on the heap, keeps no
 *     state between calls, and never returns a pointer the caller must free. Every export
 *     is therefore safe to call from any number of threads at once.
 *   - No callbacks into managed code, and no exceptions across this boundary: every export
 *     is noexcept, and nothing it calls can throw.
 *   - Nothing here opens a file, a registry key or a socket. Input arrives in the caller's
 *     buffers and results leave in them. One export asks Windows for anything:
 *     sipe_smbios_read, which copies the firmware's tables into the caller's buffer through
 *     GetSystemFirmwareTable, in KERNEL32.dll like everything else the engine imports.
 *   - Calling convention stated explicitly, although x86-64 Windows has only one.
 *
 * VERSIONING: call sipe_abi_version() once at start-up. DllImport binds lazily, so a
 * packaging mistake that leaves this DLL out would otherwise fail in the middle of a
 * transfer instead of at start. A version mismatch means the DLL and the program were built
 * from different sources; the program refuses to start its checks rather than guess.
 */

#ifndef SIPENGINE_H
#define SIPENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#  define SIPE_NOEXCEPT noexcept
extern "C" {
#else
#  define SIPE_NOEXCEPT
#endif

#if defined(_WIN32)
#  if defined(SIPENGINE_BUILDING)
#    define SIPE_EXPORT __declspec(dllexport)
#  else
#    define SIPE_EXPORT __declspec(dllimport)
#  endif
#  define SIPE_CALL __cdecl
#else
#  define SIPE_EXPORT __attribute__((visibility("default")))
#  define SIPE_CALL
#endif

/* ------------------------------------------------------------------------------------ */
/* Constants                                                                            */
/* ------------------------------------------------------------------------------------ */

/* Bumped on any change to a signature, a constant or a meaning below. 2 added SMBIOS and the
   randomness test. */
#define SIPE_ABI_VERSION 2u

/* Return codes. */
#define SIPE_OK                0
#define SIPE_ERR_NULL_ARG    (-1)
#define SIPE_ERR_CAPACITY    (-2)
#define SIPE_ERR_UNKNOWN     (-3)
#define SIPE_ERR_UNAVAILABLE (-4)  /* Windows would not give what was asked for */
#define SIPE_ERR_MALFORMED   (-5)  /* the input is not in the format the export reads */

/* The most of a file the content check reads. A longer head is read only this far. */
#define SIPE_CONTENT_HEAD_BYTES 65536u

/* Where each part of a content check's result lands in the caller's array. */
#define SIPE_FIELD_VERDICT  0u
#define SIPE_FIELD_REASON   1u
#define SIPE_FIELD_DETECTED 2u
#define SIPE_FIELD_CLAIMED  3u
#define SIPE_CONTENT_FIELDS 4u

/* Verdicts: where the receiving machine puts the file. */
#define SIPE_VERDICT_INBOX              1u  /* content matches the name, or the name claims nothing it contradicts */
#define SIPE_VERDICT_INBOX_UNRECOGNISED 2u  /* neither the name nor the content is a type the engine knows */
#define SIPE_VERDICT_QUARANTINE         3u  /* see the reason */

/* Why a file goes to quarantine. */
#define SIPE_REASON_NONE               0u
#define SIPE_REASON_EXECUTABLE_CONTENT 1u  /* its bytes are a program, whatever it is named */
#define SIPE_REASON_EXECUTABLE_NAME    2u  /* its name is a type Windows runs or installs */
#define SIPE_REASON_MISMATCH           3u  /* its bytes are not what its name says */

/*
 * Content types. The numbers are part of the ABI: they are stored in quarantine records,
 * so a type keeps its number for ever, and a retired number is never reused.
 */
#define SIPE_TYPE_UNKNOWN            0u

#define SIPE_TYPE_PNG                1u
#define SIPE_TYPE_JPEG               2u
#define SIPE_TYPE_GIF                3u
#define SIPE_TYPE_BMP                4u
#define SIPE_TYPE_TIFF               5u
#define SIPE_TYPE_WEBP               6u
#define SIPE_TYPE_ICO                7u
#define SIPE_TYPE_HEIF               8u
#define SIPE_TYPE_AVIF               9u
#define SIPE_TYPE_PSD               10u
#define SIPE_TYPE_JPEG_XL           11u

#define SIPE_TYPE_MP3               20u
#define SIPE_TYPE_WAV               21u
#define SIPE_TYPE_FLAC              22u
#define SIPE_TYPE_OGG               23u
#define SIPE_TYPE_M4A               24u
#define SIPE_TYPE_AAC               25u
#define SIPE_TYPE_MIDI              26u
#define SIPE_TYPE_AIFF              27u

#define SIPE_TYPE_MP4               40u
#define SIPE_TYPE_QUICKTIME         41u
#define SIPE_TYPE_MATROSKA          42u
#define SIPE_TYPE_AVI               43u
#define SIPE_TYPE_ASF               44u
#define SIPE_TYPE_FLV               45u
#define SIPE_TYPE_MPEG_TS           46u
#define SIPE_TYPE_MPEG_PS           47u
#define SIPE_TYPE_3GP               48u

#define SIPE_TYPE_PDF               60u
#define SIPE_TYPE_RTF               61u
#define SIPE_TYPE_OLE               62u  /* Office 97-2003 documents, Outlook messages */
#define SIPE_TYPE_POSTSCRIPT        63u

#define SIPE_TYPE_ZIP               80u  /* also Office Open XML, OpenDocument, EPUB */
#define SIPE_TYPE_7Z                81u
#define SIPE_TYPE_RAR               82u
#define SIPE_TYPE_GZIP              83u
#define SIPE_TYPE_BZIP2             84u
#define SIPE_TYPE_XZ                85u
#define SIPE_TYPE_ZSTD              86u
#define SIPE_TYPE_TAR               87u
#define SIPE_TYPE_CAB               88u

#define SIPE_TYPE_TEXT             100u
#define SIPE_TYPE_HTML             101u
#define SIPE_TYPE_XML              102u

/* Programs, and things Windows launches or mounts. Every one of these is quarantined. */
#define SIPE_TYPE_WINDOWS_PROGRAM  120u  /* PE: .exe, .dll, .sys, .scr ... */
#define SIPE_TYPE_DOS_PROGRAM      121u  /* MZ without a PE header */
#define SIPE_TYPE_ELF              122u
#define SIPE_TYPE_MACHO            123u
#define SIPE_TYPE_MACHO_FAT        124u
#define SIPE_TYPE_JAVA_CLASS       125u
#define SIPE_TYPE_SCRIPT           126u  /* starts with #! */
#define SIPE_TYPE_SHORTCUT         127u  /* Windows .lnk */
#define SIPE_TYPE_WINDOWS_INSTALLER 128u /* .msi, .msp, .mst */
#define SIPE_TYPE_ENCODED_SCRIPT   129u  /* .vbe, .jse */
#define SIPE_TYPE_WEBASSEMBLY      130u
#define SIPE_TYPE_ANDROID_DEX      131u
#define SIPE_TYPE_COMPILED_HELP    132u  /* .chm */
#define SIPE_TYPE_DISK_IMAGE       133u  /* ISO 9660, VHD, VHDX */

/*
 * SMBIOS: which physical machine this is (docs/SERVER-ID.md).
 *
 * The values sipe_smbios_identity reports, with the structure type and field offset each
 * comes from in DMTF's SMBIOS specification, DSP0134.
 */
#define SIPE_SMBIOS_UUID            0u  /* type 1, 08h: the system UUID, 16 bytes as stored */
#define SIPE_SMBIOS_SYSTEM_MAKER    1u  /* type 1, 04h: the manufacturer */
#define SIPE_SMBIOS_SYSTEM_PRODUCT  2u  /* type 1, 05h: the product name */
#define SIPE_SMBIOS_SYSTEM_VERSION  3u  /* type 1, 06h: the version, where some makers put the model */
#define SIPE_SMBIOS_BOARD_MAKER     4u  /* type 2, 04h: the baseboard's manufacturer */
#define SIPE_SMBIOS_BOARD_PRODUCT   5u  /* type 2, 05h: the baseboard's product */
#define SIPE_SMBIOS_BOARD_SERIAL    6u  /* type 2, 07h: the baseboard's serial number */
#define SIPE_SMBIOS_VALUES          7u

/*
 * Where each part of sipe_smbios_identity's result lands in the caller's array. The first two
 * places hold the table's version and how the walk through it ended. Then each value takes
 * three places, from SIPE_SMBIOS_FIELD_VALUES + 3 * value: its state, its offset and its length.
 */
#define SIPE_SMBIOS_FIELD_VERSION  0u  /* the SMBIOS version: major << 8 | minor */
#define SIPE_SMBIOS_FIELD_ENDING   1u  /* SIPE_SMBIOS_ENDED_* */
#define SIPE_SMBIOS_FIELD_VALUES   2u
#define SIPE_SMBIOS_FIELDS        23u  /* 2 + 3 * SIPE_SMBIOS_VALUES */

/* A value's state. */
#define SIPE_SMBIOS_ABSENT       0u  /* its structure or field is not in the table; offset and length are 0 */
#define SIPE_SMBIOS_PRESENT      1u
#define SIPE_SMBIOS_PLACEHOLDER  2u  /* there, but a value firmware reports when it has none */

/* How the walk through the structures ended. */
#define SIPE_SMBIOS_ENDED_AT_MARKER  1u  /* at the end-of-table structure, type 127 */
#define SIPE_SMBIOS_ENDED_AT_LENGTH  2u  /* at the end of the data, with no marker */
#define SIPE_SMBIOS_ENDED_AT_DAMAGE  3u  /* at a structure under 4 bytes, or one running past the end */

/*
 * Randomness: whether a file's content looks like encrypted data (docs/PEER-HEALTH.md, the
 * mass-change hold).
 */

/* The most of a sample the test reads. A longer sample is read only this far. */
#define SIPE_RANDOMNESS_SAMPLE_BYTES 65536u

/* The least it judges: with fewer bytes, too few land on each byte value to tell. */
#define SIPE_RANDOMNESS_MINIMUM_BYTES 4096u

/* Where each part of sipe_randomness's result lands in the caller's array. */
#define SIPE_RANDOMNESS_FIELD_VERDICT  0u  /* SIPE_RANDOMNESS_* */
#define SIPE_RANDOMNESS_FIELD_ENTROPY  1u  /* Shannon entropy, in thousandths of a bit per byte: 0 to 8000 */
#define SIPE_RANDOMNESS_FIELD_CHI      2u  /* the chi-square statistic over the 256 byte values, in hundredths */
#define SIPE_RANDOMNESS_FIELD_JUDGED   3u  /* how many bytes were judged */
#define SIPE_RANDOMNESS_FIELDS         4u

/* Verdicts. */
#define SIPE_RANDOMNESS_TOO_SMALL   0u  /* fewer than SIPE_RANDOMNESS_MINIMUM_BYTES: not judged */
#define SIPE_RANDOMNESS_STRUCTURED  1u  /* not random-looking: text, documents, images, archives */
#define SIPE_RANDOMNESS_RANDOM      2u  /* random-looking: what encrypted data looks like */

/* ------------------------------------------------------------------------------------ */
/* Exports                                                                              */
/* ------------------------------------------------------------------------------------ */

/* Returns SIPE_ABI_VERSION. */
SIPE_EXPORT uint32_t SIPE_CALL sipe_abi_version(void) SIPE_NOEXCEPT;

/*
 * Decides where a received file goes, from its first bytes and its name.
 *
 *   head        the file's first bytes; NULL only when head_len is 0. Only the first
 *               SIPE_CONTENT_HEAD_BYTES are read.
 *   head_len    how many bytes head holds.
 *   total_len   the file's whole length, which may be more than head_len.
 *   name_utf8   the file's name as sent, UTF-8, without a directory; NULL only when
 *               name_len is 0. Trailing dots and spaces are ignored, as Windows ignores
 *               them, so "run.exe." is judged as "run.exe".
 *   name_len    its length in bytes.
 *   out_fields  the caller's array; on SIPE_OK it holds SIPE_CONTENT_FIELDS values, at
 *               the SIPE_FIELD_* positions.
 *   out_capacity  how many uint32_t out_fields holds.
 *
 * The rule, in order:
 *   1. Content that is a program, or a disk image, is quarantined whatever it is named.
 *   2. A name Windows runs or installs is quarantined whatever it holds.
 *   3. A name the engine knows, over content that is not a type that name may hold, is
 *      quarantined as a mismatch. Unrecognisable content under a known name counts too.
 *   4. Otherwise the file goes to the inbox, marked unrecognised when neither its name
 *      nor its content is a type the engine knows.
 *
 * Returns SIPE_OK, SIPE_ERR_NULL_ARG or SIPE_ERR_CAPACITY. Allocates nothing.
 */
SIPE_EXPORT int32_t SIPE_CALL sipe_content_check(const uint8_t *head,
                                                 size_t         head_len,
                                                 uint64_t       total_len,
                                                 const uint8_t *name_utf8,
                                                 size_t         name_len,
                                                 uint32_t      *out_fields,
                                                 size_t         out_capacity) SIPE_NOEXCEPT;

/*
 * Writes a content type's name for a person, UTF-8, into the caller's buffer.
 *
 * The name is short and in English, for example "PNG image". out_len receives its length
 * in bytes whether or not it fit. Returns SIPE_OK, SIPE_ERR_NULL_ARG, SIPE_ERR_CAPACITY
 * (nothing written) or SIPE_ERR_UNKNOWN for a number that is not a type.
 */
SIPE_EXPORT int32_t SIPE_CALL sipe_content_type_name(uint32_t type,
                                                     uint8_t *out_utf8,
                                                     size_t   out_capacity,
                                                     size_t  *out_len) SIPE_NOEXCEPT;

/*
 * Writes the extension a file of this type is normally given, UTF-8, lower case, without
 * the dot, for releasing a quarantined file under the name its content matches. Empty for
 * a type with no usual extension. Returns as sipe_content_type_name does.
 */
SIPE_EXPORT int32_t SIPE_CALL sipe_content_type_extension(uint32_t type,
                                                          uint8_t *out_utf8,
                                                          size_t   out_capacity,
                                                          size_t  *out_len) SIPE_NOEXCEPT;

/*
 * Copies the firmware's SMBIOS tables into the caller's buffer, as Windows' raw SMBIOS
 * provider ('RSMB') returns them: a RawSMBIOSData, which sipe_smbios_identity reads.
 *
 * The one export that asks Windows for anything. It calls GetSystemFirmwareTable in
 * KERNEL32.dll, which needs no administrator rights; smbios_read.cpp cites Microsoft's
 * documentation for that, and for the behaviour below.
 *
 *   out           the caller's buffer; NULL only when out_capacity is 0, to ask the size.
 *   out_capacity  how many bytes out holds. Only the first 4 GiB less one byte is used, far
 *                 more than any table.
 *   out_len       on SIPE_OK, how many bytes were written; on SIPE_ERR_CAPACITY, how many
 *                 are needed; 0 otherwise.
 *   out_os_error  on SIPE_ERR_UNAVAILABLE, Windows' error code; 0 otherwise.
 *
 * Returns SIPE_OK, SIPE_ERR_NULL_ARG, SIPE_ERR_CAPACITY (nothing usable was written; call
 * again with out_len bytes) or SIPE_ERR_UNAVAILABLE (Windows has no tables to give).
 */
SIPE_EXPORT int32_t SIPE_CALL sipe_smbios_read(uint8_t  *out,
                                               size_t    out_capacity,
                                               size_t   *out_len,
                                               uint32_t *out_os_error) SIPE_NOEXCEPT;

/*
 * Finds what identifies the machine in a RawSMBIOSData buffer: the system UUID, the
 * baseboard's serial number, and the names a label is made from. Pure computation over the
 * caller's buffer, like the content check.
 *
 *   raw           the buffer sipe_smbios_read filled; NULL only when raw_len is 0.
 *   raw_len       how many bytes it holds.
 *   out_fields    the caller's array; on SIPE_OK it holds SIPE_SMBIOS_FIELDS values, at the
 *                 SIPE_SMBIOS_FIELD_* positions. Offsets count from the start of raw, its
 *                 header included, so the caller slices its own buffer and nothing is copied.
 *   out_capacity  how many uint32_t out_fields holds.
 *
 * Text values are given without the spaces at either end. When a structure type appears more
 * than once, the first counts. A value is SIPE_SMBIOS_PLACEHOLDER when firmware filled it with
 * a word for nothing ("To be filled by O.E.M.", "Default string") or the field's own name
 * ("System Serial Number"), or the UUID is all one byte; smbios.cpp has every rule. A damaged
 * table is read as far as the damage, and the ending says so.
 *
 * Returns SIPE_OK, SIPE_ERR_NULL_ARG, SIPE_ERR_CAPACITY, or SIPE_ERR_MALFORMED when raw is
 * shorter than its 8-byte header, claims more table than it holds, or is 4 GiB or longer,
 * which no buffer GetSystemFirmwareTable fills can be. Allocates nothing.
 */
SIPE_EXPORT int32_t SIPE_CALL sipe_smbios_identity(const uint8_t *raw,
                                                   size_t         raw_len,
                                                   uint32_t      *out_fields,
                                                   size_t         out_capacity) SIPE_NOEXCEPT;

/*
 * Judges whether a sample of a file's content looks random, as encrypted data does.
 *
 *   sample        the file's first bytes; NULL only when sample_len is 0. Only the first
 *                 SIPE_RANDOMNESS_SAMPLE_BYTES are read.
 *   sample_len    how many bytes sample holds.
 *   out_fields    the caller's array; on SIPE_OK it holds SIPE_RANDOMNESS_FIELDS values, at
 *                 the SIPE_RANDOMNESS_FIELD_* positions.
 *   out_capacity  how many uint32_t out_fields holds.
 *
 * The verdict is the chi-square test over how often each of the 256 byte values occurs, with
 * 255 degrees of freedom: random-looking when the statistic lies from 150 to 400. Uniformly
 * random bytes fall outside that window fewer than once in ten million samples. Text and
 * documents are far from uniform, and so are most compressed formats, whose headers and codes
 * leave some byte values more common than others; data too even to be random, such as a
 * counter, falls below 150. The entropy is reported for people, and plays no part in the
 * verdict.
 *
 * What it cannot do: one sample cannot tell encryption from other uniform-looking data, and
 * some archives compressed hard already look random. That is why peer health judges a file
 * before and after a change, counts only files that became random, and asks the person rather
 * than acting. Returns SIPE_OK, SIPE_ERR_NULL_ARG or SIPE_ERR_CAPACITY. Allocates nothing.
 */
SIPE_EXPORT int32_t SIPE_CALL sipe_randomness(const uint8_t *sample,
                                              size_t         sample_len,
                                              uint32_t      *out_fields,
                                              size_t         out_capacity) SIPE_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif /* SIPENGINE_H */
