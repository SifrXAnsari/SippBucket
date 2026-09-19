# sipengine

SippBucket's native engine: self-contained computation in C++20, behind a small C ABI
(`sipengine.h`). The app around it is C#, and calls it through
`SippBucket.Core/Native/SipEngine.cs`.

**Written, not yet built.** Written 2026-09-19 in a read-and-write-only round, at the owner's
order; the owner's next build-and-debug round is its first build. Until then nothing here has
been compiled or run, and every claim below is what the code is written to do.

## Why C++, and why only this

The owner's rule for new work is "C lang stack. C++ preferred." The engine holds the work that
fits native code: pure computation over buffers the caller owns, with nothing to do with the
network, files or the registry. Today that is the content check, reading the SMBIOS tables, and
the randomness test for mass changes. The plan (`taskslist.md`) adds diff and blame, and page
search.

## The randomness test

Peer health holds an incoming change that looks like ransomware's work
(`docs/PEER-HEALTH.md`): among other signs, files whose content turns random-looking when it
was not before. `sipe_randomness` judges one sample, up to 64 KiB of a file's start, by
Pearson's chi-square over how often each byte value occurs. It is random-looking when the
statistic lies from 150 to 400, where uniformly random bytes land all but a few times in a
hundred million. The statistic is computed exactly in integers, so no compiler's rounding can
change a verdict. It cannot tell encryption from other uniform data, which is why the caller
compares a file before and after and asks the person.

The app around it stays C#. It is the sample, and 99.99% of it carries into the real app. The
SSH library the owner approved for Direct Push is .NET. And the protocol state machines stay in
memory-safe code.

## What is in here

| File | What it is |
| --- | --- |
| `sipengine.h` | The C ABI: constants, and seven exports. The only thing that crosses the DLL boundary. |
| `content_check.hpp` / `.cpp` | The content check: what a file's bytes are, and where it may go given its name. |
| `randomness.hpp` / `.cpp` | The randomness test: whether a file's content looks like encrypted data, for the mass-change hold. |
| `smbios.hpp` / `.cpp` | The SMBIOS reader: the system UUID, the board's serial number and the names, with placeholders marked. |
| `smbios_read.cpp` | The one call to Windows: `GetSystemFirmwareTable`, with its rights and behaviour cited. |
| `exports.cpp` | The exports, over the C++. |
| `selftest.cpp` | Known answers through the exported ABI: every type, the verdicts, every truncation, SMBIOS tables of every shape, and this machine's own tables. |
| `fuzz_content.cpp` | A libFuzzer entry point for the content check. |
| `fuzz_smbios.cpp` | A libFuzzer entry point for the SMBIOS reader. |
| `.clang-tidy` | The checks the audit runs, and why each one that is off is off. |
| `build.ps1` | Builds the DLL and the self-test, runs the self-test, and audits. |

## The content check

Direct Push's rule 4 (`docs/DIRECT-PUSH.md`): the receiving machine checks each file's bytes
against its name. `sipe_content_check` takes the file's first 64 KiB, its whole length and its
name, and decides, in this order:

1. **Content that is a program**, or a disk image, is quarantined whatever it is named: Windows
   and DOS programs, ELF, Mach-O, Java classes, `#!` scripts, Windows shortcuts, encoded Windows
   scripts, WebAssembly, Android programs, compiled help, Windows Installer packages (recognised
   inside the compound file by the root storage's class ID), and ISO, VHD and VHDX images.
2. **A name Windows runs or installs** is quarantined whatever it holds: the attachment types
   Outlook blocks, from Microsoft's published list, plus a few packages and program files the
   list leaves out. The list and its source are in `content_check.cpp`.
3. **A name the engine knows, over content that is not a type that name may hold**, is
   quarantined as a mismatch. An MP4 named `.md` is the owner's own example.
4. Otherwise the file goes to **the inbox**, marked *type not recognised* when neither its name
   nor its content is a type the engine knows.

Names are judged as Windows opens them: only the last component, trailing dots and spaces
dropped, extension compared in any case.

**What it cannot do** (standard A3): it catches a *disguised* file, not a *malicious* one. A
genuine JPEG can carry a malformed payload, and a file can be valid as two formats at once. The
antivirus still scans whatever arrives, and SippBucket never gets in its way.

## Reading the SMBIOS tables

Server.ID's permanent ID (`docs/SERVER-ID.md`) is made from the baseboard's serial number and
the system UUID, which the firmware keeps in its SMBIOS tables. Two exports:

- `sipe_smbios_read` asks Windows for the tables, through `GetSystemFirmwareTable` with the raw
  SMBIOS provider, `'RSMB'`. It is the only export that asks Windows for anything, and it is in
  `KERNEL32.dll`, so the import audit still holds. Microsoft's documentation of the call names
  no privilege for desktop applications; `smbios_read.cpp` cites it point by point. The
  self-test calls it on every build.
- `sipe_smbios_identity` reads the buffer that fills, as DMTF's specification (DSP0134) lays it
  out: the UUID from type 1; the manufacturer, product and version from type 1; the
  manufacturer, product and serial number from type 2. It returns where each value is in the
  caller's buffer, and copies nothing.

Each value comes back *present*, *absent*, or a *placeholder*: something firmware writes when
it has nothing, such as "To be filled by O.E.M.", "Default string", a field's own name, a
serial number of fewer than four characters or one character repeated, or a UUID of one
repeated byte. The rules and why they lean the way they do are at the top of `smbios.cpp`.

## Why reading untrusted bytes in C++ is safe here

- Every read of a caller's bytes goes through one bounds check, `Has`, or indexes a span
  already cut to a checked length. No index can leave a buffer.
- It allocates nothing, keeps no state and throws nothing. Every export is `noexcept`.
- The self-test runs every signature cut to every shorter length, and an SMBIOS table cut at
  every length. The audit builds it under AddressSanitizer and UndefinedBehaviorSanitizer, so a
  read past the end fails the build.
- `fuzz_content.cpp` and `fuzz_smbios.cpp` feed arbitrary input to the two parsers, when
  `build.ps1 -Fuzz <seconds>` asks.

## Building

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

SippBucket.Core's build runs it with `-SkipAudit` whenever a source here is newer than the
DLL, and copies `sipengine.dll` beside every output and into every publish. The root
`build.ps1` runs the whole audit with `-RequireAudit`.

**Toolchains.** Set `SIPPBUCKET_CPPENV` to an activation script that takes
`-Toolchain msvc|clang-cl|gcc -Quiet`, as the owner's `E:\dev\cppenv.ps1` does, and every
toolchain comes from it. Without it, MSVC and clang-cl come from the newest Visual Studio with
the C++ tools (found by `vswhere`), and g++ and clang-tidy from `PATH`.

**The shipping flags**, each explained in `build.ps1`: `/std:c++20 /permissive- /W4 /WX /sdl`,
`/GS /guard:cf` with `/GUARD:CF /CETCOMPAT` at the link, `/DYNAMICBASE /NXCOMPAT
/HIGHENTROPYVA`, and `/MT`, so the DLL needs nothing beside it but Windows. The build then
checks that it imports only `KERNEL32.dll` and exports exactly the seven functions `sipengine.h`
declares.

**The audit**, each pass in its own PowerShell with its own toolchain:

| Pass | What it runs |
| --- | --- |
| `gcc` | MinGW-w64 g++ with `-Werror` and the project's extra warnings; builds and runs the self-test |
| `clang-cl` | clang-cl with `/WX` and the same extra warnings; builds and runs the self-test |
| `tidy` | clang-tidy with `.clang-tidy` on every source; any finding fails |
| `asan` | the self-test under AddressSanitizer |
| `ubsan` | the self-test under UndefinedBehaviorSanitizer, trapping on the first error |

A pass whose toolchain is missing is reported SKIPPED, never passed.

## The ABI's rules

The ones `../sipnative/README.md` measured, kept here:

- Every parameter blittable: pointers, `size_t` (`nuint`), fixed-width integers, `int32_t`
  return codes. No strings, no `bool`, no padded structs.
- No `SetLastError`. The caller owns every buffer, and nothing is returned for the caller to
  free.
- No callbacks. Nothing opens a socket, a registry key or a file. The one call to Windows is
  `sipe_smbios_read`'s, and Windows' error code comes back in an out parameter.
- Call `sipe_abi_version()` at start-up. SippBucket.exe does, before anything else, and refuses
  to start without the DLL or with one from a different build (`SipEngine.Problem`).

Content type numbers are part of the ABI: quarantine records store them, so a type keeps its
number for ever, and a retired number is never reused.
