// smbios_read.cpp - the one place the engine asks Windows for anything: the firmware's SMBIOS
// tables, through GetSystemFirmwareTable. Kept apart from smbios.cpp, so the parser stays pure
// computation and the only file that includes windows.h is this one.
//
// docs/SERVER-ID.md asks for the call's rights and behaviour to be verified, with the source
// cited, before anything relies on them. The source is Microsoft's documentation of the
// function (sysinfoapi.h), read 2026-09-19:
// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable
//
//   - Rights. Its requirements name no privilege for desktop applications. The one access rule
//     it states is for Universal Windows apps, which need the smbios restricted capability
//     from Windows 10 version 1803. A desktop program running as the person, as SippBucket's
//     daemon does, therefore needs no administrator rights, and no WMI. The self-test calls it
//     on every build, as whoever runs the build, so a machine where that stops being true
//     fails the build instead of a user's first start.
//   - Where it lives. Kernel32.dll, so the engine still imports nothing else, which build.ps1's
//     import audit holds it to.
//   - What 'RSMB' returns. The raw SMBIOS firmware table, laid out as RawSMBIOSData: the layout
//     smbios.cpp reads. The documentation's own example passes 0 as the table ID for 'RSMB',
//     and so does this.
//   - How it answers. With a buffer big enough, the bytes written, never more than the buffer.
//     With one too small, or none at all, the size needed, always more than the buffer. On any
//     other failure 0, and GetLastError says why.
//   - Why this call. Since Windows Server 2003 SP1 an application cannot map the low physical
//     memory the tables sit in; the documentation names this call, and WMI, as the ways left.

#include "smbios.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace sipengine::smbios {
namespace {

// The documentation writes the provider as the multi-character constant 'RSMB', whose value
// C++ leaves to each compiler. Spelled out, so every compiler the audit runs agrees.
constexpr DWORD RawSmbiosProvider = (DWORD{'R'} << 24U) | (DWORD{'S'} << 16U) | (DWORD{'M'} << 8U) | DWORD{'B'};

static_assert(RawSmbiosProvider == 0x52534D42U, "'RSMB' as MSVC, the shipping compiler, reads the constant");

}  // namespace

std::int32_t Read(std::span<std::uint8_t> out, std::size_t& length, std::uint32_t& osError) noexcept
{
    length = 0U;
    osError = 0U;

    // The call takes a 32-bit size. No table comes near it, so a bigger buffer is used only
    // that far.
    constexpr std::size_t largest = std::numeric_limits<DWORD>::max();
    const DWORD capacity = static_cast<DWORD>(out.size() > largest ? largest : out.size());

    const UINT result = GetSystemFirmwareTable(RawSmbiosProvider, 0U, out.empty() ? nullptr : out.data(), capacity);
    if (result == 0U) {
        osError = GetLastError();
        return SIPE_ERR_UNAVAILABLE;
    }

    length = result;
    return result > capacity ? SIPE_ERR_CAPACITY : SIPE_OK;
}

}  // namespace sipengine::smbios
