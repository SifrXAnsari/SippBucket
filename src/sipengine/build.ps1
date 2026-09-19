<#
.SYNOPSIS
    Builds sipengine.dll and its self-test with MSVC, runs the self-test, and audits the
    sources with other compilers, clang-tidy and the sanitizers.

.DESCRIPTION
    The shipping DLL is MSVC's. Flags, and why each is here:

      /std:c++20 /permissive-   standard C++20, with Microsoft's extensions to it refused.
      /W4 /WX                   every level-4 warning, and every warning an error, as the
                                managed side holds with TreatWarningsAsErrors.
      /sdl                      the Security Development Lifecycle checks: more warnings made
                                errors, and runtime checks the compiler can add cheaply.
      /GS /guard:cf             stack buffer checks and Control Flow Guard, with /GUARD:CF
                                and /CETCOMPAT (shadow-stack compatible) at the link.
      /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA
                                address-space randomisation and no-execute data, stated
                                although they are the linker's defaults, so a change of
                                default cannot drop them unnoticed.
      /MT                       the C runtime linked in, so the DLL needs nothing beside it
                                but Windows itself. The import audit below checks that.
      /EHsc                     C++ exceptions for the standard library's headers. Nothing in
                                the engine throws, and every export is noexcept.
      /utf-8                    source and execution character sets are UTF-8.

    Then the self-test runs, and dumpbin checks two things about the DLL: that it imports
    nothing but KERNEL32.dll, and that it exports exactly the seven functions sipengine.h
    declares.

    The audit, unless -SkipAudit, runs each pass in its own PowerShell, with that pass's
    toolchain, so no two toolchains' environments mix:

      gcc       MinGW-w64 g++ with -Werror and the project's extra warnings. The self-test is
                built and run under it too. _WIN32_WINNT is set to Windows 10's, as the
                Windows SDK sets it for MSVC, so MinGW's headers declare the same functions.
      clang-cl  clang-cl with /WX and the same extra warnings, building and running the
                self-test.
      tidy      clang-tidy with ./.clang-tidy on every source; any finding fails.
      asan      the self-test under AddressSanitizer, with clang's own ASan runtime put beside
                it (Copy-SanitizerRuntime below says why).
      ubsan     the self-test under UndefinedBehaviorSanitizer, trapping on the first error.

    A pass whose toolchain cannot be found is reported SKIPPED, never passed. -RequireAudit
    turns a SKIPPED pass into a failure, which is how the root build.ps1 runs it.

    Toolchains: when SIPPBUCKET_CPPENV names an activation script taking
    -Toolchain msvc|clang-cl|gcc -Quiet (the owner's machines have one), every toolchain comes
    from it. Otherwise MSVC and clang-cl come from the newest Visual Studio with the C++ tools,
    found by vswhere, and g++ and clang-tidy from PATH. The finding is NativeToolchain.psm1's,
    which the installer's custom action builds with too.

.PARAMETER Configuration
    Release (the default) or Debug.

.PARAMETER OutDir
    Where the DLL, the self-test and the audit's logs go. Default: build\<Configuration>
    beside this script.

.PARAMETER SkipAudit
    Build and self-test only. The project's build runs it this way on every build; the root
    build.ps1 runs the audit.

.PARAMETER RequireAudit
    Fail when an audit pass is SKIPPED because its toolchain is missing.

.PARAMETER Fuzz
    After the audit, build each libFuzzer entry point (one per parser: the content check and
    the SMBIOS reader) with clang-cl and run each for this many seconds. 0, the default, does
    not run them.

.PARAMETER AuditPass
    Internal: run one audit pass in this process. Used by this script for each pass.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Configuration Debug -SkipAudit
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',
    [string] $OutDir,
    [switch] $SkipAudit,
    [switch] $RequireAudit,
    [ValidateRange(0, 86400)]
    [int] $Fuzz = 0,
    [ValidateSet('', 'gcc', 'clang-cl', 'tidy', 'asan', 'ubsan', 'fuzz')]
    [string] $AuditPass = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'NativeToolchain.psm1') -Force
if (-not $OutDir) {
    $OutDir = Join-Path $here (Join-Path 'build' $Configuration)
}

$OutDir = [IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$sources = @('content_check.cpp', 'exports.cpp', 'randomness.cpp', 'smbios.cpp', 'smbios_read.cpp') | ForEach-Object { Join-Path $here $_ }
$selftestSource = Join-Path $here 'selftest.cpp'
$fuzzTargets = @('fuzz_content.cpp', 'fuzz_smbios.cpp') | ForEach-Object { Join-Path $here $_ }
$tidyConfig = Join-Path $here '.clang-tidy'

# The exit code an audit pass uses to say its toolchain is not on this machine.
$SkippedExitCode = 3

function Copy-SanitizerRuntime([string] $exe) {
    <#
      Puts the ASan runtime an executable imports beside it. Current clang ships no static ASan
      runtime for Windows, so even a /MT build loads clang_rt.asan_dynamic at run time, and the
      loader takes the first copy it finds. With MSVC's environment active, PATH holds MSVC's
      own build of that DLL, which lacks the exports clang's instrumentation calls: the process
      dies before main with STATUS_ENTRYPOINT_NOT_FOUND (0xC0000139). The executable's folder is
      searched before PATH, so the runtime from clang's resource directory is copied there. An
      executable that imports no ASan runtime needs nothing.
    #>
    $resource = @(Invoke-Tool 'clang-cl' @('/clang:-print-resource-dir'))[0].Trim()
    foreach ($name in @(Get-DllImports $exe | Where-Object { $_ -like 'clang_rt.asan*' })) {
        $runtime = @(Get-ChildItem -LiteralPath $resource -Recurse -File -Filter $name)
        if ($runtime.Count -ne 1) {
            throw "Found $($runtime.Count) copies of $name under $resource; expected exactly one."
        }

        Copy-Item -LiteralPath $runtime[0].FullName -Destination (Split-Path -Parent $exe) -Force
    }
}

# The exports sipengine.h declares, and nothing else may be exported. Sorted, as the check
# below sorts what dumpbin lists.
$expectedExports = @('sipe_abi_version', 'sipe_content_check', 'sipe_content_type_extension', 'sipe_content_type_name',
    'sipe_randomness', 'sipe_smbios_identity', 'sipe_smbios_read')

function Invoke-AuditPassBody([string] $pass) {
    <# One audit pass, in this process. Exits 0 on a pass, $SkippedExitCode when skipped. #>
    $work = Join-Path $OutDir "audit-$pass"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    Push-Location $work

    try {
        switch ($pass) {
            'gcc' {
                if (-not (Use-Toolchain 'gcc')) { exit $SkippedExitCode }

                $exe = Join-Path $work 'selftest-gcc.exe'
                $flags = @('-std=c++20', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Werror', '-Wshadow',
                    '-Wconversion', '-Wsign-conversion', '-Wcast-qual', '-Wold-style-cast', '-Wmissing-declarations',
                    '-Wnon-virtual-dtor', '-Woverloaded-virtual', '-Wundef', '-Wimplicit-fallthrough', '-Wformat=2',
                    '-Wduplicated-cond', '-Wlogical-op', '-D_WIN32_WINNT=0x0A00', '-DSIPENGINE_BUILDING', "-I$here")

                # -static: the MinGW C++ runtime is otherwise three DLLs this test would need
                # beside it (sipnative's README measured the same for its C++ case).
                Invoke-Tool 'g++' ($flags + $sources + @($selftestSource, '-static', '-o', $exe))
                Invoke-Tool $exe @()
            }

            'clang-cl' {
                if (-not (Use-Toolchain 'clang-cl')) { exit $SkippedExitCode }

                $exe = Join-Path $work 'selftest-clang.exe'
                $flags = @('/nologo', '/std:c++20', '/W4', '/WX', '/EHsc', '/utf-8', '/O2', '/MT', '-Wextra',
                    '-Wpedantic', '-Wshadow', '-Wconversion', '-Wsign-conversion', '-Wcast-qual', '-Wold-style-cast',
                    '-Wmissing-prototypes', '-Wundef', '-Wimplicit-fallthrough', '/DSIPENGINE_BUILDING', "/I$here")
                Invoke-Tool 'clang-cl' ($flags + $sources + @($selftestSource, "/Fe:$exe"))
                Invoke-Tool $exe @()
            }

            'tidy' {
                if (-not (Use-Toolchain 'clang-cl')) { exit $SkippedExitCode }
                if (-not (Get-Command clang-tidy -ErrorAction SilentlyContinue)) { exit $SkippedExitCode }

                foreach ($file in ($sources + @($selftestSource) + $fuzzTargets)) {
                    Invoke-Tool 'clang-tidy' @('--quiet', "--config-file=$tidyConfig", $file, '--',
                        '--driver-mode=cl', '/std:c++20', '/EHsc', '/utf-8', '/DSIPENGINE_BUILDING', "/I$here")
                }
            }

            'asan' {
                if (-not (Use-Toolchain 'clang-cl')) { exit $SkippedExitCode }

                $exe = Join-Path $work 'selftest-asan.exe'
                Invoke-Tool 'clang-cl' (@('/nologo', '/std:c++20', '/EHsc', '/utf-8', '/Od', '/Zi', '/MT',
                    '/fsanitize=address', '/DSIPENGINE_BUILDING', "/I$here") + $sources + @($selftestSource, "/Fe:$exe"))
                Copy-SanitizerRuntime $exe
                Invoke-Tool $exe @()
            }

            'ubsan' {
                if (-not (Use-Toolchain 'clang-cl')) { exit $SkippedExitCode }

                # Trapping mode needs no sanitizer runtime: the first undefined behaviour stops
                # the process, which fails the run.
                $exe = Join-Path $work 'selftest-ubsan.exe'
                Invoke-Tool 'clang-cl' (@('/nologo', '/std:c++20', '/EHsc', '/utf-8', '/Od', '/MT',
                    '-fsanitize=undefined', '-fsanitize-trap=undefined', '/DSIPENGINE_BUILDING', "/I$here") +
                    $sources + @($selftestSource, "/Fe:$exe"))
                Invoke-Tool $exe @()
            }

            'fuzz' {
                if (-not (Use-Toolchain 'clang-cl')) { exit $SkippedExitCode }

                # One run per parser, each with its own corpus, for the seconds asked.
                foreach ($target in $fuzzTargets) {
                    $name = [IO.Path]::GetFileNameWithoutExtension($target)
                    $exe = Join-Path $work "$name.exe"
                    $corpus = Join-Path $work "corpus-$name"
                    New-Item -ItemType Directory -Force -Path $corpus | Out-Null
                    Invoke-Tool 'clang-cl' (@('/nologo', '/std:c++20', '/EHsc', '/utf-8', '/Od', '/Zi', '/MT',
                        '-fsanitize=fuzzer,address', '/DSIPENGINE_BUILDING', "/I$here") + $sources + @($target, "/Fe:$exe"))
                    Copy-SanitizerRuntime $exe
                    Invoke-Tool $exe @("-max_total_time=$Fuzz", $corpus)
                }
            }
        }
    }
    finally {
        Pop-Location
    }

    exit 0
}

if ($AuditPass) {
    Invoke-AuditPassBody $AuditPass
}

# --- The shipping build ----------------------------------------------------------------------

if (-not (Use-Toolchain 'msvc')) {
    throw ('MSVC was not found. Install Visual Studio or its Build Tools with "Desktop development ' +
        'with C++", or set SIPPBUCKET_CPPENV to a toolchain activation script.')
}

$objDir = Join-Path $OutDir 'obj'
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

$dll = Join-Path $OutDir 'sipengine.dll'
$selftest = Join-Path $OutDir 'sipengine-selftest.exe'

$compile = @('/nologo', '/std:c++20', '/permissive-', '/W4', '/WX', '/sdl', '/EHsc', '/utf-8', '/Zc:__cplusplus',
    '/Zc:preprocessor', '/GS', '/guard:cf', '/DSIPENGINE_BUILDING', "/I$here")
$link = @('/INCREMENTAL:NO', '/DYNAMICBASE', '/NXCOMPAT', '/HIGHENTROPYVA', '/GUARD:CF', '/CETCOMPAT')

if ($Configuration -eq 'Release') {
    $compile += @('/O2', '/MT', '/DNDEBUG')
    $link += @('/OPT:REF', '/OPT:ICF')
}
else {
    $compile += @('/Od', '/MTd', '/Z7', '/RTC1')
}

# Objects land in obj\, from there, so no /Fo path needs a trailing backslash.
Push-Location $objDir
try {
    Write-Host "Building $dll ..."
    Invoke-Tool 'cl.exe' ($compile + $sources + @('/LD', "/Fe:$dll", '/link') + $link)

    Write-Host "Building $selftest ..."
    Invoke-Tool 'cl.exe' ($compile + $sources + @($selftestSource, "/Fe:$selftest", '/link') + $link)
}
finally {
    Pop-Location
}

Write-Host 'Running the self-test ...'
Invoke-Tool $selftest @()

Write-Host 'Auditing the imports and exports ...'
$imports = Get-DllImports $dll

$foreign = @($imports | Where-Object { $_ -notmatch '^KERNEL32\.dll$' })
if ($foreign.Count -gt 0) {
    throw ('sipengine.dll imports more than KERNEL32.dll, so it is not self-contained: ' + ($foreign -join ', '))
}

$exported = Get-DllExports $dll
if (($exported -join ',') -ne ($expectedExports -join ',')) {
    throw ('sipengine.dll exports ' + ($exported -join ', ') + '; sipengine.h declares ' + ($expectedExports -join ', '))
}

Write-Host "  imports: $($imports -join ', ')"
Write-Host "  exports: $($exported -join ', ')"

if ($SkipAudit) {
    Write-Host 'BUILD OK (audit skipped)'
    exit 0
}

# --- The audit -------------------------------------------------------------------------------

$shell = (Get-Process -Id $PID).Path
$passes = @('gcc', 'clang-cl', 'tidy', 'asan', 'ubsan')
if ($Fuzz -gt 0) {
    $passes += 'fuzz'
}

$failed = $false
foreach ($pass in $passes) {
    $log = Join-Path $OutDir "audit-$pass.log"
    & $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $PSCommandPath -AuditPass $pass `
        -Configuration $Configuration -OutDir $OutDir -Fuzz $Fuzz *> $log
    $code = $LASTEXITCODE

    $result = if ($code -eq 0) { 'PASS' } elseif ($code -eq $SkippedExitCode) { 'SKIPPED' } else { 'FAIL' }
    if ($result -eq 'FAIL' -or ($result -eq 'SKIPPED' -and $RequireAudit)) {
        $failed = $true
    }

    Write-Host ("  {0,-8} {1}  (log: {2})" -f $result, $pass, $log)
}

if ($failed) {
    throw 'The audit failed. Each log above says why.'
}

Write-Host 'BUILD OK'
