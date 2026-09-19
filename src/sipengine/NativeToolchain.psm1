<#
.SYNOPSIS
    Finds and activates the C++ toolchains SippBucket's native code is built with: MSVC,
    clang-cl and MinGW-w64 g++.

.DESCRIPTION
    Shared by the two native builds, so they cannot come to disagree about which compiler they
    use: the engine (sample/src/sipengine/build.ps1) and the installer's custom action
    (install/msi/setup/build.ps1).

    When SIPPBUCKET_CPPENV names an activation script taking -Toolchain msvc|clang-cl|gcc -Quiet
    (the owner's machines have one), every toolchain comes from it. Otherwise MSVC and clang-cl
    come from the newest Visual Studio with the C++ tools, found by vswhere, and g++ and
    clang-tidy from PATH. Activating changes this process's environment, which is why each
    audit pass runs in a PowerShell of its own.
#>

Set-StrictMode -Version Latest

$script:VsPath = $null

function Enter-VisualStudio {
    <# Puts MSVC on PATH from the newest Visual Studio with the C++ tools. True when cl is there. #>
    if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
        if ($env:VSINSTALLDIR) {
            $script:VsPath = $env:VSINSTALLDIR
        }

        return $true
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        return $false
    }

    $path = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $path) {
        return $false
    }

    $script:VsPath = $path
    Import-Module (Join-Path $path 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
    Enter-VsDevShell -VsInstallPath $path -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64' | Out-Null
    return [bool](Get-Command cl.exe -ErrorAction SilentlyContinue)
}

function Use-Toolchain {
    <# Activates a toolchain in this process. True when its compiler is on PATH afterwards. #>
    param([Parameter(Mandatory)] [ValidateSet('msvc', 'clang-cl', 'gcc')] [string] $Name)

    if ($env:SIPPBUCKET_CPPENV) {
        if (-not (Test-Path -LiteralPath $env:SIPPBUCKET_CPPENV)) {
            throw "SIPPBUCKET_CPPENV names '$($env:SIPPBUCKET_CPPENV)', which does not exist."
        }

        . $env:SIPPBUCKET_CPPENV -Toolchain $Name -Quiet
    }
    elseif ($Name -eq 'msvc') {
        return Enter-VisualStudio
    }
    elseif ($Name -eq 'clang-cl') {
        if (-not (Enter-VisualStudio)) {
            return $false
        }

        if ($script:VsPath) {
            $llvm = Join-Path $script:VsPath 'VC\Tools\Llvm\x64\bin'
            if (Test-Path -LiteralPath $llvm) {
                $env:PATH = "$llvm;$($env:PATH)"
            }
        }
    }

    $compiler = switch ($Name) {
        'msvc' { 'cl.exe' }
        'clang-cl' { 'clang-cl.exe' }
        default { 'g++.exe' }
    }

    return [bool](Get-Command $compiler -ErrorAction SilentlyContinue)
}

function Invoke-Tool {
    <# Runs a native tool and throws on a non-zero exit, naming the tool. #>
    param([Parameter(Mandatory)] [string] $Tool, [string[]] $Arguments = @())

    & $Tool @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Tool failed (exit $LASTEXITCODE)"
    }
}

function Get-DllImports {
    <# The DLLs a binary imports, as dumpbin lists them. #>
    param([Parameter(Mandatory)] [string] $Path)

    $imports = & dumpbin.exe /nologo /imports $Path | ForEach-Object {
        if ($_ -match '^\s{4}(\S+\.dll)\s*$') { $Matches[1] }
    }
    if ($LASTEXITCODE -ne 0) { throw "dumpbin /imports failed on $Path" }
    return @($imports)
}

function Get-DllExports {
    <# The functions a DLL exports, sorted, as dumpbin lists them. #>
    param([Parameter(Mandatory)] [string] $Path)

    $exports = & dumpbin.exe /nologo /exports $Path | ForEach-Object {
        if ($_ -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]{8}\s+(\S+)') { $Matches[1] }
    }
    if ($LASTEXITCODE -ne 0) { throw "dumpbin /exports failed on $Path" }
    return @($exports | Sort-Object)
}

Export-ModuleMember -Function Enter-VisualStudio, Use-Toolchain, Invoke-Tool, Get-DllImports, Get-DllExports
