[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Source,

    [Parameter(Mandatory = $true)]
    [string]$Output,

    [string]$FxcPath,

    [string]$IncludePath
)

$ErrorActionPreference = 'Stop'

function Resolve-Fxc {
    if ($FxcPath -and (Test-Path -LiteralPath $FxcPath)) {
        return (Resolve-Path -LiteralPath $FxcPath).Path
    }

    $sdkRoot = $env:WindowsSdkDir
    $sdkVersion = $env:WindowsSDKVersion
    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($sdkRoot) {
        if ($sdkVersion) {
            $candidates.Add((Join-Path $sdkRoot "bin\$sdkVersion\x64\fxc.exe"))
        }
        $candidates.Add((Join-Path $sdkRoot 'bin\x64\fxc.exe'))
    }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path -LiteralPath $kitsRoot) {
        $latestKit = Get-ChildItem -LiteralPath $kitsRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if ($latestKit) {
            $candidates.Add((Join-Path $latestKit.FullName 'x64\fxc.exe'))
        }
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    $command = Get-Command fxc.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    throw 'fxc.exe was not found. Install the Windows SDK shader tools or pass -FxcPath explicitly.'
}

function Resolve-IncludePath {
    if ($IncludePath -and (Test-Path -LiteralPath (Join-Path $IncludePath 'd2d1effecthelpers.hlsli'))) {
        return (Resolve-Path -LiteralPath $IncludePath).Path
    }

    $sdkRoot = $env:WindowsSdkDir
    $sdkVersion = $env:WindowsSDKVersion
    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($sdkRoot -and $sdkVersion) {
        $candidates.Add((Join-Path $sdkRoot "Include\$sdkVersion\um"))
    }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Include'
    if (Test-Path -LiteralPath $kitsRoot) {
        $latestInclude = Get-ChildItem -LiteralPath $kitsRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if ($latestInclude) {
            $candidates.Add((Join-Path $latestInclude.FullName 'um'))
        }
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if (Test-Path -LiteralPath (Join-Path $candidate 'd2d1effecthelpers.hlsli')) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw 'd2d1effecthelpers.hlsli was not found. Pass -IncludePath to the Windows SDK um include directory.'
}

$fxc = Resolve-Fxc
$include = Resolve-IncludePath
$outputDirectory = Split-Path -Parent $Output
$library = Join-Path $outputDirectory 'MissionControllerGlow.fxlib'
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$libraryArguments = @(
    $Source,
    '/nologo',
    '/T', 'lib_4_0_level_9_3_ps_only',
    '/D', 'D2D_FUNCTION',
    '/D', 'D2D_ENTRY=main',
    '/Fl', $library,
    '/I', $include
)
& $fxc @libraryArguments
if ($LASTEXITCODE -ne 0) {
    throw "fxc failed while generating the Win2D effect library ($LASTEXITCODE)."
}

$shaderArguments = @(
    $Source,
    '/nologo',
    '/T', 'ps_4_0_level_9_3',
    '/D', 'D2D_FULL_SHADER',
    '/D', 'D2D_ENTRY=main',
    '/E', 'main',
    '/setprivate', $library,
    '/Fo', $Output,
    '/I', $include
)
& $fxc @shaderArguments
if ($LASTEXITCODE -ne 0) {
    throw "fxc failed while generating the Win2D shader bytecode ($LASTEXITCODE)."
}

Remove-Item -LiteralPath $library -Force -ErrorAction SilentlyContinue
