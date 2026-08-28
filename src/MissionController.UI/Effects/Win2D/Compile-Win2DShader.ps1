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
        # Only versioned kit folders are candidates, sorted AS VERSIONS rather than as strings.
        # A plain name sort ranks the legacy 'x86'/'x64'/'arm64' tool folders above '10.0.26100.0',
        # so the newest SDK was never reached and discovery failed on machines that had it installed.
        $versionedKits = Get-ChildItem -LiteralPath $kitsRoot -Directory |
            Where-Object { $_.Name -as [version] } |
            Sort-Object { [version]$_.Name } -Descending
        foreach ($kit in $versionedKits) {
            $candidates.Add((Join-Path $kit.FullName 'x64\fxc.exe'))
        }

        # Some SDK layouts place the tools directly under bin\x64 with no version folder.
        $candidates.Add((Join-Path $kitsRoot 'x64\fxc.exe'))
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
        # Same version-vs-string sort issue as the fxc lookup above.
        $versionedIncludes = Get-ChildItem -LiteralPath $kitsRoot -Directory |
            Where-Object { $_.Name -as [version] } |
            Sort-Object { [version]$_.Name } -Descending
        foreach ($inc in $versionedIncludes) {
            $candidates.Add((Join-Path $inc.FullName 'um'))
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
$shaderBaseName = [System.IO.Path]::GetFileNameWithoutExtension($Source)
$library = Join-Path $outputDirectory "$shaderBaseName.fxlib"
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$libraryArguments = @(
    $Source,
    '/nologo',
    # ps_4_0 rather than the level_9_3 variants: feature level 9_3 caps constants at 32 registers,
    # which MissionControllerGlow blows on its own (it is a mega-shader carrying every effect mode)
    # once D2D adds its reserved transform registers. Level 9_3 targets pre-DX10 GPUs that cannot
    # run WinUI 3 with DirectComposition in the first place, so the compatibility it buys is nil.
    '/T', 'lib_4_0',
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
    '/T', 'ps_4_0',
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
