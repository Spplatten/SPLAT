[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Source,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string]$FxcPath,

    [string]$DxcPath
)

$ErrorActionPreference = 'Stop'

function Resolve-Compiler {
    if ($FxcPath -and (Test-Path -LiteralPath $FxcPath)) {
        return [pscustomobject]@{ Path = (Resolve-Path -LiteralPath $FxcPath).Path; Kind = 'fxc' }
    }

    $command = Get-Command fxc.exe -ErrorAction SilentlyContinue
    if ($command) {
        return [pscustomobject]@{ Path = $command.Source; Kind = 'fxc' }
    }

    if ($DxcPath -and (Test-Path -LiteralPath $DxcPath)) {
        return [pscustomobject]@{ Path = (Resolve-Path -LiteralPath $DxcPath).Path; Kind = 'dxc' }
    }

    $dxcCommand = Get-Command dxc.exe -ErrorAction SilentlyContinue
    if ($dxcCommand) {
        return [pscustomobject]@{ Path = $dxcCommand.Source; Kind = 'dxc' }
    }

    $sdkRoot = $env:WindowsSdkDir
    $sdkVersion = $env:WindowsSDKVersion
    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($sdkRoot -and $sdkVersion) {
        $candidates.Add((Join-Path $sdkRoot "bin\$sdkVersion\x64\fxc.exe"))
    }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path -LiteralPath $kitsRoot) {
        $latestKit = Get-ChildItem -LiteralPath $kitsRoot -Directory |
            Sort-Object Name -Descending |
            Select-Object -First 1
        if ($latestKit) {
            $candidates.Add((Join-Path $latestKit.FullName 'x64\fxc.exe'))
        }
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw 'fxc.exe or dxc.exe was not found. Install the Windows SDK shader tools or pass -FxcPath/-DxcPath explicitly.'
}

$compiler = Resolve-Compiler
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$vertexOutput = Join-Path $OutputDirectory 'MissionControllerComposite.VS.cso'
$pixelOutput = Join-Path $OutputDirectory 'MissionControllerComposite.PS.cso'
$computeOutput = Join-Path $OutputDirectory 'MissionControllerComposite.CS.cso'

$vertexProfile = if ($compiler.Kind -eq 'dxc') { 'vs_6_0' } else { 'vs_5_0' }
$pixelProfile = if ($compiler.Kind -eq 'dxc') { 'ps_6_0' } else { 'ps_5_0' }
$computeProfile = if ($compiler.Kind -eq 'dxc') { 'cs_6_0' } else { 'cs_5_0' }
$switchPrefix = if ($compiler.Kind -eq 'dxc') { '-' } else { '/' }

& $compiler.Path $Source "${switchPrefix}nologo" "${switchPrefix}T" $vertexProfile "${switchPrefix}E" VSMain "${switchPrefix}Fo" $vertexOutput
if ($LASTEXITCODE -ne 0) {
    throw "$($compiler.Kind) failed while compiling the Direct3D vertex shader ($LASTEXITCODE)."
}

& $compiler.Path $Source "${switchPrefix}nologo" "${switchPrefix}T" $pixelProfile "${switchPrefix}E" PSMain "${switchPrefix}Fo" $pixelOutput
if ($LASTEXITCODE -ne 0) {
    throw "$($compiler.Kind) failed while compiling the Direct3D pixel shader ($LASTEXITCODE)."
}

& $compiler.Path $Source "${switchPrefix}nologo" "${switchPrefix}T" $computeProfile "${switchPrefix}E" CSMain "${switchPrefix}Fo" $computeOutput
if ($LASTEXITCODE -ne 0) {
    throw "$($compiler.Kind) failed while compiling the Direct3D compute shader ($LASTEXITCODE)."
}
