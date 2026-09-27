<#
.SYNOPSIS
    Compiles and packages Mission Controller into an Enterprise-Signed MSIX package.
.DESCRIPTION
    Builds the solution in Release mode for win-x64, ensures code signing certificate trust,
    and creates the signed .msix bundle in the dist/ output directory.
#>
[CmdletBinding()]
param (
    [string]$Configuration = "Release",
    [string]$Architecture = "win-x64",
    [string]$CertSubject = "CN=Enterprise IT Systems, O=Enterprise, C=US"
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
$ProjectRoot = (Resolve-Path "$ScriptRoot\..").Path
$OutputDir = "$ProjectRoot\dist"
$DotNetExe = "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe"
if (-not (Test-Path $DotNetExe)) {
    $DotNetExe = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
}
# With neither present this was $null, and `& $null publish` throws a message about an empty pipeline
# element that says nothing about a missing SDK. The user-local path is first because the dotnet on
# PATH here is SDK 9, which cannot build this net10 tree.
if (-not $DotNetExe) {
    Write-Error ("No dotnet executable found. Looked for " +
        "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe and then PATH.")
    exit 1
}

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  ENTERPRISE MSIX PACKAGING PIPELINE (MISSION CONTROLLER)" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan

# 1. Prepare Output Directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# 2. Build & Publish Solution in Release Mode
Write-Host "`n[1/4] Publishing application binaries in $Configuration mode ($Architecture)..." -ForegroundColor Yellow
$PublishDir = "$ProjectRoot\src\MissionController.UI\bin\x64\$Configuration\net10.0-windows10.0.19041.0\$Architecture\publish"

& $DotNetExe publish "$ProjectRoot\src\MissionController.UI\MissionController.UI.csproj" `
    -c $Configuration `
    -r $Architecture `
    --self-contained true `
    /p:Platform=x64 `
    /p:WindowsPackageType=None `
    /p:PublishSingleFile=false

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to publish MissionController.UI."
    exit 1
}

# 3. Verify / Generate Enterprise Code-Signing Certificate
Write-Host "`n[2/4] Verifying Enterprise Code-Signing Certificate..." -ForegroundColor Yellow
$Cert = Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq $CertSubject } | Select-Object -First 1

if (-not $Cert) {
    Write-Host "Generating self-signed Enterprise Code-Signing Certificate..." -ForegroundColor Gray
    $Cert = New-SelfSignedCertificate `
        -Type Custom `
        -Subject $CertSubject `
        -KeyUsage DigitalSignature `
        -FriendlyName "Enterprise Mission Controller Code Signing" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
}

# Export public CER for silent Intune/SCCM trust
$CerPath = "$OutputDir\Enterprise.MissionController.cer"
Export-Certificate -Cert $Cert -FilePath $CerPath -Force | Out-Null
Write-Host "Exported Enterprise Certificate to $CerPath" -ForegroundColor Green

# 4. Create AppX / MSIX Package Layout
Write-Host "`n[3/4] Structuring MSIX Package Layout..." -ForegroundColor Yellow
$PackageLayout = "$OutputDir\PackageLayout"
if (Test-Path $PackageLayout) {
    Remove-Item $PackageLayout -Recurse -Force
}
New-Item -ItemType Directory -Path $PackageLayout -Force | Out-Null

Copy-Item -Path "$PublishDir\*" -Destination $PackageLayout -Recurse -Force
Copy-Item -Path "$ProjectRoot\src\MissionController.UI\Package.appxmanifest" -Destination "$PackageLayout\AppxManifest.xml" -Force

# Create Assets directory with placeholder logos if not present
$AssetsDir = "$PackageLayout\Assets"
if (-not (Test-Path $AssetsDir)) {
    New-Item -ItemType Directory -Path $AssetsDir -Force | Out-Null
}

# 5. Pack MSIX using Windows SDK MakeAppx or produce deployment payload
Write-Host "`n[4/4] Generating Signed Enterprise Package Bundle..." -ForegroundColor Yellow
$MsixPath = "$OutputDir\Enterprise.MissionController.msix"

$MakeAppx = (Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Filter "makeappx.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
$SignTool = (Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Filter "signtool.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1).FullName

# What this run actually produced, decided by what actually happened rather than by which branch was
# entered. The banner at the bottom reads these, because a pipeline whose last line is an
# unconditional "COMPLETED SUCCESSFULLY" tells you the script reached the end, not that it worked.
$Artifact = $null
$ArtifactKind = "nothing"
$Signed = $false

if ($MakeAppx -and (Test-Path $MakeAppx)) {
    # $ErrorActionPreference = "Stop" does NOT apply to a native executable's exit code: makeappx and
    # signtool report failure the only way a console program can, and until 2026-09-27 neither was
    # read. A manifest naming an asset that is not in the layout fails the pack, and the script went
    # on to announce a signed enterprise package.
    & $MakeAppx pack /d $PackageLayout /p $MsixPath /o
    if ($LASTEXITCODE -ne 0) {
        Write-Error "makeappx pack failed with exit code $LASTEXITCODE. No package was produced."
        exit 1
    }
    if (-not (Test-Path $MsixPath)) {
        Write-Error "makeappx pack reported success but $MsixPath does not exist."
        exit 1
    }
    $Artifact = $MsixPath
    $ArtifactKind = "MSIX"

    # A missing signtool is a REFUSAL, not a skip. The one thing this script exists to hand someone
    # is a signed package; producing an unsigned .msix and calling the run a success is how an
    # unsigned build reaches a machine that was told to trust it.
    if (-not ($SignTool -and (Test-Path $SignTool))) {
        Write-Error ("signtool.exe was not found under the Windows 10 SDK, so $MsixPath cannot be " +
            "signed. Install the SDK's signing tools, or package without MSIX by removing makeappx " +
            "from PATH to take the archive path deliberately. An unsigned MSIX is not shipped.")
        exit 1
    }

    & $SignTool sign /fd SHA256 /a /sha1 $Cert.Thumbprint $MsixPath
    if ($LASTEXITCODE -ne 0) {
        Write-Error "signtool sign failed with exit code $LASTEXITCODE. $MsixPath is NOT signed."
        exit 1
    }

    # signtool exits 0 having signed; ask the certificate store rather than trust the exit code,
    # because this is the claim the package is distributed on.
    $Signature = Get-AuthenticodeSignature -FilePath $MsixPath
    if ($Signature.Status -ne "Valid" -and $Signature.Status -ne "UnknownError") {
        # UnknownError is what a self-signed chain reads as until the .cer is trusted, which is
        # exactly what install-enterprise.ps1 does on the target. An absent signature is not that.
        Write-Error "After signing, $MsixPath reports signature status '$($Signature.Status)'."
        exit 1
    }
    if ($Signature.SignerCertificate -eq $null) {
        Write-Error "After signing, $MsixPath carries no signer certificate."
        exit 1
    }
    $Signed = $true
    Write-Host "Generated Signed MSIX Package: $MsixPath" -ForegroundColor Green
} else {
    # Fallback to standard enterprise zip bundle for IntuneWin wrapper if SDK MakeAppx is omitted on
    # host. This path produces an UNSIGNED archive, and the banner says so rather than inheriting the
    # word "signing" from the MSIX path.
    $ZipPath = "$OutputDir\Enterprise.MissionController.zip"
    Compress-Archive -Path "$PackageLayout\*" -DestinationPath $ZipPath -Force
    if (-not (Test-Path $ZipPath)) {
        Write-Error "Compress-Archive reported success but $ZipPath does not exist."
        exit 1
    }
    $Artifact = $ZipPath
    $ArtifactKind = "ZIP"
    Write-Host "Created Enterprise Distribution Archive: $ZipPath" -ForegroundColor Yellow
    Write-Warning "makeappx.exe was not found, so this is an UNSIGNED archive and not an MSIX."
}

# Copy deployment scripts to dist/
Copy-Item "$ScriptRoot\install-enterprise.ps1" "$OutputDir\install-enterprise.ps1" -Force
Copy-Item "$ScriptRoot\uninstall-enterprise.ps1" "$OutputDir\uninstall-enterprise.ps1" -Force

# Ship the plain-English guide beside the package. Whoever evaluates a build is rarely whoever
# produced it, and this is a self-contained page - no server, no install, just open it.
Copy-Item "$ProjectRoot\docs\SPLAT-Field-Guide.html" "$OutputDir\SPLAT-Field-Guide.html" -Force

# The banner names what was produced and whether it is signed, read from what the steps above
# recorded. It used to say "MSIX BUILD & ENTERPRISE SIGNING COMPLETED SUCCESSFULLY" whatever
# happened, including when makeappx was absent and the output was a zip, and including when signing
# never ran at all.
$Colour = if ($Signed) { "Green" } else { "Yellow" }
Write-Host "`n===============================================================================" -ForegroundColor $Colour
Write-Host "  BUILD COMPLETE - $ArtifactKind$(if ($Signed) { ', SIGNED' } else { ', UNSIGNED' })" -ForegroundColor $Colour
Write-Host "  Artifact: $Artifact" -ForegroundColor $Colour
Write-Host "  Output Directory: $OutputDir" -ForegroundColor $Colour
Write-Host "===============================================================================" -ForegroundColor $Colour
