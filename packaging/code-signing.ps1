# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Platten Industries LLC. Separate commercial licensing: COMMERCIAL.md.
#requires -Version 5.1

# Authenticode signing for the Windows artifacts, dot-sourced by the packaging scripts.
#
# The identity is chosen by environment, so no packaging script grows a credential parameter and no
# secret is ever on a command line:
#   SPLAT_SIGNING_METADATA    an Azure Artifact Signing metadata.json (Endpoint, CodeSigningAccountName,
#                             CertificateProfileName). The private key never leaves Microsoft's HSM:
#                             signtool reaches it through the Artifact Signing dlib, which signs in with
#                             DefaultAzureCredential (az login on a workstation, a service principal in CI).
#   SPLAT_SIGNING_THUMBPRINT  a code-signing certificate in CurrentUser\My or LocalMachine\My, such as an
#                             OV certificate whose USB token or cloud HSM exposes it to the Windows store.
# With neither set the build is unsigned, and every record it writes says UNSIGNED. Both set is refused,
# because which identity a release carries must not hang on a precedence rule.
# SPLAT_SIGNING_DLIB overrides where the dlib is looked for. SPLAT_SIGNING_TIMESTAMP overrides the
# RFC 3161 timestamp authority.

function Get-SplatSigningProfile {
    [CmdletBinding()]
    param()
    $metadata = $env:SPLAT_SIGNING_METADATA
    $thumbprint = $env:SPLAT_SIGNING_THUMBPRINT
    if (-not $metadata -and -not $thumbprint) { return $null }
    if ($metadata -and $thumbprint) { throw 'Set SPLAT_SIGNING_METADATA or SPLAT_SIGNING_THUMBPRINT, not both.' }

    # Configuration is judged before the machine, so a wrong file is named as such on any host.
    if ($metadata) {
        if (-not (Test-Path -LiteralPath $metadata -PathType Leaf)) { throw "SPLAT_SIGNING_METADATA names no file: $metadata" }
        $config = Get-Content -LiteralPath $metadata -Raw | ConvertFrom-Json
        foreach ($key in @('Endpoint', 'CodeSigningAccountName', 'CertificateProfileName')) {
            if (-not $config.$key) { throw "Artifact Signing metadata $metadata has no $key." }
        }
        # Any other host would receive the signing requests, and a wrong region fails later only as a
        # bare 403 from inside signtool.
        if ($config.Endpoint -notmatch '^https://[a-z0-9]+\.codesigning\.azure\.net/?$') {
            throw "Artifact Signing metadata $metadata names '$($config.Endpoint)', not a regional codesigning.azure.net endpoint."
        }
    } else {
        $thumbprint = $thumbprint.ToUpperInvariant()
        if ($thumbprint -notmatch '^[0-9A-F]{40}$') { throw "SPLAT_SIGNING_THUMBPRINT must be a certificate's 40-hex-digit SHA-1 thumbprint." }
    }

    # The newest x64 signtool. The dlib is x64 and loads only into an x64 signtool from SDK
    # 10.0.22621.755 or later, and the first hit of a recursive search can be x86, arm64 or older.
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $tools = @(Get-ChildItem -LiteralPath $kits -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $path = Join-Path $_.FullName 'x64\signtool.exe'
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $info = (Get-Item -LiteralPath $path).VersionInfo
            [pscustomobject]@{ Path = $path
                Version = [version]::new($info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart) }
        }
    } | Sort-Object Version -Descending)
    if (-not $tools) { throw "No x64 signtool.exe under $kits. Install the Windows SDK signing tools." }
    $signTool = $tools[0]
    # Every certificate Artifact Signing issues lives three days, so an untimestamped signature stops
    # verifying that fast. The timestamp is part of the signature here, never an option.
    $timestamp = if ($env:SPLAT_SIGNING_TIMESTAMP) { $env:SPLAT_SIGNING_TIMESTAMP } else { 'http://timestamp.acs.microsoft.com' }

    if ($metadata) {
        if ($signTool.Version -lt [version]'10.0.22621.755') {
            throw "signtool $($signTool.Version) predates 10.0.22621.755, the oldest the Artifact Signing dlib loads into."
        }
        $dlib = $env:SPLAT_SIGNING_DLIB
        if (-not $dlib) {
            # Where the client-tools installer or an extracted Microsoft.ArtifactSigning.Client package
            # puts it. Only directories named for signing are searched, never a whole profile.
            $dlib = @(foreach ($base in @("$env:LOCALAPPDATA\Microsoft", $env:ProgramFiles, "$env:ProgramFiles\Microsoft", ${env:ProgramFiles(x86)})) {
                Get-ChildItem -LiteralPath $base -Directory -Filter '*Signing*' -ErrorAction SilentlyContinue |
                    Get-ChildItem -Recurse -File -Filter 'Azure.CodeSigning.Dlib.dll' -ErrorAction SilentlyContinue
            }) | Where-Object { $_.FullName -notmatch '\\(x86|arm64)\\' } |
                Sort-Object { $i = $_.VersionInfo; [version]::new($i.FileMajorPart, $i.FileMinorPart, $i.FileBuildPart, $i.FilePrivatePart) } -Descending |
                Select-Object -First 1 -ExpandProperty FullName
        }
        if (-not $dlib -or -not (Test-Path -LiteralPath $dlib -PathType Leaf)) {
            throw ('The Artifact Signing dlib (Azure.CodeSigning.Dlib.dll) was not found. Install it with ' +
                '"winget install -e --id Microsoft.Azure.ArtifactSigningClientTools", or set SPLAT_SIGNING_DLIB to its path.')
        }
        return [pscustomobject]@{
            Kind = 'ArtifactSigning'; SignTool = $signTool.Path; Timestamp = $timestamp
            Identity = "$($config.CodeSigningAccountName)/$($config.CertificateProfileName)"
            Arguments = @('/dlib', (Resolve-Path -LiteralPath $dlib).Path, '/dmdf', (Resolve-Path -LiteralPath $metadata).Path)
        }
    }

    $certificate = @(Get-ChildItem -LiteralPath 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My' |
        Where-Object { $_.Thumbprint -eq $thumbprint }) | Select-Object -First 1
    if (-not $certificate) { throw "No certificate with thumbprint $thumbprint is in CurrentUser\My or LocalMachine\My." }
    if (-not $certificate.HasPrivateKey) { throw "Certificate $thumbprint has no private key on this machine; is its token connected?" }
    if (@($certificate.EnhancedKeyUsageList.ObjectId) -notcontains '1.3.6.1.5.5.7.3.3') { throw "Certificate $thumbprint is not issued for code signing." }
    $arguments = @('/sha1', $thumbprint)
    if ($certificate.PSParentPath -match 'LocalMachine') { $arguments = @('/sm') + $arguments }
    [pscustomobject]@{
        Kind = 'Certificate'; SignTool = $signTool.Path; Timestamp = $timestamp
        Identity = "$($certificate.Subject) ($thumbprint)"; Arguments = $arguments
    }
}

function Assert-SplatSigned {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Path)
    # What a release is distributed on is the signature each file carries, not signtool's exit code.
    $signer = $null
    foreach ($file in $Path) {
        $signature = Get-AuthenticodeSignature -LiteralPath $file
        if ($signature.Status -ne 'Valid') { throw "$file reports signature status '$($signature.Status)': $($signature.StatusMessage)" }
        # Get-AuthenticodeSignature answers from a system catalog first: a copy of a Windows binary
        # re-signed by anyone still reads Valid with Microsoft as signer (measured on whoami.exe).
        if ($signature.SignatureType -eq 'Catalog') { throw "$file is vouched for by a Windows catalog, not by a signature it carries." }
        if (-not $signature.TimeStamperCertificate) { throw "$file is signed without a timestamp, so its signature lapses with its certificate." }
        if ($signer -and $signature.SignerCertificate.Subject -ne $signer.Subject) {
            throw "$file is signed by '$($signature.SignerCertificate.Subject)', not '$($signer.Subject)' like the files before it."
        }
        $signer = $signature.SignerCertificate
    }
    [pscustomobject]@{ Subject = $signer.Subject; Thumbprint = $signer.Thumbprint; Files = $Path.Count }
}

function Invoke-SplatCodeSigning {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Signing, [Parameter(Mandatory)][string[]]$Path)
    $files = @($Path | ForEach-Object { (Resolve-Path -LiteralPath $_).Path })
    # Out-Host keeps signtool's lines off this function's output, which is the signer record alone.
    & $Signing.SignTool sign /fd SHA256 /tr $Signing.Timestamp /td SHA256 @($Signing.Arguments) @files | Out-Host
    # $ErrorActionPreference = 'Stop' does not cover a native exit code.
    if ($LASTEXITCODE -ne 0) { throw "signtool sign exited $LASTEXITCODE; none of the files it was given may ship." }
    Assert-SplatSigned -Path $files
}

function Get-SplatUnsignedOwnBinaries {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string]$Root)
    # Only what this repository compiles carries its publisher's name. The runtime, the Windows App SDK
    # and the NuGet dependencies are other people's work, mostly signed by them already, and signing
    # them again would claim them.
    $names = @(Get-ChildItem -LiteralPath (Join-Path $Root 'src') -Recurse -File -Filter '*.csproj' | ForEach-Object {
        $assembly = Select-Xml -LiteralPath $_.FullName -XPath '//AssemblyName' | Select-Object -First 1
        if ($assembly) { $assembly.Node.InnerText } else { $_.BaseName }
    })
    @(Get-ChildItem -LiteralPath $Directory -Recurse -File -Include '*.exe', '*.dll' | Where-Object {
        $names -contains ($_.BaseName -replace '\.resources$', '') -and
        (Get-AuthenticodeSignature -LiteralPath $_.FullName).Status -eq 'NotSigned'
    } | ForEach-Object { $_.FullName })
}

function Get-SplatInnoSignCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Signing)
    # Inno Setup runs this for Setup.exe and for the uninstaller inside it, and fails the compile when it
    # fails. $q is Inno's quote and $f the file; single-quoted pieces keep PowerShell from expanding them.
    $arguments = @($Signing.Arguments | ForEach-Object { if ($_.StartsWith('/')) { $_ } else { '$q' + $_ + '$q' } })
    '$q' + $Signing.SignTool + '$q sign /fd SHA256 /tr ' + $Signing.Timestamp + ' /td SHA256 ' + ($arguments -join ' ') + ' $f'
}
