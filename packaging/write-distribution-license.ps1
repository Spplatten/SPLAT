# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Platten Industries. Separate commercial licensing is available; see COMMERCIAL.md.
#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Destination)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
foreach ($name in @('LICENSE', 'COMMERCIAL.md')) {
    Copy-Item -LiteralPath (Join-Path $root $name) -Destination (Join-Path $Destination $name) -Force
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'DISTRIBUTION-NOTICE.txt') -Destination $Destination -Force
# License acceptance shows the actual grant; the commercial option does not replace its text.
$text = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'DISTRIBUTION-NOTICE.txt') -Raw) +
    "`r`n`r`n" + (Get-Content -LiteralPath (Join-Path $root 'LICENSE') -Raw)
[IO.File]::WriteAllText((Join-Path $Destination 'INSTALLER-LICENSE.txt'), $text, [Text.UTF8Encoding]::new($true))
