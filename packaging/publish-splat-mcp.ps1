<#
.SYNOPSIS
    Produces the one file a stranger downloads: a self-contained splat-mcp.exe that carries the Linux
    daemon `splat-mcp provision` installs, and its SHA-256.

.DESCRIPTION
    Self-contained on purpose. The machine that runs an MCP client is not required to have the .NET
    10 runtime, and the native SQLite the ledger uses is packed inside the executable rather than
    laid beside it (IncludeNativeLibrariesForSelfExtract in splat-mcp.csproj).

    The daemon is built first, inside WSL, and embedded (roadmap 1.9). Without it, provision builds the
    daemon from a checkout of this repository with cargo, and a stranger has neither. It is linked with
    the crate's `portable` feature, so libelf, zlib and zstd travel inside it. glibc cannot, so the oldest
    glibc the binary accepts is read from its symbol versions and printed beside the hash.

    Every step is checked. F22 is in this repository because a packaging script can announce success
    while producing nothing: a non-zero publish, a missing output, an executable that cannot even print
    its own usage, or one that turns out not to carry its daemon each stop this script with a non-zero
    exit rather than a reassuring log line.

    There is no `dotnet tool` package: PackAsTool refuses a platform TFM (NETSDK1146) and splat-mcp
    must target net10.0-windows for the Win32 containment primitives. See splat-mcp.csproj.
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
if (-not $OutputDir) { $OutputDir = Join-Path $root 'dist' }

$dotnet = "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe"
if (-not (Test-Path $dotnet)) { $dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source }
if (-not $dotnet) { Write-Error 'No dotnet found: this machine cannot build the artifact.'; exit 1 }

$publishDir = Join-Path $root "src\splat-mcp\bin\$Configuration\net10.0-windows\$Runtime\publish"
$daemonStage = Join-Path $root 'src\splat-mcp\obj\publish-daemon\splat-agent'

# Cleared first, because the check below - "nothing beside the executable" - is only meaningful
# against a directory this run produced. A symbol file left by an earlier publish would otherwise
# either fail the run or, worse, be copied out as part of the artifact. The staged daemon goes too:
# an embed that quietly picked up an earlier binary would defeat the build that follows.
if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }
if (Test-Path $daemonStage) { Remove-Item $daemonStage -Force }

function Invoke-Guest([string]$script) {
    # Run from a file rather than passed to `sh -c`: Windows PowerShell 5.1 does not escape quotes inside
    # a native argument, so an inline script arrives in the guest cut wherever it quoted. stderr is folded
    # into stdout inside the guest, because 2>&1 on a native command here turns cargo's progress output
    # into terminating errors under ErrorActionPreference Stop.
    $file = Join-Path ([System.IO.Path]::GetTempPath()) ('splat-publish-' + [guid]::NewGuid().ToString('N') + '.sh')
    [System.IO.File]::WriteAllText($file, ("exec 2>&1`n" + $script).Replace("`r`n", "`n"), (New-Object System.Text.UTF8Encoding($false)))
    try {
        $guestFile = (& wsl.exe -e wslpath -a $file | Out-String).Trim()
        $output = (& wsl.exe -e sh $guestFile | Out-String).Trim()
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    }
    finally {
        Remove-Item $file -Force -ErrorAction SilentlyContinue
    }
}

function ConvertTo-GuestPath([string]$windowsPath) {
    $guest = (& wsl.exe -e wslpath -a $windowsPath | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $guest) { Write-Error "WSL could not resolve $windowsPath"; exit 1 }
    if ($guest.Contains("'")) { Write-Error "refusing a path the guest script would have to unquote: $guest"; exit 1 }
    return $guest
}

Write-Host "[1/6] building the daemon inside WSL, with libelf, zlib and zstd linked in" -ForegroundColor Cyan
# Build, check and copy out in ONE guest invocation. The guest's /tmp is tmpfs and the distro stops soon
# after its last process exits, so a binary left there between two wsl.exe calls can simply be gone.
$guestCrate = ConvertTo-GuestPath (Join-Path $root 'native\splat-agent')
$guestStage = ConvertTo-GuestPath $daemonStage
$build = Invoke-Guest (@'
set -e
cd '__CRATE__'
export EXTRA_CFLAGS=-Wno-error CFLAGS=-Wno-error
# Kept between publishes so the next one is incremental; not /tmp, for the reason above.
export CARGO_TARGET_DIR="$HOME/.cache/splat-agent-publish"
# libbpf-sys links libelf and zlib statically only from a directory it is told about.
export LIBBPF_SYS_LIBRARY_PATH="$(pkg-config --variable=libdir libelf)"
# The distribution's libelf.a references zstd, which libbpf-sys never links. Through RUSTFLAGS rather
# than build.rs because the build script needs it as well: libbpf-sys declares links = "bpf", so Cargo
# builds one copy for host and target, and the build script links the same static libelf as the daemon.
# No --target, which would neither split the copies nor let RUSTFLAGS reach the build script.
export RUSTFLAGS='-C link-arg=-l:libzstd.a'
CARGO="$(command -v cargo || echo "$HOME/.cargo/bin/cargo")"
"$CARGO" build --release --features portable
B="$CARGO_TARGET_DIR/release/splat-agent"
set +e
if ldd "$B" | grep -E 'libelf|libz\.so|libzstd'; then exit 5; fi
"$B" --help > /dev/null || exit 6
echo "FLOOR=$(objdump -T "$B" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)"
echo "BUILDID=$(readelf -n "$B" | sed -n 's/.*Build ID: *//p')"
install -D -m 0755 "$B" '__STAGE__' || exit 7
'@).Replace('__CRATE__', $guestCrate).Replace('__STAGE__', $guestStage)

$tail = ($build.Output -split "`n" | Select-Object -Last 12) -join "`n"
switch ($build.ExitCode) {
    0 { }
    5 { Write-Host $tail; Write-Error 'the daemon links libelf, zlib or zstd dynamically, so a guest without them installed cannot start it'; exit 1 }
    6 { Write-Host $tail; Write-Error 'the daemon cannot start even in the guest that built it'; exit 1 }
    7 { Write-Host $tail; Write-Error "the daemon built, but could not be staged at $daemonStage"; exit 1 }
    default { Write-Host $tail; Write-Error "the daemon build failed (exit $($build.ExitCode))"; exit 1 }
}

$floor = [regex]::Match($build.Output, 'FLOOR=GLIBC_([0-9.]+)').Groups[1].Value
$buildId = [regex]::Match($build.Output, 'BUILDID=([0-9a-f]{40})').Groups[1].Value
if (-not $floor -or -not $buildId -or -not (Test-Path $daemonStage)) {
    Write-Host $tail
    Write-Error "the daemon build reported success but produced no measurable binary at $daemonStage"
    exit 1
}

Write-Host "[2/6] publishing splat-mcp ($Configuration, $Runtime, self-contained single file, daemon embedded)" -ForegroundColor Cyan
& $dotnet publish "$root\src\splat-mcp" `
    -c $Configuration `
    -r $Runtime `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:DebugType=none `
    "-p:SplatAgentBinary=$daemonStage" `
    --nologo
if ($LASTEXITCODE -ne 0) { Write-Error "publish failed with exit code $LASTEXITCODE"; exit 1 }

$published = Join-Path $publishDir 'splat-mcp.exe'
if (-not (Test-Path $published)) { Write-Error "publish reported success but produced no $published"; exit 1 }

Write-Host "[3/6] checking it is one file and nothing else is required beside it" -ForegroundColor Cyan
$strays = Get-ChildItem (Split-Path $published) -File | Where-Object { $_.Name -ne 'splat-mcp.exe' }
if ($strays) {
    Write-Error ("the publish left files beside the executable, so it is not self-contained: " +
                 ($strays.Name -join ', '))
    exit 1
}

Write-Host "[4/6] running it, because an artifact that cannot start is not an artifact" -ForegroundColor Cyan
& $published --help | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "the published executable failed to print its usage (exit $LASTEXITCODE)"; exit 1 }

Write-Host "[5/6] checking the executable carries the daemon it was built with" -ForegroundColor Cyan
# The daemon's GNU build ID is twenty bytes no other file shares. Single-file publishing stores the
# managed assembly uncompressed and the resource inside it verbatim, so those bytes are in the executable
# exactly when the daemon is - checked here, not trusted to the MSBuild condition that put it there.
$needle = -join ((0..19) | ForEach-Object { [char][Convert]::ToByte($buildId.Substring($_ * 2, 2), 16) })
$latin1 = [System.Text.Encoding]::GetEncoding(28591)
if ($latin1.GetString([System.IO.File]::ReadAllBytes($published)).IndexOf($needle, [StringComparison]::Ordinal) -lt 0) {
    Write-Error "the published executable does not carry the daemon it was built with (build ID $buildId)"
    exit 1
}

Write-Host "[6/6] staging the artifact and its hash" -ForegroundColor Cyan
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$artifact = Join-Path $OutputDir 'splat-mcp.exe'
Copy-Item $published $artifact -Force
$hash = (Get-FileHash $artifact -Algorithm SHA256).Hash
$commit = (& git -C $root rev-parse --short HEAD 2>$null)
# Without a byte order mark: Set-Content -Encoding utf8 in Windows PowerShell 5.1 writes one, and a checksum
# file whose first bytes are not the hash breaks whatever parses it.
[System.IO.File]::WriteAllText("$artifact.sha256",
    "$hash  splat-mcp.exe  built from $commit, carrying splat-agent $buildId (needs glibc $floor or newer in the WSL guest)`n",
    (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "artifact : $artifact  ($([math]::Round((Get-Item $artifact).Length / 1MB, 1)) MB)"
Write-Host "sha256   : $hash"
Write-Host "commit   : $commit"
Write-Host "daemon   : splat-agent, build ID $buildId, needs glibc $floor or newer in the guest"
Write-Host ""
Write-Host "On the target machine, 'splat-mcp provision --apply' installs that daemon - no Rust toolchain"
Write-Host "and no checkout of this repository - and 'splat-mcp doctor' exits 0 only when a lease there"
Write-Host "would reach the kernel."
