<#
.SYNOPSIS
    Builds the turnkey end-user package: dist\Client\ (unpack-and-run) and dist\SPLAT-Client-<commit>.zip.

.DESCRIPTION
    The package a workstation user receives has to start with nothing installed. This publishes the
    console self-contained - the .NET 10 runtime and the Windows App SDK 2.5.1 travel inside App\ -
    strips symbols, stages the launcher, config template and guide beside it, hashes every file, and
    zips the result.

    Not single-file, on purpose. PublishSingleFile is unsupported for Windows App SDK / WinUI 3
    applications: the XAML compiler and the WinRT activation path resolve .pri, .winmd and the
    bootstrapper from files beside the executable, and a single-file publish either fails at
    publish time or produces an executable that dies before its window opens. The nearest honest
    equivalent is a self-contained directory published straight into a clean stage.

    Every step is checked, in the same spirit as publish-splat-mcp.ps1: a packaging script that can
    announce success while producing nothing is worse than none. A failed test run, a missing
    runtime marker, a symbol left behind, or a published console that cannot open every one of its
    pages each stop this script with a non-zero exit.

    dist\App - the tree the operator runs from - is never touched unless -InstallToApp says so, and
    then only after every gate above has passed. The output is otherwise a separate dist\Client\
    stage, so a bad build here cannot break the working console.

.PARAMETER InstallToApp
    Replace dist\App with this build once it has passed, verify every file by hash, and remove the
    staging copy. Without it the build stops at dist\Client and dist\App is left alone.

    This is the switch to use on the machine that runs SPLAT: the operator launches dist\App, so a
    stage they then have to copy by hand is a second copy to keep in step and a step to forget. The
    zip is still produced either way - that is the artifact for a different machine.

    Refused while the console is running, rather than closing it: a mission in flight is writing to
    the ledger.

.PARAMETER SkipTests
    Skip the unit test gate. For iterating on the packaging itself only - a shipped package is
    built with the gate on.

.PARAMETER SkipSmokeTest
    Skip launching the published console for its self-test. For a build agent with no interactive
    desktop; the result is then an unproven package and the summary says so.

.PARAMETER IncludeMcp
    Also build splat-mcp.exe via publish-splat-mcp.ps1 (needs WSL with cargo) and ship it under
    Client\Tools\. Off by default because the console has no dependency on it and most client
    workstations have no WSL.
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [string]$OutputDir,
    [switch]$InstallToApp,
    [switch]$SkipTests,
    [switch]$SkipSmokeTest,
    [switch]$IncludeMcp
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
if (-not $OutputDir) { $OutputDir = Join-Path $root 'dist' }
$stage = Join-Path $OutputDir 'Client'
$appDir = Join-Path $stage 'App'

function Fail([string]$message) { Write-Error $message; exit 1 }

# ------------------------------------------------------------------------------------------------
# Toolchain. The user-local SDK first: the machine-wide dotnet on the operator's PC is SDK 9 and
# fails this net10 tree with NETSDK1045, so PATH alone is not trusted.
# ------------------------------------------------------------------------------------------------
$dotnet = "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe"
if (-not (Test-Path $dotnet)) { $dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source }
if (-not $dotnet) { Fail 'No dotnet SDK found: this machine cannot build the package.' }
$sdkVersion = (& $dotnet --version | Out-String).Trim()
if ([int]($sdkVersion.Split('.')[0]) -lt 10) { Fail "dotnet SDK $sdkVersion found at $dotnet; the tree needs SDK 10 or newer." }

$commit = (& git -C $root rev-parse --short HEAD 2>$null | Out-String).Trim()
if (-not $commit) { $commit = 'nogit' }
$dirty = (& git -C $root status --porcelain -- src 2>$null | Out-String).Trim()

Write-Host "[1/8] toolchain: dotnet SDK $sdkVersion, commit $commit$(if ($dirty) { ' (src has uncommitted changes)' })" -ForegroundColor Cyan

# ------------------------------------------------------------------------------------------------
# Clean stage. Published into a directory this run created, so "nothing unexpected is in App\" is a
# claim about this build and not about whatever an earlier run left behind.
# ------------------------------------------------------------------------------------------------
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $appDir -Force | Out-Null

# ------------------------------------------------------------------------------------------------
# Test gate. Runs before publish so a red suite never produces a green-looking artifact.
# ------------------------------------------------------------------------------------------------
if ($SkipTests) {
    Write-Host '[2/8] tests: SKIPPED by request' -ForegroundColor Yellow
} else {
    Write-Host "[2/8] tests: building and running the suite ($Configuration)" -ForegroundColor Cyan
    & $dotnet test "$root\tests\MissionController.Tests\MissionController.Tests.csproj" -c $Configuration --nologo -v q
    if ($LASTEXITCODE -ne 0) { Fail "the test suite failed (exit $LASTEXITCODE); no package is produced from a red tree" }
}

# ------------------------------------------------------------------------------------------------
# Publish. -o writes straight into the stage; no bin\ mirroring step to get subtly wrong.
# DebugType=none keeps symbols out of the published set; the check below proves it.
# ------------------------------------------------------------------------------------------------
Write-Host "[3/8] publishing MissionController.UI ($Configuration, $Runtime, self-contained, unpackaged)" -ForegroundColor Cyan
& $dotnet publish "$root\src\MissionController.UI\MissionController.UI.csproj" `
    -c $Configuration `
    -r $Runtime `
    --self-contained true `
    -p:Platform=x64 `
    -p:WindowsPackageType=None `
    -p:WindowsAppSDKSelfContained=true `
    -p:PublishSingleFile=false `
    -p:DebugType=none `
    -p:DebugSymbols=false `
    -o $appDir `
    --nologo
if ($LASTEXITCODE -ne 0) { Fail "publish failed with exit code $LASTEXITCODE" }

# ------------------------------------------------------------------------------------------------
# Verify the publish is what the package claims: a console that needs nothing installed.
# ------------------------------------------------------------------------------------------------
Write-Host '[4/8] checking the publish is self-contained and stripped' -ForegroundColor Cyan
$exe = Join-Path $appDir 'MissionController.UI.exe'
if (-not (Test-Path $exe)) { Fail "publish reported success but produced no $exe" }

$markers = @{
    'hostfxr.dll'                              = '.NET runtime host (self-contained .NET)'
    'coreclr.dll'                              = '.NET runtime (self-contained .NET)'
    'Microsoft.WindowsAppRuntime.Bootstrap.dll' = 'Windows App SDK bootstrapper (self-contained App SDK)'
    'Microsoft.WinUI.dll'                      = 'WinUI 3'
    'e_sqlite3.dll'                            = 'native SQLite for the audit ledger'
    'Microsoft.Graphics.Canvas.dll'            = 'Win2D'
    'MissionController.UI.pri'                 = 'XAML resource index'
}
foreach ($name in $markers.Keys) {
    if (-not (Test-Path (Join-Path $appDir $name))) {
        Fail "App\$name is missing - $($markers[$name]) - so the package would need something installed on the workstation"
    }
}

$pdbs = Get-ChildItem $appDir -Recurse -Filter '*.pdb'
if ($pdbs) {
    # Runtime packs ship a handful of native symbol files that DebugType=none does not govern; they
    # are deleted rather than tolerated so "stripped" stays a true statement.
    $pdbs | Remove-Item -Force
}
if (Get-ChildItem $appDir -Recurse -Filter '*.pdb') { Fail 'symbol files survived stripping' }

# ------------------------------------------------------------------------------------------------
# Self-test. A console that cannot open its pages is not a package, and neither "the process is
# running" nor "a window appeared" says anything about the pages: the XAML compiler does not check
# resource keys, so two pages that threw the moment they were opened shipped through a green build
# and a green window check on 2026-09-23. The published console is started with --self-test: it
# opens every page its navigation offers, waits for each to load, writes a report, and exits with a
# code - the one channel a windowed executable has back to a script. The crash log's timestamp is
# read before launch so an older crash cannot be mistaken for this one.
# ------------------------------------------------------------------------------------------------
$smoke = 'SKIPPED'
if ($SkipSmokeTest) {
    Write-Host '[5/8] self-test: SKIPPED by request - the package is unproven' -ForegroundColor Yellow
} else {
    Write-Host '[5/8] self-test: launching the published console with --self-test; it opens every page and exits' -ForegroundColor Cyan
    $crashLog = Join-Path $env:LOCALAPPDATA 'SPLAT\crash.log'
    $crashBefore = if (Test-Path $crashLog) { (Get-Item $crashLog).LastWriteTimeUtc } else { [datetime]::MinValue }
    $report = Join-Path $OutputDir "SPLAT-Client-$commit.self-test.json"
    if (Test-Path $report) { Remove-Item $report -Force }

    # DOTNET_ROOT cleared: a self-contained app must not be steered to a machine runtime.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = "--self-test --self-test-report `"$report`""
    $psi.WorkingDirectory = $appDir
    $psi.UseShellExecute = $false
    $psi.Environment['DOTNET_ROOT'] = ''
    $proc = [System.Diagnostics.Process]::Start($psi)

    # The window is still watched for: a self-test that exited 0 without ever showing one would have
    # tested nothing. 180 s covers the console's own 150 s ceiling and its start.
    $deadline = (Get-Date).AddSeconds(180)
    $handle = [IntPtr]::Zero
    $title = ''
    while ((Get-Date) -lt $deadline -and -not $proc.HasExited) {
        Start-Sleep -Milliseconds 500
        $proc.Refresh()
        if ($handle -eq [IntPtr]::Zero -and $proc.MainWindowHandle -ne [IntPtr]::Zero) {
            $handle = $proc.MainWindowHandle
            $title = $proc.MainWindowTitle
        }
    }
    if (-not $proc.HasExited) {
        $proc.Kill()
        $proc.WaitForExit(5000)
        Fail "the published console's self-test did not finish within 180 s (window shown: $($handle -ne [IntPtr]::Zero))"
    }
    $code = $proc.ExitCode

    $crashAfter = if (Test-Path $crashLog) { (Get-Item $crashLog).LastWriteTimeUtc } else { [datetime]::MinValue }
    if ($crashAfter -gt $crashBefore) {
        Write-Host (Get-Content $crashLog -Tail 30 | Out-String)
    }

    $pagesOpened = 0
    $pagesTotal = 0
    if (Test-Path $report) {
        $result = Get-Content $report -Raw | ConvertFrom-Json
        foreach ($page in @($result.pages)) {
            $pagesTotal++
            if ($page.ok) { $pagesOpened++ }
            $mark = if ($page.ok) { 'ok  ' } else { 'FAIL' }
            $colour = if ($page.ok) { 'Green' } else { 'Red' }
            Write-Host ("      {0} {1,-26} {2,6} ms  {3}" -f $mark, $page.page, $page.ms, $page.detail) -ForegroundColor $colour
        }
        foreach ($problem in @($result.unhandled)) {
            Write-Host "      unhandled on $($problem.page): $($problem.error)" -ForegroundColor Red
        }
        Write-Host "      status bar: $(@($result.statusBar) -join ' | ')"
        Write-Host "      $($result.summary)"
    } else {
        Write-Host "      no report was written at $report" -ForegroundColor Yellow
    }

    if ($crashAfter -gt $crashBefore) { Fail "the published console wrote to $crashLog during the self-test" }
    if ($code -ne 0) {
        Fail "the published console's self-test exited $code (1: failed before its window, 2: a page failed, 3: did not finish); the report is $report"
    }
    if ($handle -eq [IntPtr]::Zero) { Fail 'the published console exited 0 from its self-test without ever showing a window' }
    if ($pagesTotal -eq 0) { Fail "the self-test exited 0 but its report at $report lists no pages" }
    $smoke = "self-test passed: $pagesOpened of $pagesTotal pages opened and loaded in '$title'"
    Write-Host "      $smoke" -ForegroundColor Green
}

# ------------------------------------------------------------------------------------------------
# Stage the parts of the package that are not the publish: launcher, config template, guides.
# ------------------------------------------------------------------------------------------------
Write-Host '[6/8] staging launcher, config template and guides' -ForegroundColor Cyan
Copy-Item "$PSScriptRoot\run.bat" (Join-Path $stage 'run.bat') -Force
Copy-Item "$PSScriptRoot\README_CLIENT.md" (Join-Path $stage 'README_CLIENT.md') -Force
New-Item -ItemType Directory -Path (Join-Path $stage 'config') -Force | Out-Null
Copy-Item "$PSScriptRoot\splat.env.example" (Join-Path $stage 'config\splat.env.example') -Force
New-Item -ItemType Directory -Path (Join-Path $stage 'docs') -Force | Out-Null
Copy-Item "$root\docs\SPLAT-Field-Guide.html" (Join-Path $stage 'docs\SPLAT-Field-Guide.html') -Force

if ($IncludeMcp) {
    Write-Host '      building splat-mcp.exe (WSL + cargo required)' -ForegroundColor Cyan
    $tools = Join-Path $stage 'Tools'
    New-Item -ItemType Directory -Path $tools -Force | Out-Null
    & "$PSScriptRoot\publish-splat-mcp.ps1" -Configuration $Configuration -Runtime $Runtime -OutputDir $tools
    if ($LASTEXITCODE -ne 0) { Fail 'publish-splat-mcp.ps1 failed; the package is not produced half-built' }
}

# ------------------------------------------------------------------------------------------------
# Provenance. VERSION.txt says what this is; SHA256SUMS.txt lets anyone check nothing changed in
# transit. Both written without a byte order mark so a plain tool can parse them.
# ------------------------------------------------------------------------------------------------
Write-Host '[7/8] writing VERSION.txt and SHA256SUMS.txt' -ForegroundColor Cyan
$utf8 = New-Object System.Text.UTF8Encoding($false)
# Package versions from the publish's own manifests: the DLL version resources say "2.0" for the
# App SDK bootstrapper and a build number for coreclr, neither of which is what a reader wants.
$depsJson = Get-Content (Join-Path $appDir 'MissionController.UI.deps.json') -Raw | ConvertFrom-Json
$appSdk = ($depsJson.libraries.PSObject.Properties.Name | Where-Object { $_ -like 'Microsoft.WindowsAppSDK/*' } | Select-Object -First 1) -replace '^.*/', ''
$runtimeConfig = Get-Content (Join-Path $appDir 'MissionController.UI.runtimeconfig.json') -Raw | ConvertFrom-Json
$netRuntime = ($runtimeConfig.runtimeOptions.includedFrameworks | Where-Object { $_.name -eq 'Microsoft.NETCore.App' } | Select-Object -First 1).version
if (-not $appSdk -or -not $netRuntime) { Fail 'the publish manifests do not name the bundled runtime versions' }
$fileCount = (Get-ChildItem $appDir -Recurse -File).Count
$sizeMb = [math]::Round(((Get-ChildItem $appDir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB), 1)
[System.IO.File]::WriteAllText((Join-Path $stage 'VERSION.txt'), @"
SPLAT client package
commit        : $commit$(if ($dirty) { ' (built from a tree with uncommitted src changes)' })
built         : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC
configuration : $Configuration / $Runtime, self-contained, unpackaged (WindowsPackageType=None)
dotnet sdk    : $sdkVersion
.net runtime  : $netRuntime (bundled)
windows appsdk: $appSdk (bundled)
app files     : $fileCount files, $sizeMb MB
tests         : $(if ($SkipTests) { 'SKIPPED' } else { 'passed' })
self-test     : $smoke
"@ + "`n", $utf8)

$sums = Get-ChildItem $stage -Recurse -File |
    Where-Object { $_.Name -ne 'SHA256SUMS.txt' } |
    ForEach-Object {
        $rel = $_.FullName.Substring($stage.Length + 1).Replace('\', '/')
        "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $rel"
    }
[System.IO.File]::WriteAllText((Join-Path $stage 'SHA256SUMS.txt'), (($sums | Sort-Object) -join "`n") + "`n", $utf8)

# ------------------------------------------------------------------------------------------------
# Zip. ZipFile rather than Compress-Archive: it has no 2 GB limit and is several times faster on a
# quarter-gigabyte tree. Entries are rooted at Client\ so unzipping produces one folder.
# ------------------------------------------------------------------------------------------------
Write-Host '[8/8] zipping' -ForegroundColor Cyan
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = Join-Path $OutputDir "SPLAT-Client-$commit.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip, [System.IO.Compression.CompressionLevel]::Optimal, $true)
$zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText("$zip.sha256", "$zipHash  $(Split-Path $zip -Leaf)`n", $utf8)

Write-Host ''
Write-Host "stage    : $stage  ($fileCount app files, $sizeMb MB)"
Write-Host "zip      : $zip  ($([math]::Round((Get-Item $zip).Length / 1MB, 1)) MB)"
Write-Host "sha256   : $zipHash"
Write-Host "commit   : $commit"
Write-Host "runtime  : .NET $netRuntime + Windows App SDK $appSdk, bundled"
Write-Host "self-test: $smoke"

# ------------------------------------------------------------------------------------------------
# Install over the console the operator actually runs.
#
# Deliberately last, after every gate above has passed: the tests, the runtime markers, the symbol
# strip, and the published console opening all nine of its pages. Each of those calls Fail on the
# way, which exits, so reaching this line is the build saying it is fit to run. dist\App is never
# touched before that point - a half-built or failing package must not be able to break the console
# that currently works.
#
# The stage is still built, verified and zipped first rather than publishing straight into App. The
# zip is the artifact for another machine, and a staged copy is what makes "every file matches"
# checkable at all.
# ------------------------------------------------------------------------------------------------
if ($InstallToApp) {
    Write-Host ''
    $appDir = Join-Path $OutputDir 'App'

    # A running console holds its own files open, and a mission in flight is writing to the ledger.
    # Refused rather than stopped: killing the app mid-mission to save a prompt is the wrong trade,
    # and a half-copied App directory is the failure this whole script exists to prevent.
    $running = Get-Process -Name 'MissionController.UI' -ErrorAction SilentlyContinue
    if ($running) {
        Fail ("SPLAT is running (process $($running.Id -join ', ')), so $appDir cannot be replaced while " +
              'its files are open. Close the console - let any mission finish first - and run this again. ' +
              "The package is already built and verified at $stage.")
    }

    Write-Host "[install] replacing $appDir with the build that just passed" -ForegroundColor Cyan

    # robocopy /MIR rather than a delete-and-copy: it leaves no window in which App is absent, and it
    # removes files this build no longer ships. Exit codes 0-7 are success (8 and above are real
    # failures); anything else is a partial copy and must stop the script.
    & robocopy "$stage\App" $appDir /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
    $robocopy = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    if ($robocopy -ge 8) { Fail "robocopy could not mirror $stage\App into $appDir (exit $robocopy)" }

    # Verified by content, not by robocopy's word: every file the stage holds must be present in App
    # with the same hash, and App must hold nothing else.
    $staged = @{}
    foreach ($file in Get-ChildItem "$stage\App" -Recurse -File) {
        $staged[$file.FullName.Substring("$stage\App".Length)] = (Get-FileHash $file.FullName -Algorithm SHA256).Hash
    }
    $installed = Get-ChildItem $appDir -Recurse -File
    $wrong = @($installed | Where-Object {
        $rel = $_.FullName.Substring($appDir.Length)
        -not $staged.ContainsKey($rel) -or $staged[$rel] -ne (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    })
    if ($installed.Count -ne $staged.Count -or $wrong.Count -gt 0) {
        Fail ("$appDir does not match the build: $($installed.Count) files against the stage's $($staged.Count), " +
              "$($wrong.Count) with the wrong contents. The stage at $stage is intact; nothing was removed.")
    }

    # Only now is the stage redundant, and it is removed so it cannot be mistaken for a second copy
    # to keep in step by hand.
    Remove-Item $stage -Recurse -Force
    Write-Host "installed: $appDir  ($($installed.Count) files verified by hash; the staging copy has been removed)"
    Write-Host "launch   : $appDir\MissionController.UI.exe"
}
