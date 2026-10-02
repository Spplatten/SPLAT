<#
.SYNOPSIS
    Renders the demo tape's title cards, captures screen acts, and assembles the final cut.

.DESCRIPTION
    The tape described in demo\SHOT-LIST.md is a sequence of generated cards and screen captures.
    This script owns all three mechanical steps so that re-cutting the tape after the evidence
    moves costs one command per step rather than an afternoon in an editor.

    Card text lives in demo\cards.psd1, never in a command line. ffmpeg's filtergraph treats
    colons, commas, backslashes, brackets and single quotes as syntax, so text passed inline is a
    standing escaping hazard - and the first card's text contains an apostrophe. Every card's lines
    are therefore written to individual UTF-8 files and handed to drawtext with `textfile=`, which
    removes that entire class of failure. For the same reason ffmpeg is invoked with its working
    directory set to the scratch folder and the font is copied in beside the text: a bare filename
    carries no drive-letter colon for the filtergraph parser to choke on.

.PARAMETER Cards
    Render every card declared in cards.psd1 to demo\cards\<id>.mp4.

.PARAMETER Capture
    Record a screen act to demo\raw\<id>.mp4. Give the id from the shot list. Pair with -WindowTitle
    to capture one window, or -Desktop for the whole screen.

.PARAMETER WindowTitle
    The exact title of the window to capture. gdigrab resolves this at start; anything overlapping
    that window lands in the frame.

.PARAMETER Desktop
    Capture the full desktop instead of a single window.

.PARAMETER Seconds
    How long -Capture records before stopping on its own. Default 30.

.PARAMETER Assemble
    Concatenate the ids in cards.psd1's Sequence into demo\out\SPLAT-demo.mp4, normalising every
    clip to 1920x1080 at 30 fps. Reports any id that resolved to no file rather than dropping it.

.EXAMPLE
    .\demo\record-demo.ps1 -Cards
    .\demo\record-demo.ps1 -Capture 08-console -WindowTitle 'SPLAT Mission Controller' -Seconds 45
    .\demo\record-demo.ps1 -Assemble
#>
[CmdletBinding()]
param(
    [switch] $Cards,
    [string] $Capture,
    [string] $WindowTitle,
    [switch] $Desktop,
    [int]    $Seconds = 30,
    [switch] $Assemble,
    [string] $Terminal,
    [string] $From,
    [int]    $FontSize   = 20,
    [double] $LineDelay  = 0.07,
    [double] $Hold       = 4.0,
    [string] $FfmpegPath,
    [int]    $Width  = 1920,
    [int]    $Height = 1080,
    [int]    $Fps    = 30
)

$ErrorActionPreference = 'Stop'
$inv = [System.Globalization.CultureInfo]::InvariantCulture

$demoRoot = $PSScriptRoot
$cardsDir = Join-Path $demoRoot 'cards'
$rawDir   = Join-Path $demoRoot 'raw'
$outDir   = Join-Path $demoRoot 'out'
$specFile = Join-Path $demoRoot 'cards.psd1'

function Fail([string] $message) { Write-Error $message; exit 1 }

# ------------------------------------------------------------------------------------------------
# Toolchain. ffmpeg arrives here by winget more often than by a system install, so PATH is tried
# first and the winget package layout second; neither is assumed.
# ------------------------------------------------------------------------------------------------
function Resolve-Ffmpeg {
    if ($FfmpegPath) {
        if (-not (Test-Path $FfmpegPath)) { Fail "No ffmpeg at $FfmpegPath." }
        return (Resolve-Path $FfmpegPath).Path
    }
    $onPath = Get-Command ffmpeg -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $winget = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
    if (Test-Path $winget) {
        $found = Get-ChildItem -Path $winget -Filter 'ffmpeg.exe' -Recurse -ErrorAction SilentlyContinue |
                 Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    Fail 'No ffmpeg found. Install it (winget install Gyan.FFmpeg) or pass -FfmpegPath.'
}

# drawtext needs libfreetype, which a minimal ffmpeg build omits - and omits silently until a card
# render fails with an unhelpful filter error. Checked once, up front.
function Assert-Drawtext([string] $ffmpeg) {
    $filters = & $ffmpeg -hide_banner -filters 2>&1 | Out-String
    if ($filters -notmatch '\sdrawtext\s') {
        Fail "This ffmpeg build has no drawtext filter (no libfreetype); cards cannot be rendered."
    }
}

function Assert-Gdigrab([string] $ffmpeg) {
    $devices = & $ffmpeg -hide_banner -devices 2>&1 | Out-String
    if ($devices -notmatch 'gdigrab') {
        Fail "This ffmpeg build has no gdigrab device; screen capture is unavailable."
    }
}

function Invoke-Ffmpeg {
    param([string] $Ffmpeg, [string[]] $FfArgs, [string] $WorkingDirectory, [string] $What)

    # stderr goes to a file rather than through `2>&1`: Windows PowerShell wraps a native
    # command's stderr lines in ErrorRecords, which turns ffmpeg's ordinary progress chatter into
    # a terminating error and loses the one line that says what actually broke.
    $log = Join-Path ([System.IO.Path]::GetTempPath()) 'splat-demo-ffmpeg.log'
    $previous = (Get-Location).Path
    if ($WorkingDirectory) { Set-Location -LiteralPath $WorkingDirectory }
    try {
        $null = & $Ffmpeg @FfArgs 2> $log
        $code = $LASTEXITCODE
    } finally {
        Set-Location -LiteralPath $previous
    }
    if ($code -ne 0) {
        $detail = ''
        if (Test-Path $log) { $detail = (Get-Content -LiteralPath $log -Tail 8 | Out-String).Trim() }
        Fail "$What failed: ffmpeg exited $code.`n$detail"
    }
}

# ------------------------------------------------------------------------------------------------
# Cards
# ------------------------------------------------------------------------------------------------
function New-Card {
    param([string] $Ffmpeg, $Spec, $Card)

    $id      = $Card.Id
    $seconds = [double] $Card.Seconds
    $scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("splat-card-" + $id)
    if (Test-Path $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
    New-Item -ItemType Directory -Path $scratch -Force | Out-Null

    # The font travels into the scratch folder so the filtergraph can name it without a colon.
    $font = Join-Path $env:WINDIR 'Fonts\segoeui.ttf'
    if (-not (Test-Path $font)) { $font = Join-Path $env:WINDIR 'Fonts\arial.ttf' }
    if (-not (Test-Path $font)) { Fail "No usable font found under $env:WINDIR\Fonts." }
    Copy-Item -LiteralPath $font -Destination (Join-Path $scratch 'card.ttf') -Force

    # Lay the lines out as one vertically centred block. Positions are computed here rather than
    # with drawtext expressions because every line would otherwise centre on top of the last.
    $gap    = 1.75
    $total  = 0.0
    foreach ($line in $Card.Lines) { $total += ([double] $line.Size) * $gap }
    $cursor = ($Height - $total) / 2.0

    $filters = New-Object System.Collections.Generic.List[string]
    $index   = 0
    foreach ($line in $Card.Lines) {
        $size = [double] $line.Size
        $text = [string] $line.Text
        if ($text.Trim().Length -gt 0) {
            $file = "l$index.txt"
            # No BOM: drawtext renders a leading byte order mark as a visible glyph.
            [System.IO.File]::WriteAllText(
                (Join-Path $scratch $file),
                $text,
                (New-Object System.Text.UTF8Encoding($false)))

            $colorKey = [string] $line.Color
            $color    = [string] $Spec.$colorKey
            if (-not $color) { $color = [string] $Spec.Headline }

            $y = [int][Math]::Round($cursor + (($size * $gap) - $size) / 2.0)
            # ${color} is braced deliberately: a bare "$color:" is parsed by PowerShell as a scope
            # qualifier, which silently yields $null and hands ffmpeg "fontcolor==104".
            $filters.Add(
                "drawtext=fontfile=card.ttf:textfile=$file" +
                ":fontcolor=${color}:fontsize=$([int]$size)" +
                ":x=(w-text_w)/2:y=$y")
        }
        $cursor += $size * $gap
        $index++
    }
    if ($filters.Count -eq 0) { Fail "Card $id declares no visible text." }

    $fadeOut = [Math]::Max(0.0, $seconds - 0.4)
    $chain   = ($filters -join ',') +
               ",fade=t=in:st=0:d=0.4,fade=t=out:st=$($fadeOut.ToString('0.###', $inv)):d=0.4"

    $target = Join-Path $cardsDir "$id.mp4"
    $ffArgs = @(
        '-hide_banner', '-loglevel', 'error', '-y',
        '-f', 'lavfi',
        '-i', "color=c=$($Spec.Background):s=$($Width)x$($Height):d=$($seconds.ToString('0.###', $inv)):r=$Fps",
        '-vf', $chain,
        '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '18', '-pix_fmt', 'yuv420p', '-an',
        $target
    )
    Invoke-Ffmpeg -Ffmpeg $Ffmpeg -FfArgs $ffArgs -WorkingDirectory $scratch -What "Card $id"
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host ("  card  {0,-12} {1,5}s  {2}" -f $id, $seconds, $target)
}

# ------------------------------------------------------------------------------------------------
# Terminal replays
#
# A transcript under demo\transcripts is real output, captured from a real run and committed so it
# can be diffed when the tool's output changes. Replaying it as a clip rather than screen-grabbing
# a console window buys three things: the operator's home directory never reaches the frame, the
# text is legible at 1080p instead of whatever the console happened to be sized to, and the clip
# re-renders when the output changes instead of needing the window set up again.
#
# It is a replay, and the shot list requires the caption to say so. A rendered clip must never be
# cut in a way that implies a live run.
# ------------------------------------------------------------------------------------------------
function New-TerminalClip {
    param([string] $Ffmpeg, $Spec, [string] $Id, [string] $TranscriptPath)

    if (-not (Test-Path $TranscriptPath)) { Fail "No transcript at $TranscriptPath." }
    $lines = Get-Content -LiteralPath $TranscriptPath

    $scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("splat-term-" + $Id)
    if (Test-Path $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
    New-Item -ItemType Directory -Path $scratch -Force | Out-Null

    $font = Join-Path $env:WINDIR 'Fonts\consola.ttf'
    if (-not (Test-Path $font)) { Fail "No Consolas at $font; a terminal replay needs a monospace face." }
    Copy-Item -LiteralPath $font -Destination (Join-Path $scratch 'term.ttf') -Force

    $lineHeight = [int]([Math]::Round($FontSize * 1.42))
    $marginX    = 70
    $marginY    = [int]([Math]::Max(40, ($Height - ($lines.Count * $lineHeight)) / 2))

    $ok      = '0x7FD88F'   # a check that passed
    $note    = '0xE8C07A'   # a row doctor marks "--": available, not claimed
    $refused = '0xFF8A7A'   # the kernel said no
    $plain   = '0xC8D0DC'
    $accent  = [string] $Spec.Accent
    $head    = [string] $Spec.Headline

    $filters = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $text = [string] $lines[$i]
        if ($text.Trim().Length -eq 0) { continue }

        # A refusal is the one line the tape exists to show, so it gets its own colour in both the
        # doctor table and the probe's JSON, where it arrives as a quoted violation string.
        if     ($text -match '^\s*(PS|\$)>')    { $color = $accent }
        elseif ($text -match '\-EPERM')         { $color = $refused }
        elseif ($text -match '"?PASS"?')        { $color = $ok }
        elseif ($text -match '^\s*ok\s')        { $color = $ok }
        elseif ($text -match '^\s*--\s')        { $color = $note }
        elseif ($text -match '^Verdict:')       { $color = $accent }
        elseif ($text -match '^\S')             { $color = $head }
        else                                    { $color = $plain }

        # drawtext reads a backslash in its text as an escape, so a Windows path renders as
        # "C:UsersoperatorAppData" unless each one is doubled. The transcripts are full of them.
        $file = "t$i.txt"
        [System.IO.File]::WriteAllText(
            (Join-Path $scratch $file), $text.Replace('\', '\\'),
            (New-Object System.Text.UTF8Encoding($false)))

        $y  = $marginY + ($i * $lineHeight)
        $at = ($i * $LineDelay).ToString('0.###', $inv)
        # Each line carries its own enable window, which is what makes the block appear to stream
        # the way the command produced it without rendering a frame sequence by hand.
        $filters.Add(
            "drawtext=fontfile=term.ttf:textfile=$file" +
            ":fontcolor=${color}:fontsize=$FontSize" +
            ":x=${marginX}:y=$y" +
            ":enable='gte(t,$at)'")
    }
    if ($filters.Count -eq 0) { Fail "Transcript $TranscriptPath has no visible lines." }

    $seconds = ($lines.Count * $LineDelay) + $Hold
    $fadeOut = [Math]::Max(0.0, $seconds - 0.5)
    $chain   = ($filters -join ',') + ",fade=t=out:st=$($fadeOut.ToString('0.###', $inv)):d=0.5"

    $target = Join-Path $cardsDir "$Id.mp4"
    $ffArgs = @(
        '-hide_banner', '-loglevel', 'error', '-y',
        '-f', 'lavfi',
        '-i', "color=c=$($Spec.Background):s=$($Width)x$($Height):d=$($seconds.ToString('0.###', $inv)):r=$Fps",
        '-vf', $chain,
        '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '18', '-pix_fmt', 'yuv420p', '-an',
        $target
    )
    Invoke-Ffmpeg -Ffmpeg $Ffmpeg -FfArgs $ffArgs -WorkingDirectory $scratch -What "Terminal $Id"
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host ("  term  {0,-12} {1,5}s  {2} lines  {3}" -f $Id, [Math]::Round($seconds,1), $lines.Count, $target)
}

# ------------------------------------------------------------------------------------------------
# Entry points
# ------------------------------------------------------------------------------------------------
if (-not ($Cards -or $Capture -or $Assemble -or $Terminal)) {
    Fail 'Nothing to do. Pass -Cards, -Capture <id>, -Terminal <id> -From <file> or -Assemble.'
}

if (-not (Test-Path $specFile)) { Fail "Missing card spec: $specFile" }
$spec = Import-PowerShellDataFile -LiteralPath $specFile
$ffmpeg = Resolve-Ffmpeg
foreach ($dir in @($cardsDir, $rawDir, $outDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

if ($Cards) {
    Assert-Drawtext $ffmpeg
    Write-Host "Rendering $($spec.Cards.Count) cards at $($Width)x$($Height)@$Fps ..."
    foreach ($card in $spec.Cards) { New-Card -Ffmpeg $ffmpeg -Spec $spec -Card $card }
}

if ($Terminal) {
    Assert-Drawtext $ffmpeg
    if (-not $From) {
        $From = Join-Path $demoRoot "transcripts\$Terminal.txt"
    }
    Write-Host "Rendering terminal replay '$Terminal' from $From ..."
    New-TerminalClip -Ffmpeg $ffmpeg -Spec $spec -Id $Terminal -TranscriptPath $From
}

if ($Capture) {
    Assert-Gdigrab $ffmpeg
    if (-not $Desktop -and -not $WindowTitle) {
        Fail 'Pass -WindowTitle "<exact title>" or -Desktop to say what to capture.'
    }
    if ($Desktop) { $source = 'desktop' } else { $source = "title=$WindowTitle" }

    $target = Join-Path $rawDir "$Capture.mp4"
    Write-Host "Capturing '$source' for $Seconds s -> $target"
    Write-Host 'Bring the window to the front now.'
    Start-Sleep -Seconds 3

    # yuv420p needs even dimensions and a captured window is rarely even on both axes.
    $ffArgs = @(
        '-hide_banner', '-loglevel', 'error', '-y',
        '-f', 'gdigrab', '-framerate', "$Fps", '-i', $source,
        '-t', "$Seconds",
        '-vf', 'scale=trunc(iw/2)*2:trunc(ih/2)*2',
        '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '18', '-pix_fmt', 'yuv420p', '-an',
        $target
    )
    Invoke-Ffmpeg -Ffmpeg $ffmpeg -FfArgs $ffArgs -WorkingDirectory $demoRoot -What "Capture $Capture"
    Write-Host "  captured $target"
}

if ($Assemble) {
    $inputs  = New-Object System.Collections.Generic.List[string]
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($id in $spec.Sequence) {
        $fromCards = Join-Path $cardsDir "$id.mp4"
        $fromRaw   = Join-Path $rawDir   "$id.mp4"
        if     (Test-Path $fromCards) { $inputs.Add($fromCards) }
        elseif (Test-Path $fromRaw)   { $inputs.Add($fromRaw) }
        else                          { $missing.Add($id) }
    }
    if ($missing.Count -gt 0) {
        Write-Warning ("Not yet recorded, and left out of this cut: " + ($missing -join ', '))
    }
    if ($inputs.Count -eq 0) { Fail 'No clips to assemble.' }

    # Re-encoded rather than stream-copied: the concat demuxer needs identical parameters across
    # every input, and a gdigrab capture never matches a lavfi card on SAR or frame timing.
    $norm = "scale=$($Width):$($Height):force_original_aspect_ratio=decrease," +
            "pad=$($Width):$($Height):(ow-iw)/2:(oh-ih)/2:color=$($spec.Background)," +
            "setsar=1,fps=$Fps,format=yuv420p"

    $ffArgs = New-Object System.Collections.Generic.List[string]
    $ffArgs.AddRange([string[]] @('-hide_banner', '-loglevel', 'error', '-y'))
    foreach ($clip in $inputs) { $ffArgs.AddRange([string[]] @('-i', $clip)) }

    $graph = ''
    for ($i = 0; $i -lt $inputs.Count; $i++) { $graph += "[$($i):v]$norm[v$i];" }
    for ($i = 0; $i -lt $inputs.Count; $i++) { $graph += "[v$i]" }
    $graph += "concat=n=$($inputs.Count):v=1:a=0[out]"

    $target = Join-Path $outDir 'SPLAT-demo.mp4'
    $ffArgs.AddRange([string[]] @(
        '-filter_complex', $graph, '-map', '[out]',
        '-c:v', 'libx264', '-preset', 'slow', '-crf', '20', '-pix_fmt', 'yuv420p', '-an',
        '-movflags', '+faststart',
        $target))

    Write-Host "Assembling $($inputs.Count) clips -> $target"
    Invoke-Ffmpeg -Ffmpeg $ffmpeg -FfArgs $ffArgs.ToArray() -WorkingDirectory $demoRoot -What 'Assemble'
    $size = [Math]::Round((Get-Item -LiteralPath $target).Length / 1MB, 1)
    Write-Host "  wrote $target ($size MB)"
}
