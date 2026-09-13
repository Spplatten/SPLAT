[CmdletBinding()]
param(
    [ValidateSet('Lab', 'Regression', 'Links')]
    [string]$Gate = 'Lab',
    [ValidateSet('all', 'representation', 'executor')]
    [string]$LabMode = 'all',
    [string]$DotNetPath
)

$ErrorActionPreference = 'Stop'
$courseRoot = Split-Path -Parent $PSScriptRoot

if ($Gate -eq 'Links') {
    $courseDocs = Join-Path $courseRoot 'docs\course'
    $courseBrokenLinks = @()
    $courseLinkCount = 0
    foreach ($courseFile in Get-ChildItem -LiteralPath $courseDocs -Filter '*.md' -File) {
        $courseBody = Get-Content -LiteralPath $courseFile.FullName -Raw
        foreach ($courseMatch in [regex]::Matches($courseBody, '\]\((?<target>[^)\s]+)\)')) {
            $courseTarget = $courseMatch.Groups['target'].Value
            if ($courseTarget -match '^(https?://|#)') { continue }
            $courseLocalTarget = ($courseTarget -split '#', 2)[0]
            $courseResolved = [IO.Path]::GetFullPath(
                (Join-Path $courseFile.DirectoryName $courseLocalTarget))
            $courseLinkCount++
            if (-not (Test-Path -LiteralPath $courseResolved)) {
                $courseBrokenLinks += "$($courseFile.Name): $courseTarget"
            }
        }
        if (([regex]::Matches($courseBody, '(?m)^~~~').Count % 2) -ne 0) {
            throw "Unbalanced fenced examples: $($courseFile.Name)"
        }
    }
    if ($courseBrokenLinks.Count -gt 0) { throw ($courseBrokenLinks -join [Environment]::NewLine) }
    Write-Output "PASS $courseLinkCount local course links; example fences balanced."
    return
}

if (-not $DotNetPath) {
    # This workstation has two SDK roots; PATH alone currently selects the older SDK.
    $courseUserDotnet = Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe'
    if (Test-Path -LiteralPath $courseUserDotnet) {
        $DotNetPath = $courseUserDotnet
    } else {
        $DotNetPath = (Get-Command dotnet -ErrorAction Stop).Source
    }
}

Push-Location -LiteralPath $courseRoot
try {
    $courseSdk = & $DotNetPath --version
    if ($LASTEXITCODE -ne 0 -or $courseSdk -notmatch '^10\.') {
        throw "Select a .NET 10 SDK with -DotNetPath. Selected SDK: $courseSdk"
    }
    if ($Gate -eq 'Lab') {
        & $DotNetPath run --project coursework/Splat.CourseLab/Splat.CourseLab.csproj -- $LabMode
    } else {
        # These suites exercise local fixtures and repository evidence; they do not start a root daemon.
        $courseFilter = @(
            'AuditPayloadAndPreExecutionAuthTests',
            'ArgumentVectorContractTests',
            'WslLeasedExecutorWireTests',
            'WorkspaceConfinementTests',
            'SubstrateHealthHonestyTests',
            'FailureIsNotEvidenceTests',
            'ProjectExecutionEngineTests',
            'DocumentationDriftTests'
        ) | ForEach-Object { "FullyQualifiedName~$_" }
        $courseEvidence = Join-Path ([IO.Path]::GetTempPath()) ('SplatCourse-' + [Guid]::NewGuid().ToString('N'))
        & $DotNetPath test tests/MissionController.Tests/MissionController.Tests.csproj --nologo --filter ($courseFilter -join '|') --logger 'trx;LogFileName=course.trx' --results-directory $courseEvidence --verbosity minimal
    }
    if ($LASTEXITCODE -ne 0) { throw "Course gate $Gate failed with exit code $LASTEXITCODE." }
    if ($Gate -eq 'Regression') {
        # A renamed filter can match no tests and still exit successfully; inspect the evidence.
        [xml]$courseReport = Get-Content -LiteralPath (Join-Path $courseEvidence 'course.trx') -Raw
        if ([int]$courseReport.TestRun.ResultSummary.Counters.total -le 0) {
            throw 'The regression filter matched no tests.'
        }
    }
} finally {
    Pop-Location
}
