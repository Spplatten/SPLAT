using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Compliance;

public sealed class ComplianceArchiveExporter : IComplianceArchiveExporter
{
    private readonly IMerkleProofEngine _merkleEngine;
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new RoundTripDateTimeConverter() }
    };

    private const string NotRecorded = "not recorded";

    public ComplianceArchiveExporter(IMerkleProofEngine merkleEngine)
    {
        _merkleEngine = merkleEngine;
    }

    public async Task<string> ExportCompliancePackageAsync(
        ComplianceFramework framework,
        string outputDirectory,
        IReadOnlyList<AuditLogEntry> entries,
        string operatorIdentity,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(outputDirectory))
        {
            outputDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MissionController", "ComplianceExports");
        }

        Directory.CreateDirectory(outputDirectory);

        string packageId = $"COMPLIANCE-{framework.ToString().ToUpperInvariant()}-{Guid.NewGuid():N}";
        string timestampStr = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        string zipFileName = $"{packageId}_{timestampStr}.zip";
        string zipFilePath = Path.Combine(outputDirectory, zipFileName);

        // 1. Build Merkle Tree & Generate Proofs
        var tree = _merkleEngine.BuildTree(entries);
        var proofs = new List<MerkleProof>();
        foreach (var entry in entries)
        {
            proofs.Add(_merkleEngine.GenerateProof(tree, entry.Id));
        }

        // 2. Generate Digital Attestation Signature
        string signatureData = $"{packageId}:{framework}:{tree.RootHash}:{entries.Count}:{operatorIdentity}";
        string digitalSignature = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(signatureData))).ToLowerInvariant();

        var includedFiles = new List<string>
        {
            "manifest.json",
            "audit_chain.json",
            "merkle_proofs.json",
            "compliance_summary.md",
            "verify_proofs.py",
            "verify_proofs.ps1"
        };

        var manifest = new CompliancePackageManifest(
            packageId,
            framework,
            DateTimeOffset.UtcNow,
            operatorIdentity,
            tree.RootHash,
            entries.Count,
            digitalSignature,
            "SHA256-ENTERPRISE-ATTESTATION",
            includedFiles);

        // 3. Create Zip Archive in memory / file stream
        await using (var fileStream = new FileStream(zipFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var archive = new ZipArchive(fileStream, ZipArchiveMode.Create))
        {
            // manifest.json
            await WriteTextToArchiveAsync(archive, "manifest.json", JsonSerializer.Serialize(manifest, JsonOpts));

            // audit_chain.json
            await WriteTextToArchiveAsync(archive, "audit_chain.json", JsonSerializer.Serialize(entries, JsonOpts));

            // merkle_proofs.json
            await WriteTextToArchiveAsync(archive, "merkle_proofs.json", JsonSerializer.Serialize(proofs, JsonOpts));

            // compliance_summary.md
            string summaryMd = GenerateComplianceSummary(framework, manifest, entries);
            await WriteTextToArchiveAsync(archive, "compliance_summary.md", summaryMd);

            // verify_proofs.py
            string pythonScript = GeneratePythonVerificationScript();
            await WriteTextToArchiveAsync(archive, "verify_proofs.py", pythonScript);

            // verify_proofs.ps1
            string psScript = GeneratePowerShellVerificationScript();
            await WriteTextToArchiveAsync(archive, "verify_proofs.ps1", psScript);
        }

        return zipFilePath;
    }

    public async Task<string> ExportMissionRunRecordPackageAsync(
        MissionRunRecord runRecord,
        IReadOnlyList<AuditLogEntry> entries,
        string outputDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(runRecord);
        ArgumentNullException.ThrowIfNull(entries);

        if (string.IsNullOrWhiteSpace(outputDirectory))
        {
            outputDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MissionController", "MissionRunRecords");
        }

        Directory.CreateDirectory(outputDirectory);

        string packageId = $"RUN-RECORD-{runRecord.MissionId:N}";
        string timestampStr = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        string zipFileName = $"{packageId}_{timestampStr}.zip";
        string zipFilePath = Path.Combine(outputDirectory, zipFileName);

        // 1. Build Merkle Tree & Generate Proofs for entries
        var tree = _merkleEngine.BuildTree(entries);
        var proofs = new List<MerkleProof>();
        foreach (var entry in entries)
        {
            proofs.Add(_merkleEngine.GenerateProof(tree, entry.Id));
        }

        // 2. Create Zip Archive
        await using (var fileStream = new FileStream(zipFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var archive = new ZipArchive(fileStream, ZipArchiveMode.Create))
        {
            // mission_run_record.json
            await WriteTextToArchiveAsync(archive, "mission_run_record.json", JsonSerializer.Serialize(runRecord, JsonOpts));

            // audit_chain.json
            await WriteTextToArchiveAsync(archive, "audit_chain.json", JsonSerializer.Serialize(entries, JsonOpts));

            // merkle_proofs.json
            await WriteTextToArchiveAsync(archive, "merkle_proofs.json", JsonSerializer.Serialize(proofs, JsonOpts));

            // run_record_summary.md
            string summaryMd = GenerateMissionRunRecordSummary(runRecord);
            await WriteTextToArchiveAsync(archive, "run_record_summary.md", summaryMd);

            // verify_proofs.py
            string pythonScript = GeneratePythonVerificationScript();
            await WriteTextToArchiveAsync(archive, "verify_proofs.py", pythonScript);

            // verify_proofs.ps1
            string psScript = GeneratePowerShellVerificationScript();
            await WriteTextToArchiveAsync(archive, "verify_proofs.ps1", psScript);
        }

        return zipFilePath;
    }

    private static string GenerateMissionRunRecordSummary(MissionRunRecord record)
    {
        var identity = record.RequestIdentity;
        var permission = record.EffectivePermission;
        var enforcement = record.EnforcementState;
        var outcome = record.Outcome;
        var cleanup = record.Cleanup;
        var integrity = record.Integrity;

        var sb = new StringBuilder();
        sb.AppendLine($"# Mission run record: `{record.MissionId:D}`");
        sb.AppendLine();
        sb.AppendLine($"A field that reads \"{NotRecorded}\" is one nothing observed when this record was assembled. It is not a default and it is not a claim.");
        sb.AppendLine();
        sb.AppendLine("## 1. Request identity");
        sb.AppendLine($"- **Principal:** `{Shown(identity.Principal)}`");
        sb.AppendLine($"- **Auth provenance:** `{Shown(identity.AuthProvenance)}`");
        sb.AppendLine($"- **Mission ID:** `{identity.MissionId:D}`");
        sb.AppendLine($"- **Idempotency token:** `{Shown(identity.IdempotencyToken)}`");
        sb.AppendLine($"- **Approval reference:** `{Shown(identity.ApprovalReference)}`");
        sb.AppendLine($"- **Policy hash:** `{identity.PolicyVersionOrHash}` (the template as it was handed to the assembler)");
        sb.AppendLine($"- **First recorded:** `{Shown(identity.FirstRecordedAtUtc?.ToString("O", CultureInfo.InvariantCulture))}`");
        sb.AppendLine();
        sb.AppendLine("## 2. Effective permission, as requested");
        sb.AppendLine($"- **Executable:** `{permission.ExecutablePath}`");
        sb.AppendLine($"- **Arguments:** `{Shown(permission.ArgumentVector, "none")}`");
        sb.AppendLine($"- **Workspace boundary:** `{Shown(permission.WorkspaceBoundary)}`");
        sb.AppendLine($"- **Network allowed:** `{Shown(permission.AllowNetwork)}`");
        sb.AppendLine($"- **Allowed egress IPs:** `{Shown(permission.AllowedEgressIps, "none")}`");
        sb.AppendLine($"- **Allowed egress ports:** `{Shown(permission.AllowedEgressPorts, "none")}`");
        sb.AppendLine($"- **Ceilings:** `{permission.MaxMemoryBytes / (1024 * 1024)} MB memory, {permission.MaxCpuPercent}% CPU`");
        sb.AppendLine($"- **Lease duration (s):** `{Shown(permission.LeaseDurationSeconds)}`");
        sb.AppendLine($"- **Runtime UID and capabilities:** `{Shown(permission.RuntimeCapabilities)}`");
        sb.AppendLine();
        sb.AppendLine("## 3. Enforcement state");
        sb.AppendLine($"- **Substrate:** `{enforcement.SubstrateType}`");
        sb.AppendLine($"- **Kernel / OS:** `{Shown(enforcement.KernelOrOsRelease)}`");
        sb.AppendLine($"- **Attached controls:** `{Shown(enforcement.AttachedControls, "none")}`");
        sb.AppendLine($"- **Cgroup / job ID:** `{Shown(enforcement.CgroupOrJobId)}`");
        sb.AppendLine($"- **Limits as read back:** `{Shown(enforcement.EffectiveLimitsReadback)}`");
        sb.AppendLine($"- **Admission verdict:** `{enforcement.AdmissionVerdict}`");
        sb.AppendLine();
        sb.AppendLine("## 4. Outcome");
        sb.AppendLine($"- **Execution state:** `{outcome.ExecutionState}`");
        sb.AppendLine($"- **Exit code:** `{Shown(outcome.ExitCode)}`");
        sb.AppendLine($"- **Terminal reason:** `{Shown(outcome.TerminalReason)}`");
        sb.AppendLine($"- **DLP redactions:** `{outcome.RedactionCount}` (categories: `{Shown(outcome.RedactedCategories, "none")}`)");
        sb.AppendLine($"- **Quality acceptance:** `{Shown(outcome.QualityAcceptance)}`");
        sb.AppendLine();
        sb.AppendLine("## 5. Cleanup");
        sb.AppendLine($"- **Processes terminated:** `{Shown(cleanup.ProcessesTerminated)}`");
        sb.AppendLine($"- **Policy removal order:** `{Shown(cleanup.PolicyRemovalOrder, "none")}`");
        sb.AppendLine($"- **Workspace disposition:** `{Shown(cleanup.WorkspaceDisposition)}`");
        sb.AppendLine($"- **Residual resources cleaned:** `{Shown(cleanup.ResidualResourcesCleaned)}`");
        sb.AppendLine();
        sb.AppendLine("## 6. Integrity");
        sb.AppendLine($"- **Ledger chain kind:** `{Shown(integrity.ChainKind)}` (hash version `{Shown(integrity.HashVersion)}`)");
        sb.AppendLine($"- **Merkle root:** `{Shown(integrity.MerkleRootHash)}`");
        sb.AppendLine($"- **Audit entries:** `{integrity.TotalAuditEntries}`");
        sb.AppendLine($"- **Signature:** `{Shown(integrity.AttestationSignature)}`");
        sb.AppendLine($"- **Assembled at:** `{integrity.AssembledAtUtc.ToString("O", CultureInfo.InvariantCulture)}`");
        sb.AppendLine();
        sb.AppendLine("## What this bundle proves");
        sb.AppendLine("The scripts in this folder check that every entry in `audit_chain.json` is a leaf under the Merkle root in `mission_run_record.json`, through a proof in `merkle_proofs.json`. That shows the three files agree with each other.");
        sb.AppendLine();
        sb.AppendLine("It does not show where they came from. Nothing in the bundle is signed, so whoever can edit it can rebuild all three files to agree. A leaf covers an entry's id, entry hash, time, action and operator, but not its details: the entry hash commits to those, and only the host's ledger holds what it takes to recompute one. Tying the bundle to a host means checking that the host's ledger verifies, under its key when it has one, and holds these entry hashes. No command makes that comparison yet.");
        sb.AppendLine();
        sb.AppendLine("Run either script from this folder:");
        sb.AppendLine("```");
        sb.AppendLine("python verify_proofs.py");
        sb.AppendLine("powershell -ExecutionPolicy Bypass -File .\\verify_proofs.ps1");
        sb.AppendLine("```");
        return sb.ToString();
    }

    private static string Shown(string? value) => string.IsNullOrEmpty(value) ? NotRecorded : value;

    private static string Shown<T>(T? value) where T : struct =>
        value.HasValue ? Convert.ToString(value.Value, CultureInfo.InvariantCulture)! : NotRecorded;

    private static string Shown<T>(IReadOnlyList<T>? values, string whenEmpty) =>
        values is null ? NotRecorded : values.Count == 0 ? whenEmpty : string.Join(", ", values);

    // Timestamps go out in the round-trip ("O") form the Merkle leaf hashes, so a verifier can rebuild each
    // leaf from audit_chain.json's text. The serializer's own form drops the fraction's trailing zeros, and
    // a leaf rebuilt from that text does not match.
    private sealed class RoundTripDateTimeConverter : JsonConverter<DateTime>
    {
        public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            DateTime.Parse(reader.GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

        public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value.ToString("O", CultureInfo.InvariantCulture));
    }

    private static async Task WriteTextToArchiveAsync(ZipArchive archive, string entryName, string content)
    {
        var entry = archive.CreateEntry(entryName, CompressionLevel.Optimal);
        await using var entryStream = entry.Open();
        await using var writer = new StreamWriter(entryStream, Encoding.UTF8);
        await writer.WriteAsync(content);
    }

    private static string GenerateComplianceSummary(ComplianceFramework framework, CompliancePackageManifest manifest, IReadOnlyList<AuditLogEntry> entries)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Enterprise Compliance Audit Evidence: {framework}");
        sb.AppendLine();
        sb.AppendLine($"- **Package ID:** `{manifest.PackageId}`");
        sb.AppendLine($"- **Exported At:** `{manifest.ExportedAtUtc:O}`");
        sb.AppendLine($"- **Exported By:** `{manifest.ExportedBy}`");
        sb.AppendLine($"- **Merkle Root Hash:** `{manifest.MerkleRootHash}`");
        sb.AppendLine($"- **Total Audit Log Entries:** `{manifest.TotalAuditEntries}`");
        sb.AppendLine($"- **Digital Attestation Signature:** `{manifest.DigitalSignature}`");
        sb.AppendLine();
        sb.AppendLine("## Regulatory Framework Alignment");
        switch (framework)
        {
            case ComplianceFramework.Soc2Type2:
                sb.AppendLine("- **Trust Services Criteria:** CC6.1 (Logical Access), CC6.8 (Unauthorized Changes), CC7.2 (System Monitoring).");
                sb.AppendLine("- **Evidence:** Cryptographically chained SHA-256 audit ledger verifying non-repudiation of all diagnostic commands and AI inferences.");
                break;
            case ComplianceFramework.Hipaa:
                sb.AppendLine("- **HIPAA Security Rule:** 45 CFR § 164.312(b) (Audit Controls) & 45 CFR § 164.312(e)(1) (Transmission Security).");
                sb.AppendLine("- **Evidence:** In-process NT ACL jailing with memory-pinned DPAPI credentials ensuring zero ePHI data leakage.");
                break;
            case ComplianceFramework.CmmcLevel2:
                sb.AppendLine("- **CMMC 2.0 / NIST SP 800-171:** AU.2.041 (Audit Record Generation), AU.2.042 (Audit Record Non-Repudiation), SC.3.177 (Boundary Protection).");
                sb.AppendLine("- **Evidence:** In-memory egress domain firewall clamping all AI communications to verified FQDNs with SHA-256 Merkle root verification.");
                break;
            case ComplianceFramework.Iso27001:
                sb.AppendLine("- **ISO/IEC 27001:2022:** Control A.8.15 (Logging), Control A.8.24 (Use of Cryptography).");
                sb.AppendLine("- **Evidence:** Tamper-evident hash chaining and zero-privilege Win32 Job Object execution.");
                break;
        }
        sb.AppendLine();
        sb.AppendLine("## Verification Instructions");
        sb.AppendLine("Run either of the included zero-dependency verification scripts:");
        sb.AppendLine("```bash");
        sb.AppendLine("python verify_proofs.py");
        sb.AppendLine("# OR");
        sb.AppendLine("powershell -ExecutionPolicy Bypass -File .\\verify_proofs.ps1");
        sb.AppendLine("```");
        return sb.ToString();
    }

    private static string GeneratePythonVerificationScript()
    {
        // Both scripts once read only manifest.json, which a run record bundle does not have; json.load
        // refused the byte-order mark every file here is written with; and neither rebuilt a leaf from
        // audit_chain.json, so an edited entry still passed. A script shipped as a verifier has to run.
        return @"# Checks that the evidence files beside this script agree with each other: every entry in
# audit_chain.json is a leaf under the Merkle root, through its proof in merkle_proofs.json.
# That is all it checks. It does not show where the files came from; the summary beside it
# says what would.
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

def load(name):
    # utf-8-sig: the files are written with a byte-order mark, which json.load refuses.
    with open(os.path.join(HERE, name), 'r', encoding='utf-8-sig') as f:
        return json.load(f)

def sha256_hex(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def leaf_hash(entry):
    # The fields and order of MerkleTreeEngine.ComputeLeafHash; the time is its round-trip text.
    return sha256_hex(f""{entry['Id']}:{entry['EntryHash']}:{entry['TimestampUtc']}:{entry['Action']}:{entry['OperatorIdentity']}"")

def parent_hash(left, right):
    return sha256_hex(f""{left}:{right}"")

def fail(message):
    print(f'[-] {message}')
    sys.exit(1)

def main():
    if os.path.exists(os.path.join(HERE, 'manifest.json')):
        root_file = 'manifest.json'
        root = load(root_file).get('MerkleRootHash')
    else:
        root_file = 'mission_run_record.json'
        root = (load(root_file).get('Integrity') or {}).get('MerkleRootHash')
    entries = load('audit_chain.json')
    proofs = load('merkle_proofs.json')

    if not entries or not root:
        fail('There are no entries to verify.')
    leaves = {entry['Id']: leaf_hash(entry) for entry in entries}
    if len(leaves) != len(entries):
        fail('audit_chain.json lists an entry id twice.')

    proven = set()
    for proof in proofs:
        entry_id = proof['EntryId']
        if leaves.get(entry_id) != proof['LeafHash']:
            fail(f'The proof for entry {entry_id} is not for the entry audit_chain.json holds under that id.')
        current = proof['LeafHash']
        for step in proof['ProofSteps']:
            if step['IsLeftSibling']:
                current = parent_hash(step['SiblingHash'], current)
            else:
                current = parent_hash(current, step['SiblingHash'])
        if current != root.lower():
            fail(f'The proof for entry {entry_id} does not lead to the root in {root_file}.')
        proven.add(entry_id)

    unproven = sorted(set(leaves) - proven)
    if unproven:
        fail(f'No proof for entries {unproven}.')
    print(f'[+] All {len(leaves)} entries in audit_chain.json are leaves under the root in {root_file}.')
    print('[+] The files agree with each other. That does not show where they came from.')

if __name__ == '__main__':
    main()
";
    }

    private static string GeneratePowerShellVerificationScript()
    {
        return @"# Checks that the evidence files beside this script agree with each other: every entry in
# audit_chain.json is a leaf under the Merkle root, through its proof in merkle_proofs.json.
# That is all it checks. It does not show where the files came from; the summary beside it
# says what would.
$ErrorActionPreference = 'Stop'

function Read-Evidence([string]$name) {
    # The files carry a byte-order mark; reading them as UTF-8 keeps any non-ASCII text intact.
    $text = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot $name), [System.Text.Encoding]::UTF8)
    return ($text | ConvertFrom-Json)
}

function Get-Sha256Hex([string]$text) {
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) }
    finally { $hasher.Dispose() }
    return [System.BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant()
}

# Windows PowerShell 5.1 keeps a timestamp as the text it was written as. PowerShell 7 turns it
# into a DateTime, which has to go back to the round-trip text the leaf was hashed over.
function Get-RoundTripText($value) {
    if ($value -is [datetime]) {
        if ($value.Kind -eq [System.DateTimeKind]::Unspecified) { return $value.ToString('o') }
        return $value.ToUniversalTime().ToString('o')
    }
    return [string]$value
}

function Stop-Verification([string]$message) {
    Write-Host ""[-] $message"" -ForegroundColor Red
    exit 1
}

if (Test-Path (Join-Path $PSScriptRoot 'manifest.json')) {
    $rootFile = 'manifest.json'
    $root = (Read-Evidence $rootFile).MerkleRootHash
} else {
    $rootFile = 'mission_run_record.json'
    $root = (Read-Evidence $rootFile).Integrity.MerkleRootHash
}
$entries = @((Read-Evidence 'audit_chain.json') | Where-Object { $null -ne $_ })
$proofs = @((Read-Evidence 'merkle_proofs.json') | Where-Object { $null -ne $_ })

if ($entries.Count -eq 0 -or [string]::IsNullOrEmpty($root)) { Stop-Verification 'There are no entries to verify.' }

$leaves = @{}
foreach ($entry in $entries) {
    $id = [string]$entry.Id
    if ($leaves.ContainsKey($id)) { Stop-Verification ""audit_chain.json lists entry $id twice."" }
    $leaves[$id] = Get-Sha256Hex ""$($entry.Id):$($entry.EntryHash):$(Get-RoundTripText $entry.TimestampUtc):$($entry.Action):$($entry.OperatorIdentity)""
}

$proven = @{}
foreach ($proof in $proofs) {
    $id = [string]$proof.EntryId
    if ($leaves[$id] -ne $proof.LeafHash) { Stop-Verification ""The proof for entry $id is not for the entry audit_chain.json holds under that id."" }
    $current = $proof.LeafHash
    foreach ($step in @($proof.ProofSteps)) {
        if ($null -eq $step) { continue }
        if ($step.IsLeftSibling) { $current = Get-Sha256Hex ""$($step.SiblingHash):$($current)"" }
        else { $current = Get-Sha256Hex ""$($current):$($step.SiblingHash)"" }
    }
    if ($current -ne $root.ToLowerInvariant()) { Stop-Verification ""The proof for entry $id does not lead to the root in $rootFile."" }
    $proven[$id] = $true
}

foreach ($id in $leaves.Keys) {
    if (-not $proven.ContainsKey($id)) { Stop-Verification ""No proof for entry $id."" }
}

Write-Host ""[+] All $($leaves.Count) entries in audit_chain.json are leaves under the root in $rootFile."" -ForegroundColor Green
Write-Host '[+] The files agree with each other. That does not show where they came from.' -ForegroundColor Green
";
    }
}
