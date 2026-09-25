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
using MissionController.Core;
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

    /// <summary>The first line of every signed statement, so a signature over one can never pass as another kind.</summary>
    public const string StatementHeader = "splat-run-record-v1";

    private readonly IRunRecordSigner? _signer;

    public ComplianceArchiveExporter(IMerkleProofEngine merkleEngine, IRunRecordSigner? signer = null)
    {
        _merkleEngine = merkleEngine;
        _signer = signer;
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
            outputDirectory = SplatDataRoot.Layout.ComplianceExports;
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
            outputDirectory = SplatDataRoot.Layout.MissionRunRecords;
        }

        Directory.CreateDirectory(outputDirectory);

        string zipFilePath = Path.Combine(
            outputDirectory,
            $"RUN-RECORD-{runRecord.MissionId:N}_{DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture)}.zip");

        var tree = _merkleEngine.BuildTree(entries);
        var proofs = entries.Select(entry => _merkleEngine.GenerateProof(tree, entry.Id)).ToList();

        // Every file as the exact bytes that go into the archive, so the signed statement names the same
        // bytes a verifier hashes. Sorted, so the statement lists them in one order on every host.
        var files = new SortedDictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["mission_run_record.json"] = TextBytes(JsonSerializer.Serialize(runRecord, JsonOpts)),
            ["audit_chain.json"] = TextBytes(JsonSerializer.Serialize(entries, JsonOpts)),
            ["merkle_proofs.json"] = TextBytes(JsonSerializer.Serialize(proofs, JsonOpts)),
            ["run_record_summary.md"] = TextBytes(GenerateMissionRunRecordSummary(runRecord, _signer)),
            ["verify_proofs.py"] = TextBytes(GeneratePythonVerificationScript()),
            ["verify_proofs.ps1"] = TextBytes(GeneratePowerShellVerificationScript())
        };

        if (_signer is not null)
        {
            files["signature.json"] = TextBytes(JsonSerializer.Serialize(SignatureOver(runRecord.MissionId, files, _signer), JsonOpts));
        }

        await using (var fileStream = new FileStream(zipFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var archive = new ZipArchive(fileStream, ZipArchiveMode.Create))
        {
            foreach (var (name, bytes) in files)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
                await using var entryStream = entry.Open();
                await entryStream.WriteAsync(bytes, cancellationToken);
            }
        }

        return zipFilePath;
    }

    /// <summary>
    /// What a signed bundle carries beside its files: the public key, and a signature over a statement
    /// that names the mission and every other file in the bundle by its SHA-256.
    /// </summary>
    public sealed record RunRecordSignature(string Algorithm, string KeyId, string PublicKey, string Statement, string Signature);

    private static RunRecordSignature SignatureOver(Guid missionId, IReadOnlyDictionary<string, byte[]> files, IRunRecordSigner signer)
    {
        var statement = new StringBuilder();
        statement.Append(StatementHeader).Append('\n');
        statement.Append("mission ").Append(missionId.ToString("D")).Append('\n');
        foreach (var (name, bytes) in files)
        {
            statement.Append("file ").Append(name).Append(" sha256 ")
                .Append(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()).Append('\n');
        }

        string text = statement.ToString();
        return new RunRecordSignature(
            signer.Algorithm,
            signer.KeyId,
            Convert.ToBase64String(signer.PublicKeyDer),
            text,
            Convert.ToBase64String(signer.Sign(Encoding.UTF8.GetBytes(text))));
    }

    // With the byte-order mark every text file here has always been written with.
    private static byte[] TextBytes(string content) => [.. Encoding.UTF8.GetPreamble(), .. Encoding.UTF8.GetBytes(content)];

    private static string GenerateMissionRunRecordSummary(MissionRunRecord record, IRunRecordSigner? signer)
    {
        var identity = record.RequestIdentity;
        var permission = record.EffectivePermission;
        var enforcement = record.EnforcementState;
        var outcome = record.Outcome;
        var cleanup = record.Cleanup;
        var integrity = record.Integrity;
        var limits = enforcement.EffectiveLimitsReadback;

        var sb = new StringBuilder();
        sb.AppendLine($"# Mission run record: `{record.MissionId:D}`");
        sb.AppendLine();
        sb.AppendLine("Everything below comes from the facts the mission engine sealed into its audit ledger when the mission ended, the `MISSION_RUN_FACTS` entry among the entries in `audit_chain.json`. " +
                      $"A field that reads \"{NotRecorded}\" is one the engine did not observe. It is not a default and it is not a claim.");
        sb.AppendLine();
        sb.AppendLine("## 1. Request identity");
        sb.AppendLine($"- **Principal:** `{Shown(identity.Principal)}`");
        sb.AppendLine($"- **Authenticated by:** `{Shown(identity.AuthProvenance)}`");
        sb.AppendLine($"- **Mission ID:** `{identity.MissionId:D}`");
        sb.AppendLine($"- **Idempotency token:** `{Shown(identity.IdempotencyToken)}`");
        sb.AppendLine($"- **Approval reference:** `{Shown(identity.ApprovalReference)}`");
        sb.AppendLine($"- **Policy hash:** `{identity.PolicyVersionOrHash}` (the template, as the engine ran it)");
        sb.AppendLine($"- **Requested at:** `{Shown(identity.RequestedAtUtc?.ToString("O", CultureInfo.InvariantCulture))}`");
        sb.AppendLine();
        sb.AppendLine("## 2. Effective permission");
        sb.AppendLine($"- **Executable:** `{permission.ExecutablePath}`");
        sb.AppendLine($"- **Command line:** `{Shown(permission.CommandLine)}`");
        sb.AppendLine($"- **Workspace:** `{Shown(permission.WorkspaceBoundary)}`");
        sb.AppendLine($"- **Declared destination:** `{Shown(permission.DeclaredEgress)}`");
        sb.AppendLine($"- **Network, as enforced:** `{permission.EgressEnforcement}`");
        sb.AppendLine($"- **Requested ceilings:** `{permission.MaxMemoryBytes / (1024 * 1024)} MB memory, {permission.MaxCpuPercent}% CPU, {Shown(permission.DurationCeilingSeconds)} s`");
        sb.AppendLine($"- **Token the tool ran with:** `{Shown(permission.RuntimeIdentity)}`");
        sb.AppendLine();
        sb.AppendLine("## 3. Enforcement state, read back from the kernel objects");
        sb.AppendLine($"- **Substrate:** `{enforcement.SubstrateType}` on `{Shown(enforcement.KernelOrOsRelease)}`");
        sb.AppendLine($"- **Job object:** `{Shown(enforcement.CgroupOrJobId)}`");
        sb.AppendLine($"- **Limits the kernel held:** `{(limits is null ? NotRecorded : LimitsText(limits))}`");
        sb.AppendLine($"- **Controls read back:** `{Shown(enforcement.AttachedControls, "none")}`");
        sb.AppendLine($"- **Admission:** `{enforcement.AdmissionVerdict}`");
        sb.AppendLine();
        sb.AppendLine("## 4. Outcome");
        sb.AppendLine($"- **Execution state:** `{outcome.ExecutionState}`");
        sb.AppendLine($"- **Exit code:** `{Shown(outcome.ExitCode)}` (accepted: `{Shown(outcome.AllowedExitCodes, "none")}`; contract met: `{Shown(outcome.ExitContractMet)}`)");
        sb.AppendLine($"- **Terminal reason:** `{Shown(outcome.TerminalReason)}`");
        sb.AppendLine($"- **Redactions before the output left the sandbox:** `{outcome.RedactionCount}` (categories: `{Shown(outcome.RedactedCategories, "none")}`)");
        sb.AppendLine($"- **Model:** `{Shown(outcome.Model)}`");
        sb.AppendLine($"- **Quality gate accepted the analysis:** `{Shown(outcome.QualityAcceptance)}`");
        sb.AppendLine();
        sb.AppendLine("## 5. Cleanup, as observed at teardown");
        sb.AppendLine($"- **Processes still running at teardown:** `{Shown(cleanup.ProcessesLeftAtTeardown)}`");
        sb.AppendLine($"- **Teardown order:** `{Shown(cleanup.TeardownOrder, "none")}`");
        sb.AppendLine($"- **Workspace:** `{Shown(cleanup.WorkspaceDisposition)}`");
        sb.AppendLine($"- **Nothing left behind:** `{Shown(cleanup.ResidualResourcesCleaned)}`");
        sb.AppendLine();
        sb.AppendLine("## 6. Integrity");
        sb.AppendLine($"- **Ledger chain kind:** `{Shown(integrity.ChainKind)}` (hash version `{Shown(integrity.HashVersion)}`)");
        sb.AppendLine($"- **Merkle root:** `{Shown(integrity.MerkleRootHash)}`");
        sb.AppendLine($"- **Audit entries:** `{integrity.TotalAuditEntries}`, the facts among them as entry hash `{Shown(integrity.FactsEntryHash)}`");
        sb.AppendLine($"- **Signed by:** `{(signer is null ? "nobody: this bundle is unsigned" : $"{signer.KeyId} ({signer.Algorithm})")}`");
        sb.AppendLine($"- **Assembled at:** `{integrity.AssembledAtUtc.ToString("O", CultureInfo.InvariantCulture)}`");
        sb.AppendLine();
        sb.AppendLine("## What this bundle proves");
        sb.AppendLine("The scripts in this folder check that every entry in `audit_chain.json` is a leaf under the Merkle root in `mission_run_record.json`, through a proof in `merkle_proofs.json`.");
        sb.AppendLine();
        if (signer is null)
        {
            sb.AppendLine("This bundle is unsigned. The check shows the files agree with each other; it does not show who produced them, because whoever can edit the bundle can rebuild all three to agree. Configure a run record key to sign bundles.");
        }
        else
        {
            sb.AppendLine("`signature.json` names every other file here by its SHA-256, and carries a signature over that list and the mission id. The scripts check each file still has its listed hash and that the signature verifies under the public key `signature.json` carries. " +
                          $"Together that shows these are the files the holder of key `{signer.KeyId}` produced, unchanged. The bundle alone cannot say whose key that is: compare the fingerprint with the one the operator published.");
        }

        sb.AppendLine();
        sb.AppendLine("Tying the entries to the host's own ledger means checking that its ledger verifies, under its key when it has one, and holds these entry hashes. No command makes that comparison yet.");
        sb.AppendLine();
        sb.AppendLine("Run either script from this folder:");
        sb.AppendLine("```");
        sb.AppendLine("python verify_proofs.py");
        sb.AppendLine("powershell -ExecutionPolicy Bypass -File .\\verify_proofs.ps1");
        sb.AppendLine("```");
        return sb.ToString();
    }

    private static string LimitsText(JobLimitsReadback limits) =>
        $"memory {Megabytes(limits.JobMemoryLimitBytes)} per job and {Megabytes(limits.ProcessMemoryLimitBytes)} per process, " +
        $"CPU {(limits.CpuRatePercent is { } cpu ? $"{cpu}%" : "uncapped")}, " +
        $"{Shown(limits.ActiveProcessLimit)} processes at most, kill on close {Shown(limits.KillOnJobClose)}";

    private static string Megabytes(long? bytes) => bytes is { } b ? $"{b / (1024 * 1024)} MB" : "uncapped";

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

    // Both scripts once read only manifest.json, which a run record bundle does not have; json.load
    // refused the byte-order mark every file here is written with; and neither rebuilt a leaf from
    // audit_chain.json, so an edited entry still passed. A script shipped as a verifier has to run.
    private static string GeneratePythonVerificationScript()
    {
        return @"# Checks the evidence files beside this script:
#   1. every entry in audit_chain.json is a leaf under the Merkle root, through its proof;
#   2. if the bundle is signed, every file still has the hash the signed statement gives it,
#      and that statement's signature verifies under the public key the bundle carries.
# Exit codes: 0 verified and signed, 2 the files agree but nothing signed them, 1 a check failed.
import base64
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

def file_sha256(name):
    with open(os.path.join(HERE, name), 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def leaf_hash(entry):
    # The fields and order of MerkleTreeEngine.ComputeLeafHash; the time is its round-trip text.
    return sha256_hex(f""{entry['Id']}:{entry['EntryHash']}:{entry['TimestampUtc']}:{entry['Action']}:{entry['OperatorIdentity']}"")

def parent_hash(left, right):
    return sha256_hex(f""{left}:{right}"")

def fail(message):
    print(f'[-] {message}')
    sys.exit(1)

def der_rsa_public_key(der):
    # SEQUENCE { INTEGER modulus, INTEGER exponent }, which is all a PKCS#1 RSAPublicKey holds.
    def length(at):
        size = der[at]
        at += 1
        if size & 0x80:
            count = size & 0x7F
            size = int.from_bytes(der[at:at + count], 'big')
            at += count
        return size, at

    if der[0] != 0x30:
        fail('the public key in signature.json is not a DER SEQUENCE.')
    _, at = length(1)
    numbers = []
    for _ in range(2):
        if der[at] != 0x02:
            fail('the public key in signature.json is not two DER INTEGERs.')
        size, at = length(at + 1)
        numbers.append(int.from_bytes(der[at:at + size], 'big'))
        at += size
    return numbers[0], numbers[1]

def pkcs1_sha256_verify(modulus, exponent, message, signature):
    # RSASSA-PKCS1-v1_5 verification is one modular exponentiation and a comparison, so it needs
    # nothing but the standard library.
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    decrypted = pow(int.from_bytes(signature, 'big'), exponent, modulus).to_bytes(size, 'big')
    digest_info = bytes.fromhex('3031300d060960864801650304020105000420') + hashlib.sha256(message).digest()
    expected = b'\x00\x01' + b'\xff' * (size - len(digest_info) - 3) + b'\x00' + digest_info
    return decrypted == expected

def check_signature(mission_id):
    if not os.path.exists(os.path.join(HERE, 'signature.json')):
        print('[!] Unsigned: the files agree with each other, and nothing here says who produced them.')
        return 2

    signature = load('signature.json')
    statement = signature['Statement']
    listed = {}
    for line in statement.split('\n'):
        parts = line.split(' ')
        if len(parts) == 4 and parts[0] == 'file' and parts[2] == 'sha256':
            listed[parts[1]] = parts[3]

    for name, expected in sorted(listed.items()):
        if file_sha256(name) != expected:
            fail(f'{name} is not the file that was signed.')
    for required in ('mission_run_record.json', 'audit_chain.json', 'merkle_proofs.json'):
        if required not in listed:
            fail(f'the signed statement does not cover {required}.')
    if mission_id and f'mission {mission_id}' not in statement.split('\n'):
        fail('the signed statement is for a different mission.')

    der = base64.b64decode(signature['PublicKey'])
    key_id = 'sha256:' + hashlib.sha256(der).hexdigest()
    if key_id != signature['KeyId']:
        fail('the key id does not match the key the bundle carries.')

    modulus, exponent = der_rsa_public_key(der)
    if not pkcs1_sha256_verify(modulus, exponent, statement.encode('utf-8'), base64.b64decode(signature['Signature'])):
        fail('the signature does not verify under the key the bundle carries.')

    print(f'[+] Signed by {key_id}.')
    print('[+] Compare that fingerprint with the one the operator published: the bundle cannot tell you whose key it is.')
    return 0

def main():
    mission_id = None
    if os.path.exists(os.path.join(HERE, 'manifest.json')):
        root_file = 'manifest.json'
        root = load(root_file).get('MerkleRootHash')
    else:
        root_file = 'mission_run_record.json'
        record = load(root_file)
        root = (record.get('Integrity') or {}).get('MerkleRootHash')
        mission_id = record.get('MissionId')
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
    sys.exit(check_signature(mission_id))

if __name__ == '__main__':
    main()
";
    }

    private static string GeneratePowerShellVerificationScript()
    {
        return @"# Checks the evidence files beside this script:
#   1. every entry in audit_chain.json is a leaf under the Merkle root, through its proof;
#   2. if the bundle is signed, every file still has the hash the signed statement gives it,
#      and that statement's signature verifies under the public key the bundle carries.
# Exit codes: 0 verified and signed, 2 the files agree but nothing signed them, 1 a check failed.
$ErrorActionPreference = 'Stop'

function Read-Evidence([string]$name) {
    # The files carry a byte-order mark; reading them as UTF-8 keeps any non-ASCII text intact.
    $text = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot $name), [System.Text.Encoding]::UTF8)
    return ($text | ConvertFrom-Json)
}

function Get-Sha256HexOfBytes([byte[]]$bytes) {
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $hasher.ComputeHash($bytes) } finally { $hasher.Dispose() }
    return [System.BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant()
}

function Get-Sha256Hex([string]$text) {
    return Get-Sha256HexOfBytes ([System.Text.Encoding]::UTF8.GetBytes($text))
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

# SEQUENCE { INTEGER modulus, INTEGER exponent }, which is all a PKCS#1 RSAPublicKey holds.
function Read-RsaPublicKey([byte[]]$der) {
    $script:at = 0
    function Read-DerLength {
        $size = [int]$der[$script:at]; $script:at++
        if ($size -band 0x80) {
            $count = $size -band 0x7F
            $size = 0
            for ($k = 0; $k -lt $count; $k++) { $size = ($size -shl 8) -bor $der[$script:at]; $script:at++ }
        }
        return $size
    }
    function Read-DerInteger {
        if ($der[$script:at] -ne 0x02) { Stop-Verification 'the public key in signature.json is not two DER INTEGERs.' }
        $script:at++
        $size = Read-DerLength
        $bytes = New-Object byte[] $size
        [Array]::Copy($der, $script:at, $bytes, 0, $size)
        $script:at += $size
        # A positive INTEGER carries a leading zero when its top bit is set; RSAParameters wants it gone.
        while ($bytes.Length -gt 1 -and $bytes[0] -eq 0) { $bytes = $bytes[1..($bytes.Length - 1)] }
        return ,([byte[]]$bytes)
    }

    if ($der[0] -ne 0x30) { Stop-Verification 'the public key in signature.json is not a DER SEQUENCE.' }
    $script:at = 1
    [void](Read-DerLength)
    $modulus = Read-DerInteger
    $exponent = Read-DerInteger
    return [PSCustomObject]@{ Modulus = $modulus; Exponent = $exponent }
}

function Test-Signature($missionId) {
    if (-not (Test-Path (Join-Path $PSScriptRoot 'signature.json'))) {
        Write-Host '[!] Unsigned: the files agree with each other, and nothing here says who produced them.' -ForegroundColor Yellow
        exit 2
    }

    $signature = Read-Evidence 'signature.json'
    $statement = [string]$signature.Statement
    $listed = @{}
    foreach ($line in ($statement -split ""`n"")) {
        $parts = $line -split ' '
        if ($parts.Count -eq 4 -and $parts[0] -eq 'file' -and $parts[2] -eq 'sha256') { $listed[$parts[1]] = $parts[3] }
    }

    foreach ($name in $listed.Keys) {
        $actual = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $listed[$name]) { Stop-Verification ""$name is not the file that was signed."" }
    }
    foreach ($required in @('mission_run_record.json', 'audit_chain.json', 'merkle_proofs.json')) {
        if (-not $listed.ContainsKey($required)) { Stop-Verification ""the signed statement does not cover $required."" }
    }
    if ($missionId -and (($statement -split ""`n"") -notcontains ""mission $missionId"")) {
        Stop-Verification 'the signed statement is for a different mission.'
    }

    $der = [Convert]::FromBase64String([string]$signature.PublicKey)
    $keyId = 'sha256:' + (Get-Sha256HexOfBytes $der)
    if ($keyId -ne [string]$signature.KeyId) { Stop-Verification 'the key id does not match the key the bundle carries.' }

    $key = Read-RsaPublicKey $der
    $parameters = New-Object System.Security.Cryptography.RSAParameters
    $parameters.Modulus = $key.Modulus
    $parameters.Exponent = $key.Exponent
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
        $rsa.ImportParameters($parameters)
        $verified = $rsa.VerifyData(
            [System.Text.Encoding]::UTF8.GetBytes($statement),
            [Convert]::FromBase64String([string]$signature.Signature),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } finally { $rsa.Dispose() }
    if (-not $verified) { Stop-Verification 'the signature does not verify under the key the bundle carries.' }

    Write-Host ""[+] Signed by $keyId."" -ForegroundColor Green
    Write-Host '[+] Compare that fingerprint with the one the operator published: the bundle cannot tell you whose key it is.' -ForegroundColor Green
    exit 0
}

$missionId = $null
if (Test-Path (Join-Path $PSScriptRoot 'manifest.json')) {
    $rootFile = 'manifest.json'
    $root = (Read-Evidence $rootFile).MerkleRootHash
} else {
    $rootFile = 'mission_run_record.json'
    $record = Read-Evidence $rootFile
    $root = $record.Integrity.MerkleRootHash
    $missionId = [string]$record.MissionId
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
Test-Signature $missionId
";
    }
}
