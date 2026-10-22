#!/usr/bin/env python3
"""Bounded local A2A stress with exact packaged artifacts and installed-service restoration."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import uuid

spec = importlib.util.spec_from_file_location("a2a_stress_runner", Path(__file__).with_name("probe-secrets.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
proxy_spec = importlib.util.spec_from_file_location("a2a_fault_proxy", Path(__file__).with_name("a2a-fault-proxy.py"))
proxy_module = importlib.util.module_from_spec(proxy_spec)
proxy_spec.loader.exec_module(proxy_module)


def windows_path(path):
    return subprocess.check_output(["wslpath", "-w", str(path.resolve())], text=True).strip()


class A2aStressProof(runner.Proof):
    def __init__(self, args, root):
        super().__init__(args, root)
        assert 10 <= args.seconds <= 60
        self.repo = Path(__file__).resolve().parents[2]
        self.client = Path(__file__).with_name("a2a-stress-client.py")
        self.build = json.loads(args.build_manifest.read_text(encoding="utf-8-sig"))
        self.inputs = [item for item in self.build["sourceInputs"]
            if Path(item["path"]).suffix in (".cs", ".csproj", ".py", ".rs", ".c", ".h", ".toml", ".lock", ".props", ".targets")]
        assert self.sources_match(), "packaged compiled sources differ from checkout"
        assert runner.digest(args.mcp_exe.read_bytes()) == self.build["sha256"], "MCP artifact mismatch"
        assert runner.digest(args.daemon.read_bytes()) == self.build["daemonSha256"], "daemon artifact mismatch"
        assert args.windows_python.is_file() and args.contract.is_file()
        self.command.extend(["--receipt-root", str(root / "receipts")])
        self.command[self.command.index("--missions-root") + 1] = "/var/lib/splat/missions"
        self.artifacts = args.client_root.resolve() / ("a2a-stress-" + uuid.uuid4().hex)
        self.artifacts.mkdir(parents=True)
        self.proxy = proxy_module.FaultProxy(self.port, self.artifacts / "drop-connection.once")
        self.observations = {"scope": "Packaged local Windows HTTPS A2A hosts and real Linux template leases; synthetic callers, read-only guest metadata, no model API or external HTTP.",
            "mcpExecutableSha256": self.build["sha256"], "artifactLicenseLabel": self.build["license"],
            "buildManifestSha256": runner.digest(args.build_manifest.read_bytes()),
            "clientSourceSha256": runner.digest(self.client.read_bytes()), "compiledSourceInputs": self.inputs,
            "requestedSustainedSeconds": args.seconds, "modelApiRequests": 0, "clientArtifacts": str(self.artifacts)}
        self.stop_monitor = threading.Event()
        self.health_samples, self.health_errors = [], []

    def start(self):
        super().start()
        self.proxy.start()

    def stop(self, crash=False):
        try:
            self.proxy.stop()
        finally:
            super().stop(crash)

    def sources_match(self):
        return bool(self.inputs) and all(self.repo in (self.repo / item["path"]).resolve().parents
            and runner.digest((self.repo / item["path"]).read_bytes()) == item["sha256"] for item in self.inputs)

    def crypto(self, *arguments):
        return subprocess.run(["openssl", *arguments], check=True, capture_output=True, timeout=15).stdout

    def monitor(self):
        while not self.stop_monitor.is_set():
            try:
                session = runner.Session(self.port, (self.root / "token").read_bytes().strip())
                try:
                    self.health_samples.append({"enforcing": session.health["enforcing"],
                        "active": session.health["activeLeaseCount"]})
                finally:
                    session.close()
            except Exception as error:
                self.health_errors.append(type(error).__name__ + ": " + str(error))
            self.stop_monitor.wait(.1)

    def run(self):
        cert, key = self.root / "server.crt", self.root / "server.key"
        pfx, signing = self.artifacts / "server.pfx", self.artifacts / "delegation.pem"
        self.crypto("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
            "-out", str(cert), "-days", "1", "-subj", "/CN=SPLAT local stress",
            "-addext", "subjectAltName=IP:127.0.0.1")
        self.crypto("pkcs12", "-export", "-out", str(pfx), "-inkey", str(key), "-in", str(cert), "-passout", "pass:")
        self.crypto("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(signing))
        settings = {"certificateSha256": runner.digest(self.crypto("x509", "-in", str(cert), "-outform", "DER")),
            "delegationPublicKey": base64.b64encode(self.crypto("pkey", "-in", str(signing), "-pubout", "-outform", "DER")).decode()}
        (self.artifacts / "settings.json").write_text(json.dumps(settings))
        environment = dict(os.environ)
        environment["SPLAT_AGENT_TOKEN"] = (self.root / "token").read_text().strip()
        environment["WSLENV"] = ":".join(filter(None, [environment.get("WSLENV"), "SPLAT_AGENT_TOKEN/w"]))
        monitor = threading.Thread(target=self.monitor, daemon=True)
        monitor.start()
        try:
            with open(self.artifacts / "client.stdout.txt", "w") as stdout, open(self.artifacts / "client.stderr.txt", "w") as stderr:
                result = subprocess.run([str(self.args.windows_python), windows_path(self.client),
                    "--exe", windows_path(self.args.mcp_exe), "--directory", windows_path(self.artifacts),
                    "--contract", windows_path(self.args.contract), "--seconds", str(self.args.seconds)],
                    env=environment, stdout=stdout, stderr=stderr, text=True, timeout=270)
            client = json.loads((self.artifacts / "a2a-stress.json").read_text())
            self.observations["client"] = client["observations"]
            self.observations["transportFaults"] = self.proxy.drops
            self.check("two_authenticated_connections_dropped", len(self.proxy.drops) == 2
                and {drop["boundary"] for drop in self.proxy.drops} == {"POLICY_APPLIED", "EXIT"})
            self.checks.update({"client_" + name: value for name, value in client["checks"].items()})
            # Verify evidence even when an independent load category failed; retain the actual failure.
            receipts_path = self.artifacts / "receipts.json"
            receipts = json.loads(receipts_path.read_text())
            verified = 0
            sample = {}
            for identifier, receipt in receipts.items():
                (self.root / "public.der").write_bytes(base64.b64decode(receipt["OutcomePublicKey"], validate=True))
                (self.root / "signature").write_bytes(base64.b64decode(receipt["OutcomeSignature"], validate=True))
                (self.root / "canonical").write_text(receipt["SignedOutcome"])
                self.crypto("dgst", "-sha256", "-verify", str(self.root / "public.der"), "-keyform", "DER",
                    "-signature", str(self.root / "signature"), str(self.root / "canonical"))
                fields = dict(part.split("=", 1) for part in receipt["SignedOutcome"].split("|")[1:])
                self.check("signed_receipts_bind_drain_and_counts", fields["workloadDrained"] == "true"
                    and fields["workspaceRemoved"] == "true" and fields["enforcing"] == "true"
                    and int(fields["counted"]) == receipt["ViolationsCounted"]
                    and int(fields["reported"]) == receipt["ViolationsReported"]
                    and int(fields["uid"]) == receipt["WorkloadUid"])
                self.check("receipted_cgroups_and_workspaces_removed",
                    not Path(receipt["CgroupPath"]).exists() and not Path(receipt["Workspace"]).exists())
                verified += 1
                if len(sample) < 8:
                    sample[identifier] = receipt
            self.observations["receipts"] = {"verified": verified, "archiveSha256": runner.digest(receipts_path.read_bytes()),
                "archiveBytes": receipts_path.stat().st_size, "sample": sample}
            self.check("receipt_archive_nonempty", verified > 0)
            self.check("sources_unchanged", self.sources_match()
                and runner.digest(self.client.read_bytes()) == self.observations["clientSourceSha256"])
        finally:
            self.stop_monitor.set()
            monitor.join(timeout=15)
            # Only keys generated for this run are removed; installed credentials are never touched.
            pfx.unlink(missing_ok=True)
            signing.unlink(missing_ok=True)
            self.observations["health"] = {"samples": len(self.health_samples), "errors": self.health_errors,
                "maximumActiveLeasesObserved": max((s["active"] for s in self.health_samples), default=None),
                "allEnforcing": all(s["enforcing"] for s in self.health_samples)}
        self.check("health_remained_enforcing", len(self.health_samples) > 10 and not self.health_errors
            and all(s["enforcing"] for s in self.health_samples))
        runner.assert_idle()
        # Restart only the temporary proof daemon after load has ended. The original installed
        # service is still restored by the outer runner, including if cache recovery fails here.
        runner.Proof.stop(self)
        runner.Proof.start(self)
        session = self.session()
        self.check("receipt_lookup_advertised_after_daemon_restart", session.health.get("boundReceiptLookup") is True)
        recovered = 0
        for drop in self.proxy.drops:
            receipt = receipts[drop["mission"].replace("-", "")]
            fields = dict(part.split("=", 1) for part in receipt["SignedOutcome"].split("|")[1:])
            request = {"type": "RECEIPT_LOOKUP", "missionId": drop["mission"],
                "executionContext": fields["executionContext"], "executionPolicySha256": fields["executionPolicySha256"]}
            session.send(request)
            response = session.receive()
            self.check("signed_receipt_survives_daemon_restart", response.get("status") == "complete"
                and response["outcome"]["outcomeCanonical"] == receipt["SignedOutcome"]
                and response["outcome"]["outcomeSignature"] == receipt["OutcomeSignature"])
            for changed in (dict(request, executionContext=fields["executionContext"] + " "),
                            dict(request, executionPolicySha256="0" * 64)):
                session.send(changed)
                self.check("receipt_lookup_cannot_cross_binding", session.receive().get("status") == "unavailable")
            recovered += 1
        self.check("both_dropped_receipts_recovered_after_daemon_restart", recovered == 2)
        self.check("no_populated_leases_remain", self.session().health["activeLeaseCount"] == 0)
        self.check("windows_client_passed", result.returncode == 0 and client["verdict"] == "PASS")


def configure(parser):
    parser.add_argument("--mcp-exe", required=True, type=Path)
    parser.add_argument("--build-manifest", required=True, type=Path)
    parser.add_argument("--windows-python", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--client-root", required=True, type=Path)
    parser.add_argument("--seconds", type=int, default=60)


if __name__ == "__main__":
    raise SystemExit(runner.main(A2aStressProof, __file__, configure))
