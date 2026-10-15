#!/usr/bin/env python3
"""Drive a published Windows MCP host into a real enforcing guest using saved agent contracts.

The shared root runner owns the temporary daemon and restores the installed service and pins.
Only synthetic manifests/databases are written. The source example reads public guest metadata.
This is a live-host proof, not a clean-machine installer or commercial-license certification.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import uuid

spec = importlib.util.spec_from_file_location("splat_agent_proof_runner", Path(__file__).with_name("probe-secrets.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def windows_path(path):
    return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()


class AgentProof(runner.Proof):
    def __init__(self, args, root):
        super().__init__(args, root)
        # The production host's default endpoint and workspace root are exercised unchanged.
        self.port = 50051
        self.command[self.command.index("--listen") + 1] = "127.0.0.1:50051"
        self.command[self.command.index("--missions-root") + 1] = "/var/lib/splat/missions"
        self.observations = {}
        self.clients = []
        self.artifacts = args.client_root.resolve() / ("agent-proof-" + uuid.uuid4().hex)
        self.artifacts.mkdir(parents=True)

    def invoke(self, arguments, messages=None):
        env = dict(os.environ)
        # The secret travels in the child's private environment, never argv, stdout or evidence.
        env["SPLAT_AGENT_TOKEN"] = (self.root / "token").read_text().strip()
        env["SPLAT_DB_PATH"] = windows_path(self.artifacts / "registry.db")
        env["SPLAT_DATA_DIR"] = windows_path(self.artifacts / "state")
        env["WSLENV"] = ":".join(filter(None, [env.get("WSLENV"), "SPLAT_AGENT_TOKEN/w", "SPLAT_DB_PATH/w", "SPLAT_DATA_DIR/w"]))
        payload = "" if messages is None else "".join(json.dumps(m) + "\n" for m in messages)
        result = subprocess.run([str(self.args.mcp_exe.resolve()), *arguments], input=payload,
            capture_output=True, text=True, encoding="utf-8-sig", timeout=150, env=env)
        # Keep local diagnostics; the report contains only assertions, hashes and public metadata.
        index = len(list(self.artifacts.glob("client-*.stderr.txt")))
        (self.artifacts / f"client-{index}.stderr.txt").write_text(result.stderr)
        (self.artifacts / f"client-{index}.stdout.jsonl").write_text(result.stdout)
        return result

    def imported(self, manifest, suffix):
        manifest = copy.deepcopy(manifest)
        manifest["agentId"] = "proof-" + uuid.uuid4().hex
        path = self.artifacts / f"{suffix}.json"
        path.write_text(json.dumps(manifest))
        result = self.invoke(["import-agent", windows_path(path)])
        self.check(suffix + "_imported", result.returncode == 0)
        approval = json.loads(result.stdout)
        self.check(suffix + "_version_recorded", len(approval["contractSha256"]) == 64)
        return ["--agent", approval["agentId"], "--agent-version", approval["contractSha256"]], approval

    @staticmethod
    def call(number, name, arguments=None):
        return {"jsonrpc": "2.0", "id": number, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}}}

    @staticmethod
    def text(message):
        return "\n".join(item.get("text", "") for item in message.get("result", {}).get("content", []))

    def conversation(self, arguments, messages):
        result = self.invoke(arguments, messages)
        self.check("client_exited_" + str(len(self.clients)), result.returncode == 0)
        self.clients.append(result.returncode)
        return {row["id"]: row for row in map(json.loads, result.stdout.splitlines()) if "id" in row}

    def run(self):
        executable = self.args.mcp_exe.resolve(strict=True)
        initial_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
        build_path = executable.with_name("MCP-BUILD-MANIFEST.json")
        build = json.loads(build_path.read_text(encoding="utf-8-sig"))
        self.check("published_host_matches_build_manifest", build["sha256"] == initial_hash)
        self.check("daemon_matches_published_embedded_payload", build["daemonSha256"]
            == hashlib.sha256(self.args.daemon.read_bytes()).hexdigest())
        repository = Path(__file__).resolve().parents[2]
        compiled_inputs = [item for item in build["sourceInputs"]
            if Path(item["path"]).suffix in (".cs", ".csproj", ".rs", ".c", ".h", ".toml", ".lock")]

        def sources_match():
            return bool(compiled_inputs) and all(repository in (repository / item["path"]).resolve().parents
                and hashlib.sha256((repository / item["path"]).read_bytes()).hexdigest() == item["sha256"]
                for item in compiled_inputs)

        self.check("published_compiled_sources_match_checkout", sources_match())
        self.observations["mcpExecutableSha256"] = initial_hash
        self.observations["mcpBuildManifestSha256"] = hashlib.sha256(build_path.read_bytes()).hexdigest()
        self.observations["artifactLicenseLabel"] = build["license"]
        self.observations["compiledSourceInputs"] = compiled_inputs
        self.observations["clientArtifacts"] = str(self.artifacts)
        self.check("real_daemon_enforcing", self.session().health.get("enforcing") is True)
        original = json.loads(self.args.manifest.read_text())
        name = original["tools"][0]["name"]
        arguments, approval = self.imported(original, "allowed")
        calls = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, self.call(3, name)]
        escapes = ["run_command", "run_code", "fs_read", "fs_write", "diagnose_system",
            "investigate_system", "run_agent_brain", "run_governed_crew"]
        for index, tool in enumerate(escapes, 10):
            calls.append(self.call(index, tool, {"command": "/bin/sh", "args": ["-c", "exit 99"],
                "code": "raise SystemExit(99)", "templateId": "linux-disk-usage"}))
        calls.append(self.call(30, name, {"command": "/bin/sh", "allowNetwork": True}))
        responses = self.conversation(arguments, calls)
        self.check("only_approved_tools_advertised", [tool["name"] for tool in responses[2]["result"]["tools"]]
            == [tool["name"] for tool in original["tools"]])
        self.check("approved_tool_succeeded", responses[3]["result"]["isError"] is False)
        output = self.text(responses[3])
        self.check("declared_guest_read_completed", "MemTotal:" in output and "PRETTY_NAME=" in output)
        self.check("contract_version_in_receipt", approval["contractSha256"] in output)
        lease = next(json.loads(line)["agentLease"] for line in output.splitlines() if line.startswith('{"agentLease":'))
        self.check("enforcing_jail_observed", lease["Enforcing"] is True and lease["Jailed"] is True)
        self.check("policy_installation_acknowledged", len(lease["ExecutionPolicySha256"]) == 64)
        self.check("lease_has_private_unprivileged_identity", lease["WorkloadUid"] > 65535)
        self.check("successful_workspace_removed", lease["WorkspaceRemoved"] is True)
        self.observations["allowedLease"] = {key: lease[key] for key in
            ("CgroupId", "WorkloadUid", "Enforcing", "Jailed", "WorkspaceRemoved", "ExecutionPolicySha256")}
        for index, tool in enumerate(escapes, 10):
            text = self.text(responses[index])
            self.check(tool + "_cannot_bypass_manifest", responses[index]["result"]["isError"] is True
                and "outside the host" in text and "Process Exited" not in text)
        self.check("caller_cannot_rewrite_contract", responses[30]["result"]["isError"] is True
            and "Process Exited" not in self.text(responses[30]))
        wrong = arguments[:-1] + ["0" * 64]
        result = self.invoke(wrong, [self.call(1, name)])
        self.check("wrong_contract_version_refused_at_startup", result.returncode == 2 and not result.stdout.strip())

        for variant in ("file", "syscall", "exec", "network"):
            manifest = copy.deepcopy(original)
            policy = manifest["tools"][0]["executionPolicy"]
            if variant == "file":
                policy["fileGrants"] = [grant for grant in policy["fileGrants"] if grant["path"] != "/proc/meminfo"]
            elif variant == "syscall":
                policy["syscalls"] = [call for call in policy["syscalls"] if call != "openat"]
            elif variant == "exec":
                for grant in policy["fileGrants"]:
                    if grant["path"].endswith("/cat"):
                        grant["access"] = ["read"]
            else:
                policy["syscalls"].append("socket")
            bound, _ = self.imported(manifest, variant)
            response = self.conversation(bound, [self.call(1, name)])[1]
            text = self.text(response)
            self.check(variant + "_restriction_refused_operation", response["result"]["isError"] is True
                and "MemTotal:" not in text)
            if variant == "file":
                self.check("landlock_denial_came_from_running_tool", "Permission denied" in text and '"agentLease":' in text)
            if variant == "network":
                self.check("offline_contract_rejects_network_syscall", "network syscall socket conflicts" in text)
        self.check("client_binary_unchanged", hashlib.sha256(executable.read_bytes()).hexdigest() == initial_hash)
        self.check("published_compiled_sources_unchanged", sources_match())
        runner.assert_idle()
        self.check("no_populated_lease_after_calls", True)
        self.observations["scope"] = "Published Windows MCP import/binding -> authenticated real daemon -> file/syscall/exec controls; network contract admission refusal. Lifecycle is a separate probe."


def configure(parser):
    parser.add_argument("--mcp-exe", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--client-root", required=True, type=Path)


if __name__ == "__main__":
    raise SystemExit(runner.main(AgentProof, __file__, configure))
