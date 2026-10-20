#!/usr/bin/env python3
"""Windows HTTPS load client for the packaged SPLAT host; no model or external HTTP calls."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
import uuid

EXTENSION = "urn:splat:a2a:template-lease:v1"


def digest(value):
    return hashlib.sha256(value).hexdigest()


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def message(identifier, skill="read_guest_identity", token=None, immediate=False):
    data = {"skill": skill, "parameters": {}}
    if token is not None:
        data["delegationToken"] = token
    return {"message": {"messageId": identifier, "role": "ROLE_USER", "parts": [{"data": data}]},
            "configuration": {"returnImmediately": immediate}}


class Host:
    def __init__(self, suite, name, manifest, callers, retained=4096, concurrent=4, issuer=None):
        self.suite, self.name, self.callers = suite, name, callers
        self.directory = suite.directory / name
        self.directory.mkdir()
        self.database = self.directory / "ledger.db"
        self.environment = dict(os.environ)
        for key in ("SPLAT_LEDGER_KEY_FILE", "SPLAT_RUN_RECORD_KEY_FILE", "SPLAT_A2A_CERT_PASSWORD",
                    "SPLAT_ALLOW_ANTHROPIC_TEST_REQUESTS", "SPLAT_ALLOW_HOST_TELEMETRY_TO_ANTHROPIC",
                    "SPLAT_RECORD_CORPUS"):
            self.environment.pop(key, None)
        self.environment.update(SPLAT_DB_PATH=str(self.database), SPLAT_DATA_DIR=str(self.directory / "state"))
        manifest = json.loads(json.dumps(manifest))
        manifest["agentId"] = "stress-" + name + "-" + uuid.uuid4().hex[:8]
        contract = self.directory / "contract.json"
        contract.write_text(json.dumps(manifest), encoding="utf-8")
        imported = subprocess.run([str(suite.exe), "import-agent", str(contract)],
            env=self.environment, capture_output=True, text=True, encoding="utf-8-sig",
            timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
        (self.directory / "import.stderr.txt").write_text(imported.stderr, encoding="utf-8")
        suite.check(name + "_imported", imported.returncode == 0)
        approval = json.loads(imported.stdout)
        self.agent, self.version = approval["agentId"], approval["contractSha256"]
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        self.config = {"schemaVersion": 1, "agentId": self.agent, "agentVersion": self.version,
            "port": self.port, "certificateFile": str(suite.directory / "server.pfx"),
            "callers": callers, "maxTasks": retained, "maxConcurrentTasks": concurrent}
        if issuer:
            self.config["delegationIssuers"] = [{"agentId": issuer.agent, "contractSha256": issuer.version,
                                               "publicKey": suite.settings["delegationPublicKey"]}]
        else:
            self.config["delegationKeyFile"] = str(suite.directory / "delegation.pem")
        self.config_path = self.directory / "configuration.json"
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        self.process = None
        self.logs = []
        suite.hosts.append(self)
        self.start()

    def start(self):
        index = len(self.logs)
        stdout = open(self.directory / f"host-{index}.stdout.txt", "wb")
        stderr = open(self.directory / f"host-{index}.stderr.txt", "wb")
        self.logs.extend([stdout, stderr])
        self.process = subprocess.Popen([str(self.suite.exe), "a2a", "--configuration", str(self.config_path)],
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=self.environment,
            creationflags=subprocess.CREATE_NO_WINDOW)
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(self.name + " host exited; inspect its private stderr")
            try:
                if self.request(self.suite.tokens[0], method="GET", path="/.well-known/agent-card.json")[0] in (200, 401, 403):
                    return
            except (OSError, TimeoutError):
                pass
            time.sleep(.1)
        raise TimeoutError(self.name + " HTTPS startup")

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)
        for log in self.logs:
            log.close()

    def request(self, token, body=None, method="POST", path="/a2a", extra=None):
        # Pin the exact ephemeral certificate before transmitting a bearer credential.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = http.client.HTTPSConnection("127.0.0.1", self.port, context=context, timeout=25)
        started = time.monotonic()
        try:
            connection.connect()
            if digest(connection.sock.getpeercert(binary_form=True)) != self.suite.settings["certificateSha256"]:
                raise RuntimeError("HTTPS certificate differs from the selected proof certificate")
            headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json",
                       "A2A-Version": "1.0", "A2A-Extensions": EXTENSION}
            headers.update(extra or {})
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise RuntimeError("Unexpected response above the probe's 2 MiB bound")
            value = json.loads(data)
            with self.suite.lock:
                self.suite.http_status[response.status] = self.suite.http_status.get(response.status, 0) + 1
                self.suite.latencies.append((time.monotonic() - started) * 1000)
            return response.status, value
        finally:
            connection.close()

    def rpc(self, caller, method, parameters):
        body = json.dumps({"jsonrpc": "2.0", "id": uuid.uuid4().hex, "method": method, "params": parameters})
        return self.request(self.suite.tokens[caller], body.encode())

    def records(self):
        with sqlite3.connect("file:" + self.database.as_posix() + "?mode=ro", uri=True) as db:
            return [json.loads(row[0]) for row in db.execute("SELECT RecordJson FROM A2aTasks")]


class Suite:
    def __init__(self, args):
        self.directory, self.exe = args.directory.resolve(), args.exe.resolve()
        self.settings = json.loads((self.directory / "settings.json").read_text())
        self.seconds = args.seconds
        self.checks, self.observations, self.receipts = {}, {}, {}
        self.hosts, self.latencies, self.http_status = [], [], {}
        self.lock = threading.RLock()
        self.tokens = [uuid.uuid4().hex + uuid.uuid4().hex for _ in range(4)]
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        self.callers = [{"tenantId": "tenant-a" if i < 3 else "tenant-b",
            "callerId": "caller-" + str(i if i < 3 else 0), "tokenSha256": digest(token.encode()),
            "skills": ["read_guest_identity", "narrow_read"], "expiresUtc": expiry,
            "maxConcurrentTasks": 2, "maxRetainedTasks": 1024} for i, token in enumerate(self.tokens)]
        self.original = json.loads(args.contract.read_text())
        narrow = json.loads(json.dumps(self.original["tools"][0]))
        narrow["name"] = "narrow_read"
        narrow["executionPolicy"]["fileGrants"] = [
            g for g in narrow["executionPolicy"]["fileGrants"] if g["path"] != "/proc/meminfo"]
        self.original["tools"].append(narrow)

    def check(self, name, value):
        with self.lock:
            self.checks[name] = self.checks.get(name, True) and bool(value)
        if not value:
            raise AssertionError(name)

    def phase(self, name, function):
        started = time.monotonic()
        try:
            function()
        except Exception as error:
            self.checks[name + "_finished"] = False
            self.observations[name + "Error"] = type(error).__name__ + ": " + str(error)
        else:
            self.checks[name + "_finished"] = True
        self.observations[name + "Seconds"] = round(time.monotonic() - started, 3)

    def task(self, reply):
        self.check("successful_rpc_envelope", reply[0] == 200 and "result" in reply[1])
        return reply[1]["result"]["task"]

    def record(self, host, caller, task, expected="TASK_STATE_COMPLETED", delegated=None, optional=False):
        self.check("expected_task_states", task["status"]["state"] == expected)
        text = "\n".join(part.get("text", "") for artifact in task.get("artifacts", []) for part in artifact["parts"])
        leases = [json.loads(line)["agentLease"] for line in text.splitlines() if line.startswith('{"agentLease":')]
        if optional and not leases:
            return False
        self.check("one_receipt_per_executed_task", len(leases) == 1)
        lease = leases[0]
        self.check("enforcing_private_drained_receipts", lease["Enforcing"] and lease["Jailed"]
            and lease["WorkloadUid"] >= 65536 and lease["WorkloadDrained"] and lease["WorkspaceRemoved"])
        fields = dict(part.split("=", 1) for part in lease["SignedOutcome"].split("|")[1:])
        context = json.loads(fields["executionContext"])
        principal = self.callers[caller]
        self.check("receipts_bind_actual_principal", context["agentId"] == host.agent
            and context["contractSha256"] == host.version and context["taskId"] == task["id"]
            and context["tenantId"] == principal["tenantId"] and context["callerId"] == principal["callerId"]
            and fields["executionPolicySha256"] == lease["ExecutionPolicySha256"]
            and fields["effectivePolicySha256"] == lease["EffectivePolicySha256"])
        if delegated:
            self.check("receipts_bind_delegation", context["delegationSha256"] == digest(delegated.encode())
                and context["requestingAgentId"] == self.parent.agent
                and context["requestingContractSha256"] == self.parent.version)
        with self.lock:
            previous = self.receipts.get(task["id"])
            self.check("retries_preserve_receipt", previous is None or previous == lease)
            self.receipts[task["id"]] = lease
        return True

    def grant(self, caller=0, skill="read_guest_identity"):
        parent = self.task(self.parent.rpc(caller, "SendMessage", message(uuid.uuid4().hex)))
        self.record(self.parent, caller, parent)
        reply = self.parent.rpc(caller, "splat/DelegateTask", {"parentTaskId": parent["id"],
            "audience": self.worker.agent, "audienceVersion": self.worker.version,
            "callerId": self.callers[caller]["callerId"], "skill": skill})
        self.check("delegation_issued", reply[0] == 200 and "result" in reply[1])
        return reply[1]["result"]["delegationToken"]

    @staticmethod
    def parallel(count, function):
        barrier = threading.Barrier(count)
        def started(index):
            barrier.wait(timeout=10)
            return function(index)
        with ThreadPoolExecutor(max_workers=count) as pool:
            return list(pool.map(started, range(count)))

    def retry_races(self):
        identifier = uuid.uuid4().hex
        replies = self.parallel(16, lambda _: self.parent.rpc(0, "SendMessage", message(identifier)))
        tasks = [self.task(reply) for reply in replies]
        self.check("concurrent_retry_one_task", len({task["id"] for task in tasks}) == 1)
        for task in tasks:
            self.record(self.parent, 0, task)
        records = [r for r in self.parent.records() if r["messageId"] == identifier]
        self.check("concurrent_retry_one_persisted_task", len(records) == 1)
        changed = message(identifier, "narrow_read")
        reply = self.parent.rpc(0, "SendMessage", changed)
        self.check("retry_cannot_change_request", reply[1].get("error", {}).get("code") == -32602)
        self.parent.stop()
        self.parent.start()
        restarted = self.task(self.parent.rpc(0, "SendMessage", message(identifier)))
        self.check("restart_preserves_idempotency", restarted["id"] == tasks[0]["id"])
        self.record(self.parent, 0, restarted)
        self.observations["retryRace"] = {"simultaneousRequests": 16, "persistedTasks": len(records)}

    def delegation_races(self):
        grant = self.grant()
        ids = [uuid.uuid4().hex for _ in range(16)]
        replies = self.parallel(16, lambda i: self.worker.rpc(0, "SendMessage", message(ids[i], token=grant)))
        accepted = [self.task(reply) for reply in replies if "result" in reply[1]]
        self.check("concurrent_delegation_one_consumer", len(accepted) == 1)
        self.check("replay_denials_are_explicit", all(reply[0] in (200, 403, 429) for reply in replies))
        self.record(self.worker, 0, accepted[0], delegated=grant)
        self.worker.stop()
        self.worker.start()
        reply = self.worker.rpc(0, "SendMessage", message(uuid.uuid4().hex, token=grant))
        self.check("restart_preserves_nonce_consumption", reply[0] == 403)
        scope_grant = self.grant()
        for caller in (1, 3):
            # An already-spent nonce would mask a broken caller/tenant binding check.
            reply = self.worker.rpc(caller, "SendMessage", message(uuid.uuid4().hex, token=scope_grant))
            self.check("delegation_cannot_cross_principal", reply[0] == 403)
        scoped = self.task(self.worker.rpc(0, "SendMessage", message(uuid.uuid4().hex, token=scope_grant)))
        self.record(self.worker, 0, scoped, delegated=scope_grant)
        self.check("scope_refusals_leave_valid_grant_usable", scoped["status"]["state"] == "TASK_STATE_COMPLETED")
        narrowed = self.grant(skill="narrow_read")
        task = self.task(self.worker.rpc(0, "SendMessage", message(uuid.uuid4().hex, "narrow_read", narrowed)))
        self.record(self.worker, 0, task, expected="TASK_STATE_FAILED", delegated=narrowed)
        self.check("narrowed_file_read_refused", "Permission denied" in str(task))
        payload, signature = self.grant().split(".")
        decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        decoded["authority"]["allowNetwork"] = True
        tampered = base64.urlsafe_b64encode(json.dumps(decoded).encode()).decode().rstrip("=") + "." + signature
        self.check("altered_authority_refused", self.worker.rpc(0, "SendMessage",
            message(uuid.uuid4().hex, token=tampered))[0] == 403)
        self.observations["delegationRace"] = {"simultaneousUses": 16, "accepted": len(accepted),
            "httpStatuses": [status for status, _ in replies]}

    def isolation_and_input(self):
        task = self.task(self.parent.rpc(0, "SendMessage", message(uuid.uuid4().hex)))
        self.record(self.parent, 0, task)
        def outsider(index):
            caller = 1 if index % 2 else 3
            return self.parent.rpc(caller, "GetTask" if index % 4 < 2 else "CancelTask", {"id": task["id"]})
        replies = self.parallel(16, outsider)
        self.check("cross_caller_and_tenant_denied", all(r[1].get("error", {}).get("code") == -32001 for r in replies))
        self.check("invalid_bearer_refused", self.parent.request("0" * 64, b"{}")[0] == 401)
        self.check("browser_origin_refused", self.parent.request(self.tokens[0], b"{}", extra={"Origin": "https://invalid.example"})[0] == 403)
        self.check("oversized_body_refused", self.parent.request(self.tokens[0], b" " * 65537)[0] == 413)
        duplicate = b'{"jsonrpc":"2.0","id":1,"id":2,"method":"GetTask","params":{}}'
        self.check("duplicate_json_refused", self.parent.request(self.tokens[0], duplicate)[1]["error"]["code"] == -32602)
        forged = message(uuid.uuid4().hex)
        forged["message"]["parts"][0]["data"]["parentTaskId"] = task["id"]
        self.check("bare_parent_id_is_not_authority", self.worker.rpc(0, "SendMessage", forged)[0] == 403)
        self.check("generic_escape_tool_refused", self.parent.rpc(0, "SendMessage",
            message(uuid.uuid4().hex, "run_command"))[0] == 403)

    def sustained(self):
        started = time.monotonic()
        deadline = started + self.seconds
        def caller_loop(caller):
            completed = errors = 0
            while time.monotonic() < deadline and completed + errors < 128:
                iteration = time.monotonic()
                grant = self.grant(caller)
                reply = self.worker.rpc(caller, "SendMessage", message(uuid.uuid4().hex, token=grant))
                if "result" in reply[1]:
                    self.record(self.worker, caller, self.task(reply), delegated=grant)
                    completed += 1
                else:
                    errors += 1
                # Bound retained evidence and CPU while maintaining four independent active callers.
                time.sleep(max(0, .5 - (time.monotonic() - iteration)))
            return {"caller": caller, "delegatedCompleted": completed, "refused": errors}
        results = self.parallel(4, caller_loop)
        elapsed = time.monotonic() - started
        self.observations["sustained"] = {"requestedSeconds": self.seconds, "elapsedSeconds": elapsed,
            "callers": results, "pairLimitPerCaller": 128, "minimumIterationSeconds": .5}
        self.check("sustained_duration_exercised", elapsed >= self.seconds)
        self.check("sustained_each_caller_progressed", all(r["delegatedCompleted"] >= 5 and r["refused"] == 0 for r in results))

    def cancellations(self):
        outcomes = {"confirmedCanceled": 0, "unconfirmedCanceled": 0, "completedBeforeCancel": 0}
        for index in range(24):
            task = self.task(self.parent.rpc(0, "SendMessage", message(uuid.uuid4().hex, immediate=True)))
            time.sleep((0, .002, .01, .03, .08, .15)[index % 6])
            status, reply = self.parent.rpc(0, "CancelTask", {"id": task["id"]})
            if "error" in reply:
                self.check("cancel_terminal_race_explicit", reply["error"]["code"] == -32002)
                task = self.parent.rpc(0, "GetTask", {"id": task["id"]})[1]["result"]
            else:
                self.check("cancel_response_success", status == 200)
                task = reply["result"]
            state = task["status"]["state"]
            if state == "TASK_STATE_COMPLETED":
                outcomes["completedBeforeCancel"] += 1
                self.record(self.parent, 0, task)
            else:
                self.check("cancel_terminal_state", state == "TASK_STATE_CANCELED")
                confirmed = task["metadata"][EXTENSION]["workloadTerminationConfirmed"]
                outcomes["confirmedCanceled" if confirmed else "unconfirmedCanceled"] += 1
                receipt = self.record(self.parent, 0, task, expected=state, optional=not confirmed)
                self.check("cancel_drain_claim_has_receipt", not confirmed or receipt)
        self.observations["cancellationRaces"] = outcomes
        self.check("active_cancellation_exercised", outcomes["confirmedCanceled"] > 0)

    def quotas(self):
        callers = [dict(c, maxConcurrentTasks=1, maxRetainedTasks=2) for c in self.callers[:3]]
        host = Host(self, "quota", self.original, callers, retained=6, concurrent=2)
        ids = [uuid.uuid4().hex for _ in range(2)]
        for identifier in ids:
            self.record(host, 0, self.task(host.rpc(0, "SendMessage", message(identifier))))
        # Caller A's retained quota is full; B must still progress during A's rejected burst.
        replies = self.parallel(16, lambda i: host.rpc(1 if i == 15 else 0, "SendMessage", message(uuid.uuid4().hex)))
        self.check("retained_quota_burst_refused", all(status == 429 for status, _ in replies[:15]))
        self.record(host, 1, self.task(replies[15]))
        self.check("quota_did_not_consume_extra_slots", len(host.records()) == 3)
        self.record(host, 1, self.task(host.rpc(1, "SendMessage", message(uuid.uuid4().hex))))
        for _ in range(2):
            self.record(host, 2, self.task(host.rpc(2, "SendMessage", message(uuid.uuid4().hex))))
        self.check("global_retained_capacity_refused", host.rpc(0, "SendMessage", message(uuid.uuid4().hex))[0] == 429)
        host.stop()
        host.start()
        self.check("restart_does_not_reset_quotas", host.rpc(0, "SendMessage", message(uuid.uuid4().hex))[0] == 429)
        self.record(host, 0, self.task(host.rpc(0, "SendMessage", message(ids[0]))))
        self.observations["retainedCapacity"] = {"configured": 6, "persisted": len(host.records()),
            "newTasksRefusedAfterCompletionAndRestart": True}

    def running_quotas(self):
        callers = [dict(c, maxConcurrentTasks=1, maxRetainedTasks=128) for c in self.callers[:2]]
        host = Host(self, "running", self.original, callers, retained=256, concurrent=2)
        stop = threading.Event()
        samples, errors = [], []
        def observe():
            while not stop.is_set():
                try:
                    records = [r for r in host.records() if r["state"] == "TASK_STATE_WORKING"]
                    samples.append([sum(r["callerId"] == self.callers[i]["callerId"] for r in records) for i in range(2)])
                except Exception as error:
                    errors.append(type(error).__name__)
                stop.wait(.005)
        observer = threading.Thread(target=observe, daemon=True)
        observer.start()
        try:
            replies = self.parallel(16, lambda i: host.rpc(1 if i == 15 else 0, "SendMessage", message(uuid.uuid4().hex)))
        finally:
            stop.set()
            observer.join(timeout=10)
        for i, reply in enumerate(replies):
            if "result" in reply[1]:
                self.record(host, 1 if i == 15 else 0, self.task(reply))
        self.check("running_quota_burst_exercised", any(status == 429 for status, _ in replies[:15]))
        self.check("running_quota_preserves_other_caller", "result" in replies[15][1])
        self.check("running_quota_state_never_exceeded", bool(samples) and not errors
            and all(max(row) <= 1 and sum(row) <= 2 for row in samples))
        self.check("running_quota_observed_active_work", any(sum(row) > 0 for row in samples))
        self.observations["runningCapacity"] = {"samples": len(samples), "observedMaximumPerCaller":
            [max(row[i] for row in samples) for i in range(2)], "observedMaximumTotal": max(map(sum, samples)),
            "httpStatuses": [status for status, _ in replies], "observationIntervalMs": 5}

    def revocation(self):
        # An operator writes only this probe's private store; this measures reload, not the admin UI.
        with sqlite3.connect(self.parent.database) as database:
            principals = database.execute("SELECT OperatorIdentity FROM AuditLedger WHERE Action='A2A_TASK_AUTHORIZED'").fetchall()
            principal = next(row[0] for row in principals if "[a2a:tenant-a:caller-0]" in row[0])
            database.execute("INSERT INTO Revocations VALUES (?,?,?,?,?)", (principal, "API_KEY",
                "Synthetic stress revocation", "local-stress-operator", datetime.now(timezone.utc).isoformat()))
        replies = self.parallel(16, lambda i: self.parent.request(self.tokens[0 if i < 8 else 3],
            method="GET", path="/.well-known/agent-card.json"))
        self.check("live_revocation_refuses_burst", all(status == 403 for status, _ in replies[:8]))
        self.check("revocation_preserves_other_tenant", all(status == 200 for status, _ in replies[8:]))
        self.parent.stop()
        self.parent.start()
        self.check("revocation_survives_restart", self.parent.request(self.tokens[0],
            method="GET", path="/.well-known/agent-card.json")[0] == 403)
        self.observations["revocation"] = {"revokedRequests": 8, "otherTenantRequests": 8,
            "scope": "Fresh authorization after an operator change to the private store; no active-workload revocation claim."}

    def run(self):
        self.parent = Host(self, "parent", self.original, self.callers)
        self.worker = Host(self, "worker", self.original,
            [dict(c, requireDelegation=True) for c in self.callers], issuer=self.parent)
        for name in ("retry_races", "delegation_races", "isolation_and_input", "sustained", "cancellations", "running_quotas", "quotas", "revocation"):
            self.phase(name, getattr(self, name))
        for host in self.hosts:
            records = host.records()
            self.check(host.name + "_no_working_tasks", all(r["state"] != "TASK_STATE_WORKING" for r in records))
            with sqlite3.connect("file:" + host.database.as_posix() + "?mode=ro", uri=True) as database:
                facts = database.execute("SELECT Details FROM AuditLedger WHERE Action='MISSION_RUN_FACTS'").fetchall()
                admissions = [row[0].replace("-", "") for row in database.execute(
                    "SELECT MissionId FROM AuditLedger WHERE Action='A2A_TASK_AUTHORIZED'")]
            mission_ids = [json.loads(row[0])["MissionId"].replace("-", "") for row in facts]
            task_ids = {r["id"] for r in records}
            self.check(host.name + "_one_execution_per_task", len(mission_ids) == len(set(mission_ids))
                and set(mission_ids).issubset(task_ids))
            orphaned = sorted(set(admissions) - task_ids)
            # Retain all independent findings when audit consistency fails; never bless the row labels.
            self.checks[host.name + "_admission_audit_matches_tasks"] = not orphaned
            unconfirmed = [r for r in records if r["state"] == "TASK_STATE_CANCELED"
                and not r["workloadTerminationConfirmed"]]
            self.observations[host.name + "Persistence"] = {"tasks": len(records), "sealedRuns": len(facts),
                "databaseBytes": host.database.stat().st_size, "authorizationRows": len(admissions),
                "authorizedWithoutRetainedTask": orphaned,
                "unconfirmedCancellationsWithoutRunFacts": sum(r["id"] not in mission_ids for r in unconfirmed)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=60)
    args = parser.parse_args()
    assert os.name == "nt" and 10 <= args.seconds <= 60
    suite = Suite(args)
    def watchdog():
        for host in suite.hosts:
            host.stop()
        os._exit(124)
    timer = threading.Timer(240, watchdog)
    timer.daemon = True
    timer.start()
    try:
        suite.run()
    except Exception as error:
        suite.checks["suite_finished"] = False
        suite.observations["suiteError"] = type(error).__name__ + ": " + str(error)
    finally:
        for host in suite.hosts:
            host.stop()
        timer.cancel()
        suite.observations["http"] = {"requests": len(suite.latencies), "statuses": suite.http_status,
            "p50Ms": percentile(suite.latencies, .5), "p95Ms": percentile(suite.latencies, .95),
            "maxMs": max(suite.latencies, default=None)}
        suite.observations["receiptCount"] = len(suite.receipts)
        (suite.directory / "receipts.json").write_text(json.dumps(suite.receipts, indent=2), encoding="utf-8")
        report = {"checks": suite.checks, "observations": suite.observations,
                  "verdict": "PASS" if suite.checks and all(suite.checks.values()) else "FAIL"}
        (suite.directory / "a2a-stress.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "checks": len(suite.checks)}))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
