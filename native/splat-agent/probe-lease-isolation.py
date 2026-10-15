#!/usr/bin/env python3
"""Root proof of ordinary sibling-lease signal and procfs isolation, using synthetic files only.

Usage: sudo python3 probe-lease-isolation.py --daemon /absolute/splat-agent --output evidence/lease-isolation.json
The shared runner owns its test daemon, refuses active leases, and restores the installed service.
A failure records the tested operations; a pass makes no claim about untested IPC or procfs paths.
"""
import errno
import importlib.util
import json
from pathlib import Path


spec = importlib.util.spec_from_file_location("splat_probe_runner", Path(__file__).with_name("probe-secrets.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


TARGET = r'''
import grp, json, os, pwd, signal, time
from pathlib import Path
value = 'synthetic-sibling-workspace'
Path('marker').write_text(value)
marker = open('marker')
seen = []
signal.signal(signal.SIGUSR1, lambda signum, frame: seen.append(signum))
signal.signal(signal.SIGCONT, lambda signum, frame: seen.append(signum))
print(json.dumps({'pid': os.getpid(), 'uid': os.getuid(), 'fd': marker.fileno(),
    'nss_identity': pwd.getpwuid(os.getuid()).pw_gid == os.getgid() and grp.getgrgid(os.getgid()).gr_gid == os.getgid(),
    'own_marker': Path('/proc/self/cwd/marker').read_text() == value}), flush=True)
deadline = time.monotonic() + 20
while not Path('stop').exists() and time.monotonic() < deadline:
    time.sleep(0.02)
print(json.dumps({'signals_received': len(seen), 'stopped': Path('stop').exists()}), flush=True)
'''


ATTACKER = r'''
import json, os, signal, sys
from pathlib import Path
target = json.loads(sys.argv[1])
results = {}
def attempt(name, operation):
    try:
        value = operation()
        results[name] = {'allowed': True, 'synthetic_value': value == 'synthetic-sibling-workspace'}
    except OSError as error:
        results[name] = {'allowed': False, 'errno': error.errno}

# Successful same-lease controls distinguish isolation from a broken interpreter or proc mount.
Path('own-marker').write_text('own')
results['own_workspace'] = Path('/proc/self/cwd/own-marker').read_text() == 'own'
read_fd, write_fd = os.pipe()
child = os.fork()
if child == 0:
    os.close(write_fd)
    os.read(read_fd, 1)
    os._exit(0)
os.close(read_fd)
try:
    os.kill(child, 0)
    results['own_child_signal'] = True
finally:
    os.write(write_fd, b'x')
    os.close(write_fd)
    os.waitpid(child, 0)

pid = target['pid']
attempt('sibling_signal', lambda: os.kill(pid, signal.SIGUSR1))
attempt('sibling_continue', lambda: os.kill(pid, signal.SIGCONT))
attempt('sibling_cwd', lambda: os.readlink('/proc/%d/cwd' % pid))
attempt('sibling_workspace', lambda: Path('/proc/%d/cwd/marker' % pid).read_text())
attempt('sibling_root_workspace', lambda: Path('/proc/%d/root%s/marker' % (pid, target['workspace'])).read_text())
attempt('sibling_descriptor', lambda: Path('/proc/%d/fd/%d' % (pid, target['fd'])).read_text())
print(json.dumps(results), flush=True)
'''


class IsolationProof(runner.Proof):
    """Exercise two ordinary enforcing leases; preserve signed wire checks and service restoration."""

    def __init__(self, args, root):
        super().__init__(args, root)
        # Ordinary isolation is mandatory even when the opt-in secret broker is disabled.
        index = self.command.index('--secret-socket')
        del self.command[index:index + 2]

    def request(self, label, program, duration=30):
        request = super().request(label, program, duration)
        request['overlayFs'] = {'enableCow': False}
        return request

    def ready(self, session, label='target'):
        lease = session.receive()
        self.check(label + '_has_enforcing_jail', lease.get('type') == 'LEASE'
            and lease.get('enforcing') is True and lease.get('jailed') is True)
        output = ''
        while '\n' not in output:
            frame = session.receive()
            assert frame['type'] != 'EXIT', 'target exited before its positive control'
            if frame['type'] == 'STDOUT':
                output += frame['data']
            assert len(output) <= 4096, 'oversized target control'
        return lease, json.loads(output)

    def run(self):
        self.observations = {}
        target, attacker = self.session(), self.session()
        self.check('daemon_enforcing', target.health.get('enforcing') is True)
        target_request = self.request('isolation-target', TARGET)
        target.send(target_request)
        target_lease, identity = self.ready(target)
        self.check('target_reads_own_workspace', identity.get('own_marker') is True)
        self.check('private_identity_resolves_in_jail', identity.get('nss_identity') is True)
        procs = Path(target_lease['cgroupPath']) / 'cgroup.procs'
        self.check('target_pid_in_its_cgroup', str(identity['pid']) in procs.read_text().split())
        identity['workspace'] = target_request['workingDirectory']
        attack_request = self.request('isolation-attacker', ATTACKER)
        attack_request['argv'].append(json.dumps(identity))
        attacker.send(attack_request)
        frames = attacker.collect()
        self.check('attacker_completed', frames[-1].get('exitCode') == 0)
        attacker_lease = next(frame for frame in frames if frame['type'] == 'LEASE')
        self.check('distinct_enforcing_cgroups', attacker_lease.get('enforcing') is True
            and attacker_lease.get('jailed') is True
            and attacker_lease['cgroupId'] != target_lease['cgroupId'])
        self.check('distinct_private_uids', attacker_lease['workloadUid'] != target_lease['workloadUid']
            and min(attacker_lease['workloadUid'], target_lease['workloadUid']) >= 65536)
        self.check('target_alive_during_attempts', str(identity['pid']) in procs.read_text().split())
        result = json.loads(''.join(frame['data'] for frame in frames if frame['type'] == 'STDOUT'))
        self.observations.update(targetUid=target_lease['workloadUid'],
            attackerUid=attacker_lease['workloadUid'], operations=result)
        self.check('attacker_reads_own_workspace', result.get('own_workspace') is True)
        self.check('attacker_signals_own_child', result.get('own_child_signal') is True)
        # Complete both leases before scoring refusals so a regression still produces all evidence
        # and restores the service. ESRCH/ENOENT cannot count as isolation: the target was alive.
        Path(target_request['workingDirectory'], 'stop').write_text('synthetic-control')
        target_frames = target.collect()
        self.check('target_completed', target_frames[-1].get('exitCode') == 0)
        observed = json.loads(''.join(frame['data'] for frame in target_frames if frame['type'] == 'STDOUT'))
        self.observations['target'] = observed
        self.check('target_received_stop_control', observed.get('stopped') is True)
        self.check('both_workspaces_removed', self.wait_removed(target_request) and self.wait_removed(attack_request))
        for name in ('sibling_signal', 'sibling_continue', 'sibling_cwd', 'sibling_workspace', 'sibling_root_workspace', 'sibling_descriptor'):
            operation = result[name]
            self.checks[name + '_denied'] = operation.get('allowed') is False \
                and operation.get('errno') in (errno.EPERM, errno.EACCES)
        self.checks['target_received_no_sibling_signal'] = observed.get('signals_received') == 0
        assert all(self.checks.values()), 'ordinary sibling lease isolation failed; see recorded operations'
        self.lifecycle()

    def lifecycle(self):
        # The shared runner reserves four identities. Exhaustion must refuse before filesystem
        # effects; after all four drain, a later ordinary lease must be able to use the pool again.
        active = []
        for index in range(4):
            session = self.session()
            request = self.request('identity-capacity-' + str(index), TARGET)
            session.send(request)
            lease, identity = self.ready(session, 'capacity_' + str(index))
            active.append((session, request, lease))
        uids = {lease['workloadUid'] for _, _, lease in active}
        self.check('capacity_holders_have_distinct_uids', len(uids) == 4)
        extra = self.session()
        refused = self.request('identity-capacity-refused', 'pass')
        self.check('identity_exhaustion_refuses_without_fallback', self.refused(extra, refused))
        self.check('identity_exhaustion_has_no_workspace_effect', not Path(refused['workingDirectory']).exists())
        for session, request, _ in active:
            Path(request['workingDirectory'], 'stop').write_text('synthetic-control')
            self.check(request['missionId'] + '_drained', session.collect()[-1].get('exitCode') == 0
                and self.wait_removed(request))
        frames = self.completed(extra, self.request('identity-reuse', 'pass'))
        self.check('drained_identity_reused', next(frame for frame in frames if frame['type'] == 'LEASE')['workloadUid'] in uids)

        expired = self.request('identity-expiry', 'import time; time.sleep(60)', duration=5)
        extra.send(expired)
        self.check('expiry_drains_and_removes_workspace', extra.collect()[-1].get('exitCode') != 0
            and self.wait_removed(expired))
        self.check('identity_available_after_expiry', bool(self.completed(extra, self.request('identity-after-expiry', 'pass'))))

        failed = self.request('identity-spawn-failure', 'pass')
        failed.update(command='/etc/hostname', argv=[], allowedExecPaths=['/etc/hostname'])
        self.check('spawn_failure_cleans_workspace', self.spawn_failure(extra, failed))
        self.check('identity_available_after_spawn_failure', bool(self.completed(extra, self.request('identity-after-failure', 'pass'))))

        disconnected = self.session()
        abandoned = self.request('identity-disconnect', '''
import json, os, time
child = os.fork()
if child == 0:
    time.sleep(60)
    os._exit(0)
print(json.dumps({'pid': os.getpid(), 'child': child}), flush=True)
time.sleep(60)
''')
        disconnected.send(abandoned)
        lease, processes = self.ready(disconnected, 'disconnect')
        members = (Path(lease['cgroupPath']) / 'cgroup.procs').read_text().split()
        self.check('disconnect_descendant_is_in_lease', all(str(pid) in members for pid in processes.values()))
        disconnected.close()
        self.check('disconnect_drains_descendants_and_workspace', self.wait_removed(abandoned))
        self.check('identity_available_after_disconnect', bool(self.completed(extra, self.request('identity-after-disconnect', 'pass'))))

        queued = [self.request('identity-pipeline-' + str(index), 'import time; time.sleep(0.1)') for index in range(2)]
        for request in queued:
            extra.send(request)
        self.check('ordinary_pipelining_preserves_both_requests', all(extra.collect()[-1].get('exitCode') == 0 for _ in queued))
        self.check('pipelined_workspaces_removed', all(self.wait_removed(request) for request in queued))

        crashed = self.request('identity-crash', TARGET)
        extra.send(crashed)
        self.ready(extra, 'crash')
        self.stop(crash=True)
        self.start()
        self.check('restart_drains_orphan_and_removes_workspace', self.wait_removed(crashed))
        fresh = self.session()
        self.check('restart_enforces', fresh.health.get('enforcing') is True)
        self.check('identity_available_after_restart', bool(self.completed(fresh, self.request('identity-after-restart', 'pass'))))

    def spawn_failure(self, session, request):
        session.send(request)
        return session.collect()[-1].get('exitCode') == -1 and self.wait_removed(request)


if __name__ == '__main__':
    raise SystemExit(runner.main(IsolationProof, __file__))
