"""Offline regressions. Kernel observations are simulated, never claimed as native proof.

Run: python3 -I validation/test_audit_gaps.py
"""
from contextlib import ExitStack, redirect_stdout
import ast
from copy import deepcopy
import io
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, mock_open, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import approval as authority
import gate
import run_842

SHIPPED_PROFILE = json.loads(Path(__file__).with_name('profile.json').read_text())
PROFILE = deepcopy(SHIPPED_PROFILE)
# Explicit synthetic tags for offline collector tests, not assertions about this native build.
PROFILE['programs']['exec']['expectedTag'] = '1111111111111111'
PROFILE['programs']['open']['expectedTag'] = '2222222222222222'


def lease_hex(deadline, epoch=1):
    return (deadline.to_bytes(8, 'little') + epoch.to_bytes(8, 'little')).hex()
START, DEADLINE, NOW = 100_000_000_000, 120_000_000_000, 100_500_000_000
CGROUP = 42
KEY = '2a00000000000000'
EXEC = KEY + '6400000000000000' + '07000000' + '00000000'
PROTECTED = KEY + 'c800000000000000' + '07000000' + '00000000'


def inputs():
    state = {'leased_cgroups': [(KEY, lease_hex(DEADLINE))],
             'allowed_exec': [(EXEC, '01')], 'scratch_exec_devs': [],
             'protected': [(PROTECTED, '01')]}
    approved = dict(authority.lifetime(20, START), missionId='audit-1', bootId='boot-1',
                    executables=[{'path': '/approved', 'sha256': 'not-read-by-offline-double'}],
                    protected=['/protected'])
    written = {'leasedCgroup': {'key': KEY, 'value': state['leased_cgroups'][0][1]},
               'allowedExec': [EXEC], 'scratchExec': False, 'protected': [PROTECTED]}
    return state, approved, written


def semantic_check(module, state, approved, now=NOW):
    # Filesystem identity is an explicit test double. These tests do not prove path stability.
    with patch('builtins.open', mock_open(read_data='boot-1')), \
         patch.object(module, 'resolve_approved', return_value={(7, 100): '/approved'}), \
         patch.object(module.os, 'stat', return_value=SimpleNamespace(st_dev=7, st_ino=200)), \
         patch.object(module, 'kernel_dev', return_value=7):
        return module.check_b3(state, approved, CGROUP, 'audit-1', now)


def observe(module, profile=None, changed_role=None, tag=None, foreign=False):
    profile = deepcopy(PROFILE if profile is None else profile)
    links, programs, maps = [], {}, {}
    for n, (role, spec) in enumerate(PROFILE['programs'].items(), 1):
        links.append({'id': n, 'prog_id': n, 'attach_type': 'lsm_mac',
                      'target_obj_id': 1, 'target_btf_id': n})
        programs[n] = {'id': n, 'name': spec['name'], 'type': spec['progType'],
                       'tag': tag if role == changed_role else spec['expectedTag'], 'map_ids': []}
        for m, (map_role, desc) in enumerate(PROFILE['maps'].items(), 10):
            if desc['program'] == role:
                programs[n]['map_ids'].append(m)
                maps[m] = {'id': m, 'name': desc['name'], 'type': desc['type'],
                           'bytes_key': desc['key'], 'bytes_value': desc['value']}
    if foreign:
        links.append(dict(links[0], id=99, prog_id=99))
        programs[99] = dict(programs[1], id=99)

    def bpftool(*args):
        if args == ('link', 'show'):
            return links
        return (programs if args[0] == 'prog' else maps)[int(args[-1])]

    with patch.object(module, 'bpftool', side_effect=bpftool), \
         patch.object(module, 'programs_held_by', return_value={1, 2}), \
         patch.object(module, 'btf_func_names', return_value={
             n: spec['attachFunc'] for n, spec in enumerate(PROFILE['programs'].values(), 1)}):
        return module.observe_deployment(profile, 1234)


class DriverVerdictTests(unittest.TestCase):
    def aggregate(self, harness_verdict):
        # Execute the driver's actual embedded Python, not a reimplementation of its verdict.
        source = Path(__file__).with_name('run_unified.sh').read_text()
        program = source.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temp:
            root = Path(temp)
            for directory in ('probe', '842', '843'):
                (root / directory).mkdir()
            (root / 'SHA256SUMS').write_text('binary-sha  splat-agent\n')
            documents = {
                'build.json': {'bpfSourceSha256': 'bpf-sha', 'commit': 'candidate'},
                'probe/daemon-probe.json': {'daemon_binary_sha256': 'binary-sha',
                    'bpf_source_sha256': 'bpf-sha', 'verdict': 'PASS'},
                '842/manifest.json': {'stagedSha256': {'splat-agent': 'binary-sha'},
                    'deployment': {'programs': [{'name': 'splat_bprm_check', 'tag': 'reviewed'}]},
                    'verdict': harness_verdict},
                '843/manifest.json': {'stagedSha256': {'splat-agent': 'binary-sha'}, 'verdict': 'PASS'}}
            for name, value in documents.items():
                (root / name).write_text(json.dumps(value))
            result = subprocess.run([sys.executable, '-I', '-', temp], input=program,
                                    text=True, capture_output=True)
            return result.returncode, json.loads((root / 'unified.json').read_text())

    def test_failed_manifest_has_nonzero_driver_exit(self):
        code, record = self.aggregate('FAIL')
        self.assertEqual(code, 1)
        self.assertEqual(record['verdict'], 'FAIL')

    def test_matching_pass_manifests_have_zero_exit(self):
        code, record = self.aggregate('PASS')
        self.assertEqual(code, 0)
        self.assertEqual(record['verdict'], 'PASS')


class TraceEvidenceTests(unittest.TestCase):
    def test_raw_cpu_statistics_are_saved_with_derived_total(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temp:
            root = Path(temp)
            raw = {'cpu0': 'entries: 20\noverrun: 0\n', 'cpu1': 'entries: 30\noverrun: 7\n'}
            for cpu, content in raw.items():
                directory = root / 'per_cpu' / cpu
                directory.mkdir(parents=True)
                (directory / 'stats').write_text(content)
            with patch.object(run_842, 'TRACE', temp):
                self.assertEqual(run_842.trace_overruns(temp), 7)
            self.assertEqual(json.loads((root / 'trace-stats.json').read_text()), raw)

    def test_missing_cpu_statistics_do_not_report_zero(self):
        with patch.object(run_842.os, 'listdir', return_value=[]):
            with self.assertRaisesRegex(RuntimeError, 'no per-CPU'):
                run_842.trace_overruns()


class ProgramIdentityTests(unittest.TestCase):
    def test_shipped_profile_is_reviewed_for_the_source_in_this_tree(self):
        # Reviewed tags certify only the program they were reviewed against, so the profile pins
        # that source's hash: a changed BPF source fails here until it is reviewed again.
        source = Path(__file__).resolve().parents[1] / 'src' / 'bpf' / 'lease_lsm.bpf.c'
        self.assertEqual(SHIPPED_PROFILE['bpfSourceSha256'], hashlib.sha256(source.read_bytes()).hexdigest())
        # A null or malformed tag makes the gate refuse every lease (see the missing-tag test below).
        for role in ('exec', 'open'):
            self.assertRegex(SHIPPED_PROFILE['programs'][role]['expectedTag'], r'^[0-9a-f]{16}$')

    def test_reviewed_programs_admitted(self):
        self.assertEqual(set(observe(gate)['programs']), {'exec', 'open'})

    def test_same_name_different_exec_tag_refused(self):
        with self.assertRaisesRegex(gate.Indeterminate, 'tag mismatch for exec'):
            observe(gate, changed_role='exec', tag='0000000000000000')

    def test_same_name_different_open_tag_refused(self):
        with self.assertRaisesRegex(gate.Indeterminate, 'tag mismatch for open'):
            observe(gate, changed_role='open', tag='0000000000000000')

    def test_missing_observed_tag_refused(self):
        with self.assertRaises(gate.Indeterminate):
            observe(gate, changed_role='exec', tag=None)

    def test_missing_or_malformed_profile_tag_refused(self):
        for value in (None, '', 'abc', 'DEBFFEC9428E2CCF', 123):
            with self.subTest(value=value), self.assertRaises(gate.Indeterminate):
                profile = deepcopy(PROFILE)
                profile['programs']['exec']['expectedTag'] = value
                observe(gate, profile=profile)

    def test_foreign_program_still_refused(self):
        with self.assertRaisesRegex(gate.Indeterminate, 'other programs'):
            observe(gate, foreign=True)


class LifetimeTests(unittest.TestCase):
    def setUp(self):
        self.state, self.approved, self.written = inputs()

    def test_exact_deadline_control(self):
        self.assertEqual(semantic_check(gate, self.state, self.approved)[0], [])

    def test_epoch_is_recorded_without_becoming_deadline_high_bits(self):
        self.state['leased_cgroups'] = [(KEY, lease_hex(DEADLINE, 12345))]
        reasons, semantics = semantic_check(gate, self.state, self.approved)
        self.assertEqual(reasons, [])
        self.assertEqual(semantics['deadlineBootNs'], DEADLINE)
        self.assertEqual(semantics['epoch'], 12345)

    def test_old_or_malformed_lease_layout_is_refused(self):
        for size in (0, 8, 15, 17):
            with self.subTest(size=size), self.assertRaises(gate.Indeterminate):
                self.state['leased_cgroups'] = [(KEY, bytes(size).hex())]
                semantic_check(gate, self.state, self.approved)

    def test_audit_extension_no_longer_accepted(self):
        self.state['leased_cgroups'] = [(KEY, lease_hex(DEADLINE + 457_044_676))]
        reasons, _ = semantic_check(gate, self.state, self.approved)
        self.assertIn('installed deadline differs from the approved absolute deadline', reasons)

    def test_even_one_nanosecond_change_is_refused(self):
        for delta in (-1, 1):
            with self.subTest(delta=delta):
                self.state['leased_cgroups'] = [(KEY, lease_hex(DEADLINE + delta))]
                self.assertTrue(semantic_check(gate, self.state, self.approved)[0])

    def test_expiry_boundary_is_refused(self):
        for now in (DEADLINE, DEADLINE + 1):
            with self.subTest(now=now):
                self.assertIn('the installed deadline has already passed',
                              semantic_check(gate, self.state, self.approved, now)[0])

    def test_clock_before_approval_is_refused(self):
        self.assertTrue(semantic_check(gate, self.state, self.approved, START - 1)[0])

    def test_missing_or_wrong_clock_is_refused(self):
        for clock in (None, 'wall-clock', 'monotonic'):
            with self.subTest(clock=clock), self.assertRaises(gate.Indeterminate):
                gate.approved_deadline(dict(self.approved, clock=clock))

    def test_invalid_lifetime_fields_are_refused(self):
        for field in ('approvedAtBootNs', 'deadlineBootNs', 'leaseDurationSeconds'):
            for value in (None, True, -1, 2**64, 1.5, '20'):
                with self.subTest(field=field, value=value), self.assertRaises(gate.Indeterminate):
                    gate.approved_deadline(dict(self.approved, **{field: value}))

    def test_inconsistent_start_duration_deadline_refused(self):
        with self.assertRaises(gate.Indeterminate):
            gate.approved_deadline(dict(self.approved, deadlineBootNs=DEADLINE + 1))

    def test_wrong_boot_and_mission_are_refused(self):
        for field in ('missionId', 'bootId'):
            with self.subTest(field=field), self.assertRaises(gate.Indeterminate):
                semantic_check(gate, self.state, dict(self.approved, **{field: 'wrong'}))

    def test_authority_mints_exact_deadline(self):
        self.assertEqual(gate.approved_deadline(authority.lifetime(20, START)), DEADLINE)

    def test_authority_refuses_invalid_or_overflowing_inputs(self):
        for seconds, start in ((True, START), (4, START), (301, START), (20, True),
                               (20, -1), (20, 2**64 - 1)):
            with self.subTest(seconds=seconds, start=start), self.assertRaises(ValueError):
                authority.lifetime(seconds, start)

    def test_b2_still_compares_writer_bytes(self):
        self.assertEqual(gate.check_b2(self.state, self.written, CGROUP), [])
        changed = lease_hex(DEADLINE + 457_044_676)
        self.state['leased_cgroups'] = [(KEY, changed)]
        self.written['leasedCgroup']['value'] = changed
        self.assertEqual(gate.check_b2(self.state, self.written, CGROUP), [])
        self.assertTrue(semantic_check(gate, self.state, self.approved)[0])

    def test_exec_overgrant_and_missing_protection_still_refused(self):
        for role in ('allowed_exec', 'protected'):
            state = deepcopy(self.state)
            if role == 'allowed_exec':
                state[role].append((KEY + '65000000000000000700000000000000', '01'))
            else:
                state[role] = []
            with self.subTest(role=role):
                self.assertTrue(semantic_check(gate, state, self.approved)[0])

    def test_two_pass_capture_still_detects_mutation(self):
        with patch.object(gate, 'dump', side_effect=[[], [('key', 'value')]]):
            with self.assertRaisesRegex(gate.Indeterminate, 'changed between'):
                gate.capture({'allowed_exec': {'id': 1}})

    def test_duplicate_json_keys_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            gate.read_json(io.StringIO('{"deadlineBootNs":1,"deadlineBootNs":2}'))

    def test_expiry_during_gate_validation_refused_and_recorded(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temp:
            root = Path(temp)
            (root / 'cgroup.procs').write_text('')
            (root / 'audit-1.json').write_text(json.dumps(self.approved))
            config = root / 'config.json'
            config.write_text(json.dumps({'variant': 'B3', 'recordDir': temp}))
            with ExitStack() as stack:
                stack.enter_context(patch.object(gate, 'CONFIG', str(config)))
                stack.enter_context(patch.object(gate, 'PROFILE', str(Path(__file__).with_name('profile.json'))))
                stack.enter_context(patch.object(gate, 'APPROVALS', temp))
                stack.enter_context(patch.object(sys, 'argv', ['gate', '--cgroup-id', str(CGROUP),
                    '--cgroup-path', temp, '--mission-id', 'audit-1']))
                stack.enter_context(patch.object(sys, 'stdin', io.StringIO(json.dumps(self.written))))
                stack.enter_context(patch.object(gate.os, 'stat', return_value=SimpleNamespace(st_ino=CGROUP)))
                stack.enter_context(patch.object(gate.time, 'CLOCK_BOOTTIME', 7, create=True))
                stack.enter_context(patch.object(gate.time, 'clock_gettime_ns',
                    side_effect=[NOW, NOW + 1, DEADLINE], create=True))
                stack.enter_context(patch.object(gate, 'observe_deployment', return_value={'maps': {}}))
                stack.enter_context(patch.object(gate, 'capture', return_value=self.state))
                stack.enter_context(patch.object(gate, 'check_b3', return_value=([], {})))
                stack.enter_context(redirect_stdout(io.StringIO()))
                self.assertEqual(gate.main(), gate.REJECT)
            record = json.loads((root / 'audit-1.gate.json').read_text())
            self.assertEqual(record['decision'], 'reject')
            self.assertIn('approval expired while validation ran', record['reasons'])


class ProbeLayoutTests(unittest.TestCase):
    def decode(self, value, name='leased_cgroups'):
        source = Path(__file__).parents[1].joinpath('probe-daemon.sh').read_text()
        program = source.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        function = next(n for n in ast.parse(program).body
                        if isinstance(n, ast.FunctionDef) and n.name == 'pinned_value')
        path = MagicMock()
        path.return_value.read_bytes.return_value = b'fixture-source'
        namespace = {'Path': path, 'hashlib': hashlib,
                     'bpftool': lambda *args: [{'key': CGROUP, 'value': value}]}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<actual probe decoder>', 'exec'), namespace)
        return namespace['pinned_value'](name, CGROUP)

    def test_raw_deadline_ignores_epoch_word(self):
        raw = bytes.fromhex(lease_hex(DEADLINE, 12345))
        self.assertEqual(self.decode([hex(b) for b in raw]), DEADLINE)

    def test_btf_deadline_is_selected_by_name_not_field_order(self):
        self.assertEqual(self.decode({'epoch': 12345, 'deadline_ns': DEADLINE}), DEADLINE)

    def test_wrong_lease_layout_is_refused(self):
        with self.assertRaises(ValueError):
            self.decode(['0x00'] * 8)

    def test_counter_scalar_is_unchanged(self):
        self.assertEqual(self.decode(9, 'violation_counts'), 9)


if __name__ == '__main__':
    unittest.main(verbosity=2)
