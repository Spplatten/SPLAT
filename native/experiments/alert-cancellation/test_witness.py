"""Portable parser/contract tests only. These do not exercise pidfds or cgroup enforcement."""
import importlib.util
import errno
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

loader = importlib.util.spec_from_file_location("witness", Path(__file__).with_name("witness.py"))
witness = importlib.util.module_from_spec(loader)
loader.loader.exec_module(witness)


class WitnessContractTests(unittest.TestCase):
    def test_stat_parentheses_and_spaces_do_not_shift_birth_field(self):
        fields = ["S"] + ["0"] * 25
        fields[11], fields[12], fields[19] = "17", "19", "9001"
        sample = witness.parse_stat("77 (a tricky ) process) " + " ".join(fields), 77)
        self.assertEqual(sample, dict(startTicks=9001, cpuTicks=36, state="S"))

    def test_wrong_pid_refused(self):
        with self.assertRaises(ValueError):
            witness.parse_stat("78 (x) S " + "0 " * 25, 77)

    def test_short_stat_refused(self):
        with self.assertRaises(ValueError):
            witness.parse_stat("77 (x) S 1", 77)

    def test_duplicate_fields_refused(self):
        with self.assertRaises(ValueError):
            witness.strict_object([("pid", 77), ("pid", 88)])

    def spec(self):
        return dict(version=1, boot="11111111-2222-3333-4444-555555555555", sourceSha256="a" * 64,
                    target=dict(taskId="a" * 32, cgroup=123, pid=77, startTicks=9000),
                    control=dict(taskId="b" * 32, cgroup=456, pid=78, startTicks=9001))

    def test_valid_disjoint_tuple(self):
        witness.validate_spec(self.spec())

    def test_each_overlap_rejected(self):
        for field in ("taskId", "pid", "cgroup"):
            spec = self.spec()
            spec["control"][field] = spec["target"][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                witness.validate_spec(spec)

    def test_bare_pid_has_no_authority(self):
        spec = self.spec()
        del spec["target"]["startTicks"]
        with self.assertRaises(ValueError):
            witness.validate_spec(spec)

    def test_boolean_is_not_integer_identity(self):
        spec = self.spec()
        spec["control"]["pid"] = True
        with self.assertRaises(ValueError):
            witness.validate_spec(spec)

    def test_unknown_fields_refused(self):
        spec = self.spec()
        spec["target"]["signal"] = 9
        with self.assertRaises(ValueError):
            witness.validate_spec(spec)

    def test_version_boolean_and_numeric_overflow_refused(self):
        for field, value in (("version", True), ("pid", 1 << 31), ("cgroup", 1 << 64)):
            spec = self.spec()
            if field == "version":
                spec[field] = value
            else:
                spec["target"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                witness.validate_spec(spec)

    def test_command_framing(self):
        self.assertEqual(witness.read_command(io.BytesIO(b"check\n")), "check")
        self.assertEqual(witness.read_command(io.BytesIO(b"after\n")), "after")
        self.assertIsNone(witness.read_command(io.BytesIO(b"")))
        for frame in (b"check\r\n", b"after", b"unknown\n", b"x" * 33):
            with self.subTest(frame=frame), self.assertRaises(ValueError):
                witness.read_command(io.BytesIO(frame))


class DrainDecisionTests(unittest.TestCase):
    """Injected OS outcomes exercise failure branches, not real kernel evidence."""
    def held(self, populated=True):
        held = witness.HeldProcess.__new__(witness.HeldProcess)
        held.expected = {"cgroup": 123}
        held.path = "/sys/fs/cgroup/splat_leases/mission_test"
        held.cgroup_fd = 71
        held.exited = lambda: True
        def read_populated():
            if isinstance(populated, Exception):
                raise populated
            return populated
        held.populated = read_populated
        return held

    def test_missing_path_with_populated_held_group_is_not_drain(self):
        with patch.object(witness.os, "stat", side_effect=FileNotFoundError()):
            self.assertFalse(self.held(True).drained())

    def test_empty_held_group_is_drain(self):
        with patch.object(witness.os, "stat", side_effect=FileNotFoundError()):
            self.assertTrue(self.held(False).drained())

    def test_confirmed_deleted_handle_with_removed_interface(self):
        held = self.held(OSError(errno.ENODEV, "removed"))
        with patch.object(witness.os, "stat", side_effect=FileNotFoundError()), \
                patch.object(witness.os, "readlink", return_value=held.path + " (deleted)"):
            self.assertTrue(held.drained())

    def test_renamed_handle_is_not_deleted_handle(self):
        held = self.held(OSError(errno.ENODEV, "removed"))
        with patch.object(witness.os, "stat", side_effect=FileNotFoundError()), \
                patch.object(witness.os, "readlink", return_value=held.path + "_renamed"), self.assertRaises(ValueError):
            held.drained()

    def test_permission_denied_is_not_removal(self):
        with patch.object(witness.os, "stat", side_effect=FileNotFoundError()), self.assertRaises(PermissionError):
            self.held(PermissionError(errno.EACCES, "denied")).drained()

    def test_alive_original_process_is_not_drain(self):
        held = self.held(False)
        held.exited = lambda: False
        self.assertFalse(held.drained())


def wire_peer():
    # Exercise the actual guest command parser over real process pipes, even on Windows.
    # This peer performs NO process/cgroup observations and never emits a native proof.
    request = sys.stdin.buffer.readline(16385)
    if not request.endswith(b"\n") or b"\r" in request or request.startswith(b"\xef\xbb\xbf"):
        raise ValueError("host wire framing differs from Linux contract")
    value = json.loads(request, object_pairs_hook=witness.strict_object)
    if value != {"version": 1, "probe": "wire-λ"}:
        raise ValueError("wrong UTF-8 request")
    sys.stderr.buffer.write(b"x" * (256 * 1024))
    sys.stderr.buffer.flush()
    def send(body):
        sys.stdout.buffer.write(json.dumps(body).encode("utf-8") + b"\n")
        sys.stdout.buffer.flush()
    send({"probe": value["probe"]})
    for expected in ("check", "after"):
        actual = witness.read_command(sys.stdin.buffer)
        if actual != expected:
            raise ValueError("wrong command phase")
        send({"phase": actual, "scope": "stdio-contract-only"})
    if witness.read_command(sys.stdin.buffer) is not None:
        raise ValueError("EOF expected")


if __name__ == "__main__":
    if sys.argv[1:] == ["--wire-peer"]:
        wire_peer()
    else:
        unittest.main(verbosity=2)
