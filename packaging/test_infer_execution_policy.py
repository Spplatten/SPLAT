import importlib.util
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("infer_policy", Path(__file__).with_name("infer-execution-policy.py"))
infer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(infer)


class InferenceTests(unittest.TestCase):
    def test_attempted_failed_and_resumed_calls_are_candidates_not_authority(self):
        trace = '10 execve("/tool",[],[]) = 0\n10 openat(0,"/data",0) = -1 EACCES\n10 read(3, <unfinished ...>\n10 <... read resumed> "x",1) = 1\n10 exit_group(0) = ?\n10 +++ exited with 0 +++\n'
        with tempfile.TemporaryDirectory() as root:
            executable = Path(root) / "tool"
            executable.write_bytes(b"fixture")
            result = infer.candidate(trace.encode(), executable, [{"path": "/data", "access": ["read"]}])
        self.assertEqual(result["status"], "candidate-needs-review")
        self.assertEqual(result["addedLaunchSyscalls"], ["close", "write"])
        self.assertEqual(result["executionPolicy"]["syscalls"], ["close", "execve", "exit_group", "openat", "read", "write"])
        self.assertEqual(len(result["traceSha256"]), 64)

    def test_unrecognized_or_truncated_trace_is_not_silently_dropped(self):
        for trace in ["", "read(3,0,1) = 0", "12:30:00 execve(0) = 0", "execve(0)=0\nunknown data\nexit_group(0)=?"]:
            with self.subTest(trace=trace), self.assertRaises(ValueError):
                infer.observed_syscalls(trace)

    def test_missing_trace_is_a_clean_cli_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run([sys.executable, str(Path(infer.__file__)),
                "--trace", str(Path(root) / "missing"), "--executable", "unused", "--file-grants", "unused"],
                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("error:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
