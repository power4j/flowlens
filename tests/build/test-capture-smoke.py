#!/usr/bin/env python3
"""No real processes or network: regression coverage for capture smoke outcomes."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import signal
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "smoke-capture.py"
FRAME = json.dumps({"totals": {"in_bytes": 1, "out_bytes": 0}})


class Process:
    def __init__(self, status, early, output, errors):
        self.returncode = status if early else None
        self.status, self.output, self.errors = status, output, errors

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = self.status

    def communicate(self, timeout):
        return self.output, self.errors


class CaptureSmokeTests(unittest.TestCase):
    def run_smoke(self, status=-signal.SIGTERM, early=False, output=FRAME, errors="", denied=False):
        args = [str(SCRIPT), "fixture-binary", "lo"] + (["denied"] if denied else [])
        with patch("sys.argv", args), patch("subprocess.Popen", return_value=Process(status, early, output, errors)), patch("socket.socket"), patch("time.sleep"), contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(SCRIPT), run_name="__main__")

    def test_running_capture_terminated_by_test(self):
        self.run_smoke()

    def test_graceful_response_to_test_termination(self):
        self.run_smoke(status=0)

    def test_early_failure_after_a_nonzero_frame(self):
        with self.assertRaisesRegex(SystemExit, "exited unexpectedly"):
            self.run_smoke(status=1, early=True)

    def test_early_successful_exit_is_not_a_running_capture(self):
        with self.assertRaisesRegex(SystemExit, "exited unexpectedly"):
            self.run_smoke(status=0, early=True)

    def test_crash_racing_with_test_termination(self):
        with self.assertRaisesRegex(SystemExit, "exited unexpectedly"):
            self.run_smoke(status=-signal.SIGABRT)

    def test_no_captured_bytes_fails(self):
        with self.assertRaisesRegex(SystemExit, "nonzero loopback"):
            self.run_smoke(output="")

    def test_expected_denial(self):
        self.run_smoke(status=1, early=True, output="", errors="Failed to open interface", denied=True)

    def test_unrelated_failure_is_not_permission_denial(self):
        with self.assertRaisesRegex(SystemExit, "permission denial"):
            self.run_smoke(status=1, early=True, output="", errors="other failure", denied=True)


if __name__ == "__main__":
    unittest.main()
