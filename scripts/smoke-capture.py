#!/usr/bin/env python3
"""Smoke-test only the selected loopback interface with locally generated UDP."""
import json
import signal
import socket
import subprocess
import sys
import time

binary, interface = sys.argv[1:3]
denied = len(sys.argv) > 3 and sys.argv[3] == "denied"
process = subprocess.Popen(
    [binary, interface, "--format", "json"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    universal_newlines=True,
)
terminated_by_test = False
try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for _ in range(160):
            if process.poll() is not None:
                break
            sender.sendto(b"flowlens-loopback-smoke-" * 40, ("127.0.0.1", 29999))
            time.sleep(0.05)
finally:
    if process.poll() is None:
        terminated_by_test = True
        process.terminate()
    output, errors = process.communicate(timeout=10)
if denied:
    if process.returncode == 0 or "Failed to open interface" not in errors:
        raise SystemExit("Expected capture permission denial: " + errors + output)
    print("PASS: capture denied without root/capability")
else:
    if not terminated_by_test or process.returncode not in (0, -signal.SIGTERM):
        raise SystemExit("Capture exited unexpectedly: " + str(process.returncode) + ": " + errors)
    frames = [json.loads(line) for line in output.splitlines() if line.strip()]
    if not frames or not any(
        frame["totals"]["in_bytes"] + frame["totals"]["out_bytes"] > 0
        for frame in frames
    ):
        raise SystemExit("Expected nonzero loopback capture: " + errors + output)
    print("PASS: actual loopback capture; totals=" + str(frames[-1]["totals"]))
