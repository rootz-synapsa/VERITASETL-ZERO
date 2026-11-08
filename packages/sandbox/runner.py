"""Docker Sandbox Containment Engine (EA-02, EA-03).
Runs bounded programs inside hardened ephemeral containers with network disabled, read-only rootfs,
dropped capabilities, non-root user, and strict resource/timeout caps.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

CONTAINER_IMAGE = "python:3.11-slim"

PREAMBLE = """
import csv, hashlib, inspect, io, re, collections, datetime
from datetime import date
from decimal import Decimal
"""

RUNNER_SCRIPT = """
import sys, json
from pathlib import Path
sys.path.insert(0, "/workspace")
try:
    import program
    data = Path("/workspace/input.csv").read_bytes()
    res = program.supplier_repair_v1(data)
    print(json.dumps({"status": "SUCCESS", "result": res}))
except BaseException as e:
    print(json.dumps({"status": "ERROR", "error": str(e)}))
"""


def run_in_sandbox(program_source: str, input_bytes: bytes, timeout_s: float = 10.0) -> dict:
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "program.py").write_text(PREAMBLE + "\n" + program_source, encoding="utf-8")
        (tdp / "input.csv").write_bytes(input_bytes)
        (tdp / "runner.py").write_text(RUNNER_SCRIPT, encoding="utf-8")
        
        os.chmod(tdp, 0o755)
        for f in tdp.iterdir():
            os.chmod(f, 0o644)

        name = f"vz-sbx-{uuid.uuid4().hex[:12]}"
        cmd = [
            "docker", "run", "--rm",
            "--name", name,
            "--network", "none",
            "--read-only",
            "--user", "65534:65534",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "64",
            "--memory", "256m",
            "--cpus", "0.5",
            "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--volume", f"{tdp}:/workspace:ro",
            CONTAINER_IMAGE,
            "python", "/workspace/runner.py",
        ]

        lifecycle = {"created": True, "started_at": time.time()}
        p = None
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
            lifecycle["exit_code"] = p.returncode
            lifecycle["timed_out"] = False
            raw_out = p.stdout.strip()
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            lifecycle["exit_code"] = -1
            lifecycle["timed_out"] = True
            raw_out = json.dumps({"status": "TIMEOUT", "error": "execution timed out"})
        lifecycle["finished_at"] = time.time()
        lifecycle["duration_ms"] = int((lifecycle["finished_at"] - lifecycle["started_at"]) * 1000)

        parsed = {}
        for line in raw_out.splitlines():
            try:
                parsed = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
        if not parsed:
            parsed = {"status": "PARSE_ERROR", "raw": raw_out[:500]}

        return {
            "lifecycle": lifecycle,
            "output": parsed.get("result"),
            "execution_status": parsed.get("status"),
            "error": parsed.get("error"),
            "stderr": (p.stderr[:500] if p is not None else ""),
        }
