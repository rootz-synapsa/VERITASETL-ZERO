"""EA-02 & EA-03 Acceptance Test: Sandbox Containment & Lifecycle Evidence."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from packages.admission.programs import builtin_program  # noqa: E402
from packages.sandbox.runner import run_in_sandbox  # noqa: E402
from tests.security.secret_scan import scan_text  # noqa: E402

TEST_ID = "EA-02-03"
TITLE = "Sandbox containment and lifecycle evidence (EA-02, EA-03)"
INVARIANT = "All worker execution must occur inside isolated ephemeral containers enforcing network disablement, read-only rootfs, non-root user, capability dropping, and resource/timeout limits."
EXPECTED_HOST = "veritasetl-zero"
FIXTURE = ROOT / "fixtures" / "supplier-input" / "supplier_batch_p0.csv"
_ENV_DIR = os.environ.get("VZ_EVIDENCE_DIR", "").strip()
EVIDENCE = Path(_ENV_DIR).resolve() if _ENV_DIR else ROOT / "evidence"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(p) -> str:
    p = Path(p).resolve()
    try:
        return p.relative_to(ROOT).as_posix()
    except ValueError:
        return str(p)


def main() -> int:
    host = socket.gethostname()
    if host != EXPECTED_HOST and not _ENV_DIR:
        print(f"PROVENANCE GUARD: host={host} != {EXPECTED_HOST}; refusing to write evidence.")
        return 2

    print(f"\n### {TEST_ID} - {TITLE}")
    cases = []

    def check(cid, title, passed, obs):
        passed = bool(passed)
        cases.append({"case": cid, "title": title, "passed": passed, "observed": obs})
        print(f"  [{'PASS' if passed else 'FAIL'}] {cid} {title}")
        if not passed:
            print("         observed:", json.dumps(obs, default=str)[:800])

    data = FIXTURE.read_bytes()
    prog = builtin_program("supplier_repair_v1")

    # Case 1: Legitimate execution inside sandbox
    res = run_in_sandbox(prog.source, data, timeout_s=15.0)
    lc = res["lifecycle"]
    out = res["output"] or {}
    check("C1", "Legitimate repair inside Docker sandbox succeeds with valid artifacts",
          res["execution_status"] == "SUCCESS" and lc["exit_code"] == 0 and lc["timed_out"] is False
          and "normalized_csv" in out and "job_summary" in out,
          {"execution_status": res["execution_status"], "exit_code": lc["exit_code"], "duration_ms": lc["duration_ms"]})

    # Case 2: Network isolation (--network none)
    net_probe = prog.source + "\n\nimport urllib.request\ntry:\n    urllib.request.urlopen('http://1.1.1.1', timeout=1)\nexcept Exception:\n    pass\nelse:\n    raise RuntimeError('NETWORK_ACCESSIBLE')\n"
    res2 = run_in_sandbox(net_probe, data, timeout_s=15.0)
    check("C2", "Egress network attempt is blocked (--network none)",
          res2["execution_status"] == "SUCCESS",
          {"execution_status": res2["execution_status"], "error": res2.get("error")})

    # Case 3: Read-only rootfs (--read-only)
    fs_probe = prog.source + "\n\nfrom pathlib import Path\ntry:\n    Path('/evil.txt').write_text('test')\n    raise RuntimeError('FS_WRITABLE')\nexcept Exception as e:\n    if 'Read-only file system' not in str(e) and 'Permission denied' not in str(e):\n        raise"
    res3 = run_in_sandbox(fs_probe, data, timeout_s=15.0)
    check("C3", "Root filesystem is read-only (--read-only blocks writes)",
          res3["execution_status"] == "SUCCESS",
          {"execution_status": res3["execution_status"], "error": res3.get("error")})

    # Case 4: Infinite loop / timeout enforcement
    infinite_loop_prog = "import time\ndef supplier_repair_v1(d):\n    while True:\n        time.sleep(0.1)\n"
    res4 = run_in_sandbox(infinite_loop_prog, data, timeout_s=3.0)
    check("C4", "Infinite loop is terminated by sandbox timeout enforcement",
          res4["lifecycle"]["timed_out"] is True and res4["lifecycle"]["exit_code"] == -1,
          {"timed_out": res4["lifecycle"]["timed_out"], "exit_code": res4["lifecycle"]["exit_code"]})

    # Write evidence
    status = "PASS" if cases and all(c["passed"] for c in cases) else "FAIL"
    passed = f"{sum(c['passed'] for c in cases)}/{len(cases)}"
    doc = {
        "test_id": TEST_ID, "title": TITLE, "invariant": INVARIANT, "status": status,
        "timestamp_utc": utc_now(),
        "environment": {"host": host, "python": platform.python_version(), "platform": platform.platform()},
        "cases_passed": passed, "cases": cases
    }
    findings = scan_text(json.dumps(doc, indent=2, default=str))
    doc["secret_free"] = not findings
    text = json.dumps(doc, indent=2, default=str) + "\n"
    out_path = EVIDENCE / "ea" / f"{TEST_ID}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")

    index = EVIDENCE / "index.json"
    idx = json.loads(index.read_text(encoding="utf-8")) if index.exists() else {"gates": []}
    gates = [g for g in idx.get("gates", []) if g.get("gate") != TEST_ID]
    gates.append({
        "gate": TEST_ID, "title": TITLE, "status": status, "timestamp_utc": doc["timestamp_utc"],
        "provider": f"Vultr VM ({host}) Docker", "evidence_file": rel(out_path),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "cases_passed": passed,
        "secret_free": not findings
    })
    gates.sort(key=lambda g: g["gate"])
    idx["gates"] = gates
    idx["updated_utc"] = utc_now()
    index.write_text(json.dumps(idx, indent=2) + "\n", encoding="utf-8")
    print(f"==> {TEST_ID}: {status} ({passed} cases, evidence: {rel(out_path)})")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
