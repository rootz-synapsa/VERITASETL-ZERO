"""Shared harness for RR/EA acceptance tests. Writes sanitized evidence + updates index."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from packages.admission.admission import WorkerAdmission
from packages.admission.programs import builtin_program
from packages.admission.worker import WorkerRuntime
from packages.authority.gate import AuthorityGate, PolicyStore
from packages.dispatcher.dispatcher import GovernedDispatcher
from tests.security.secret_scan import scan_text

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evidence"
INDEX = EVIDENCE / "index.json"
PROJECT = "supplier-repair-p0"
OPERATOR = "rootz-operator"
SAMPLE_CSV = b"supplier_id,supplier_name,amount,currency\nS001,Acme Thai Co,1200.50,THB\nS002,Siam Parts,99.00,THB\n"
_DEFAULT = object()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_system(tmpdir: str) -> SimpleNamespace:
    store = PolicyStore()
    store.add_actor(OPERATOR, [PROJECT])
    gate = AuthorityGate(store)
    admission = WorkerAdmission(os.path.join(tmpdir, "admission.db"))
    worker = WorkerRuntime(admission)
    dispatcher = GovernedDispatcher(gate, admission, worker, os.path.join(tmpdir, "dispatch.db"))
    return SimpleNamespace(store=store, gate=gate, admission=admission, worker=worker, dispatcher=dispatcher)


def new_job(s, actor=OPERATOR, project=PROJECT, data=SAMPLE_CSV, program_name="row_count_v1") -> SimpleNamespace:
    program = builtin_program(program_name)
    proposal, sm = s.gate.propose(actor, project, data, program)
    ctx = s.gate.bind_context(proposal, sm)
    decision = s.gate.evaluate(proposal, ctx, sm)
    return SimpleNamespace(program=program, proposal=proposal, sm=sm, ctx=ctx, decision=decision, data=data)


def dispatch_job(s, job, attempt_id, authorization=_DEFAULT) -> dict:
    auth = job.decision if authorization is _DEFAULT else authorization
    return s.dispatcher.dispatch(attempt_id, auth, job.program, job.ctx, input_bytes=job.data, sm=job.sm)


def upsert_index(entry: dict) -> None:
    idx = json.loads(INDEX.read_text(encoding="utf-8")) if INDEX.exists() else {"gates": []}
    gates = [g for g in idx.get("gates", []) if g.get("gate") != entry["gate"]]
    gates.append(entry)
    gates.sort(key=lambda g: g["gate"])
    idx["gates"] = gates
    idx["updated_utc"] = utc_now()
    INDEX.write_text(json.dumps(idx, indent=2) + "\n", encoding="utf-8")


class Recorder:
    def __init__(self, test_id: str, title: str, invariant: str):
        self.test_id, self.title, self.invariant = test_id, title, invariant
        self.cases: list[dict] = []
        print(f"\n### {test_id} - {title}")

    def check(self, case_id: str, title: str, passed, observed: dict) -> None:
        passed = bool(passed)
        self.cases.append({"case": case_id, "title": title, "passed": passed, "observed": observed})
        print(f"  [{'PASS' if passed else 'FAIL'}] {case_id} {title}")
        if not passed:
            print("         observed:", json.dumps(observed, default=str)[:600])

    def finish(self) -> int:
        status = "PASS" if self.cases and all(c["passed"] for c in self.cases) else "FAIL"
        doc = {"test_id": self.test_id, "title": self.title, "invariant": self.invariant, "status": status,
               "timestamp_utc": utc_now(),
               "environment": {"host": socket.gethostname(), "python": platform.python_version(), "platform": platform.platform()},
               "cases_passed": f"{sum(c['passed'] for c in self.cases)}/{len(self.cases)}", "cases": self.cases}
        text = json.dumps(doc, indent=2, default=str)
        findings = scan_text(text)
        if findings:
            status = "FAIL"
            doc["status"] = "FAIL"
        doc["secret_free"] = not findings
        text = json.dumps(doc, indent=2, default=str) + "\n"
        out = EVIDENCE / "rr" / f"{self.test_id}.json"
        out.write_text(text, encoding="utf-8")
        upsert_index({"gate": self.test_id, "title": self.title, "status": status, "timestamp_utc": doc["timestamp_utc"],
                      "provider": "local Vultr VM", "evidence_file": out.relative_to(ROOT).as_posix(),
                      "sha256": hashlib.sha256(text.encode()).hexdigest(), "cases_passed": doc["cases_passed"],
                      "secret_free": not findings})
        print(f"==> {self.test_id}: {status}  ({doc['cases_passed']} cases, evidence: {out.relative_to(ROOT).as_posix()})")
        return 0 if status == "PASS" else 1
