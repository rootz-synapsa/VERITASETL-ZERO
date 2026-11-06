"""RR-AT-03: an application path invoking the worker without dispatch authorization is rejected."""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import re
import secrets
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from packages.admission.admission import AdmissionDenied, AdmissionTicket, _IssuerCapability  # noqa: E402
from packages.contracts.state import IllegalTransition, InvariantViolation, JobStateMachine, State  # noqa: E402
from tests.acceptance.common import ROOT, Recorder, build_system, dispatch_job, new_job  # noqa: E402

GOVERNED = {"packages/admission", "packages/dispatcher"}
RULES = [
    (re.compile(r"\bWorkerRuntime\b"), GOVERNED, "worker runtime reference"),
    (re.compile(r"\bclaim_issuer\b"), GOVERNED, "issuer capability"),
    (re.compile(r"\bredeem\s*\("), GOVERNED, "ticket redemption"),
    (re.compile(r"^\s*(?:import|from)\s+(?:subprocess|docker)\b", re.M), {"packages/sandbox"}, "process/container primitive import"),
    (re.compile(r"\bos\.(?:system|popen|exec\w*|spawn\w*)\s*\("), {"packages/sandbox"}, "os process primitive"),
]


def expect_denied(fn):
    try:
        fn()
        return None
    except AdmissionDenied as e:
        return e.code
    except PermissionError:
        return "PermissionError"


def static_scan():
    scanned, violations = 0, []
    for base in ("apps", "packages"):
        for p in sorted((ROOT / base).rglob("*.py")):
            rel = p.relative_to(ROOT).as_posix()
            scanned += 1
            text = p.read_text(encoding="utf-8")
            for rx, allowed, label in RULES:
                if any(rel.startswith(a + "/") for a in allowed):
                    continue
                for m in rx.finditer(text):
                    violations.append({"file": rel, "line": text.count("\n", 0, m.start()) + 1, "rule": label})
    return scanned, violations


def main() -> int:
    rec = Recorder("RR-AT-03", "Direct worker bypass is blocked",
                   "EXEC-INV-01: no execution-capable interface is reachable except via GovernedDispatcher + WorkerAdmission")
    with tempfile.TemporaryDirectory() as td:
        s = build_system(td)
        job = new_job(s)
        ind, pd = job.ctx.input_digest, job.ctx.program_digest

        sm = JobStateMachine("probe-a")
        try:
            sm.advance(State.EXECUTION)
            skipped = True
        except IllegalTransition:
            skipped = False
        rec.check("C0a", "State machine forbids WORK_PROPOSED -> EXECUTION", not skipped, {"skipped": skipped})

        sm2 = JobStateMachine("probe-b")
        sm2.advance(State.CONTEXT_BOUND)
        sm2.advance(State.AUTHORITY_EVALUATED)
        sm2.advance(State.DENY)
        try:
            sm2.advance(State.EXECUTION)
            reach = True
        except IllegalTransition:
            reach = False
        try:
            sm2.mark_worker_invoked()
            flagged = True
        except InvariantViolation:
            flagged = False
        rec.check("C0b", "After DENY: no path to EXECUTION, worker_invoked cannot be set",
                  not reach and not flagged and sm2.worker_invoked is False,
                  {"reach_execution": reach, "flag_set": flagged, "worker_invoked": sm2.worker_invoked})

        code = expect_denied(lambda: s.worker.run(None, job.program, job.data))
        rec.check("C1", "Direct WorkerRuntime.run() with no ticket is rejected",
                  code == "NO_VALID_ADMISSION_TICKET" and s.worker.invocations == 0,
                  {"code": code, "worker_invocations": s.worker.invocations})

        forged = AdmissionTicket(secrets.token_hex(16), "att-forged", "ad_forged", ind, pd, time.time())
        code = expect_denied(lambda: s.worker.run(forged, job.program, job.data))
        rec.check("C2", "Forged AdmissionTicket object is rejected",
                  code == "NO_VALID_ADMISSION_TICKET" and s.worker.invocations == 0,
                  {"code": code, "worker_invocations": s.worker.invocations})

        body = base64.urlsafe_b64encode(json.dumps({"aid": "att-x", "did": "ad_x", "in": ind, "pg": pd,
                                                    "exp": time.time() + 60, "nonce": "n0"}).encode()).rstrip(b"=").decode()
        sig = hmac.new(secrets.token_bytes(32), body.encode(), hashlib.sha256).hexdigest()
        code = expect_denied(lambda: s.admission.admit(f"{body}.{sig}", attempt_id="att-x", input_digest=ind, program_digest=pd))
        rec.check("C3", "Token signed with attacker key is rejected", code == "BAD_SIGNATURE", {"code": code})

        code = expect_denied(lambda: s.admission.admit(None, attempt_id="att-x", input_digest=ind, program_digest=pd))
        rec.check("C4", "Admission without any dispatch authorization is rejected",
                  code == "NO_VALID_DISPATCH_AUTHORIZATION", {"code": code})

        c_issue = expect_denied(lambda: s.admission.issue(_IssuerCapability(), attempt_id="att-x", decision_id="d",
                                                          input_digest=ind, program_digest=pd))
        c_claim = expect_denied(lambda: s.admission.claim_issuer())
        rec.check("C5", "Token minting outside the single GovernedDispatcher is impossible",
                  c_issue == "PermissionError" and c_claim == "PermissionError",
                  {"issue_with_fake_capability": c_issue, "second_claim_issuer": c_claim})

        j2 = new_job(s)
        r = dispatch_job(s, j2, "att-noauth", authorization=None)
        rec.check("C6", "Dispatcher with no authorization -> BLOCKED_PRE_EXECUTION, worker_invoked=false",
                  r["status"] == "BLOCKED_PRE_EXECUTION" and r["worker_invoked"] is False and s.worker.invocations == 0,
                  {k: r[k] for k in ("status", "reason", "worker_invoked", "state_trail")})

        j3 = new_job(s)
        fake = dataclasses.replace(j3.decision, decision_id="ad_forged_" + secrets.token_hex(4), actor_id="mallory")
        r = dispatch_job(s, j3, "att-forged-decision", authorization=fake)
        rec.check("C7", "Forged ALLOW decision is caught by dispatch-time revalidation",
                  r["status"] == "BLOCKED_PRE_EXECUTION" and r["reason"] == "UNKNOWN_ACTOR"
                  and r["worker_invoked"] is False and s.worker.invocations == 0,
                  {k: r[k] for k in ("status", "reason", "worker_invoked", "state_trail")})

        scanned, violations = static_scan()
        rec.check("C8", "Static scan: no execution-capable reference outside dispatcher/admission",
                  scanned > 0 and not violations, {"files_scanned": scanned, "violations": violations})

        j4 = new_job(s)
        r = dispatch_job(s, j4, "att-legit-001")
        rec.check("C9", "Control: legitimate governed dispatch starts the worker exactly once",
                  r["status"] == "EXECUTED_AWAITING_VERIFICATION" and r["worker_invoked"] is True
                  and s.worker.invocations == 1 and (r["output"] or {}).get("data_rows") == 2,
                  {k: r[k] for k in ("status", "reason", "worker_invoked", "state_trail", "output")}
                  | {"worker_invocations": s.worker.invocations})
    return rec.finish()


if __name__ == "__main__":
    sys.exit(main())
