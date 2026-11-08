"""EA-04 / G5: Independent Business Verifier.
A worker that returns normally has only made a claim. Business correctness is decided by an independent
verifier that reads a sealed trusted reference from disk and recomputes money with Decimal."""
from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import os
import platform
import shutil
import socket
import sys
import tempfile
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from packages.admission.admission import WorkerAdmission  # noqa: E402
from packages.admission.programs import builtin_program  # noqa: E402
from packages.admission.worker import WorkerRuntime  # noqa: E402
from packages.authority.gate import AuthorityGate, PolicyStore  # noqa: E402
from packages.contracts.state import State  # noqa: E402
from packages.dispatcher.dispatcher import GovernedDispatcher  # noqa: E402
from packages.evidence.artifacts import write_job_artifacts  # noqa: E402
from packages.verifier.oracle import BusinessVerifier, apply_verdict  # noqa: E402
from tests.security.secret_scan import scan_text  # noqa: E402

TEST_ID = "EA-04"
TITLE = "Independent business verifier (G5 false-completion rejection)"
INVARIANT = ("A clean worker return is a claim, not a verdict. Only the independent verifier, reading a sealed "
             "trusted reference and recomputing money with Decimal, may classify BUSINESS_VERIFIED.")
EXPECTED_HOST = "veritasetl-zero"
PROJECT = "supplier-repair-p0"
OPERATOR = "rootz-operator"
EXEC = "EXECUTED_AWAITING_VERIFICATION"
FIXTURE = ROOT / "fixtures" / "supplier-input" / "supplier_batch_p0.csv"
ORACLE = ROOT / "fixtures" / "trusted-reference" / "oracle_manifest_p0.json"
_ENV_DIR = os.environ.get("VZ_EVIDENCE_DIR", "").strip()
EVIDENCE = Path(_ENV_DIR).resolve() if _ENV_DIR else ROOT / "evidence"
ART_ROOT = EVIDENCE / "ea" / TEST_ID


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(p) -> str:
    return "sha256:" + hashlib.sha256(Path(p).read_bytes()).hexdigest()


def rel(p) -> str:
    p = Path(p).resolve()
    try:
        return p.relative_to(ROOT).as_posix()
    except ValueError:
        return str(p)


def build_system(td: str):
    store = PolicyStore()
    store.add_actor(OPERATOR, [PROJECT])
    gate = AuthorityGate(store)
    admission = WorkerAdmission(os.path.join(td, "admission.db"))
    worker = WorkerRuntime(admission)
    dispatcher = GovernedDispatcher(gate, admission, worker, os.path.join(td, "dispatch.db"))
    return gate, dispatcher


def governed_run(system, attempt_id: str, data: bytes, program_name: str):
    gate, dispatcher = system
    program = builtin_program(program_name)
    proposal, sm = gate.propose(OPERATOR, PROJECT, data, program)
    ctx = gate.bind_context(proposal, sm)
    decision = gate.evaluate(proposal, ctx, sm)
    r = dispatcher.dispatch(attempt_id, decision, program, ctx, input_bytes=data, sm=sm)
    return r, sm


def finish_case(name, output, data, sm, verifier, mutate=None, post_write=None):
    case_dir = ART_ROOT / name
    out = copy.deepcopy(output) if isinstance(output, dict) else {}
    if mutate:
        mutate(out)
    hashes = write_job_artifacts(out, case_dir)
    if post_write:
        post_write(case_dir)
    verdict = verifier.verify(data, case_dir)
    if sm.state is State.EXECUTION:
        apply_verdict(sm, verdict)
    (case_dir / "verdict.json").write_text(json.dumps(verdict.to_dict(), indent=2, default=str) + "\n", encoding="utf-8")
    return verdict, hashes, case_dir


def observed(r, sm, v, hashes, case_dir, **extra) -> dict:
    d = {"dispatch_status": r["status"], "worker_invoked": r["worker_invoked"],
         "verdict": v.classification, "verdict_reason": v.reason,
         "failed_checks": [k for k, ok in v.checks.items() if not ok],
         "state_trail": sm.trail(), "artifact_dir": rel(case_dir), "artifacts": hashes}
    d.update(extra)
    return d


def _rewrite_csv(text: str, fn) -> tuple:
    rd = csv.DictReader(io.StringIO(text))
    rows = fn(list(rd))
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=rd.fieldnames, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue(), rows


def tamper_amount_and_fake_total(out: dict) -> None:
    def fn(rows):
        for r in rows:
            if r["supplier_id"] == "S0003":
                r["amount"] = "1200.00"
        return rows
    out["normalized_csv"], rows = _rewrite_csv(out["normalized_csv"], fn)
    out["job_summary"]["normalized_total"] = format(sum((Decimal(r["amount"]) for r in rows), Decimal("0.00")), "f")


def misreport_summary_total(out: dict) -> None:
    out["job_summary"]["normalized_total"] = "64159.93"


def drop_review_row(out: dict) -> None:
    out["exceptions_csv"], rows = _rewrite_csv(out["exceptions_csv"], lambda rs: [r for r in rs if r["source_row"] != "15"])
    out["job_summary"]["review_rows"] = len(rows)
    out["job_summary"]["input_rows"] -= 1


def delete_summary(case_dir: Path) -> None:
    (case_dir / "job_summary.json").unlink()


def write_evidence(cases: list, inputs: dict) -> int:
    host = socket.gethostname()
    status = "PASS" if cases and all(c["passed"] for c in cases) else "FAIL"
    passed = f"{sum(c['passed'] for c in cases)}/{len(cases)}"
    doc = {"test_id": TEST_ID, "title": TITLE, "invariant": INVARIANT, "status": status, "timestamp_utc": utc_now(),
           "environment": {"host": host, "python": platform.python_version(), "platform": platform.platform()},
           "inputs": inputs, "cases_passed": passed, "cases": cases}
    findings = scan_text(json.dumps(doc, indent=2, default=str))
    if findings:
        status = doc["status"] = "FAIL"
    doc["secret_free"] = not findings
    text = json.dumps(doc, indent=2, default=str) + "\n"
    out = EVIDENCE / "ea" / f"{TEST_ID}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    index = EVIDENCE / "index.json"
    idx = json.loads(index.read_text(encoding="utf-8")) if index.exists() else {"gates": []}
    gates = [g for g in idx.get("gates", []) if g.get("gate") != TEST_ID]
    gates.append({"gate": TEST_ID, "title": TITLE, "status": status, "timestamp_utc": doc["timestamp_utc"],
                  "provider": f"Vultr VM ({host})", "evidence_file": rel(out),
                  "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "cases_passed": passed,
                  "oracle_sha256": inputs["oracle_sha256"], "secret_free": not findings})
    gates.sort(key=lambda g: g["gate"])
    idx["gates"] = gates
    idx["updated_utc"] = utc_now()
    index.write_text(json.dumps(idx, indent=2) + "\n", encoding="utf-8")
    print(f"==> {TEST_ID}: {status}  ({passed} cases, evidence: {rel(out)})")
    return 0 if status == "PASS" else 1


def main() -> int:
    host = socket.gethostname()
    if host != EXPECTED_HOST and not _ENV_DIR:
        print(f"PROVENANCE GUARD: host={host} != {EXPECTED_HOST}; refusing to write official evidence.")
        print("Run on the Vultr VM, or set VZ_EVIDENCE_DIR=/tmp/vz_scratch for a local dry run.")
        return 2
    print(f"\n### {TEST_ID} - {TITLE}")
    cases: list = []

    def check(cid, title, passed, obs):
        passed = bool(passed)
        cases.append({"case": cid, "title": title, "passed": passed, "observed": obs})
        print(f"  [{'PASS' if passed else 'FAIL'}] {cid} {title}")
        if not passed:
            print("          observed:", json.dumps(obs, default=str)[:900])

    data = FIXTURE.read_bytes()
    verifier = BusinessVerifier(ORACLE)
    if ART_ROOT.exists():
        shutil.rmtree(ART_ROOT)

    with tempfile.TemporaryDirectory() as td:
        system = build_system(td)

        r, sm = governed_run(system, "att-ea04-c1", data, "supplier_repair_v1")
        v, h, d = finish_case("C1_legit", r["output"], data, sm, verifier)
        summ = (r["output"] or {}).get("job_summary", {})
        check("C1", "Legit governed repair -> BUSINESS_VERIFIED (6 normalized + 8 row-level REQUIRES_REVIEW)",
              r["status"] == EXEC and r["worker_invoked"] is True and v.classification == "BUSINESS_VERIFIED"
              and sm.state is State.BUSINESS_VERIFIED and summ.get("normalized_rows") == 6
              and summ.get("review_rows") == 8 and summ.get("worker_claim") == "EXECUTION_COMPLETE_UNVERIFIED",
              observed(r, sm, v, h, d, worker_claim=summ.get("worker_claim"),
                       monetary_total=v.details.get("monetary_total"), row_accounting=v.details.get("row_accounting"),
                       rows_requiring_human_review=v.details.get("rows_requiring_human_review")))

        r, sm = governed_run(system, "att-ea04-c2", data, "supplier_repair_naive_v0")
        v, h, d = finish_case("C2_naive_program", r["output"], data, sm, verifier)
        check("C2", "G5: naive program returns normally but guesses ambiguous rows -> FAILED_VERIFICATION",
              r["status"] == EXEC and r["worker_invoked"] is True and v.classification == "FAILED_VERIFICATION"
              and not v.checks.get("ambiguous_rows_routed_to_review")
              and not v.checks.get("monetary_total_matches_reference"),
              observed(r, sm, v, h, d, monetary_total=v.details.get("monetary_total"),
                       routing_issues_sample=v.details.get("routing_issues", [])[:3]))

        r, sm = governed_run(system, "att-ea04-c3", data, "supplier_repair_v1")
        v, h, d = finish_case("C3_tampered_amount", r["output"], data, sm, verifier, mutate=tamper_amount_and_fake_total)
        check("C3", "G5: S0003 amount tampered + summary total faked to match -> FAILED_VERIFICATION",
              r["status"] == EXEC and v.classification == "FAILED_VERIFICATION"
              and not v.checks.get("normalized_values_match_reference")
              and not v.checks.get("monetary_total_matches_reference"),
              observed(r, sm, v, h, d, value_mismatches=v.details.get("value_mismatches"),
                       monetary_total=v.details.get("monetary_total")))

        r, sm = governed_run(system, "att-ea04-c4", data, "supplier_repair_v1")
        v, h, d = finish_case("C4_summary_lie", r["output"], data, sm, verifier, mutate=misreport_summary_total)
        check("C4", "G5: files correct but job_summary total misreported -> FAILED_VERIFICATION",
              v.classification == "FAILED_VERIFICATION"
              and [k for k, ok in v.checks.items() if not ok] == ["job_summary_consistent"],
              observed(r, sm, v, h, d, job_summary_checks=v.details.get("job_summary_checks")))

        r, sm = governed_run(system, "att-ea04-c5", data, "supplier_repair_v1")
        v, h, d = finish_case("C5_dropped_row", r["output"], data, sm, verifier, mutate=drop_review_row)
        check("C5", "Review row silently dropped (row accounting broken) -> FAILED_VERIFICATION",
              v.classification == "FAILED_VERIFICATION" and not v.checks.get("row_accounting"),
              observed(r, sm, v, h, d, row_accounting=v.details.get("row_accounting")))

        r, sm = governed_run(system, "att-ea04-c6", data, "supplier_repair_v1")
        v, h, d = finish_case("C6_missing_summary", r["output"], data, sm, verifier, post_write=delete_summary)
        check("C6", "Missing job_summary.json -> FAILED_VERIFICATION (never BUSINESS_VERIFIED)",
              v.classification == "FAILED_VERIFICATION" and v.reason == "MISSING_REQUIRED_ARTIFACT",
              observed(r, sm, v, h, d))

        data2 = data if data.endswith(b"\n") else data + b"\n"
        data2 += b'S0099,New Vendor Co,0105569009999,2026-10-29,"100.00",THB\n'
        r, sm = governed_run(system, "att-ea04-c7", data2, "supplier_repair_v1")
        v, h, d = finish_case("C7_uncovered_input", r["output"], data2, sm, verifier)
        check("C7", "Input not covered by trusted reference -> job-level REQUIRES_REVIEW",
              r["status"] == EXEC and v.classification == "REQUIRES_REVIEW" and sm.state is State.REQUIRES_REVIEW
              and v.reason == "INPUT_NOT_COVERED_BY_TRUSTED_REFERENCE",
              observed(r, sm, v, h, d))

        forged_dir = Path(td) / "forged-reference"
        forged_dir.mkdir()
        forged = json.loads(ORACLE.read_text(encoding="utf-8"))
        forged["expected"]["normalized_total"] = "53359.39"
        (forged_dir / ORACLE.name).write_text(json.dumps(forged, indent=2) + "\n", encoding="utf-8")
        shutil.copy(ORACLE.with_name(ORACLE.name + ".sha256"), forged_dir / (ORACLE.name + ".sha256"))
        v8 = BusinessVerifier(forged_dir / ORACLE.name).verify(data, ART_ROOT / "C3_tampered_amount")
        check("C8", "Forged trusted reference (seal mismatch) -> REQUIRES_REVIEW, not verified",
              v8.classification == "REQUIRES_REVIEW" and "ORACLE_SEAL_MISMATCH" in v8.reason,
              {"verdict": v8.classification, "verdict_reason": v8.reason})

        vsrc = (ROOT / "packages" / "verifier" / "oracle.py").read_text(encoding="utf-8")
        psrc = (ROOT / "packages" / "admission" / "programs.py").read_text(encoding="utf-8")
        ref_total = json.loads(ORACLE.read_text(encoding="utf-8"))["expected"]["normalized_total"]
        v_hits = [t for t in ("packages.admission", "app.core", "supplier_repair", "repair_supplier_csv",
                              "BUILTIN_PROGRAMS") if t in vsrc]
        p_hits = [t for t in ("oracle", "trusted-reference", "trusted_reference", ref_total) if t.lower() in psrc.lower()]
        payload = builtin_program("supplier_repair_v1").source
        leak = ref_total in payload or ref_total in data.decode("utf-8")
        check("C9", "Independence: verifier never imports the program; program/input never contain reference answers",
              not v_hits and not p_hits and not leak,
              {"verifier_forbidden_refs": v_hits, "program_forbidden_refs": p_hits,
               "reference_total_visible_to_worker": leak})

    inputs = {"fixture": rel(FIXTURE), "fixture_sha256": sha256_file(FIXTURE),
              "oracle_manifest": rel(ORACLE), "oracle_sha256": sha256_file(ORACLE),
              "program": "supplier_repair_v1", "program_digest": builtin_program("supplier_repair_v1").digest,
              "fault_injection_program": "supplier_repair_naive_v0",
              "fault_injection_digest": builtin_program("supplier_repair_naive_v0").digest}
    return write_evidence(cases, inputs)


if __name__ == "__main__":
    sys.exit(main())
