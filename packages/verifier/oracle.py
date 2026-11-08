"""Independent Business Verifier (EA-04).

Reads a sealed trusted reference from disk and checks the job artifacts written to disk.
It never imports, calls or trusts the repair program, and it never sees any agent prompt.
A clean process return is not business correctness.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path

from packages.contracts.state import JobStateMachine, State

BUSINESS_VERIFIED = "BUSINESS_VERIFIED"
FAILED_VERIFICATION = "FAILED_VERIFICATION"
REQUIRES_REVIEW = "REQUIRES_REVIEW"
ARTIFACTS = ("normalized.csv", "exceptions.csv", "job_summary.json")
NORMALIZED_FIELDS = ("supplier_id", "supplier_name", "tax_id", "invoice_date", "amount", "currency")
FORBIDDEN_CLAIMS = {"BUSINESS_VERIFIED", "VERIFIED_SUCCESS"}


class OracleIntegrityError(Exception):
    pass


@dataclass(frozen=True)
class TrustedReference:
    path: str
    sha256: str
    manifest: dict


@dataclass
class Verdict:
    classification: str
    reason: str
    checks: dict
    details: dict
    oracle_sha256: str | None
    input_sha256: str

    def to_dict(self) -> dict:
        return asdict(self)


def load_trusted_reference(manifest_path) -> TrustedReference:
    p = Path(manifest_path)
    seal = p.with_name(p.name + ".sha256")
    if not p.is_file():
        raise OracleIntegrityError("ORACLE_MISSING")
    if not seal.is_file():
        raise OracleIntegrityError("ORACLE_SEAL_MISSING")
    raw = p.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    sealed = (seal.read_text(encoding="utf-8").split() or [""])[0].strip().lower()
    if sealed != actual:
        raise OracleIntegrityError("ORACLE_SEAL_MISMATCH")
    return TrustedReference(str(p), "sha256:" + actual, json.loads(raw.decode("utf-8")))


def _dec(value):
    try:
        d = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError):
        return None
    return d if d.is_finite() else None


def _rows(text: str) -> list:
    return list(csv.DictReader(io.StringIO(text)))


def _key(x: str):
    return (len(x), x)


def _sr(row) -> str:
    return str(row.get("source_row") or "").strip()


class BusinessVerifier:
    def __init__(self, manifest_path):
        self.manifest_path = Path(manifest_path)

    def verify(self, input_bytes: bytes, artifact_dir) -> Verdict:
        input_sha = "sha256:" + hashlib.sha256(input_bytes).hexdigest()
        try:
            ref = load_trusted_reference(self.manifest_path)
        except (OracleIntegrityError, OSError, ValueError) as e:
            return Verdict(REQUIRES_REVIEW, f"NO_TRUSTED_REFERENCE:{e}", {"oracle_integrity": False}, {}, None, input_sha)
        try:
            return self._verify(ref, input_sha, Path(artifact_dir))
        except Exception as e:
            return Verdict(FAILED_VERIFICATION, f"VERIFIER_FAIL_CLOSED:{type(e).__name__}",
                           {"verifier_completed": False}, {"error": str(e)[:200]}, ref.sha256, input_sha)

    def _verify(self, ref: TrustedReference, input_sha: str, adir: Path) -> Verdict:
        exp = ref.manifest["expected"]
        checks = {"oracle_integrity": True}
        details: dict = {}

        covered = ref.manifest.get("input_sha256") == input_sha
        checks["input_covered_by_reference"] = covered
        if not covered:
            details["note"] = "the trusted reference does not cover this exact input; nothing can be certified"
            return Verdict(REQUIRES_REVIEW, "INPUT_NOT_COVERED_BY_TRUSTED_REFERENCE", checks, details, ref.sha256, input_sha)

        missing = [n for n in ARTIFACTS if not (adir / n).is_file()]
        checks["artifacts_complete"] = not missing
        if missing:
            details["missing_artifacts"] = missing
            return Verdict(FAILED_VERIFICATION, "MISSING_REQUIRED_ARTIFACT", checks, details, ref.sha256, input_sha)

        norm = _rows((adir / "normalized.csv").read_text(encoding="utf-8"))
        exc = _rows((adir / "exceptions.csv").read_text(encoding="utf-8"))
        summary = json.loads((adir / "job_summary.json").read_text(encoding="utf-8"))
        exp_norm = {str(r["source_row"]): r for r in exp["normalized"]}
        exp_rev = {str(r["source_row"]): r for r in exp["requires_review"]}
        expected_rows = set(exp_norm) | set(exp_rev)

        seen = [_sr(r) for r in norm] + [_sr(r) for r in exc]
        dupes = sorted({x for x in seen if seen.count(x) > 1}, key=_key)
        checks["row_accounting"] = (len(seen) == int(exp["input_rows"]) == len(expected_rows)
                                    and not dupes and set(seen) == expected_rows)
        details["row_accounting"] = {
            "expected_input_rows": int(exp["input_rows"]), "normalized_rows": len(norm), "review_rows": len(exc),
            "duplicate_source_rows": dupes,
            "missing_source_rows": sorted(expected_rows - set(seen), key=_key),
            "unexpected_source_rows": sorted(set(seen) - expected_rows, key=_key)}

        by_row = {_sr(r): r for r in norm}
        mism = []
        for sr, er in sorted(exp_norm.items(), key=lambda kv: _key(kv[0])):
            got = by_row.get(sr)
            if got is None:
                mism.append({"source_row": sr, "field": "*", "issue": "NOT_IN_NORMALIZED"})
                continue
            for f in NORMALIZED_FIELDS:
                observed = (got.get(f) or "").strip()
                if f == "amount":
                    g, e = _dec(observed), Decimal(str(er["amount"]))
                    ok = g is not None and g == e and g.as_tuple().exponent == -2
                else:
                    ok = observed == str(er[f])
                if not ok:
                    mism.append({"source_row": sr, "field": f, "expected": str(er[f]), "observed": observed})
        checks["normalized_values_match_reference"] = not mism
        details["value_mismatches"] = mism[:25]

        exc_by_row = {_sr(r): r for r in exc}
        routing = []
        for sr, er in sorted(exp_rev.items(), key=lambda kv: _key(kv[0])):
            want = sorted(er["reasons"])
            if sr in by_row:
                routing.append({"source_row": sr, "issue": "SILENTLY_REPAIRED_INTO_NORMALIZED", "expected_reasons": want})
            got = exc_by_row.get(sr)
            if got is None:
                if sr not in by_row:
                    routing.append({"source_row": sr, "issue": "NOT_ROUTED_TO_REVIEW", "expected_reasons": want})
                continue
            if (got.get("status") or "").strip() != REQUIRES_REVIEW:
                routing.append({"source_row": sr, "issue": "STATUS_NOT_REQUIRES_REVIEW", "observed": got.get("status")})
            have = sorted(x for x in (got.get("reason") or "").split("|") if x)
            if have != want:
                routing.append({"source_row": sr, "issue": "REASON_MISMATCH", "expected_reasons": want, "observed_reasons": have})
        checks["ambiguous_rows_routed_to_review"] = not routing
        details["routing_issues"] = routing[:25]
        details["rows_requiring_human_review"] = sorted(exp_rev, key=_key)

        exp_total = Decimal(str(exp["normalized_total"]))
        amounts = [_dec(r.get("amount") or "") for r in norm]
        bad = sum(1 for a in amounts if a is None)
        recomputed = sum((a for a in amounts if a is not None), Decimal("0.00"))
        checks["monetary_total_matches_reference"] = bad == 0 and recomputed == exp_total
        details["monetary_total"] = {"currency": ref.manifest.get("policy", {}).get("currency", "THB"),
                                     "expected": format(exp_total, "f"),
                                     "recomputed_from_normalized_csv": format(recomputed, "f"),
                                     "unparseable_amounts": bad}

        claimed = _dec(summary.get("normalized_total"))
        claim = str(summary.get("worker_claim", "")).upper()
        sc = {
            "input_sha256": summary.get("input_sha256") == input_sha,
            "input_rows": summary.get("input_rows") == int(exp["input_rows"]),
            "normalized_rows": summary.get("normalized_rows") == len(exp_norm) == len(norm),
            "review_rows": summary.get("review_rows") == len(exp_rev) == len(exc),
            "normalized_total": claimed is not None and claimed == exp_total,
            "no_self_certification": summary.get("self_certified") is not True and claim not in FORBIDDEN_CLAIMS,
        }
        checks["job_summary_consistent"] = all(sc.values())
        details["job_summary_checks"] = sc

        failed = [k for k, v in checks.items() if not v]
        if failed:
            return Verdict(FAILED_VERIFICATION, "BUSINESS_CHECKS_FAILED:" + ",".join(failed), checks, details,
                           ref.sha256, input_sha)
        return Verdict(BUSINESS_VERIFIED, "ALL_BUSINESS_CHECKS_PASSED", checks, details, ref.sha256, input_sha)


def apply_verdict(sm: JobStateMachine, verdict: Verdict) -> None:
    sm.advance(State.VERIFICATION, f"oracle={verdict.oracle_sha256}")
    sm.advance(State(verdict.classification), verdict.reason[:120])
