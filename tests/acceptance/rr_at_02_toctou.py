"""RR-AT-02 (RR-02): Stale or revoked authority at dispatch time is caught by revalidation (TOCTOU)."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.acceptance.common import Recorder, build_system, dispatch_job, new_job  # noqa: E402


def main() -> int:
    rec = Recorder("RR-AT-02", "TOCTOU and stale/revoked authority prevention (RR-02)",
                   "Authority granted at proposal time must be revalidated at dispatch boundary; changes or revocations block execution")
    with tempfile.TemporaryDirectory() as td:
        s = build_system(td)

        # Case 1: Revoked decision before dispatch
        j1 = new_job(s)
        s.store.revoke_decision(j1.decision.decision_id)
        r1 = dispatch_job(s, j1, "att-rr02-01")
        rec.check("C1", "Revoked decision ID before dispatch -> HOLD/DENY, worker_invoked=false",
                  r1["status"] == "BLOCKED_PRE_EXECUTION" and r1["reason"] == "AUTHORIZATION_REVOKED"
                  and r1["worker_invoked"] is False and s.worker.invocations == 0,
                  {k: r1[k] for k in ("status", "reason", "worker_invoked", "final_state")})

        # Case 2: Policy version changed between proposal and dispatch
        j2 = new_job(s)
        s.store.bump_policy_version("pol-2026.p0.2-revised")
        r2 = dispatch_job(s, j2, "att-rr02-02")
        rec.check("C2", "Policy version changed before dispatch -> HOLD, worker_invoked=false",
                  r2["status"] == "BLOCKED_PRE_EXECUTION" and r2["reason"] == "POLICY_VERSION_CHANGED"
                  and r2["worker_invoked"] is False and s.worker.invocations == 0,
                  {k: r2[k] for k in ("status", "reason", "worker_invoked", "final_state")})

        # Case 3: Context revision bumped (stale context)
        j3 = new_job(s)
        s.store.bump_context_revision(j3.proposal.project_id)
        r3 = dispatch_job(s, j3, "att-rr02-03")
        rec.check("C3", "Context revision bumped (stale context) -> HOLD, worker_invoked=false",
                  r3["status"] == "BLOCKED_PRE_EXECUTION" and r3["reason"] == "STALE_CONTEXT_REVISION"
                  and r3["worker_invoked"] is False and s.worker.invocations == 0,
                  {k: r3[k] for k in ("status", "reason", "worker_invoked", "final_state")})

        # Case 4: Payload / input digest drift between proposal and dispatch
        j4 = new_job(s)
        class DriftingJob:
            pass
        drift = DriftingJob()
        drift.program = j4.program
        drift.proposal = j4.proposal
        drift.ctx = j4.ctx
        drift.decision = j4.decision
        drift.sm = j4.sm
        drift.data = b"supplier_id,supplier_name,amount,currency\nS999,Tampered,999.00,THB\n"

        r4 = dispatch_job(s, drift, "att-rr02-04")
        rec.check("C4", "Input payload digest drift before dispatch -> DENY, worker_invoked=false",
                  r4["status"] == "BLOCKED_PRE_EXECUTION" and r4["reason"] == "PAYLOAD_DIGEST_DRIFT"
                  and r4["worker_invoked"] is False and s.worker.invocations == 0,
                  {k: r4[k] for k in ("status", "reason", "worker_invoked", "final_state")})
    return rec.finish()


if __name__ == "__main__":
    sys.exit(main())
