"""RR-AT-01 (RR-01 / EA-01): Upload creates only a WorkProposal. Without authority, dispatch yields HOLD/DENY and worker_invoked=false."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from packages.contracts.models import Decision  # noqa: E402
from packages.contracts.state import State  # noqa: E402
from tests.acceptance.common import Recorder, build_system, dispatch_job, new_job  # noqa: E402


def main() -> int:
    rec = Recorder("RR-AT-01", "Pre-execution denial (RR-01 / EA-01)",
                   "Upload or job creation never authorizes execution; unauthorized or invalid proposals yield HOLD/DENY and worker_invoked=false")
    with tempfile.TemporaryDirectory() as td:
        s = build_system(td)

        # Case 1: Unknown actor (unauthorized)
        job_bad_actor = new_job(s, actor="unauthorized-intruder")
        r1 = dispatch_job(s, job_bad_actor, "att-rr01-01")
        rec.check("C1", "Unknown actor -> DENY pre-execution, worker_invoked=false",
                  r1["status"] == "BLOCKED_PRE_EXECUTION" and r1["reason"] == "AUTHORITY_REFUSED_BEFORE_DISPATCH"
                  and r1["worker_invoked"] is False and s.worker.invocations == 0
                  and r1["final_state"] == State.NO_DISPATCH.value,
                  {k: r1[k] for k in ("status", "reason", "worker_invoked", "final_state", "state_trail")})

        # Case 2: Out of scope project
        s.store.add_actor("auditor-x", ["other-project"])
        job_out_scope = new_job(s, actor="auditor-x", project="supplier-repair-p0")
        r2 = dispatch_job(s, job_out_scope, "att-rr01-02")
        rec.check("C2", "Actor outside project scope -> DENY pre-execution, worker_invoked=false",
                  r2["status"] == "BLOCKED_PRE_EXECUTION" and r2["reason"] == "AUTHORITY_REFUSED_BEFORE_DISPATCH"
                  and r2["worker_invoked"] is False and s.worker.invocations == 0,
                  {k: r2[k] for k in ("status", "reason", "worker_invoked", "final_state")})

        # Case 3: Suspended / inactive actor status
        s.store.set_actor_status("rootz-operator", "suspended")
        job_suspended = new_job(s, actor="rootz-operator")
        r3 = dispatch_job(s, job_suspended, "att-rr01-03")
        rec.check("C3", "Suspended actor status -> DENY pre-execution, worker_invoked=false",
                  r3["status"] == "BLOCKED_PRE_EXECUTION" and r3["reason"] == "AUTHORITY_REFUSED_BEFORE_DISPATCH"
                  and r3["worker_invoked"] is False and s.worker.invocations == 0,
                  {k: r3[k] for k in ("status", "reason", "worker_invoked", "final_state")})

        # Restore operator status for remaining checks
        s.store.set_actor_status("rootz-operator", "active")
        job_valid = new_job(s)
        rec.check("C4", "WorkProposal and ContextBinding created successfully without invoking worker",
                  job_valid.proposal.proposal_id.startswith("wp_") and job_valid.sm.worker_invoked is False
                  and s.worker.invocations == 0,
                  {"proposal_id": job_valid.proposal.proposal_id, "worker_invoked": job_valid.sm.worker_invoked})
    return rec.finish()


if __name__ == "__main__":
    sys.exit(main())
