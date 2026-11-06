"""GovernedDispatcher: the ONLY path that can start a worker (EXEC-INV-01)."""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import time

from packages.admission.admission import AdmissionDenied, WorkerAdmission
from packages.admission.worker import WorkerRuntime
from packages.authority.gate import AuthorityGate
from packages.contracts.models import AuthorityDecision, ContextBinding, Decision, Program, sha256_bytes
from packages.contracts.state import TRANSITIONS, JobStateMachine, State


class GovernedDispatcher:
    def __init__(self, authority: AuthorityGate, admission: WorkerAdmission, worker: WorkerRuntime, db_path: str):
        self._authority = authority
        self._admission = admission
        self._worker = worker
        self._cap = admission.claim_issuer()
        self._lock = threading.Lock()
        self.events: list[dict] = []
        self._db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS dispatch_commits(attempt_id TEXT PRIMARY KEY, "
                         "decision_id TEXT NOT NULL UNIQUE, committed_at REAL NOT NULL)")

    def commit_count(self, attempt_id: str) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM dispatch_commits WHERE attempt_id=?", (attempt_id,)).fetchone()[0]

    def _result(self, sm, attempt_id, status, reason, output=None, token_hash=None) -> dict:
        r = {"attempt_id": attempt_id, "status": status, "reason": reason, "worker_invoked": sm.worker_invoked,
             "final_state": sm.state.value, "classification": sm.classification(), "state_trail": sm.trail(),
             "admission_token_sha256": token_hash, "output": output}
        self.events.append({"ts": time.time(), **{k: r[k] for k in ("attempt_id", "status", "reason", "worker_invoked", "final_state")}})
        return r

    def _refuse(self, sm, attempt_id, decision: Decision, status: str, reason: str) -> dict:
        if sm.state is not State.NO_DISPATCH:
            target = State.HOLD if decision is Decision.HOLD else State.DENY
            if target not in TRANSITIONS[sm.state]:
                target = State.DENY
            sm.advance(target, reason)
            sm.advance(State.NO_DISPATCH, "worker_invoked=false")
        return self._result(sm, attempt_id, status, reason)

    def dispatch(self, attempt_id: str, authorization, program: Program, context: ContextBinding,
                 *, input_bytes: bytes, sm: JobStateMachine) -> dict:
        if sm.state is State.NO_DISPATCH:
            return self._result(sm, attempt_id, "BLOCKED_PRE_EXECUTION", "AUTHORITY_REFUSED_BEFORE_DISPATCH")
        if sm.state is not State.AUTHORITY_EVALUATED:
            return self._result(sm, attempt_id, "BLOCKED_PRE_EXECUTION", f"STATE_ORDER_VIOLATION:{sm.state.value}")
        if not isinstance(authorization, AuthorityDecision) or authorization.decision is not Decision.ALLOW:
            return self._refuse(sm, attempt_id, Decision.DENY, "BLOCKED_PRE_EXECUTION", "NO_ALLOW_AUTHORIZATION")

        sm.advance(State.REVALIDATE_CURRENT_STATE, "dispatch-time revalidation (TOCTOU)")
        dec, reason = self._authority.revalidate(authorization, context)
        if dec is Decision.ALLOW and (program.digest != context.program_digest
                                      or sha256_bytes(input_bytes) != context.input_digest):
            dec, reason = Decision.DENY, "PAYLOAD_DIGEST_DRIFT"
        if dec is not Decision.ALLOW:
            return self._refuse(sm, attempt_id, dec, "BLOCKED_PRE_EXECUTION", reason)

        with self._lock:
            try:
                self._db.execute("INSERT INTO dispatch_commits VALUES (?, ?, ?)",
                                 (attempt_id, authorization.decision_id, time.time()))
            except sqlite3.IntegrityError:
                return self._refuse(sm, attempt_id, Decision.DENY, "REPLAY_BLOCKED", "DUPLICATE_DISPATCH_ATTEMPT_OR_DECISION")
        sm.advance(State.DISPATCH_COMMITTED, f"attempt={attempt_id}")

        token = self._admission.issue(self._cap, attempt_id=attempt_id, decision_id=authorization.decision_id,
                                      input_digest=context.input_digest, program_digest=context.program_digest)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        try:
            ticket = self._admission.admit(token, attempt_id=attempt_id, input_digest=context.input_digest,
                                           program_digest=context.program_digest)
        except AdmissionDenied as e:
            return self._refuse(sm, attempt_id, Decision.DENY, "BLOCKED_PRE_EXECUTION", f"ADMISSION_{e.code}")
        sm.advance(State.WORKER_ADMITTED, f"ticket={ticket.ticket_id[:8]}")
        sm.advance(State.EXECUTION)
        sm.mark_worker_invoked()
        try:
            output = self._worker.run(ticket, program, input_bytes)
        except Exception as e:
            sm.advance(State.SYSTEM_FAILURE, type(e).__name__)
            return self._result(sm, attempt_id, "SYSTEM_FAILURE", str(e), token_hash=token_hash)
        return self._result(sm, attempt_id, "EXECUTED_AWAITING_VERIFICATION", "ADMITTED_ONE_TIME", output, token_hash)
