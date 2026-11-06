"""Job state machine (KAIROS-VZ-EXEC-032 v3.2). Illegal transitions raise."""
from __future__ import annotations

import time
from enum import Enum


class State(str, Enum):
    WORK_PROPOSED = "WORK_PROPOSED"
    CONTEXT_BOUND = "CONTEXT_BOUND"
    AUTHORITY_EVALUATED = "AUTHORITY_EVALUATED"
    REVALIDATE_CURRENT_STATE = "REVALIDATE_CURRENT_STATE"
    DISPATCH_COMMITTED = "DISPATCH_COMMITTED"
    WORKER_ADMITTED = "WORKER_ADMITTED"
    EXECUTION = "EXECUTION"
    VERIFICATION = "VERIFICATION"
    BUSINESS_VERIFIED = "BUSINESS_VERIFIED"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    HOLD = "HOLD"
    DENY = "DENY"
    NO_DISPATCH = "NO_DISPATCH"
    CONTAINED_AT_RUNTIME = "CONTAINED_AT_RUNTIME"
    SYSTEM_FAILURE = "SYSTEM_FAILURE"
    EVIDENCE_RECEIPT = "EVIDENCE_RECEIPT"


S = State
TRANSITIONS: dict[State, set[State]] = {
    S.WORK_PROPOSED: {S.CONTEXT_BOUND},
    S.CONTEXT_BOUND: {S.AUTHORITY_EVALUATED},
    S.AUTHORITY_EVALUATED: {S.REVALIDATE_CURRENT_STATE, S.HOLD, S.DENY},
    S.REVALIDATE_CURRENT_STATE: {S.DISPATCH_COMMITTED, S.HOLD, S.DENY},
    S.DISPATCH_COMMITTED: {S.WORKER_ADMITTED, S.DENY, S.SYSTEM_FAILURE},
    S.WORKER_ADMITTED: {S.EXECUTION},
    S.EXECUTION: {S.VERIFICATION, S.CONTAINED_AT_RUNTIME, S.SYSTEM_FAILURE},
    S.VERIFICATION: {S.BUSINESS_VERIFIED, S.FAILED_VERIFICATION, S.REQUIRES_REVIEW},
    S.BUSINESS_VERIFIED: {S.EVIDENCE_RECEIPT},
    S.FAILED_VERIFICATION: {S.EVIDENCE_RECEIPT},
    S.REQUIRES_REVIEW: {S.EVIDENCE_RECEIPT},
    S.HOLD: {S.NO_DISPATCH},
    S.DENY: {S.NO_DISPATCH},
    S.NO_DISPATCH: {S.EVIDENCE_RECEIPT},
    S.CONTAINED_AT_RUNTIME: {S.EVIDENCE_RECEIPT},
    S.SYSTEM_FAILURE: {S.EVIDENCE_RECEIPT},
    S.EVIDENCE_RECEIPT: set(),
}
REFUSAL_STATES = {S.HOLD, S.DENY}


class IllegalTransition(Exception):
    pass


class InvariantViolation(Exception):
    pass


class JobStateMachine:
    def __init__(self, job_id: str):
        self.job_id = job_id
        self.state = S.WORK_PROPOSED
        self.worker_invoked = False
        self.history: list[dict] = [{"state": S.WORK_PROPOSED.value, "ts": time.time(), "note": "proposal created"}]

    @property
    def visited(self) -> set[State]:
        return {State(h["state"]) for h in self.history}

    def advance(self, to, note: str = "") -> None:
        to = State(to)
        if to not in TRANSITIONS[self.state]:
            raise IllegalTransition(f"{self.state.value} -> {to.value} is not permitted")
        self.state = to
        self.history.append({"state": to.value, "ts": time.time(), "note": note})

    def mark_worker_invoked(self) -> None:
        if self.state is not S.EXECUTION:
            raise InvariantViolation(f"worker_invoked may only be set in EXECUTION (now {self.state.value})")
        if self.visited & REFUSAL_STATES:
            raise InvariantViolation("worker_invoked is forbidden after HOLD/DENY")
        self.worker_invoked = True

    def classification(self) -> str:
        v = self.visited
        if S.NO_DISPATCH in v:
            return "BLOCKED_PRE_EXECUTION"
        if S.CONTAINED_AT_RUNTIME in v:
            return "CONTAINED_AT_RUNTIME"
        if S.SYSTEM_FAILURE in v:
            return "SYSTEM_FAILURE"
        for s in (S.BUSINESS_VERIFIED, S.FAILED_VERIFICATION, S.REQUIRES_REVIEW):
            if s in v:
                return s.value
        if S.EXECUTION in v:
            return "EXECUTED_AWAITING_VERIFICATION"
        return "IN_PROGRESS"

    def trail(self) -> list[str]:
        return [h["state"] for h in self.history]

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "state": self.state.value,
            "worker_invoked": self.worker_invoked,
            "classification": self.classification(),
            "history": list(self.history),
        }
