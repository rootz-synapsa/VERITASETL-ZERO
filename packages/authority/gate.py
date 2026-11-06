"""AuthorityGate: evaluates proposals and revalidates at dispatch time (TOCTOU)."""
from __future__ import annotations

import threading
import time

from packages.contracts.models import (
    AuthorityDecision, ContextBinding, Decision, Program, WorkProposal, new_id, sha256_bytes,
)
from packages.contracts.state import JobStateMachine, State


class PolicyStore:
    def __init__(self, policy_version: str = "pol-2026.p0.1"):
        self.lock = threading.RLock()
        self.policy_version = policy_version
        self.actors: dict[str, dict] = {}
        self.context_revisions: dict[str, int] = {}
        self.revoked_decisions: set[str] = set()

    def add_actor(self, actor_id: str, projects, status: str = "active") -> None:
        with self.lock:
            self.actors[actor_id] = {"status": status, "projects": set(projects)}
            for p in projects:
                self.context_revisions.setdefault(p, 1)

    def set_actor_status(self, actor_id: str, status: str) -> None:
        with self.lock:
            self.actors[actor_id]["status"] = status

    def revoke_decision(self, decision_id: str) -> None:
        with self.lock:
            self.revoked_decisions.add(decision_id)

    def bump_policy_version(self, new_version: str) -> None:
        with self.lock:
            self.policy_version = new_version

    def bump_context_revision(self, project_id: str) -> int:
        with self.lock:
            self.context_revisions[project_id] = self.context_revisions.get(project_id, 0) + 1
            return self.context_revisions[project_id]


class AuthorityGate:
    def __init__(self, store: PolicyStore, decision_ttl_s: float = 300.0):
        self.store = store
        self.decision_ttl_s = decision_ttl_s

    def propose(self, actor_id: str, project_id: str, input_bytes: bytes, program: Program):
        proposal = WorkProposal(
            proposal_id=new_id("wp"), actor_id=actor_id, project_id=project_id,
            input_digest=sha256_bytes(input_bytes), program_digest=program.digest, created_at=time.time(),
        )
        return proposal, JobStateMachine(proposal.proposal_id)

    def bind_context(self, proposal: WorkProposal, sm: JobStateMachine) -> ContextBinding:
        with self.store.lock:
            rev = self.store.context_revisions.get(proposal.project_id, 0)
        ctx = ContextBinding(proposal.project_id, rev, proposal.input_digest, proposal.program_digest)
        sm.advance(State.CONTEXT_BOUND, f"context_revision={rev}")
        return ctx

    def _check(self, actor_id, project_id, context_revision, input_digest, program_digest, ctx):
        actor = self.store.actors.get(actor_id)
        if actor is None:
            return Decision.DENY, "UNKNOWN_ACTOR"
        if actor["status"] != "active":
            return Decision.DENY, f"ACTOR_{actor['status'].upper()}"
        if project_id not in actor["projects"]:
            return Decision.DENY, "OUT_OF_SCOPE_PROJECT"
        current = self.store.context_revisions.get(project_id)
        if current is None:
            return Decision.DENY, "UNKNOWN_PROJECT"
        if context_revision != current:
            return Decision.HOLD, "STALE_CONTEXT_REVISION"
        if input_digest != ctx.input_digest or program_digest != ctx.program_digest:
            return Decision.DENY, "DIGEST_MISMATCH"
        return Decision.ALLOW, "POLICY_SATISFIED"

    def evaluate(self, proposal: WorkProposal, ctx: ContextBinding, sm: JobStateMachine) -> AuthorityDecision:
        with self.store.lock:
            dec, reason = self._check(proposal.actor_id, proposal.project_id, ctx.context_revision,
                                      proposal.input_digest, proposal.program_digest, ctx)
            now = time.time()
            decision = AuthorityDecision(
                decision_id=new_id("ad"), proposal_id=proposal.proposal_id, decision=dec, reason=reason,
                actor_id=proposal.actor_id, project_id=proposal.project_id,
                policy_version=self.store.policy_version, context_revision=ctx.context_revision,
                input_digest=proposal.input_digest, program_digest=proposal.program_digest,
                issued_at=now, expires_at=now + self.decision_ttl_s,
            )
        sm.advance(State.AUTHORITY_EVALUATED, f"{dec.value}:{reason}")
        if dec is not Decision.ALLOW:
            sm.advance(State(dec.value), reason)
            sm.advance(State.NO_DISPATCH, "worker_invoked=false")
        return decision

    def revalidate(self, d, ctx: ContextBinding):
        if not isinstance(d, AuthorityDecision):
            return Decision.DENY, "NO_AUTHORIZATION"
        with self.store.lock:
            if d.decision is not Decision.ALLOW:
                return d.decision, "DECISION_NOT_ALLOW"
            if time.time() > d.expires_at:
                return Decision.HOLD, "AUTHORIZATION_EXPIRED"
            if d.decision_id in self.store.revoked_decisions:
                return Decision.DENY, "AUTHORIZATION_REVOKED"
            if d.policy_version != self.store.policy_version:
                return Decision.HOLD, "POLICY_VERSION_CHANGED"
            if d.context_revision != ctx.context_revision:
                return Decision.HOLD, "CONTEXT_REVISION_MISMATCH"
            return self._check(d.actor_id, d.project_id, d.context_revision, d.input_digest, d.program_digest, ctx)
